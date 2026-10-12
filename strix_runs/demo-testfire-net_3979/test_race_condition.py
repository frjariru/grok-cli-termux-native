"""
Módulo de mitigación de condiciones de carrera (Race Conditions) y pruebas unitarias de concurrencia.

Basado en el informe de vulnerabilidad:
- vuln-0016: Race condition (non-atomic balance read-modify-write) en POST /api/transfer (CWE-362).
  Múltiples peticiones concurrentes leen el mismo balance no bloqueado en memoria,
  evalúan la suficiencia de fondos sobre un snapshot obsoleto y sobrescriben las actualizaciones,
  permitiendo el gasto duplicado del mismo dinero (double-spend) o inconsistencias contables graves.

Por qué BEGIN IMMEDIATE es necesario frente a BEGIN (DEFERRED) en SQLite:
-------------------------------------------------------------------------
En SQLite, el modo de transacción por defecto es DEFERRED:
  1. Al iniciar con 'BEGIN' (o DEFERRED), la transacción NO adquiere ningún bloqueo
     sobre la base de datos de forma inmediata.
  2. Al ejecutar 'SELECT balance', SQLite adquiere únicamente un bloqueo compartido (SHARED lock).
     Múltiples hilos o conexiones concurrentes pueden adquirir simultáneamente este SHARED lock
     y leer el mismo balance pre-transferencia.
  3. Cuando ambos hilos intentan ejecutar la escritura ('UPDATE accounts SET balance = ...'),
     cada uno necesita escalar su bloqueo a RESERVED / EXCLUSIVE.
  4. Como el otro hilo mantiene un SHARED lock activo, ninguno puede completar la escalada,
     provocando bloqueos mutuos (deadlock con error 'database is locked') o, si no hay aislamiento,
     actualizaciones perdidas (lost updates).

Por el contrario, con 'BEGIN IMMEDIATE':
  1. SQLite adquiere un bloqueo reservado (RESERVED lock) de manera INMEDIATA al iniciar la transacción,
     antes de ejecutar cualquier sentencia SQL.
  2. Ninguna otra conexión o hilo puede iniciar otra transacción de escritura concurrentemente.
  3. Cuando el hilo ejecuta 'SELECT balance', ya cuenta con la reserva exclusiva de escritura,
     garantizando que la lectura del saldo ocurra DESPUÉS de adquirir el lock y sobre el estado real.
  4. Los hilos competidores esperan en cola de forma serializada y, al adquirir el lock en su turno,
     leen el balance ya actualizado y deducido por la transacción previa, rechazando el double-spend.

Este archivo contiene:
  1. `atomic_transfer`: Función de referencia thread-safe que implementa BEGIN IMMEDIATE y lock de concurrencia.
  2. `non_atomic_transfer`: Versión vulnerable que realiza read-then-write sin lock.
  3. Suites de pruebas unitarias (`unittest`):
     - Simulación de transferencias concurrentes repetidas N=20 veces con `threading.Barrier`.
     - Demostración de vulnerabilidad y double-spend en la versión no atómica (AssertionError).
     - Casos límite: transferencias secuenciales y concurrencia con múltiples hilos (3+).
"""

import sqlite3
import threading
import time
import unittest
from typing import Any, List, Optional

# Lock global para serializar operaciones sobre conexiones SQLite compartidas en Python
_GLOBAL_DB_LOCK = threading.Lock()


def init_db(conn: sqlite3.Connection) -> None:
    """Crea la estructura de tablas para las pruebas de transferencias concurrentes."""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            balance REAL NOT NULL DEFAULT 0.0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_account INTEGER NOT NULL,
            to_account INTEGER NOT NULL,
            amount REAL NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (from_account) REFERENCES accounts (id),
            FOREIGN KEY (to_account) REFERENCES accounts (id)
        )
    """)
    cursor.execute("PRAGMA busy_timeout = 5000")


def atomic_transfer(
    from_id: Any,
    to_id: Any,
    amount: Any,
    conn: sqlite3.Connection,
    lock: Optional[threading.Lock] = None
) -> bool:
    """
    Ejecuta una transferencia bancaria atómica y thread-safe mitigando CWE-362.

    Garantías de seguridad:
      1. Adquisición de lock de exclusión mutua para sincronizar el acceso concurrente.
      2. Inicio explícito de transacción mediante 'BEGIN IMMEDIATE'.
      3. Verificación del balance disponible DESPUÉS de haber adquirido el lock de escritura.
      4. Si el saldo es insuficiente, ejecuta ROLLBACK y retorna False.
      5. Si hay fondos suficientes, aplica el débito, crédito y registro, finalizando con COMMIT.

    Parámetros:
        from_id: Identificador de la cuenta origen (débito).
        to_id: Identificador de la cuenta destino (crédito).
        amount: Monto a transferir (debe ser estrictamente positivo).
        conn: Conexión SQLite compartida configurada con check_same_thread=False.
        lock: Lock de threading opcional (usa _GLOBAL_DB_LOCK por defecto).

    Retorna:
        bool: True si la transferencia fue exitosa; False si falló por saldo insuficiente.

    Lanza:
        ValueError: Si los datos de entrada son inválidos (monto <= 0, from_id == to_id, cuentas inexistentes).
    """
    if amount is None:
        raise ValueError("El monto no puede ser nulo.")

    try:
        clean_amount = round(float(amount), 2)
    except (ValueError, TypeError):
        raise ValueError(f"Monto inválido: {amount}")

    if clean_amount <= 0.0:
        raise ValueError(f"El monto debe ser estrictamente positivo (> 0). Valor recibido: {clean_amount}")

    try:
        from_account_id = int(from_id)
        to_account_id = int(to_id)
    except (ValueError, TypeError):
        raise ValueError("Los identificadores de cuenta deben ser enteros.")

    if from_account_id == to_account_id:
        raise ValueError("No se permite auto-transferencia: origen y destino son idénticos.")

    use_lock = lock if lock is not None else _GLOBAL_DB_LOCK

    with use_lock:
        cursor = conn.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        try:
            # 1. Leer balances DESPUÉS de haber adquirido el lock
            cursor.execute("SELECT balance FROM accounts WHERE id = ?", (from_account_id,))
            from_row = cursor.fetchone()
            if from_row is None:
                cursor.execute("ROLLBACK")
                raise ValueError(f"La cuenta de origen {from_account_id} no existe.")

            from_balance = from_row[0]

            cursor.execute("SELECT balance FROM accounts WHERE id = ?", (to_account_id,))
            to_row = cursor.fetchone()
            if to_row is None:
                cursor.execute("ROLLBACK")
                raise ValueError(f"La cuenta de destino {to_account_id} no existe.")

            # 2. Comprobar fondos disponibles con el valor bloqueado
            if from_balance < clean_amount:
                cursor.execute("ROLLBACK")
                return False

            # 3. Aplicar mutaciones atómicas en el libro mayor
            new_from = round(from_balance - clean_amount, 2)
            cursor.execute(
                "UPDATE accounts SET balance = ? WHERE id = ?",
                (new_from, from_account_id)
            )
            cursor.execute(
                "UPDATE accounts SET balance = round(balance + ?, 2) WHERE id = ?",
                (clean_amount, to_account_id)
            )
            cursor.execute(
                "INSERT INTO transactions (from_account, to_account, amount) VALUES (?, ?, ?)",
                (from_account_id, to_account_id, clean_amount)
            )
            cursor.execute("COMMIT")
            return True
        except Exception:
            try:
                cursor.execute("ROLLBACK")
            except Exception:
                pass
            raise


_SQL_STMT_LOCK = threading.Lock()


def non_atomic_transfer(
    from_id: Any,
    to_id: Any,
    amount: Any,
    conn: sqlite3.Connection,
    delay: float = 0.01
) -> bool:
    """
    Versión vulnerable de referencia (read-then-write sin lock de transacción ni BEGIN IMMEDIATE).
    Modela el fallo de vuln-0016:
      1. Lee el balance actual en memoria sin lock transaccional.
      2. Evalúa 'balance >= amount' sobre un snapshot obsoleto.
      3. Experimenta una ventana de tiempo (delay / context switch).
      4. Escribe el nuevo balance calculado en memoria, permitiendo que múltiples
         hilos gasten concurrentemente los mismos fondos (double-spend).
    """
    clean_amount = round(float(amount), 2)
    from_account_id = int(from_id)
    to_account_id = int(to_id)

    # 1. Lectura del balance SIN bloqueo transaccional
    with _SQL_STMT_LOCK:
        cursor = conn.cursor()
        cursor.execute("SELECT balance FROM accounts WHERE id = ?", (from_account_id,))
        from_row = cursor.fetchone()
        if from_row is None:
            raise ValueError("Cuenta origen no encontrada")
        from_balance = from_row[0]

        cursor.execute("SELECT balance FROM accounts WHERE id = ?", (to_account_id,))
        to_row = cursor.fetchone()
        if to_row is None:
            raise ValueError("Cuenta destino no encontrada")

    # 2. Verificación sobre snapshot desactualizado
    if from_balance < clean_amount:
        return False

    # 3. Ventana de concurrencia: permite que otro hilo lea el mismo saldo antes de la escritura
    if delay > 0:
        time.sleep(delay)

    # 4. Escritura ciega del balance calculado en aplicación (lost update / double-spend)
    new_from = round(from_balance - clean_amount, 2)
    with _SQL_STMT_LOCK:
        cursor = conn.cursor()
        cursor.execute("UPDATE accounts SET balance = ? WHERE id = ?", (new_from, from_account_id))
        cursor.execute("UPDATE accounts SET balance = round(balance + ?, 2) WHERE id = ?", (clean_amount, to_account_id))
        cursor.execute(
            "INSERT INTO transactions (from_account, to_account, amount) VALUES (?, ?, ?)",
            (from_account_id, to_account_id, clean_amount)
        )
        conn.commit()
    return True


class BaseRaceConditionTestCase(unittest.TestCase):
    """
    Clase base para pruebas de concurrencia en SQLite en memoria.
    Configura conexiones con check_same_thread=False y modo de aislamiento manual.
    """

    def setUp(self):
        """Inicializa una base de datos en memoria con soporte multi-hilo."""
        self.conn = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        init_db(self.conn)
        self.test_lock = threading.Lock()

        # Cuentas de prueba:
        # Cuenta 1: saldo inicial $100.0
        # Cuenta 2: saldo inicial $0.0
        self.acc1 = 1
        self.acc2 = 2

        self.conn.execute("INSERT INTO accounts (id, user_id, balance) VALUES (1, 101, 100.0)")
        self.conn.execute("INSERT INTO accounts (id, user_id, balance) VALUES (2, 102, 0.0)")

    def tearDown(self):
        """Cierra la conexión a la base de datos."""
        self.conn.close()

    def get_balance(self, account_id: int) -> float:
        """Helper para consultar el balance persistido de una cuenta."""
        cur = self.conn.cursor()
        cur.execute("SELECT balance FROM accounts WHERE id = ?", (account_id,))
        row = cur.fetchone()
        return row[0] if row else 0.0

    def reset_balances(self, bal1: float = 100.0, bal2: float = 0.0):
        """Helper para reestablecer los balances a su estado inicial."""
        self.conn.execute("UPDATE accounts SET balance = ? WHERE id = ?", (bal1, self.acc1))
        self.conn.execute("UPDATE accounts SET balance = ? WHERE id = ?", (bal2, self.acc2))
        self.conn.execute("DELETE FROM transactions")


class TestAtomicTransferConcurrency(BaseRaceConditionTestCase):
    """
    Pruebas unitarias de concurrencia que verifican que `atomic_transfer`:
      - Evita el double-spend (saldo inicial 100, dos transferencias de 80 -> solo 1 tiene éxito).
      - Mantiene el saldo de la cuenta origen en valor positivo (nunca negativo).
      - Conserva el saldo total del sistema.
      - Supera N=20 repeticiones continuas con barrera de sincronización.
    """

    def test_two_concurrent_transfers_prevent_double_spend_repeated_20_times(self):
        """
        Simula DOS transferencias concurrentes de $80 desde una cuenta con balance inicial de $100.
        Se repite N=20 veces sincronizando el arranque de los hilos mediante threading.Barrier.
        
        Verificaciones estrictas en cada iteración:
          1. Exactamente UNA transferencia tiene éxito (retorna True).
          2. La otra transferencia es rechazada por fondos insuficientes (retorna False).
          3. El balance final de la cuenta origen queda en $20.0 (nunca negativo).
          4. El balance de la cuenta destino queda en $80.0.
          5. El balance total del sistema se conserva estrictamente en $100.0.
        """
        iterations = 20

        for i in range(iterations):
            self.reset_balances(100.0, 0.0)

            barrier = threading.Barrier(2)
            results: List[bool] = []
            results_lock = threading.Lock()

            def worker():
                # Esperar a que ambos hilos estén listos para competir exactamente al mismo tiempo
                barrier.wait()
                success = atomic_transfer(
                    self.acc1,
                    self.acc2,
                    80.0,
                    self.conn,
                    lock=self.test_lock
                )
                with results_lock:
                    results.append(success)

            thread_a = threading.Thread(target=worker)
            thread_b = threading.Thread(target=worker)

            thread_a.start()
            thread_b.start()

            thread_a.join()
            thread_b.join()

            bal_from = self.get_balance(self.acc1)
            bal_to = self.get_balance(self.acc2)
            total_system = round(bal_from + bal_to, 2)

            # Aserción 1: Solo una transferencia debe haber sido aprobada
            self.assertEqual(
                results.count(True),
                1,
                f"Iteración {i+1}: Condición de carrera detectada. Debió aprobarse exactamente 1 transferencia, "
                f"pero se aprobaron {results.count(True)}."
            )
            self.assertEqual(
                results.count(False),
                1,
                f"Iteración {i+1}: La segunda transferencia debió ser rechazada con False."
            )

            # Aserción 2: El saldo origen nunca debe ser negativo
            self.assertGreaterEqual(
                bal_from,
                0.0,
                f"Iteración {i+1}: El saldo de la cuenta origen quedó en negativo: {bal_from}."
            )
            self.assertEqual(
                bal_from,
                20.0,
                f"Iteración {i+1}: Saldo origen incorrecto ({bal_from} != 20.0)."
            )

            # Aserción 3: Saldo destino correcto
            self.assertEqual(
                bal_to,
                80.0,
                f"Iteración {i+1}: Saldo destino incorrecto ({bal_to} != 80.0)."
            )

            # Aserción 4: Conservación del saldo total del sistema
            self.assertEqual(
                total_system,
                100.0,
                f"Iteración {i+1}: El dinero total del sistema cambió ({total_system} != 100.0)."
            )


class TestVulnerableSimulationDoubleSpend(BaseRaceConditionTestCase):
    """
    Simulación de la vulnerabilidad reportada en vuln-0016:
    Demuestra que una función no atómica (read-then-write sin lock) permite double-spend,
    provocando que las aserciones de protección fallen con `AssertionError`.
    """

    def test_non_atomic_version_permits_double_spend_and_breaks_ledger(self):
        """
        Demuestra la explotación de vuln-0016:
        Con saldo inicial de $100, dos transferencias concurrentes de $80 con la versión no atómica:
          1. Ambas leen el saldo de $100 antes de que la otra escriba.
          2. Ambas evalúan '100 >= 80' como verdadero y retornan True (éxito).
          3. La cuenta destino recibe $160 en total ($80 + $80), duplicando el gasto permitido.
          4. El saldo total del sistema se incrementa espuriamente ($20 + $160 = $180), violando
             la conservación del dinero.
        
        Las aserciones de seguridad fallan lanzando `AssertionError`.
        """
        self.reset_balances(100.0, 0.0)

        barrier = threading.Barrier(2)
        results: List[bool] = []
        results_lock = threading.Lock()

        def worker():
            barrier.wait()
            success = non_atomic_transfer(
                self.acc1,
                self.acc2,
                80.0,
                self.conn,
                delay=0.01  # Pequeño retardo que simula I/O y expone la ventana de concurrencia
            )
            with results_lock:
                results.append(success)

        thread_a = threading.Thread(target=worker)
        thread_b = threading.Thread(target=worker)

        thread_a.start()
        thread_b.start()

        thread_a.join()
        thread_b.join()

        bal_from = self.get_balance(self.acc1)
        bal_to = self.get_balance(self.acc2)
        total_system = round(bal_from + bal_to, 2)

        # 1. Ambos hilos tuvieron éxito (double-spend confirmado)
        self.assertEqual(results, [True, True])

        # 2. La cuenta destino recibió dos veces el dinero ($160)
        self.assertEqual(bal_to, 160.0)

        # 3. La aserción de que solo una transferencia tuvo éxito DISPARA AssertionError
        with self.assertRaises(AssertionError):
            self.assertEqual(
                results.count(True),
                1,
                "Fallo esperado: la versión vulnerable permitió que ambas transferencias tuvieran éxito."
            )

        # 4. La aserción de conservación del saldo total del sistema DISPARA AssertionError
        # El sistema pasó de $100 iniciales a $180 ($80 creados artificialmente)
        with self.assertRaises(AssertionError):
            self.assertEqual(
                total_system,
                100.0,
                "Fallo esperado: la versión vulnerable alteró la masa monetaria total del sistema."
            )


class TestConcurrencyEdgeCases(BaseRaceConditionTestCase):
    """
    Pruebas para casos límite:
      - Transferencias secuenciales (no concurrentes) se procesan correctamente.
      - Concurrencia con 3 o más hilos simultáneos (ej: 5 hilos compitiendo por saldo limitado).
      - Validación de parámetros y excepciones.
    """

    def test_sequential_transfers_always_succeed_until_funds_exhausted(self):
        """
        Caso límite: ejecuciones secuenciales sin concurrencia.
        Balance inicial $100:
          - Transf 1: $40 -> Éxito (queda $60).
          - Transf 2: $40 -> Éxito (queda $20).
          - Transf 3: $40 -> Rechazada por fondos insuficientes (False, queda $20).
        """
        # Primera transferencia secuencial
        res1 = atomic_transfer(self.acc1, self.acc2, 40.0, self.conn, lock=self.test_lock)
        self.assertTrue(res1)
        self.assertEqual(self.get_balance(self.acc1), 60.0)
        self.assertEqual(self.get_balance(self.acc2), 40.0)

        # Segunda transferencia secuencial
        res2 = atomic_transfer(self.acc1, self.acc2, 40.0, self.conn, lock=self.test_lock)
        self.assertTrue(res2)
        self.assertEqual(self.get_balance(self.acc1), 20.0)
        self.assertEqual(self.get_balance(self.acc2), 80.0)

        # Tercera transferencia secuencial (fondos insuficientes: 40 > 20)
        res3 = atomic_transfer(self.acc1, self.acc2, 40.0, self.conn, lock=self.test_lock)
        self.assertFalse(res3)
        self.assertEqual(self.get_balance(self.acc1), 20.0)
        self.assertEqual(self.get_balance(self.acc2), 80.0)

        # Conservación del total
        self.assertEqual(self.get_balance(self.acc1) + self.get_balance(self.acc2), 100.0)

    def test_concurrency_with_multiple_threads_high_contention(self):
        """
        Caso límite: alta concurrencia con 5 hilos compitiendo simultáneamente.
        Balance inicial: $100.0.
        Cada hilo intenta transferir $30.0.
        
        Comportamiento esperado:
          - Exactamente 3 transferencias pueden tener éxito (3 x $30 = $90).
          - Exactamente 2 transferencias deben ser rechazadas por falta de fondos ($10 < $30).
          - Saldo final origen: $10.0 (nunca negativo).
          - Saldo final destino: $90.0.
          - Saldo total del sistema: $100.0 (estrictamente conservado).
        """
        num_threads = 5
        transfer_amount = 30.0
        barrier = threading.Barrier(num_threads)
        results: List[bool] = []
        results_lock = threading.Lock()

        def worker():
            barrier.wait()
            success = atomic_transfer(
                self.acc1,
                self.acc2,
                transfer_amount,
                self.conn,
                lock=self.test_lock
            )
            with results_lock:
                results.append(success)

        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Verificaciones
        self.assertEqual(results.count(True), 3, "Deben aprobarse exactamente 3 transferencias de $30.")
        self.assertEqual(results.count(False), 2, "Deben rechazarse exactamente 2 transferencias por falta de saldo.")
        self.assertEqual(self.get_balance(self.acc1), 10.0, "El saldo restante debe ser de $10.0.")
        self.assertEqual(self.get_balance(self.acc2), 90.0, "El saldo acreditado debe ser de $90.0.")
        self.assertEqual(self.get_balance(self.acc1) + self.get_balance(self.acc2), 100.0)

    def test_invalid_arguments_raise_value_error(self):
        """
        Valida que parámetros inválidos levanten ValueError inmediatamente:
          - Monto menor o igual a cero.
          - Auto-transferencia.
          - Cuentas no existentes.
        """
        with self.assertRaises(ValueError):
            atomic_transfer(self.acc1, self.acc2, -10.0, self.conn, lock=self.test_lock)

        with self.assertRaises(ValueError):
            atomic_transfer(self.acc1, self.acc2, 0.0, self.conn, lock=self.test_lock)

        with self.assertRaises(ValueError):
            atomic_transfer(self.acc1, self.acc1, 50.0, self.conn, lock=self.test_lock)

        with self.assertRaises(ValueError):
            atomic_transfer(9999, self.acc2, 50.0, self.conn, lock=self.test_lock)

        with self.assertRaises(ValueError):
            atomic_transfer(self.acc1, 9999, 50.0, self.conn, lock=self.test_lock)


if __name__ == "__main__":
    unittest.main()
