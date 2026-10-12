"""
Módulo de validación de lógica de negocio y pruebas unitarias para transferencias bancarias.

Basado en los informes de vulnerabilidad:
- vuln-0011: Transferencias con montos negativos (CWE-1284) en POST /api/transfer.
             La omisión de validación de signo permite revertir el flujo de fondos,
             restando saldo de la cuenta de destino y sumándolo a la cuenta de origen.
- vuln-0014: Auto-transferencias (CWE-682) en POST /bank/doTransfer y POST /api/transfer.
             Cuando la cuenta de origen y destino son la misma (from == to), la falta
             de validación en el servidor permite crear / inflar dinero de la nada.

Este archivo contiene:
1. `validate_and_execute_transfer(from_id, to_id, amount, cursor)`:
   Función de referencia segura con validación estricta de lógica de negocio y
   ejecución atómica (BEGIN / COMMIT / ROLLBACK).
2. `vulnerable_transfer(from_id, to_id, amount, cursor)`:
   Versión vulnerable de referencia que modela la falta de verificación de signo
   (solo evalúa 'amount > balance').
3. Suites de pruebas unitarias (`unittest`) con SQLite en memoria (:memory:) que verifican:
   - Casos de rechazo (negativos, cero, auto-transferencia, fondos insuficientes,
     cuentas inexistentes, cuentas no autorizadas).
   - Controles positivos (balances actualizados, saldo exacto, decimales).
   - Casos límite (saldo cero, mínimo 0.01, conservación global del dinero).
   - Simulación de vulnerabilidad que demuestra que la versión insegura suma fondos
     ante montos negativos (provocando `AssertionError`).
"""

import math
import sqlite3
import unittest
from typing import Any, Dict, Optional


def init_db(conn: sqlite3.Connection) -> None:
    """
    Crea las tablas relacionales mínimas requeridas para el libro contable de transferencias:
      - accounts: identificador de cuenta, usuario propietario y saldo actual.
      - transactions: registro de auditoría de cada transferencia ejecutada.
    """
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
    conn.commit()


def validate_and_execute_transfer(
    from_id: Any,
    to_id: Any,
    amount: Any,
    cursor: sqlite3.Cursor,
    user_id: Optional[Any] = None,
    current_user_id: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Valida y ejecuta una transferencia entre dos cuentas bancarias de forma atómica.

    Reglas de lógica de negocio aplicadas:
      1. Monto positivo finito: amount debe ser un número real strictly > 0 (rechaza montos <= 0).
      2. Diferenciación de cuentas: from_id != to_id (prohíbe auto-transferencias, vuln-0014).
      3. Existencia de cuentas: tanto from_id como to_id deben existir en la tabla 'accounts'.
      4. Autorización sobre origen: si se suministra el usuario de sesión, from_id debe
         pertenecer a dicho usuario.
      5. Fondos suficientes: amount <= balance de la cuenta origen (sin sobregiro no autorizado).
      6. Atomicidad: ejecución dentro de una transacción (BEGIN / COMMIT / ROLLBACK).
      7. Auditoría: inserción en el registro 'transactions'.

    Parámetros:
        from_id: Identificador de la cuenta bancaria de origen (débito).
        to_id: Identificador de la cuenta bancaria de destino (crédito).
        amount: Monto monetario a transferir.
        cursor: Cursor o conexión SQLite.
        user_id (opcional): Identificador del usuario autenticado en la sesión.
        current_user_id (opcional): Alias de user_id.

    Retorna:
        dict: Diccionario con el balance actualizado de la cuenta origen y resumen de la operación.

    Lanza:
        ValueError: Si cualquier validación de negocio falla.
    """
    # Manejar paso de conexión en lugar de cursor
    if hasattr(cursor, "cursor") and callable(cursor.cursor):
        conn = cursor
        cursor = cursor.cursor()
    else:
        conn = cursor.connection

    # Resolver el usuario de sesión esperado
    if user_id is None and current_user_id is not None:
        user_id = current_user_id
    if user_id is None:
        user_id = getattr(cursor, "current_user_id", None)
    if user_id is None and hasattr(conn, "current_user_id"):
        user_id = getattr(conn, "current_user_id", None)

    # 1. Validación del monto monetario
    if amount is None:
        raise ValueError("El monto de la transferencia no puede ser nulo.")

    try:
        numeric_amount = float(amount)
    except (ValueError, TypeError):
        raise ValueError(f"El monto '{amount}' no es un valor numérico válido.")

    if math.isnan(numeric_amount) or math.isinf(numeric_amount):
        raise ValueError("El monto debe ser un número finito válido.")

    # Mitigación vuln-0011: rechazar montos negativos o cero
    if numeric_amount <= 0.0:
        raise ValueError(
            f"El monto de la transferencia debe ser estrictamente positivo (> 0). "
            f"Valor recibido: {numeric_amount}."
        )

    # Precisión a centavos estándar
    clean_amount = round(numeric_amount, 2)
    if clean_amount <= 0.0:
        raise ValueError("El monto mínimo transferible es de 0.01.")

    # 2. Validación de identificadores de cuenta y auto-transferencia
    try:
        from_account_id = int(from_id)
        to_account_id = int(to_id)
    except (ValueError, TypeError):
        raise ValueError("Los identificadores de cuenta deben ser números enteros válidos.")

    # Mitigación vuln-0014: auto-transferencias (misma cuenta origen y destino)
    if from_account_id == to_account_id:
        raise ValueError(
            f"No se permite transferir fondos hacia la misma cuenta: origen {from_account_id} "
            f"y destino {to_account_id} no pueden ser la misma (auto-transferencia rechazada)."
        )

    # 3. Validación de existencia de cuentas en la base de datos
    cursor.execute("SELECT user_id, balance FROM accounts WHERE id = ?", (from_account_id,))
    from_row = cursor.fetchone()
    if from_row is None:
        raise ValueError(f"La cuenta de origen {from_account_id} no existe en el sistema.")

    from_owner_id, from_balance = from_row

    cursor.execute("SELECT user_id, balance FROM accounts WHERE id = ?", (to_account_id,))
    to_row = cursor.fetchone()
    if to_row is None:
        raise ValueError(f"La cuenta de destino {to_account_id} no existe en el sistema.")

    to_owner_id, to_balance = to_row

    # 4. Verificación de titularidad de la cuenta de origen (control de acceso de sesión)
    if user_id is not None:
        try:
            expected_user_id = int(user_id)
        except (ValueError, TypeError):
            raise ValueError("Identificador de usuario de sesión no válido.")

        if int(from_owner_id) != expected_user_id:
            raise ValueError(
                f"Acceso denegado: la cuenta de origen {from_account_id} pertenece al usuario "
                f"{from_owner_id}, no al usuario autenticado {expected_user_id}."
            )

    # 5. Verificación de fondos disponibles (insufficient-funds check)
    if clean_amount > from_balance:
        raise ValueError(
            f"Fondos insuficientes: el saldo disponible en la cuenta origen ({from_balance}) "
            f"es menor que el monto solicitado ({clean_amount})."
        )

    # 6. Ejecución atómica de la transferencia (débito, crédito y registro)
    new_from_balance = round(from_balance - clean_amount, 2)
    new_to_balance = round(to_balance + clean_amount, 2)

    try:
        cursor.execute("BEGIN")
        cursor.execute(
            "UPDATE accounts SET balance = ? WHERE id = ?",
            (new_from_balance, from_account_id)
        )
        cursor.execute(
            "UPDATE accounts SET balance = ? WHERE id = ?",
            (new_to_balance, to_account_id)
        )
        cursor.execute(
            "INSERT INTO transactions (from_account, to_account, amount) VALUES (?, ?, ?)",
            (from_account_id, to_account_id, clean_amount)
        )
        conn.commit()
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        raise ValueError(f"Error al procesar la transferencia atómica: {exc}") from exc

    return {
        "from_account": from_account_id,
        "to_account": to_account_id,
        "amount": clean_amount,
        "from_balance": new_from_balance,
        "to_balance": new_to_balance,
        "new_balance": new_from_balance,
    }


def vulnerable_transfer(
    from_id: Any,
    to_id: Any,
    amount: Any,
    cursor: sqlite3.Cursor,
    user_id: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Versión vulnerable de referencia que replica el defecto de lógica de negocio
    documentado en vuln-0011 y vuln-0014.

    Defectos simulados:
      - Solo verifica si 'amount > balance'. Si amount es negativo (ej: -100), la condición
        '-100 > balance' es False, permitiendo la transferencia.
      - Al restar un monto negativo: balance - (-100) = balance + 100, la cuenta origen SUMA dinero
        en lugar de restarlo, debitando arbitrariamente la cuenta destino.
      - No valida si from_id == to_id (auto-transferencia).
    """
    if hasattr(cursor, "cursor") and callable(cursor.cursor):
        conn = cursor
        cursor = cursor.cursor()
    else:
        conn = cursor.connection

    cursor.execute("SELECT balance FROM accounts WHERE id = ?", (from_id,))
    from_row = cursor.fetchone()
    if not from_row:
        raise ValueError(f"Cuenta origen {from_id} no existe")
    from_balance = from_row[0]

    # COMPROBACIÓN DEFECTUOSA: Solo verifica mayor que balance, omitiendo amount <= 0
    if amount > from_balance:
        raise ValueError("Saldo insuficiente")

    cursor.execute("SELECT balance FROM accounts WHERE id = ?", (to_id,))
    to_row = cursor.fetchone()
    if not to_row:
        raise ValueError(f"Cuenta destino {to_id} no existe")
    to_balance = to_row[0]

    # Operación matemática sin control de signo
    new_from = round(from_balance - amount, 2)
    new_to = round(to_balance + amount, 2)

    cursor.execute("UPDATE accounts SET balance = ? WHERE id = ?", (new_from, from_id))
    cursor.execute("UPDATE accounts SET balance = ? WHERE id = ?", (new_to, to_id))
    cursor.execute(
        "INSERT INTO transactions (from_account, to_account, amount) VALUES (?, ?, ?)",
        (from_id, to_id, amount)
    )
    conn.commit()

    return {
        "from_account": from_id,
        "to_account": to_id,
        "amount": amount,
        "from_balance": new_from,
        "to_balance": new_to,
        "new_balance": new_from,
    }


class BaseBusinessLogicTestCase(unittest.TestCase):
    """
    Clase base para pruebas de lógica de negocio bancaria.
    Configura una base de datos SQLite en memoria limpia para cada test.
    """

    def setUp(self):
        """Inicializa esquema y datos de prueba en :memory:."""
        self.conn = sqlite3.connect(":memory:")
        init_db(self.conn)
        self.cursor = self.conn.cursor()

        # Identificadores de usuarios
        self.user_jsmith = 1
        self.user_victim = 2

        # Cuentas bancarias de prueba:
        # jsmith: cuenta 101 con $100.0, cuenta 102 con $0.0 (saldo cero)
        # victim: cuenta 201 con $500.0
        self.account_jsmith_main = 101
        self.account_jsmith_zero = 102
        self.account_victim_main = 201

        self.cursor.execute("INSERT INTO accounts (id, user_id, balance) VALUES (101, 1, 100.0)")
        self.cursor.execute("INSERT INTO accounts (id, user_id, balance) VALUES (102, 1, 0.0)")
        self.cursor.execute("INSERT INTO accounts (id, user_id, balance) VALUES (201, 2, 500.0)")
        self.conn.commit()

        # Usuario de sesión por defecto para las pruebas
        self.session_user_id = self.user_jsmith

    def tearDown(self):
        """Cierra la conexión SQLite en memoria."""
        self.conn.close()

    def get_balance(self, account_id: int) -> float:
        """Helper para consultar el balance persistido actual de una cuenta."""
        self.cursor.execute("SELECT balance FROM accounts WHERE id = ?", (account_id,))
        row = self.cursor.fetchone()
        return row[0] if row else None


class TestTransferValidationRejections(BaseBusinessLogicTestCase):
    """
    Pruebas unitarias que verifican el rechazo estricto de cada caso inválido:
      - Monto negativo (-100)
      - Monto cero (0)
      - Auto-transferencia (origen == destino)
      - Monto mayor al balance disponible
      - Cuenta origen inexistente
      - Cuenta destino inexistente
      - Acceso a cuenta de otro usuario
    """

    def test_negative_amount_rejected(self):
        """
        Reporte vuln-0011: Un monto negativo (-100) debe ser rechazado con ValueError.
        Los balances de ambas cuentas deben permanecer intactos.
        """
        with self.assertRaises(ValueError) as ctx:
            validate_and_execute_transfer(
                self.account_jsmith_main,
                self.account_victim_main,
                -100.0,
                self.cursor,
                user_id=self.user_jsmith
            )
        self.assertIn("estrictamente positivo", str(ctx.exception))
        self.assertEqual(self.get_balance(self.account_jsmith_main), 100.0)
        self.assertEqual(self.get_balance(self.account_victim_main), 500.0)

    def test_zero_amount_rejected(self):
        """
        Verifica que una transferencia con monto 0 sea rechazada con ValueError.
        """
        with self.assertRaises(ValueError) as ctx:
            validate_and_execute_transfer(
                self.account_jsmith_main,
                self.account_victim_main,
                0,
                self.cursor,
                user_id=self.user_jsmith
            )
        self.assertIn("estrictamente positivo", str(ctx.exception))
        self.assertEqual(self.get_balance(self.account_jsmith_main), 100.0)
        self.assertEqual(self.get_balance(self.account_victim_main), 500.0)

    def test_self_transfer_rejected(self):
        """
        Reporte vuln-0014: Una transferencia hacia la misma cuenta (from_id == to_id)
        debe ser rechazada con ValueError para impedir la creación espuria de dinero.
        """
        with self.assertRaises(ValueError) as ctx:
            validate_and_execute_transfer(
                self.account_jsmith_main,
                self.account_jsmith_main,
                50.0,
                self.cursor,
                user_id=self.user_jsmith
            )
        self.assertIn("no pueden ser la misma", str(ctx.exception))
        self.assertEqual(self.get_balance(self.account_jsmith_main), 100.0)

    def test_amount_exceeding_balance_rejected(self):
        """
        Verifica que solicitar transferir más fondos de los disponibles en la cuenta origen
        sea rechazado con ValueError (no sobregiro no autorizado).
        """
        with self.assertRaises(ValueError) as ctx:
            validate_and_execute_transfer(
                self.account_jsmith_main,
                self.account_victim_main,
                150.0,  # Disponible: 100.0
                self.cursor,
                user_id=self.user_jsmith
            )
        self.assertIn("Fondos insuficientes", str(ctx.exception))
        self.assertEqual(self.get_balance(self.account_jsmith_main), 100.0)
        self.assertEqual(self.get_balance(self.account_victim_main), 500.0)

    def test_nonexistent_from_account_rejected(self):
        """
        Verifica el rechazo con ValueError cuando la cuenta origen no existe.
        """
        nonexistent_account_id = 99999
        with self.assertRaises(ValueError) as ctx:
            validate_and_execute_transfer(
                nonexistent_account_id,
                self.account_victim_main,
                20.0,
                self.cursor,
                user_id=self.user_jsmith
            )
        self.assertIn("no existe en el sistema", str(ctx.exception))

    def test_nonexistent_to_account_rejected(self):
        """
        Verifica el rechazo con ValueError cuando la cuenta destino no existe.
        """
        nonexistent_account_id = 88888
        with self.assertRaises(ValueError) as ctx:
            validate_and_execute_transfer(
                self.account_jsmith_main,
                nonexistent_account_id,
                20.0,
                self.cursor,
                user_id=self.user_jsmith
            )
        self.assertIn("no existe en el sistema", str(ctx.exception))
        self.assertEqual(self.get_balance(self.account_jsmith_main), 100.0)

    def test_transfer_from_unauthorized_user_account_rejected(self):
        """
        Verifica que un usuario autenticado (jsmith, id=1) NO pueda ordenar débitos
        desde una cuenta perteneciente a otro usuario (victim, id=2).
        """
        with self.assertRaises(ValueError) as ctx:
            validate_and_execute_transfer(
                from_id=self.account_victim_main,  # Pertenece a victim (id 2)
                to_id=self.account_jsmith_main,
                amount=50.0,
                cursor=self.cursor,
                user_id=self.user_jsmith  # Sesión de jsmith (id 1)
            )
        self.assertIn("Acceso denegado", str(ctx.exception))
        self.assertEqual(self.get_balance(self.account_victim_main), 500.0)
        self.assertEqual(self.get_balance(self.account_jsmith_main), 100.0)


class TestTransferPositiveControl(BaseBusinessLogicTestCase):
    """
    Pruebas de control positivo:
      - Transferencia válida se procesa y actualiza los balances correctamente.
      - Se acepta una transferencia por el saldo exacto disponible.
      - Manejo exacto de decimales y centavos (12.50, 0.01).
    """

    def test_valid_transfer_succeeds_and_updates_balances(self):
        """
        Control positivo: transferencia legítima de $30.0 entre cuentas válidas.
        Verifica que se debite el origen, se acredite el destino y se registre en transactions.
        """
        res = validate_and_execute_transfer(
            from_id=self.account_jsmith_main,
            to_id=self.account_victim_main,
            amount=30.0,
            cursor=self.cursor,
            user_id=self.user_jsmith
        )

        self.assertEqual(res["from_balance"], 70.0)
        self.assertEqual(res["to_balance"], 530.0)
        self.assertEqual(res["new_balance"], 70.0)

        # Confirmar en base de datos
        self.assertEqual(self.get_balance(self.account_jsmith_main), 70.0)
        self.assertEqual(self.get_balance(self.account_victim_main), 530.0)

        # Confirmar auditoría en transactions
        self.cursor.execute("SELECT from_account, to_account, amount FROM transactions")
        tx_row = self.cursor.fetchone()
        self.assertEqual(tx_row, (101, 201, 30.0))

    def test_transfer_exact_balance_amount(self):
        """
        Control positivo: transferir exactamente la totalidad del saldo disponible (100.0).
        El nuevo saldo de la cuenta origen debe quedar exactamente en 0.0.
        """
        res = validate_and_execute_transfer(
            from_id=self.account_jsmith_main,
            to_id=self.account_victim_main,
            amount=100.0,
            cursor=self.cursor,
            user_id=self.user_jsmith
        )

        self.assertEqual(res["from_balance"], 0.0)
        self.assertEqual(res["to_balance"], 600.0)
        self.assertEqual(self.get_balance(self.account_jsmith_main), 0.0)
        self.assertEqual(self.get_balance(self.account_victim_main), 600.0)

    def test_transfer_decimal_amounts(self):
        """
        Control positivo: manejo correcto de cantidades decimales con precisión de centavos (12.50, 0.01).
        """
        # Primera transferencia con decimales: $12.50
        res1 = validate_and_execute_transfer(
            self.account_jsmith_main,
            self.account_victim_main,
            12.50,
            self.cursor,
            user_id=self.user_jsmith
        )
        self.assertEqual(res1["from_balance"], 87.50)
        self.assertEqual(res1["to_balance"], 512.50)
        self.assertEqual(self.get_balance(self.account_jsmith_main), 87.50)
        self.assertEqual(self.get_balance(self.account_victim_main), 512.50)

        # Segunda transferencia con decimal mínimo: $0.01
        res2 = validate_and_execute_transfer(
            self.account_jsmith_main,
            self.account_victim_main,
            0.01,
            self.cursor,
            user_id=self.user_jsmith
        )
        self.assertEqual(res2["from_balance"], 87.49)
        self.assertEqual(res2["to_balance"], 512.51)
        self.assertEqual(self.get_balance(self.account_jsmith_main), 87.49)
        self.assertEqual(self.get_balance(self.account_victim_main), 512.51)


class TestTransferEdgeCases(BaseBusinessLogicTestCase):
    """
    Pruebas para casos límite:
      - Cuenta con saldo cero (transferencias rechazadas).
      - Transferencia mínima de $0.01 (permitida).
      - Conservación global del saldo en el sistema (el dinero total ni se crea ni se destruye).
    """

    def test_transfer_from_zero_balance_account(self):
        """
        Caso límite: una cuenta con saldo 0.0 (cuenta 102) no puede realizar transferencias:
          - Monto 0.01 -> rechazada por saldo insuficiente.
          - Monto 0.0 -> rechazada por monto no positivo.
          - Monto -10.0 -> rechazada por monto no positivo.
        """
        # Intentar transferir el mínimo positivo disponible desde cuenta en cero
        with self.assertRaises(ValueError) as ctx1:
            validate_and_execute_transfer(
                self.account_jsmith_zero,
                self.account_victim_main,
                0.01,
                self.cursor,
                user_id=self.user_jsmith
            )
        self.assertIn("Fondos insuficientes", str(ctx1.exception))

        # Intentar transferir cero
        with self.assertRaises(ValueError) as ctx2:
            validate_and_execute_transfer(
                self.account_jsmith_zero,
                self.account_victim_main,
                0,
                self.cursor,
                user_id=self.user_jsmith
            )
        self.assertIn("estrictamente positivo", str(ctx2.exception))

        # El balance sigue en 0.0
        self.assertEqual(self.get_balance(self.account_jsmith_zero), 0.0)

    def test_transfer_minimum_amount_one_cent(self):
        """
        Caso límite: el monto mínimo permitido es de 0.01 y debe procesarse exitosamente.
        """
        res = validate_and_execute_transfer(
            self.account_jsmith_main,
            self.account_victim_main,
            0.01,
            self.cursor,
            user_id=self.user_jsmith
        )
        self.assertEqual(res["from_balance"], 99.99)
        self.assertEqual(res["to_balance"], 500.01)

    def test_system_wide_conservation_of_money(self):
        """
        Invariante contable de lógica de negocio: el balance total de todas las cuentas
        combinadas en el sistema debe conservarse exactamente antes y después de cualquier
        serie de transferencias (no hay creación ni destrucción de dinero).
        """
        def total_system_money():
            self.cursor.execute("SELECT SUM(balance) FROM accounts")
            return round(self.cursor.fetchone()[0], 2)

        initial_total = total_system_money()
        self.assertEqual(initial_total, 600.0)  # 100.0 + 0.0 + 500.0 = 600.0

        # Serie de transferencias cruzadas válidas
        validate_and_execute_transfer(101, 201, 25.50, self.cursor, user_id=1)
        validate_and_execute_transfer(201, 102, 100.00, self.cursor, user_id=2)
        validate_and_execute_transfer(102, 101, 40.25, self.cursor, user_id=1)
        validate_and_execute_transfer(101, 201, 0.01, self.cursor, user_id=1)

        final_total = total_system_money()
        self.assertEqual(
            final_total,
            initial_total,
            "Violación del principio de conservación de valor: el dinero total del sistema cambió."
        )


class TestVulnerabilitySimulation(BaseBusinessLogicTestCase):
    """
    Pruebas de simulación de vulnerabilidad que demuestran que una implementación
    insegura (que solo evalúa 'amount > balance') acepta montos negativos como -100
    e incrementa el balance en lugar de restarlo, provocando `AssertionError`.
    """

    def test_vulnerable_version_accepts_negative_amount_and_adds_funds(self):
        """
        Simulación vuln-0011:
        Demuestra que `vulnerable_transfer` procesa un monto de -100.0:
          - NO levanta ValueError (haciendo que assertRaises(ValueError) falle con AssertionError).
          - En lugar de restar 100, la cuenta origen pasa de $100.0 a $200.0 (+100.0).
          - La aserción de seguridad de que el balance origen disminuyó falla con AssertionError.
        """
        initial_from = self.get_balance(self.account_jsmith_main)
        initial_to = self.get_balance(self.account_victim_main)

        # 1. Demostración de que la versión vulnerable NO lanza ValueError
        with self.assertRaises(AssertionError):
            with self.assertRaises(ValueError):
                vulnerable_transfer(
                    self.account_jsmith_main,
                    self.account_victim_main,
                    -100.0,
                    self.cursor
                )

        # 2. Demostración del robo de fondos: el saldo origen AUMENTÓ en $100
        # Tras la llamada vulnerable, los balances quedan invertidos
        current_from = self.get_balance(self.account_jsmith_main)
        current_to = self.get_balance(self.account_victim_main)

        self.assertEqual(current_from, 200.0)  # 100 - (-100) = 200
        self.assertEqual(current_to, 400.0)    # 500 + (-100) = 400

        # La aserción de seguridad exige que una transferencia nunca incremente el saldo origen.
        # Demostramos que esta aserción dispara AssertionError en la implementación defectuosa:
        with self.assertRaises(AssertionError):
            self.assertLessEqual(
                current_from,
                initial_from,
                "Fallo esperado: la transferencia con monto negativo incrementó el balance origen."
            )

    def test_vulnerable_version_permits_self_transfer_without_validation(self):
        """
        Simulación vuln-0014:
        Demuestra que la implementación vulnerable no rechaza from == to, permitiendo
        ejecutar transferencias reflexivas que violan la lógica contable.
        """
        with self.assertRaises(AssertionError):
            with self.assertRaises(ValueError):
                vulnerable_transfer(
                    self.account_jsmith_main,
                    self.account_jsmith_main,
                    50.0,
                    self.cursor
                )


if __name__ == "__main__":
    unittest.main()
