"""
Módulo de autorización y pruebas unitarias de control de acceso (AuthZ).

Este archivo implementa:
1. La clase de referencia `AuthorizationService` que aplica controles de autorización
   a nivel de objeto (BOLA / IDOR) y a nivel de función (BFLA), mitigando los hallazgos:
   - vuln-0004: IDOR / Broken Object-Level Authorization (CWE-639) en consulta de cuentas.
   - vuln-0005: Broken Function-Level Authorization (CWE-862) en funciones administrativas.
   - vuln-0008: Broken Object-Level Authorization (CWE-639) en transferencias de fondos.
2. Suites de pruebas unitarias (`unittest`) utilizando SQLite en memoria (:memory:)
   para simular las tablas `users`, `accounts` y `sessions`.
3. Pruebas de controles positivos (acceso legítimo y rol admin), controles negativos
   (bloqueo de IDOR, endpoints admin y manipulación de recursos ajenos), casos límite
   (usuarios/cuentas inexistentes, sesiones expiradas o revocadas) y pruebas de regresión
   que demuestran que implementaciones vulnerables disparan `AssertionError`.
"""

import re
import sqlite3
import time
import unittest
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Optional


def init_db(conn: sqlite3.Connection) -> None:
    """
    Crea el esquema mínimo de base de datos relacional para simular el sistema bancario.

    Tablas creadas:
      - users: almacena identificador, nombre de usuario y rol ('user', 'admin').
      - accounts: almacena cuentas bancarias vinculadas a un usuario propietario.
      - sessions: almacena tokens de sesión, usuario asociado, fecha de expiración y estado.
    """
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            balance REAL NOT NULL DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            expires_at REAL NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.commit()


class AuthorizationService:
    """
    Servicio de referencia para verificación y aplicación de políticas de autorización.

    Provee métodos robustos para:
      - Validar propiedad de cuentas bancarias (prevención de IDOR / BOLA - vuln-0004).
      - Validar privilegios administrativos (prevención de BFLA - vuln-0005).
      - Controlar acceso a endpoints por función y parámetro de objeto.
      - Validar transferencias y modificaciones sobre recursos propios (vuln-0008).
      - Comprobar la vigencia y correspondencia de sesiones de usuario.
    """

    @classmethod
    def _get_cursor(cls, db: Any) -> sqlite3.Cursor:
        """Obtiene un cursor de SQLite compatible tanto si se pasa una conexión como un cursor."""
        if hasattr(db, "cursor") and callable(db.cursor):
            return db.cursor()
        return db

    @classmethod
    def _is_expired(cls, expires_at: Any) -> bool:
        """
        Determina si una marca de expiración ha caducado respecto al tiempo actual.
        Soporta valores numéricos (timestamp UNIX en segundos), cadenas ISO y objetos datetime.
        """
        if expires_at is None:
            return True

        current_timestamp = time.time()

        if isinstance(expires_at, (int, float)):
            return current_timestamp >= expires_at

        if isinstance(expires_at, str):
            try:
                return current_timestamp >= float(expires_at)
            except ValueError:
                pass
            try:
                dt = datetime.fromisoformat(expires_at)
                if dt.tzinfo is not None:
                    return datetime.now(timezone.utc) >= dt
                return datetime.utcnow() >= dt
            except ValueError:
                return True

        if isinstance(expires_at, datetime):
            if expires_at.tzinfo is not None:
                return datetime.now(timezone.utc) >= expires_at
            return datetime.utcnow() >= expires_at

        return True

    @classmethod
    def is_session_valid(
        cls,
        session_token: Optional[str],
        db: Any,
        user_id: Optional[Any] = None
    ) -> bool:
        """
        Verifica que un token de sesión exista en la base de datos, esté activo y no haya expirado.
        Si se especifica `user_id`, valida adicionalmente que la sesión pertenezca a dicho usuario.

        Parámetros:
            session_token (str): Token de sesión o bearer token a evaluar.
            db: Conexión o cursor de SQLite.
            user_id (int, opcional): Identificador de usuario esperado.

        Retorna:
            bool: True si la sesión es válida y vigente; False en caso contrario.
        """
        if not session_token or not isinstance(session_token, str):
            return False

        cursor = cls._get_cursor(db)
        cursor.execute(
            "SELECT user_id, expires_at, is_active FROM sessions WHERE token = ?",
            (session_token,)
        )
        row = cursor.fetchone()
        if row is None:
            return False

        s_user_id, expires_at, is_active = row

        # Sesión explícitamente desactivada/revocada
        if not is_active:
            return False

        # Si se especificó user_id, debe coincidir con el dueño de la sesión
        if user_id is not None:
            try:
                if int(s_user_id) != int(user_id):
                    return False
            except (ValueError, TypeError):
                return False

        # Verificar expiración temporal
        if cls._is_expired(expires_at):
            return False

        return True

    @classmethod
    def can_view_account(
        cls,
        user_id: Any,
        account_id: Any,
        db: Any,
        session_token: Optional[str] = None
    ) -> bool:
        """
        Verifica que el usuario sea el dueño legítimo de la cuenta bancaria.
        Mitiga vulnerabilidades de tipo IDOR / Broken Object-Level Authorization (vuln-0004).

        Parámetros:
            user_id (int): Identificador del usuario autenticado.
            account_id (int): Identificador de la cuenta bancaria solicitada.
            db: Conexión o cursor de base de datos SQLite.
            session_token (str, opcional): Token de sesión para validar vigencia y titularidad.

        Retorna:
            bool: True únicamente si el usuario existe, la sesión es válida (si se envía)
                  y el usuario es el propietario registrado de la cuenta.
        """
        if user_id is None or account_id is None:
            return False

        # Si se proporciona token de sesión, verificar su validez y coincidencia con el usuario
        if session_token is not None:
            if not cls.is_session_valid(session_token, db, user_id=user_id):
                return False

        cursor = cls._get_cursor(db)

        # 1. Validar existencia del usuario
        try:
            uid = int(user_id)
            cursor.execute("SELECT id FROM users WHERE id = ?", (uid,))
            if cursor.fetchone() is None:
                return False
        except (ValueError, TypeError):
            return False

        # 2. Validar existencia de la cuenta y verificar que pertenece al usuario
        try:
            aid = int(account_id)
            cursor.execute("SELECT user_id FROM accounts WHERE id = ?", (aid,))
            account_row = cursor.fetchone()
            if account_row is None:
                return False
            owner_id = account_row[0]
            return owner_id == uid
        except (ValueError, TypeError):
            return False

    @classmethod
    def can_admin(
        cls,
        user_id: Any,
        db: Any,
        session_token: Optional[str] = None
    ) -> bool:
        """
        Verifica que el usuario tenga rol de administrador ('admin').
        Mitiga vulnerabilidades de tipo Broken Function-Level Authorization (vuln-0005).

        Parámetros:
            user_id (int): Identificador del usuario.
            db: Conexión o cursor de SQLite.
            session_token (str, opcional): Token de sesión del usuario.

        Retorna:
            bool: True si el usuario existe, la sesión es válida y su rol es 'admin'; False en caso contrario.
        """
        if user_id is None:
            return False

        if session_token is not None:
            if not cls.is_session_valid(session_token, db, user_id=user_id):
                return False

        cursor = cls._get_cursor(db)
        try:
            uid = int(user_id)
            cursor.execute("SELECT role FROM users WHERE id = ?", (uid,))
            user_row = cursor.fetchone()
            if user_row is None:
                return False
            role = str(user_row[0]).strip().lower()
            return role == "admin"
        except (ValueError, TypeError):
            return False

    @classmethod
    def can_access_endpoint(
        cls,
        user_id: Any,
        endpoint: str,
        db: Any,
        session_token: Optional[str] = None
    ) -> bool:
        """
        Verifica permisos de acceso a un endpoint específico según el principio
        de menor privilegio, control de funciones administrativas y propiedad de recursos.

        Rutas gestionadas:
          - Públicas (/login.jsp, /doLogin, /api/login, etc.): accesibles por cualquiera.
          - Administrativas (/admin/*, /api/admin/*): requieren rol 'admin'.
          - Cuentas con parámetros de objeto (/api/account/{id}, /bank/showAccount?listAccounts={id}):
            requieren que el usuario autenticado sea el dueño legítimo de dicha cuenta.
          - Protegidas de cliente (/bank/main.jsp, /api/account, /api/transfer): requieren usuario válido.

        Parámetros:
            user_id (int): Identificador del usuario (o None si es anónimo).
            endpoint (str): Ruta o URI del endpoint solicitado.
            db: Conexión o cursor de SQLite.
            session_token (str, opcional): Token de sesión del usuario.

        Retorna:
            bool: True si la petición está autorizada; False si debe ser rechazada (401/403).
        """
        if not endpoint or not isinstance(endpoint, str):
            return False

        parsed = urllib.parse.urlparse(endpoint)
        path = parsed.path
        query_params = urllib.parse.parse_qs(parsed.query)

        # 1. Endpoints de acceso público sin autenticación requerida
        public_endpoints = {
            "/",
            "/index.jsp",
            "/login.jsp",
            "/doLogin",
            "/api/login",
            "/admin/login.jsp",
            "/admin/doAdminLogin",
        }
        if path in public_endpoints:
            return True

        # 2. Cualquier endpoint protegido requiere usuario autenticado
        if user_id is None:
            return False

        if session_token is not None:
            if not cls.is_session_valid(session_token, db, user_id=user_id):
                return False

        cursor = cls._get_cursor(db)
        try:
            uid = int(user_id)
            cursor.execute("SELECT role FROM users WHERE id = ?", (uid,))
            user_row = cursor.fetchone()
            if user_row is None:
                return False
            role = str(user_row[0]).strip().lower()
        except (ValueError, TypeError):
            return False

        # 3. Verificación de funciones administrativas (vuln-0005)
        # Protege /admin/* y /api/admin/* contra llamadas de usuarios no administradores
        is_admin_path = path.startswith("/admin/") or path.startswith("/api/admin/") or path == "/admin"
        if is_admin_path:
            return role == "admin"

        # 4. Verificación de autorización a nivel de objeto para recursos específicos (vuln-0004)
        target_account_id = None

        # Detección por query string (ej: /bank/showAccount?listAccounts=800000 o /bank/balance.jsp?acctId=800000)
        for param in ("listAccounts", "acctId", "accountNo", "account"):
            if param in query_params and query_params[param]:
                try:
                    target_account_id = int(query_params[param][0])
                    break
                except (ValueError, TypeError):
                    pass

        # Detección por path parameter (ej: /api/account/800000 o /api/account/800000/transactions)
        if target_account_id is None:
            match = re.match(r"^/api/account/(\d+)(?:/.*)?$", path)
            if match:
                try:
                    target_account_id = int(match.group(1))
                except (ValueError, TypeError):
                    pass

        if target_account_id is not None:
            return cls.can_view_account(uid, target_account_id, db)

        # 5. Endpoints autenticados generales (ej: /bank/main.jsp, /api/account)
        return True

    @classmethod
    def can_modify_account(
        cls,
        user_id: Any,
        account_id: Any,
        db: Any,
        session_token: Optional[str] = None
    ) -> bool:
        """
        Verifica que el usuario tenga autorización para modificar o debitar una cuenta bancaria.
        Mitiga vulnerabilidades de tipo Broken Object-Level Authorization en operaciones
        de modificación y débito (vuln-0008).

        Parámetros:
            user_id (int): Identificador del usuario que solicita la modificación.
            account_id (int): Identificador de la cuenta bancaria sobre la cual se opera.
            db: Conexión o cursor de SQLite.
            session_token (str, opcional): Token de sesión.

        Retorna:
            bool: True si el usuario es el dueño legítimo de la cuenta; False en caso contrario.
        """
        return cls.can_view_account(user_id, account_id, db, session_token=session_token)

    @classmethod
    def can_modify_resource(
        cls,
        user_id: Any,
        resource_id: Any,
        db: Any,
        session_token: Optional[str] = None
    ) -> bool:
        """Alias semántico de `can_modify_account` para autorización a nivel de objeto."""
        return cls.can_modify_account(user_id, resource_id, db, session_token=session_token)

    @classmethod
    def can_transfer(
        cls,
        user_id: Any,
        from_account_id: Any,
        to_account_id: Any,
        db: Any,
        session_token: Optional[str] = None
    ) -> bool:
        """
        Verifica la autorización de una operación de transferencia de fondos (POST /api/transfer).
        Mitiga la vulnerabilidad vuln-0008 exigiendo que la cuenta de origen (`fromAccount`)
        sea propiedad del usuario autenticado y que la cuenta de destino exista.

        Parámetros:
            user_id (int): Identificador del usuario que ordena la transferencia.
            from_account_id (int): Cuenta de débito / origen.
            to_account_id (int): Cuenta de crédito / destino.
            db: Conexión o cursor de SQLite.
            session_token (str, opcional): Token de sesión.

        Retorna:
            bool: True si el usuario es dueño de from_account y to_account existe; False si no.
        """
        if user_id is None or from_account_id is None or to_account_id is None:
            return False

        # La cuenta origen DEBE pertenecer al usuario
        if not cls.can_modify_account(user_id, from_account_id, db, session_token=session_token):
            return False

        # La cuenta destino debe existir en el sistema
        cursor = cls._get_cursor(db)
        try:
            to_aid = int(to_account_id)
            cursor.execute("SELECT id FROM accounts WHERE id = ?", (to_aid,))
            if cursor.fetchone() is None:
                return False
        except (ValueError, TypeError):
            return False

        return True


class BaseAuthzTestCase(unittest.TestCase):
    """
    Clase base de pruebas unitarias que configura la base de datos SQLite en memoria
    y siembra usuarios, cuentas y sesiones con la topología de los reportes vuln-0004/0005/0008.
    """

    def setUp(self):
        """Inicializa una base de datos SQLite limpia en memoria antes de cada prueba."""
        self.conn = sqlite3.connect(":memory:")
        init_db(self.conn)
        self.cursor = self.conn.cursor()

        # Identificadores de usuarios
        self.jsmith_id = 1      # Usuario ordinario (rol 'user')
        self.admin_id = 2       # Administrador (rol 'admin')
        self.victim_id = 3      # Víctima / otro cliente ordinario (rol 'user')

        # Insertar usuarios
        self.cursor.execute("INSERT INTO users (id, username, role) VALUES (?, ?, ?)", (self.jsmith_id, "jsmith", "user"))
        self.cursor.execute("INSERT INTO users (id, username, role) VALUES (?, ?, ?)", (self.admin_id, "admin", "admin"))
        self.cursor.execute("INSERT INTO users (id, username, role) VALUES (?, ?, ?)", (self.victim_id, "victim_user", "user"))

        # Cuentas bancarias de jsmith (como en vuln-0004 y vuln-0008)
        self.jsmith_account_savings = 800002
        self.jsmith_account_checking = 800011
        self.cursor.execute("INSERT INTO accounts (id, user_id, balance) VALUES (?, ?, ?)", (self.jsmith_account_savings, self.jsmith_id, 1000.0))
        self.cursor.execute("INSERT INTO accounts (id, user_id, balance) VALUES (?, ?, ?)", (self.jsmith_account_checking, self.jsmith_id, 0.99))

        # Cuentas bancarias de admin
        self.admin_account = 800000
        self.cursor.execute("INSERT INTO accounts (id, user_id, balance) VALUES (?, ?, ?)", (self.admin_account, self.admin_id, 50000.0))

        # Cuentas bancarias de victim_user (800001 en vuln-0004 y vuln-0008)
        self.victim_account = 800001
        self.cursor.execute("INSERT INTO accounts (id, user_id, balance) VALUES (?, ?, ?)", (self.victim_account, self.victim_id, 1002626437452.38))

        # Sembrar sesiones temporales
        now = time.time()
        self.valid_jsmith_token = "sess_jsmith_valid_123"
        self.expired_jsmith_token = "sess_jsmith_expired_456"
        self.revoked_jsmith_token = "sess_jsmith_revoked_789"
        self.valid_admin_token = "sess_admin_valid_999"
        self.expired_admin_token = "sess_admin_expired_000"

        # Sesión válida de jsmith (expira en 1 hora)
        self.cursor.execute(
            "INSERT INTO sessions (token, user_id, expires_at, is_active) VALUES (?, ?, ?, ?)",
            (self.valid_jsmith_token, self.jsmith_id, now + 3600, 1)
        )
        # Sesión expirada de jsmith (expiró hace 1 hora)
        self.cursor.execute(
            "INSERT INTO sessions (token, user_id, expires_at, is_active) VALUES (?, ?, ?, ?)",
            (self.expired_jsmith_token, self.jsmith_id, now - 3600, 1)
        )
        # Sesión revocada / inactiva de jsmith (is_active = 0)
        self.cursor.execute(
            "INSERT INTO sessions (token, user_id, expires_at, is_active) VALUES (?, ?, ?, ?)",
            (self.revoked_jsmith_token, self.jsmith_id, now + 3600, 0)
        )
        # Sesión válida de admin (expira en 1 hora)
        self.cursor.execute(
            "INSERT INTO sessions (token, user_id, expires_at, is_active) VALUES (?, ?, ?, ?)",
            (self.valid_admin_token, self.admin_id, now + 3600, 1)
        )
        # Sesión expirada de admin (expiró hace 1 hora)
        self.cursor.execute(
            "INSERT INTO sessions (token, user_id, expires_at, is_active) VALUES (?, ?, ?, ?)",
            (self.expired_admin_token, self.admin_id, now - 3600, 1)
        )

        self.conn.commit()
        self.authz = AuthorizationService

    def tearDown(self):
        """Cierra la conexión de base de datos en memoria tras cada prueba."""
        self.conn.close()


class TestIDORAccountAccess(BaseAuthzTestCase):
    """
    Pruebas para Broken Object-Level Authorization / IDOR (vuln-0004).
    Verifica que un usuario NO pueda consultar cuentas ajenas ni por API ni por vistas web,
    y que el dueño legítimo SÍ tenga acceso a sus cuentas.
    """

    def test_user_cannot_view_other_users_account_direct(self):
        """
        Reporte vuln-0004: GET /api/account/{accountNo}.
        Verifica que jsmith NO pueda ver la cuenta de otro usuario (800000 o 800001).
        """
        can_view_admin_acct = self.authz.can_view_account(self.jsmith_id, self.admin_account, self.conn)
        self.assertFalse(
            can_view_admin_acct,
            "Fallo de seguridad (IDOR): jsmith pudo consultar la cuenta del administrador (800000)."
        )

        can_view_victim_acct = self.authz.can_view_account(self.jsmith_id, self.victim_account, self.conn)
        self.assertFalse(
            can_view_victim_acct,
            "Fallo de seguridad (IDOR): jsmith pudo consultar la cuenta de la víctima (800001)."
        )

    def test_user_cannot_view_other_users_account_via_endpoint(self):
        """
        Reporte vuln-0004: Acceso a endpoints de API y Web para cuentas ajenas:
          - /api/account/800001
          - /api/account/800001/transactions
          - /bank/showAccount?listAccounts=800001
          - /bank/balance.jsp?acctId=800001
        """
        endpoints_ajenos = [
            f"/api/account/{self.victim_account}",
            f"/api/account/{self.victim_account}/transactions",
            f"/bank/showAccount?listAccounts={self.victim_account}",
            f"/bank/balance.jsp?acctId={self.victim_account}",
            f"/api/account/{self.admin_account}",
            f"/bank/showAccount?listAccounts={self.admin_account}",
        ]
        for ep in endpoints_ajenos:
            can_access = self.authz.can_access_endpoint(self.jsmith_id, ep, self.conn)
            self.assertFalse(
                can_access,
                f"Fallo de seguridad (IDOR en endpoint): jsmith pudo acceder a endpoint ajeno {ep}."
            )

    def test_legitimate_owner_can_view_own_account(self):
        """
        Control positivo: el dueño legítimo SÍ puede consultar sus propias cuentas.
        """
        # jsmith puede ver su cuenta de ahorro (800002) y de cheques (800011)
        self.assertTrue(
            self.authz.can_view_account(self.jsmith_id, self.jsmith_account_savings, self.conn),
            "Control positivo fallido: el dueño legítimo debería poder consultar su cuenta 800002."
        )
        self.assertTrue(
            self.authz.can_view_account(self.jsmith_id, self.jsmith_account_checking, self.conn),
            "Control positivo fallido: el dueño legítimo debería poder consultar su cuenta 800011."
        )

        # Acceso por endpoints propios
        self.assertTrue(
            self.authz.can_access_endpoint(self.jsmith_id, f"/api/account/{self.jsmith_account_savings}", self.conn),
            "El dueño legítimo debería poder acceder a /api/account/800002."
        )
        self.assertTrue(
            self.authz.can_access_endpoint(self.jsmith_id, f"/bank/showAccount?listAccounts={self.jsmith_account_checking}", self.conn),
            "El dueño legítimo debería poder acceder a /bank/showAccount?listAccounts=800011."
        )

        # La víctima puede ver su propia cuenta (800001)
        self.assertTrue(
            self.authz.can_view_account(self.victim_id, self.victim_account, self.conn),
            "Control positivo fallido: victim_user debería poder consultar su cuenta 800001."
        )


class TestFunctionLevelAuthorization(BaseAuthzTestCase):
    """
    Pruebas para Broken Function-Level Authorization (vuln-0005).
    Verifica que un usuario estándar NO pueda acceder a funciones administrativas
    y que un usuario administrador SÍ tenga acceso.
    """

    def test_normal_user_cannot_admin(self):
        """
        Reporte vuln-0005: can_admin debe retornar False para usuarios sin rol 'admin'.
        """
        self.assertFalse(
            self.authz.can_admin(self.jsmith_id, self.conn),
            "Fallo de seguridad (BFLA): jsmith (rol 'user') no debe tener privilegios de admin."
        )
        self.assertFalse(
            self.authz.can_admin(self.victim_id, self.conn),
            "Fallo de seguridad (BFLA): victim_user (rol 'user') no debe tener privilegios de admin."
        )

    def test_normal_user_cannot_access_admin_endpoints(self):
        """
        Reporte vuln-0005: Endpoints administrativos expuestos:
          - /admin/admin.jsp
          - /admin/addUser
          - /admin/changePassword
          - /admin/addAccount
          - /api/admin/addUser
          - /api/admin/changePassword
        Un usuario común debe ser rechazado en todos ellos.
        """
        admin_endpoints = [
            "/admin/admin.jsp",
            "/admin/addUser",
            "/admin/changePassword",
            "/admin/addAccount",
            "/api/admin/addUser",
            "/api/admin/changePassword",
            "/admin/manageUsers",
        ]
        for ep in admin_endpoints:
            can_access = self.authz.can_access_endpoint(self.jsmith_id, ep, self.conn)
            self.assertFalse(
                can_access,
                f"Fallo de seguridad (BFLA): usuario jsmith pudo acceder indebidamente al endpoint admin {ep}."
            )

    def test_admin_user_can_admin(self):
        """
        Control positivo: un usuario con rol 'admin' SÍ tiene autorización administrativa.
        """
        self.assertTrue(
            self.authz.can_admin(self.admin_id, self.conn),
            "Control positivo fallido: el usuario admin debería tener can_admin == True."
        )

    def test_admin_user_can_access_admin_endpoints(self):
        """
        Control positivo: un administrador legítimo SÍ puede acceder a los endpoints admin.
        """
        admin_endpoints = [
            "/admin/admin.jsp",
            "/admin/addUser",
            "/admin/changePassword",
            "/admin/addAccount",
            "/api/admin/addUser",
            "/api/admin/changePassword",
        ]
        for ep in admin_endpoints:
            can_access = self.authz.can_access_endpoint(self.admin_id, ep, self.conn)
            self.assertTrue(
                can_access,
                f"Control positivo fallido: el usuario admin debería poder acceder al endpoint {ep}."
            )


class TestObjectLevelModificationAuthorization(BaseAuthzTestCase):
    """
    Pruebas para Broken Object-Level Authorization en modificación y transferencias (vuln-0008).
    Verifica que un usuario NO pueda debitar o modificar cuentas de otros usuarios,
    y que el dueño legítimo SÍ pueda debitar/transferir desde sus propias cuentas.
    """

    def test_user_cannot_modify_other_user_account(self):
        """
        Reporte vuln-0008: can_modify_account y can_modify_resource deben rechazar
        intentos de modificar cuentas pertenecientes a otros usuarios.
        """
        self.assertFalse(
            self.authz.can_modify_account(self.jsmith_id, self.victim_account, self.conn),
            "Fallo de seguridad (BOLA modificación): jsmith no debe poder modificar la cuenta ajena 800001."
        )
        self.assertFalse(
            self.authz.can_modify_resource(self.jsmith_id, self.admin_account, self.conn),
            "Fallo de seguridad (BOLA modificación): jsmith no debe poder modificar la cuenta 800000 del admin."
        )

    def test_user_cannot_transfer_funds_from_other_user_account(self):
        """
        Reporte vuln-0008: POST /api/transfer con fromAccount=800001 (víctima) y toAccount=800011 (propia).
        El sistema DEBE rechazar la transferencia si el usuario autenticado no es dueño de fromAccount.
        """
        # Intento de jsmith de drenar fondos de la víctima (800001) a su cuenta (800011)
        transfer_allowed = self.authz.can_transfer(
            user_id=self.jsmith_id,
            from_account_id=self.victim_account,
            to_account_id=self.jsmith_account_checking,
            db=self.conn
        )
        self.assertFalse(
            transfer_allowed,
            "Fallo crítico de seguridad (vuln-0008): jsmith pudo ordenar una transferencia debitando una cuenta ajena (800001)."
        )

    def test_legitimate_owner_can_modify_own_account(self):
        """
        Control positivo: el dueño legítimo SÍ puede modificar su propia cuenta.
        """
        self.assertTrue(
            self.authz.can_modify_account(self.jsmith_id, self.jsmith_account_savings, self.conn),
            "Control positivo fallido: jsmith debería poder modificar su propia cuenta 800002."
        )

    def test_legitimate_owner_can_transfer_funds_from_own_account(self):
        """
        Control positivo: el dueño legítimo SÍ puede transferir fondos desde su propia cuenta.
        """
        # jsmith transfiere desde su cuenta de ahorro (800002) a su cuenta de cheques (800011)
        transfer_own_allowed = self.authz.can_transfer(
            user_id=self.jsmith_id,
            from_account_id=self.jsmith_account_savings,
            to_account_id=self.jsmith_account_checking,
            db=self.conn
        )
        self.assertTrue(
            transfer_own_allowed,
            "Control positivo fallido: jsmith debería poder transferir fondos desde su propia cuenta 800002."
        )

        # jsmith transfiere desde su cuenta propia (800002) hacia la cuenta de otro usuario (800001)
        # Esto es legítimo: transferir fondos hacia un tercero debitando de cuenta propia
        transfer_to_third_party = self.authz.can_transfer(
            user_id=self.jsmith_id,
            from_account_id=self.jsmith_account_savings,
            to_account_id=self.victim_account,
            db=self.conn
        )
        self.assertTrue(
            transfer_to_third_party,
            "Control positivo fallido: jsmith debería poder transferir fondos propios hacia una cuenta existente."
        )


class TestEdgeCasesAndSessions(BaseAuthzTestCase):
    """
    Pruebas para casos límite:
      - Usuario inexistente en la base de datos.
      - Cuenta inexistente en la base de datos.
      - Sesión expirada temporalmente.
      - Sesión inactiva o revocada.
      - Discrepancia entre token de sesión y user_id.
    """

    def test_nonexistent_user_rejected_on_all_authorization_checks(self):
        """
        Caso límite: un identificador de usuario que no existe (ej: 99999)
        debe ser rechazado en todas las operaciones de autorización.
        """
        nonexistent_user_id = 99999

        self.assertFalse(
            self.authz.can_view_account(nonexistent_user_id, self.jsmith_account_savings, self.conn),
            "Un usuario inexistente no debe poder ver cuentas."
        )
        self.assertFalse(
            self.authz.can_admin(nonexistent_user_id, self.conn),
            "Un usuario inexistente no debe tener privilegios admin."
        )
        self.assertFalse(
            self.authz.can_access_endpoint(nonexistent_user_id, "/admin/addUser", self.conn),
            "Un usuario inexistente no debe acceder a endpoints admin."
        )
        self.assertFalse(
            self.authz.can_access_endpoint(nonexistent_user_id, "/bank/main.jsp", self.conn),
            "Un usuario inexistente no debe acceder a endpoints de usuario."
        )
        self.assertFalse(
            self.authz.can_modify_account(nonexistent_user_id, self.jsmith_account_savings, self.conn),
            "Un usuario inexistente no debe poder modificar cuentas."
        )
        self.assertFalse(
            self.authz.can_transfer(nonexistent_user_id, self.jsmith_account_savings, self.victim_account, self.conn),
            "Un usuario inexistente no debe poder ordenar transferencias."
        )

    def test_nonexistent_account_rejected_on_all_authorization_checks(self):
        """
        Caso límite: una cuenta inexistente (ej: 999999) debe retornar False.
        """
        nonexistent_account_id = 999999

        self.assertFalse(
            self.authz.can_view_account(self.jsmith_id, nonexistent_account_id, self.conn),
            "Consultar una cuenta inexistente debe retornar False."
        )
        self.assertFalse(
            self.authz.can_modify_account(self.jsmith_id, nonexistent_account_id, self.conn),
            "Modificar una cuenta inexistente debe retornar False."
        )
        self.assertFalse(
            self.authz.can_access_endpoint(self.jsmith_id, f"/api/account/{nonexistent_account_id}", self.conn),
            "Acceder al endpoint de una cuenta inexistente debe retornar False."
        )
        self.assertFalse(
            self.authz.can_transfer(self.jsmith_id, nonexistent_account_id, self.jsmith_account_checking, self.conn),
            "Transferir desde una cuenta inexistente debe retornar False."
        )
        self.assertFalse(
            self.authz.can_transfer(self.jsmith_id, self.jsmith_account_savings, nonexistent_account_id, self.conn),
            "Transferir hacia una cuenta inexistente debe retornar False."
        )

    def test_expired_session_rejected(self):
        """
        Caso límite: si la sesión está expirada, las operaciones de autorización
        deben ser denegadas aunque el usuario y los recursos sean legítimos.
        """
        # Comprobar la validez intrínseca de la sesión expirada
        self.assertFalse(
            self.authz.is_session_valid(self.expired_jsmith_token, self.conn),
            "Una sesión expirada debe ser inválida."
        )

        # can_view_account con sesión expirada debe ser denegada
        self.assertFalse(
            self.authz.can_view_account(
                self.jsmith_id, self.jsmith_account_savings, self.conn, session_token=self.expired_jsmith_token
            ),
            "No se debe autorizar ver una cuenta con sesión expirada."
        )

        # can_admin con sesión expirada debe ser denegada
        self.assertFalse(
            self.authz.can_admin(self.admin_id, self.conn, session_token=self.expired_admin_token),
            "No se deben autorizar privilegios admin con sesión expirada."
        )

        # can_access_endpoint con sesión expirada debe ser denegada
        self.assertFalse(
            self.authz.can_access_endpoint(
                self.jsmith_id, "/bank/main.jsp", self.conn, session_token=self.expired_jsmith_token
            ),
            "No se debe autorizar acceso a endpoint con sesión expirada."
        )

        # can_modify_account y can_transfer con sesión expirada deben ser denegadas
        self.assertFalse(
            self.authz.can_modify_account(
                self.jsmith_id, self.jsmith_account_savings, self.conn, session_token=self.expired_jsmith_token
            ),
            "No se debe autorizar modificar una cuenta con sesión expirada."
        )
        self.assertFalse(
            self.authz.can_transfer(
                self.jsmith_id,
                self.jsmith_account_savings,
                self.jsmith_account_checking,
                self.conn,
                session_token=self.expired_jsmith_token
            ),
            "No se debe autorizar transferencias con sesión expirada."
        )

    def test_revoked_or_invalid_session_token_rejected(self):
        """
        Caso límite: tokens inexistentes o con is_active=0 deben ser rechazados.
        """
        self.assertFalse(
            self.authz.is_session_valid(self.revoked_jsmith_token, self.conn),
            "Una sesión con is_active=0 debe ser inválida."
        )
        self.assertFalse(
            self.authz.is_session_valid("token_inexistente_completamente_falso", self.conn),
            "Un token que no existe en la base de datos debe ser inválido."
        )
        self.assertFalse(
            self.authz.is_session_valid(None, self.conn),
            "Un token None debe ser inválido."
        )

    def test_session_user_mismatch_rejected(self):
        """
        Caso límite: token válido perteneciente a un usuario A utilizado con user_id de un usuario B.
        El sistema debe detectar la inconsistencia y rechazar la autorización.
        """
        # El token pertenece a jsmith (id 1). Intentar usarlo como victim (id 3).
        self.assertFalse(
            self.authz.is_session_valid(self.valid_jsmith_token, self.conn, user_id=self.victim_id),
            "Debe rechazarse la sesión si el token no pertenece al user_id proporcionado."
        )
        self.assertFalse(
            self.authz.can_view_account(
                self.victim_id, self.victim_account, self.conn, session_token=self.valid_jsmith_token
            ),
            "Debe rechazarse can_view_account si el token pertenece a otro usuario."
        )


class TestVulnerabilitySimulationFailsAssertion(BaseAuthzTestCase):
    """
    Pruebas de regresión que verifican que si el control de acceso se rompe
    (por ejemplo, devolviendo True sin verificar pertenencia o rol),
    las aserciones de seguridad fallan lanzando `AssertionError`.
    """

    def test_broken_idor_service_fails_assertion(self):
        """
        Simulación de vuln-0004: una implementación defectuosa de can_view_account
        que retorna True sin verificar la propiedad de la cuenta disparará AssertionError.
        """
        class VulnerableIDORService(AuthorizationService):
            @classmethod
            def can_view_account(cls, user_id, account_id, db, session_token=None):
                # Simula la vulnerabilidad de AccountAPI.java:
                # busca si la cuenta existe pero jamás comprueba que pertenezca al usuario
                cursor = cls._get_cursor(db)
                cursor.execute("SELECT id FROM accounts WHERE id = ?", (int(account_id),))
                return cursor.fetchone() is not None

        with self.assertRaises(AssertionError):
            # El test de seguridad exige que jsmith NO pueda ver la cuenta de la víctima (800001).
            # Como la implementación vulnerable devuelve True, assert False lanza AssertionError.
            self.assertFalse(
                VulnerableIDORService.can_view_account(self.jsmith_id, self.victim_account, self.conn),
                "Este mensaje no debería verse si la aserción falla correctamente."
            )

    def test_broken_admin_service_fails_assertion(self):
        """
        Simulación de vuln-0005: una implementación defectuosa de can_access_endpoint
        que no exige rol de administrador disparará AssertionError.
        """
        class VulnerableAdminService(AuthorizationService):
            @classmethod
            def can_access_endpoint(cls, user_id, endpoint, db, session_token=None):
                # Simula AdminFilter deshabilitado/misconfigurado:
                # permite a cualquier usuario autenticado acceder a endpoints admin
                return user_id is not None

        with self.assertRaises(AssertionError):
            # El test de seguridad exige que un usuario estándar NO acceda a /admin/addUser.
            self.assertFalse(
                VulnerableAdminService.can_access_endpoint(self.jsmith_id, "/admin/addUser", self.conn),
                "La aserción debe fallar cuando un usuario normal accede a endpoints admin."
            )

    def test_broken_transfer_service_fails_assertion(self):
        """
        Simulación de vuln-0008: una implementación defectuosa de can_transfer
        que no verifica que la cuenta de origen pertenezca al usuario disparará AssertionError.
        """
        class VulnerableTransferService(AuthorizationService):
            @classmethod
            def can_transfer(cls, user_id, from_account_id, to_account_id, db, session_token=None):
                # Simula POST /api/transfer sin verificar ownership de fromAccount:
                # solo valida que ambas cuentas existan
                cursor = cls._get_cursor(db)
                cursor.execute("SELECT id FROM accounts WHERE id = ?", (int(from_account_id),))
                from_exists = cursor.fetchone() is not None
                cursor.execute("SELECT id FROM accounts WHERE id = ?", (int(to_account_id),))
                to_exists = cursor.fetchone() is not None
                return from_exists and to_exists

        with self.assertRaises(AssertionError):
            # El test de seguridad exige que jsmith NO pueda transferir fondos debitando cuenta de la víctima.
            self.assertFalse(
                VulnerableTransferService.can_transfer(
                    self.jsmith_id, self.victim_account, self.jsmith_account_checking, self.conn
                ),
                "La aserción debe fallar cuando se intenta debitar una cuenta ajena."
            )


if __name__ == "__main__":
    unittest.main()
