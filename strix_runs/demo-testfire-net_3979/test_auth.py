import sqlite3
import unittest

def authenticate_user(cursor: sqlite3.Cursor, username: str, password: str) -> bool:
    """
    Ejemplo de función de autenticación segura utilizando consultas preparadas
    (parámetros enlazados con '?') para evitar inyecciones SQL.
    """
    query = "SELECT COUNT(*) FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    count = cursor.fetchone()[0]
    return count > 0


class TestLoginSecurity(unittest.TestCase):

    def setUp(self):
        """Configura una base de datos SQLite en memoria para aislar la prueba."""
        self.conn = sqlite3.connect(":memory:")
        self.cursor = self.conn.cursor()

        # Crear tabla y usuario de prueba
        self.cursor.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
        )
        self.cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", "SuperSecretPassword123!")
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_valid_credentials_succeed(self):
        """Control positivo: credenciales correctas deben autenticar exitosamente."""
        is_authenticated = authenticate_user(self.cursor, "admin", "SuperSecretPassword123!")
        self.assertTrue(is_authenticated, "El login con credenciales válidas debería tener éxito.")

    def test_invalid_credentials_fail(self):
        """Control negativo: contraseña incorrecta debe ser rechazada."""
        is_authenticated = authenticate_user(self.cursor, "admin", "WrongPassword")
        self.assertFalse(is_authenticated, "El login con credenciales incorrectas debe fallar.")

    def test_sql_injection_username_bypass_rejected(self):
        """
        Verifica que el payload de truncamiento de consulta en el usuario sea rechazado.
        Si la función fuese vulnerable a concatenación, retornaría True y el test fallará.
        """
        payload_username = "admin'-- "
        dummy_password = "any_password"

        is_authenticated = authenticate_user(self.cursor, payload_username, dummy_password)
        self.assertFalse(
            is_authenticated,
            "Seguridad vulnerada: el payload de inyección en 'username' logró autenticarse."
        )

    def test_sql_injection_password_tautology_rejected(self):
        """
        Verifica que el payload de condición tautológica en la contraseña sea rechazado.
        Si la función concatenara la entrada, evaluaría True y el test fallará.
        """
        username = "admin"
        payload_password = "' OR '1'='1"

        is_authenticated = authenticate_user(self.cursor, username, payload_password)
        self.assertFalse(
            is_authenticated,
            "Seguridad vulnerada: el payload de inyección en 'password' logró autenticarse."
        )


if __name__ == "__main__":
    unittest.main()
