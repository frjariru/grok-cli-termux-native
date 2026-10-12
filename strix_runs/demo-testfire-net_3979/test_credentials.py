"""
Módulo de seguridad en manejo de credenciales y pruebas unitarias (Auth & Tokens).

Basado en los informes de vulnerabilidad:
- vuln-0002: Plaintext credential and database schema disclosure en /admin/admin.jsp (CWE-522).
             Contraseñas almacenadas en texto plano sin función hash adaptativa con salt,
             permitiendo la reutilización inmediata de credenciales comprometidas.
- vuln-0013: API Bearer Token Embeds Reversible Credentials, Ignores Its Signature,
             and Survives Logout en POST /api/login (CWE-522).
             Token Bearer reversible en base64 que expone la contraseña en claro,
             no valida la firma digital y continúa siendo válido tras el logout.

Contenido de este módulo:
1. Funciones de referencia segura:
   - `hash_password(password)`: PBKDF2-HMAC-SHA256 con salt criptográfico de 16 bytes y 100.000 iteraciones.
   - `verify_password(password, stored_hash, salt)`: Verificación segura usando `hmac.compare_digest` y
     mitigación de ataques de temporización (timing attacks).
   - `create_session_token(user_id, secret, active_sessions)`: Genera un token firmado con HMAC-SHA256.
   - `validate_session_token(token, secret, active_sessions)`: Valida la firma HMAC y comprueba revocación.
2. Funciones de simulación vulnerable:
   - `insecure_store_password`: Almacena contraseñas en texto plano (vuln-0002).
   - `insecure_create_session_token`: Genera tokens en base64 reversible sin firma (vuln-0013).
   - `insecure_validate_session_token`: Valida tokens sin verificar firma ni estado de logout.
3. Suites de pruebas unitarias (`unittest`) que evalúan:
   - Propiedades criptográficas del hashing y verificación.
   - Seguridad de firma y revocación de tokens de sesión.
   - Detección de vulnerabilidades en versiones inseguras (AssertionError).
   - Casos límite (Unicode, emojis, contraseñas de 500+ caracteres y timing attacks).
"""

import base64
import hashlib
import hmac
import json
import os
import time
import unittest
from typing import Any, Optional, Set, Tuple

# Constantes para mitigación de Timing Attacks en usuarios inexistentes
_DUMMY_SALT_HEX = "00" * 16
_DUMMY_HASH_HEX = "00" * 32
_PBKDF2_ITERATIONS = 100_000


def hash_password(password: str) -> Tuple[str, str]:
    """
    Genera un hash seguro para la contraseña utilizando PBKDF2-HMAC-SHA256 con salt aleatorio.

    Garantías:
      - Utiliza un salt criptográficamente seguro de 16 bytes (`os.urandom(16)`).
      - Aplica 100.000 iteraciones de PBKDF2 para mitigar ataques de fuerza bruta por GPU.
      - Retorna tanto el hash resultante como el salt utilizado en formato hexadecimal.

    Parámetros:
        password (str): Contraseña en texto plano a hashear.

    Retorna:
        Tuple[str, str]: Tupla `(hash_hex, salt_hex)`.

    Lanza:
        ValueError: Si la contraseña es nula, vacía o no es una cadena de texto.
    """
    if password is None or not isinstance(password, str) or len(password) == 0:
        raise ValueError("La contraseña debe ser una cadena de texto no vacía.")

    salt_bytes = os.urandom(16)
    password_bytes = password.encode("utf-8")

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password_bytes,
        salt_bytes,
        _PBKDF2_ITERATIONS
    )

    return derived_key.hex(), salt_bytes.hex()


def verify_password(
    password: Optional[str],
    stored_hash: Optional[str],
    salt: Optional[str]
) -> bool:
    """
    Verifica una contraseña contra su hash y salt almacenados de forma segura.

    Garantías contra Timing Attacks:
      - Rechaza contraseñas vacías o None inmediatamente retornando False.
      - Si `stored_hash` o `salt` son None (caso de usuario inexistente), ejecuta
        la misma computación de 100.000 iteraciones sobre datos dummy para igualar
        el tiempo de respuesta y evitar enumeración de usuarios por temporización.
      - Utiliza `hmac.compare_digest` para una comparación en tiempo constante
        que previene ataques de canal lateral (side-channel timing attacks).

    Parámetros:
        password: La contraseña candidata suministrada por el usuario.
        stored_hash: El hash hexadecimal almacenado en la base de datos.
        salt: El salt hexadecimal almacenado.

    Retorna:
        bool: True si la contraseña coincide con el hash almacenado; False en caso contrario.
    """
    if password is None or not isinstance(password, str) or len(password) == 0:
        return False

    # Mitigación de timing attack para usuarios inexistentes en la BD:
    # Se ejecuta el mismo cómputo PBKDF2 para que el tiempo sea indistinguible.
    if stored_hash is None or salt is None or not isinstance(stored_hash, str) or not isinstance(salt, str):
        dummy_salt = bytes.fromhex(_DUMMY_SALT_HEX)
        dummy_computed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            dummy_salt,
            _PBKDF2_ITERATIONS
        ).hex()
        hmac.compare_digest(dummy_computed, _DUMMY_HASH_HEX)
        return False

    if len(stored_hash) == 0 or len(salt) == 0:
        return False

    try:
        salt_bytes = bytes.fromhex(salt)
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt_bytes,
            _PBKDF2_ITERATIONS
        ).hex()
        return hmac.compare_digest(computed_hash, stored_hash)
    except (ValueError, TypeError):
        return False


def create_session_token(
    user_id: Any,
    secret: str,
    active_sessions: Optional[Any] = None
) -> str:
    """
    Crea un token de sesión seguro con firma criptográfica HMAC-SHA256.

    Estructura del token:
      `<payload_urlsafe_b64>.<hmac_sha256_hex>`

    Donde el payload contiene:
      - `user_id`: Identificador del usuario.
      - `created_at`: Marca temporal de emisión.
      - `nonce`: Cadena aleatoria única para garantizar unicidad.

    Si se proporciona `active_sessions`, el token se registra como sesión activa.

    Parámetros:
        user_id: Identificador del usuario.
        secret (str): Clave secreta del servidor para firma HMAC.
        active_sessions (opcional): Conjunto o diccionario de sesiones activas.

    Retorna:
        str: Token firmado y delimitado por punto.
    """
    if user_id is None:
        raise ValueError("user_id no puede ser nulo.")
    if not secret or not isinstance(secret, str):
        raise ValueError("El secreto debe ser una cadena de texto no vacía.")

    payload_dict = {
        "user_id": user_id,
        "created_at": time.time(),
        "nonce": os.urandom(8).hex()
    }
    payload_json = json.dumps(payload_dict, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8")

    signature = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    token = f"{payload_b64}.{signature}"

    if active_sessions is not None:
        if isinstance(active_sessions, set):
            active_sessions.add(token)
        elif isinstance(active_sessions, dict):
            active_sessions[token] = user_id
        elif isinstance(active_sessions, list):
            active_sessions.append(token)

    return token


def validate_session_token(
    token: Optional[str],
    secret: str,
    active_sessions: Optional[Any] = None
) -> bool:
    """
    Valida la autenticidad, integridad y estado de revocación de un token de sesión.

    Verificaciones aplicadas:
      1. Formato estructural (<payload>.<firma>).
      2. Verificación de firma HMAC-SHA256 con `hmac.compare_digest` frente al secreto del servidor.
      3. Decodificación exitosa del JSON del payload.
      4. Comprobación de revocación: verifica que el token esté presente en `active_sessions`
         (mitigando vuln-0013 donde los tokens sobrevivían al logout).

    Parámetros:
        token (str): Token de sesión a validar.
        secret (str): Clave secreta del servidor.
        active_sessions (opcional): Colección de sesiones activas del servidor.

    Retorna:
        bool: True si el token es válido, íntegro y no está revocado; False en caso contrario.
    """
    if not token or not isinstance(token, str):
        return False
    if not secret or not isinstance(secret, str):
        return False

    parts = token.split(".")
    if len(parts) != 2:
        return False

    payload_b64, signature = parts

    # 1. Comprobar firma criptográfica en tiempo constante
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        return False

    # 2. Comprobar integridad del payload
    try:
        # Añadir padding en caso necesario
        padded_b64 = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
        payload_json = base64.urlsafe_b64decode(padded_b64.encode("utf-8")).decode("utf-8")
        payload_dict = json.loads(payload_json)
        if "user_id" not in payload_dict:
            return False
    except Exception:
        return False

    # 3. Comprobar revocación / estado activo (mitigación vuln-0013)
    if active_sessions is not None:
        if token not in active_sessions:
            return False

    return True


# ==============================================================================
# Funciones vulnerables para simulación de fallas de seguridad (vuln-0002 y 0013)
# ==============================================================================

def insecure_store_password(password: str) -> str:
    """
    Simulación de vuln-0002: Almacena contraseñas en texto plano directamente
    en la base de datos sin función hash adaptativa ni salt.
    """
    return password


def insecure_verify_password(password: str, stored_password: str) -> bool:
    """
    Simulación de vuln-0002: Verificación por simple igualdad de cadenas en claro.
    """
    return password == stored_password


def insecure_create_session_token(user_id: Any, password: str = "") -> str:
    """
    Simulación de vuln-0013: Embebe credenciales reversibles en base64 y un sufijo
    sin firma criptográfica HMAC.
    Estructura: base64(base64(user) + ":" + base64(password) + ":" + suffix)
    """
    u_b64 = base64.b64encode(str(user_id).encode("utf-8")).decode("utf-8")
    p_b64 = base64.b64encode(str(password).encode("utf-8")).decode("utf-8")
    inner = f"{u_b64}:{p_b64}:randomsuffix123"
    return base64.b64encode(inner.encode("utf-8")).decode("utf-8")


def insecure_validate_session_token(token: str, active_sessions: Optional[Any] = None) -> bool:
    """
    Simulación de vuln-0013: Decodifica base64 pero NO valida firma y NO consulta
    `active_sessions`, por lo que el token sobrevive al logout y acepta firmas falsas.
    """
    try:
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        inner = base64.b64decode(padded.encode("utf-8")).decode("utf-8")
        parts = inner.split(":")
        # Solo comprueba estructura superficial ignorando active_sessions y firmas
        return len(parts) >= 2
    except Exception:
        return False


# ==============================================================================
# Suites de Pruebas Unitarias con unittest
# ==============================================================================

class TestPasswordHashingAndVerification(unittest.TestCase):
    """
    Pruebas unitarias para las funciones de hash y verificación de contraseñas:
      - Hashes distintos para contraseñas distintas.
      - Hashes distintos para la misma contraseña (gracias al salt aleatorio).
      - verify_password devuelve True con contraseña correcta y False con incorrecta.
      - verify_password rechaza cadenas vacías y None.
      - El hash no contiene la contraseña original (no texto plano).
    """

    def test_different_passwords_produce_different_hashes(self):
        """Verifica que dos contraseñas distintas generen hashes distintos."""
        hash_1, _ = hash_password("PasswordAlpha123!")
        hash_2, _ = hash_password("PasswordBeta456!")
        self.assertNotEqual(hash_1, hash_2, "Contraseñas distintas deben generar hashes distintos.")

    def test_same_password_hashed_twice_produces_different_hashes_due_to_salt(self):
        """
        Verifica que la misma contraseña genere hashes y salts distintos en dos ejecuciones
        consecutivas debido al uso de salts criptográficos aleatorios.
        """
        pwd = "SameMasterPassword2026!"
        hash_1, salt_1 = hash_password(pwd)
        hash_2, salt_2 = hash_password(pwd)

        self.assertNotEqual(salt_1, salt_2, "Cada llamada debe generar un salt aleatorio único.")
        self.assertNotEqual(hash_1, hash_2, "El hash debe variar entre llamadas para la misma contraseña.")

        # Ambas deben verificarse exitosamente contra su respectivo salt
        self.assertTrue(verify_password(pwd, hash_1, salt_1))
        self.assertTrue(verify_password(pwd, hash_2, salt_2))

    def test_verify_password_returns_true_with_correct_password(self):
        """Control positivo: verify_password retorna True cuando la contraseña es correcta."""
        pwd = "CorrectSecretPassword!789"
        stored_hash, salt = hash_password(pwd)
        self.assertTrue(
            verify_password(pwd, stored_hash, salt),
            "verify_password debe retornar True para la contraseña correcta."
        )

    def test_verify_password_returns_false_with_incorrect_password(self):
        """Control negativo: verify_password retorna False cuando la contraseña es incorrecta."""
        pwd = "CorrectSecretPassword!789"
        stored_hash, salt = hash_password(pwd)
        self.assertFalse(
            verify_password("IncorrectPasswordXYZ", stored_hash, salt),
            "verify_password debe retornar False para una contraseña incorrecta."
        )

    def test_verify_password_rejects_empty_strings_and_none(self):
        """Verifica que verify_password rechace valores nulos o cadenas vacías sin excepciones."""
        pwd = "ValidUserPassword#2026"
        stored_hash, salt = hash_password(pwd)

        # Contraseña vacía o None
        self.assertFalse(verify_password("", stored_hash, salt))
        self.assertFalse(verify_password(None, stored_hash, salt))

        # Hash vacío o None
        self.assertFalse(verify_password(pwd, "", salt))
        self.assertFalse(verify_password(pwd, None, salt))

        # Salt vacío o None
        self.assertFalse(verify_password(pwd, stored_hash, ""))
        self.assertFalse(verify_password(pwd, stored_hash, None))

    def test_hash_does_not_contain_original_password_not_plaintext(self):
        """
        Reporte vuln-0002: Comprueba que el hash almacenado y el salt NO contengan
        la contraseña original en claro (garantía de no texto plano).
        """
        plaintext_pw = "admin_hacked"
        stored_hash, salt = hash_password(plaintext_pw)

        self.assertNotIn(
            plaintext_pw,
            stored_hash,
            "Fallo de seguridad (vuln-0002): el hash almacena la contraseña en texto plano."
        )
        self.assertNotIn(
            plaintext_pw,
            salt,
            "Fallo de seguridad: el salt contiene la contraseña en texto plano."
        )
        self.assertNotEqual(
            stored_hash,
            plaintext_pw,
            "El valor almacenado no debe ser igual a la contraseña en claro."
        )


class TestSessionTokenSecurity(unittest.TestCase):
    """
    Pruebas unitarias para tokens de sesión con firma HMAC y control de revocación:
      - Manipulación de 1 byte en la firma hace fallar la validación.
      - Modificación del payload (user_id cambiado) hace fallar la validación.
      - Token revocado (logout) hace fallar la validación aunque la firma sea válida.
      - Token firmado con otro secreto falla la validación.
    """

    def setUp(self):
        self.secret = "super_secure_server_hmac_secret_key_2026"
        self.other_secret = "different_unauthorized_secret_key_9999"
        self.active_sessions: Set[str] = set()

    def test_valid_session_token_succeeds(self):
        """Control positivo: un token recién creado y registrado valida correctamente."""
        token = create_session_token("jsmith", self.secret, self.active_sessions)
        self.assertTrue(
            validate_session_token(token, self.secret, self.active_sessions),
            "Un token legítimo debe validar exitosamente."
        )

    def test_tampered_token_signature_fails_validation(self):
        """
        Verifica que alterar un solo byte en la firma HMAC invalide inmediatamente el token.
        """
        token = create_session_token("jsmith", self.secret, self.active_sessions)
        payload_b64, signature = token.split(".")

        # Cambiar el último carácter de la firma
        tampered_char = "0" if signature[-1] != "0" else "1"
        tampered_sig = signature[:-1] + tampered_char
        tampered_token = f"{payload_b64}.{tampered_sig}"

        self.assertFalse(
            validate_session_token(tampered_token, self.secret, self.active_sessions),
            "Un token con firma alterada debe fallar la validación."
        )

    def test_tampered_payload_user_id_fails_validation(self):
        """
        Verifica que alterar el payload (ej: cambiar user_id de 'jsmith' a 'admin')
        sin conocer el secreto invalide la firma HMAC.
        """
        token = create_session_token("jsmith", self.secret, self.active_sessions)
        _, signature = token.split(".")

        # Crear payload forjado para 'admin'
        forged_payload = json.dumps({"user_id": "admin", "created_at": time.time(), "nonce": "abc12345"})
        forged_b64 = base64.urlsafe_b64encode(forged_payload.encode("utf-8")).decode("utf-8")
        tampered_token = f"{forged_b64}.{signature}"

        self.assertFalse(
            validate_session_token(tampered_token, self.secret, self.active_sessions),
            "Un token con payload alterado (privilege escalation) debe fallar la validación."
        )

    def test_revoked_token_logout_fails_validation_even_with_valid_signature(self):
        """
        Reporte vuln-0013: Verifica que tras el logout (revocación), el token sea rechazado
        incluso si su firma HMAC es matemáticamente válida.
        """
        token = create_session_token("jsmith", self.secret, self.active_sessions)

        # Antes del logout: token válido
        self.assertTrue(validate_session_token(token, self.secret, self.active_sessions))

        # Simular logout: remover el token del registro de sesiones activas del servidor
        self.active_sessions.remove(token)

        # Después del logout: token revocado
        self.assertFalse(
            validate_session_token(token, self.secret, self.active_sessions),
            "Fallo de seguridad (vuln-0013): el token siguió siendo válido tras el logout."
        )

    def test_token_signed_with_different_secret_fails_validation(self):
        """Verifica que un token firmado con una clave secreta distinta falle la validación."""
        token_other = create_session_token("jsmith", self.other_secret, self.active_sessions)
        self.assertFalse(
            validate_session_token(token_other, self.secret, self.active_sessions),
            "Un token firmado con una clave distinta no debe ser aceptado."
        )


class TestVulnerabilitySimulations(unittest.TestCase):
    """
    Pruebas de simulación de las vulnerabilidades vuln-0002 y vuln-0013:
      - Demuestra que el almacenamiento en texto plano expone las contraseñas.
      - Demuestra que los tokens en base64 sin firma permiten recuperar credenciales
        y sobreviven al logout (disparando AssertionError al verificar seguridad).
    """

    def test_insecure_plaintext_storage_exposes_password(self):
        """
        Simulación de vuln-0002: Demuestra que almacenar en texto plano deja visible
        la contraseña original en claro (ej: 'admin_hacked').
        """
        secret_pass = "admin_hacked"
        stored_value = insecure_store_password(secret_pass)

        # En la versión vulnerable, la contraseña se expone directamente
        self.assertEqual(stored_value, secret_pass)

        # La aserción de seguridad de que la contraseña NO esté en texto plano falla con AssertionError:
        with self.assertRaises(AssertionError):
            self.assertNotEqual(
                stored_value,
                secret_pass,
                "Fallo esperado: la versión vulnerable expone la contraseña en texto plano."
            )

    def test_insecure_token_is_reversible_and_survives_logout(self):
        """
        Simulación de vuln-0013:
        1. Demuestra que el token Bearer en base64 es trivialmente reversible a texto plano.
        2. Demuestra que el token sigue considerándose válido tras el logout del usuario.
        """
        user = "admin"
        password = "admin_hacked"
        active_sessions: Set[str] = set()

        insecure_tok = insecure_create_session_token(user, password)
        active_sessions.add(insecure_tok)

        # 1. Recuperar credenciales del token vulnerable
        decoded_inner = base64.b64decode(insecure_tok.encode("utf-8")).decode("utf-8")
        u_b64, p_b64, _ = decoded_inner.split(":")
        recovered_user = base64.b64decode(u_b64).decode("utf-8")
        recovered_password = base64.b64decode(p_b64).decode("utf-8")

        self.assertEqual(recovered_user, user)
        self.assertEqual(recovered_password, password)

        # 2. Simular logout: remover de active_sessions
        active_sessions.remove(insecure_tok)

        # En la implementación vulnerable, el token sigue pasando la validación porque no consulta el estado
        is_still_valid = insecure_validate_session_token(insecure_tok, active_sessions)
        self.assertTrue(is_still_valid)

        # La aserción de seguridad de que el token sea rechazado tras logout falla con AssertionError:
        with self.assertRaises(AssertionError):
            self.assertFalse(
                is_still_valid,
                "Fallo esperado: el token vulnerable sobrevivió al logout."
            )


class TestEdgeCasesAndTimingAttacks(unittest.TestCase):
    """
    Casos límite:
      - Contraseñas complejas con Unicode, emojis y espacios.
      - Contraseñas muy largas (500+ caracteres).
      - Protección contra Timing Attacks en verify_password (tiempo equivalente
        entre contraseña incorrecta y usuario inexistente mediante compare_digest).
    """

    def test_password_with_unicode_emojis_and_spaces(self):
        """
        Caso límite: contraseñas que contienen caracteres Unicode multibyte,
        emojis diversos y múltiples espacios en blanco.
        """
        complex_pw = "P@ssw0rd con espacios y acentos ñandú 🔒🔑✨ 2026!"
        stored_hash, salt = hash_password(complex_pw)

        self.assertTrue(verify_password(complex_pw, stored_hash, salt))
        self.assertFalse(verify_password(complex_pw + "extra", stored_hash, salt))
        self.assertFalse(verify_password(complex_pw.replace("🔒", "🔓"), stored_hash, salt))

    def test_very_long_password_500_plus_characters(self):
        """
        Caso límite: contraseñas extremadamente largas (600+ caracteres).
        Verifica que PBKDF2 procese la longitud sin desbordamientos ni truncamiento.
        """
        long_pw = "A" * 600 + "SuperSecureLongPasswordEnding!2026"
        stored_hash, salt = hash_password(long_pw)

        self.assertTrue(verify_password(long_pw, stored_hash, salt))
        self.assertFalse(verify_password(long_pw[:-1] + "X", stored_hash, salt))

    def test_timing_attack_protection_similar_time_for_wrong_pass_and_nonexistent_user(self):
        """
        Caso límite / Seguridad: Protección contra ataques de temporización (Timing Attacks).
        Verifica que `verify_password`:
          1. Ejecute el cálculo de hash completo incluso para usuarios inexistentes (stored_hash=None, salt=None).
          2. El tiempo transcurrido para usuario inexistente sea del mismo orden de magnitud
             que para un usuario existente con contraseña incorrecta (ambos ejecutan 100.000 iteraciones).
        """
        real_pw = "RegisteredUserSecret2026!"
        stored_hash, salt = hash_password(real_pw)

        # Calentamiento inicial
        verify_password("warmup", stored_hash, salt)

        # Medir tiempo para usuario existente con contraseña incorrecta
        t0 = time.perf_counter()
        verify_password("WrongPassword123!", stored_hash, salt)
        time_wrong_password = time.perf_counter() - t0

        # Medir tiempo para usuario inexistente (hash y salt None)
        t0 = time.perf_counter()
        verify_password("WrongPassword123!", None, None)
        time_nonexistent_user = time.perf_counter() - t0

        # Ambas operaciones deben realizar el cómputo de 100.000 iteraciones
        # La diferencia debe ser mínima (menor a 0.05 segundos)
        time_difference = abs(time_wrong_password - time_nonexistent_user)
        self.assertLess(
            time_difference,
            0.05,
            f"Fallo de timing attack: diferencia de tiempo excesiva ({time_difference:.4f}s) "
            f"entre usuario inexistente ({time_nonexistent_user:.4f}s) y contraseña incorrecta ({time_wrong_password:.4f}s)."
        )
        self.assertGreater(
            time_nonexistent_user,
            0.005,
            "El chequeo para usuario inexistente debe ejecutar el cómputo dummy en lugar de retornar de inmediato."
        )


if __name__ == "__main__":
    unittest.main()
