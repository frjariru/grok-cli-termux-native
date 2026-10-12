"""
Módulo de mitigación y pruebas unitarias contra Path Traversal (CWE-22).

Este archivo se basa en el informe de vulnerabilidad:
- vuln-0003: Unauthenticated Path Traversal en el parámetro 'content' de /index.jsp
  que permite leer archivos fuera del directorio permitido (/static/) y acceder a
  recursos protegidos de la aplicación web (como /WEB-INF/web.xml).

Contenido del módulo:
1. Función de referencia `safe_join(base_path, user_path)`:
   - Resuelve la ruta canónica completa utilizando `os.path.realpath`.
   - Rechaza rutas que escapen del directorio base (`base_path`).
   - Rechace rutas absolutas (POSIX y Windows).
   - Rechaza inyecciones de bytes nulos (\\x00).
   - Normaliza variantes codificadas en URL y separadores de barra invertida.
   - Retorna la ruta segura y canónica o levanta `ValueError`.
2. Función vulnerable de referencia `insecure_join(base_path, user_path)`:
   - Simula la concatenación ingenua con `os.path.join` sin validación.
3. Suites de pruebas unitarias (`unittest`) que validan:
   - Bloqueo de payloads clásicos, codificados, absolutos, null bytes y backslashes.
   - Controles positivos de acceso a archivos legítimos en la raíz y subcarpetas.
   - Simulación de vulnerabilidad que demuestra que la versión insegura dispara `AssertionError`.
"""

import os
import re
import tempfile
import unittest
import urllib.parse
from typing import Any


def safe_join(base_path: str, user_path: str) -> str:
    """
    Une de manera segura un directorio base con una ruta suministrada por el usuario,
    previniendo ataques de Path Traversal / Directory Traversal (CWE-22).

    Mecanismos de protección:
      1. Validación de tipos y presencia de rutas (rechaza valores nulos).
      2. Detección inmediata de bytes nulos (\\x00 / Null byte injection).
      3. Decodificación recursiva de URL percent-encoding (mitiga ..%2f, %2e%2e%2f).
      4. Verificación de bytes nulos tras decodificación.
      5. Rechazo de rutas absolutas (POSIX como '/etc/passwd' y Windows como 'C:\\Windows').
      6. Normalización de separadores de ruta (convierte backslashes '\\' a '/').
      7. Detección de patrones de evasión con puntos múltiples (como '....//').
      8. Resolución canónica mediante `os.path.realpath` para eliminar '..' y symlinks.
      9. Verificación estricta de confinamiento dentro de `base_path`.

    Parámetros:
        base_path (str): Directorio raíz permitido en el sistema de archivos.
        user_path (str): Ruta relativa no confiable solicitada por el usuario.

    Retorna:
        str: Ruta absoluta canónica y segura que reside dentro de `base_path`.

    Lanza:
        ValueError: Si la ruta es nula, absoluta, contiene null bytes, patrones de evasión
                    o resuelve fuera del directorio base permitido.
    """
    if base_path is None or user_path is None:
        raise ValueError("Las rutas no pueden ser nulas (None).")

    if not isinstance(base_path, str) or not isinstance(user_path, str):
        raise ValueError("Tanto base_path como user_path deben ser cadenas de texto.")

    # 1. Detección temprana de null bytes en la entrada cruda
    if "\x00" in base_path or "\x00" in user_path:
        raise ValueError("Null byte detectado en la ruta suministrada.")

    # 2. Decodificación iterativa de percent-encoding (URL decoding)
    # Mitiga evasiones como ..%2f, %2e%2e%2f y doble URL encoding (%252e%252e)
    decoded_user_path = user_path
    prev_path = None
    loop_limit = 10
    while prev_path != decoded_user_path and loop_limit > 0:
        prev_path = decoded_user_path
        decoded_user_path = urllib.parse.unquote(decoded_user_path)
        loop_limit -= 1

    # Detección de null bytes expuestos tras la decodificación URL (ej: %00)
    if "\x00" in decoded_user_path:
        raise ValueError("Null byte detectado tras decodificación URL.")

    # 3. Rechazo de rutas absolutas (POSIX y Windows)
    # Ejemplos: /etc/passwd, \Windows\System32, C:\Windows
    if (
        os.path.isabs(decoded_user_path)
        or decoded_user_path.startswith("/")
        or decoded_user_path.startswith("\\")
        or bool(re.match(r"^[a-zA-Z]:", decoded_user_path))
    ):
        raise ValueError("Rutas absolutas no permitidas.")

    # 4. Normalizar barras invertidas (estilo Windows) a barras normales
    normalized_path = decoded_user_path.replace("\\", "/")

    # Verificar nuevamente si al reemplazar separadores se formó una ruta absoluta
    if normalized_path.startswith("/"):
        raise ValueError("Rutas absolutas no permitidas tras normalización de separadores.")

    # 5. Detección de secuencias de puntos múltiples (ej: ....// que buscan evadir reemplazos)
    if bool(re.search(r"(?:^|/)\.{3,}(?:/|$)", normalized_path)):
        raise ValueError("Secuencia de traversal o evasión sospechosa detectada (puntos múltiples).")

    # 6. Resolución canónica de ambas rutas con realpath
    resolved_base = os.path.realpath(base_path)
    joined_target = os.path.join(resolved_base, normalized_path)
    resolved_target = os.path.realpath(joined_target)

    # 7. Verificación de confinamiento: la ruta destino DEBE estar dentro del directorio base
    base_prefix = resolved_base if resolved_base.endswith(os.sep) else resolved_base + os.sep

    # Se permite si apunta al mismo directorio base o a un archivo/carpeta dentro de él
    is_confined = (resolved_target == resolved_base) or resolved_target.startswith(base_prefix)

    if not is_confined:
        raise ValueError(
            f"Path traversal detectado: la ruta solicitada ({resolved_target}) "
            f"escapa del directorio base permitido ({resolved_base})."
        )

    return resolved_target


def insecure_join(base_path: str, user_path: str) -> str:
    """
    Función insegura de referencia que replica el comportamiento vulnerable
    reportado en vuln-0003.

    Realiza una concatenación directa con `os.path.join` sin verificar
    si la ruta escapa de `base_path`, si es absoluta o si contiene caracteres maliciosos.
    """
    return os.path.join(base_path, user_path)


class BasePathTraversalTestCase(unittest.TestCase):
    """
    Clase base de pruebas que crea una estructura aislada de archivos en cada ejecución
    utilizando `tempfile.TemporaryDirectory()`, garantizando la limpieza en tearDown.
    """

    def setUp(self):
        """
        Configura el entorno de prueba con:
          - Un directorio base permitido (`base_dir`) con archivos legítimos y subcarpetas.
          - Un directorio exterior confidencial (`outside_dir`) con archivos protegidos
            para simular recursos como /WEB-INF/web.xml o /etc/passwd.
        """
        self.temp_base = tempfile.TemporaryDirectory()
        self.base_dir = os.path.realpath(self.temp_base.name)

        # Crear estructura dentro de base_dir:
        # base_dir/
        #   ├── legit.txt
        #   ├── index.html
        #   ├── subfolder/
        #   │     └── nested.txt
        #   └── static/
        #         └── style.css
        self.legit_file = os.path.join(self.base_dir, "legit.txt")
        with open(self.legit_file, "w", encoding="utf-8") as f:
            f.write("CONTENIDO_PUBLICO_LEGITIMO")

        self.index_file = os.path.join(self.base_dir, "index.html")
        with open(self.index_file, "w", encoding="utf-8") as f:
            f.write("<html><body>Home</body></html>")

        self.subfolder = os.path.join(self.base_dir, "subfolder")
        os.makedirs(self.subfolder, exist_ok=True)
        self.nested_file = os.path.join(self.subfolder, "nested.txt")
        with open(self.nested_file, "w", encoding="utf-8") as f:
            f.write("CONTENIDO_ANIDADO_EN_SUBCARPETA")

        self.static_dir = os.path.join(self.base_dir, "static")
        os.makedirs(self.static_dir, exist_ok=True)
        self.static_file = os.path.join(self.static_dir, "style.css")
        with open(self.static_file, "w", encoding="utf-8") as f:
            f.write("body { background: #fff; }")

        # Crear un directorio exterior fuera de base_dir (simula archivos del sistema o WEB-INF)
        self.temp_outside = tempfile.TemporaryDirectory()
        self.outside_dir = os.path.realpath(self.temp_outside.name)

        # Simular /WEB-INF/web.xml (como en vuln-0003)
        self.web_inf_dir = os.path.join(self.outside_dir, "WEB-INF")
        os.makedirs(self.web_inf_dir, exist_ok=True)
        self.secret_web_xml = os.path.join(self.web_inf_dir, "web.xml")
        with open(self.secret_web_xml, "w", encoding="utf-8") as f:
            f.write("<web-app><display-name>Altoro Mutual Deployment Descriptor</display-name></web-app>")

        # Simular /etc/passwd
        self.secret_passwd = os.path.join(self.outside_dir, "passwd")
        with open(self.secret_passwd, "w", encoding="utf-8") as f:
            f.write("root:x:0:0:root:/root:/bin/bash\njsmith:x:1000:1000::/home/jsmith:/bin/sh\n")

    def tearDown(self):
        """Limpia los directorios temporales tras finalizar cada test."""
        self.temp_base.cleanup()
        self.temp_outside.cleanup()


class TestSafeJoinSecurity(BasePathTraversalTestCase):
    """
    Pruebas unitarias que validan la seguridad y robustez de `safe_join` contra
    diversas clases de payloads de Path Traversal y vectores de evasión.
    """

    def test_classic_payloads_rejected(self):
        """
        Verifica el rechazo de secuencias clásicas de traversal:
          - ../../../etc/passwd
          - ....//....//etc/passwd (evasión de reemplazo no recursivo)
          - ../WEB-INF/web.xml (vector directo de vuln-0003)
        """
        classic_payloads = [
            "../../../etc/passwd",
            "../../../../etc/shadow",
            "....//....//etc/passwd",
            "....//....//....//etc/passwd",
            "../WEB-INF/web.xml",
            "../../WEB-INF/web.xml",
            "static/../../WEB-INF/web.xml",
        ]

        for payload in classic_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(
                    ValueError,
                    msg=f"Fallo de seguridad: safe_join no rechazó el payload clásico '{payload}'"
                ):
                    safe_join(self.base_dir, payload)

    def test_encoded_variants_rejected(self):
        """
        Verifica el rechazo de variantes con codificación URL (percent-encoding):
          - ..%2F..%2Fetc%2Fpasswd
          - %2e%2e%2f%2e%2e%2f
          - ..%2fWEB-INF/web.xml (documentado en vuln-0003)
          - %2e%2e%2fWEB-INF/web.xml (documentado en vuln-0003)
          - ..%5cWEB-INF/web.xml (documentado en vuln-0003)
          - Doble codificación URL (%252e%252e%252f)
        """
        encoded_payloads = [
            "..%2F..%2Fetc%2Fpasswd",
            "..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2fWEB-INF/web.xml",
            "%2e%2e%2fWEB-INF/web.xml",
            "..%5cWEB-INF/web.xml",
            "%252e%252e%252fWEB-INF/web.xml",  # Doble codificación
        ]

        for payload in encoded_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(
                    ValueError,
                    msg=f"Fallo de seguridad: safe_join no rechazó la variante codificada '{payload}'"
                ):
                    safe_join(self.base_dir, payload)

    def test_absolute_paths_rejected(self):
        """
        Verifica el rechazo de rutas absolutas:
          - /etc/passwd
          - /var/log/syslog
          - C:\\Windows\\System32
          - C:/Windows/System32
          - \\\\server\\share\\file.txt (UNC path)
        """
        absolute_payloads = [
            "/etc/passwd",
            "/var/log/syslog",
            "/WEB-INF/web.xml",
            "C:\\Windows\\System32",
            "C:/Windows/System32",
            "D:\\secret.txt",
            "\\\\127.0.0.1\\c$\\secret.txt",
        ]

        for payload in absolute_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(
                    ValueError,
                    msg=f"Fallo de seguridad: safe_join no rechazó la ruta absoluta '{payload}'"
                ):
                    safe_join(self.base_dir, payload)

    def test_null_byte_injection_rejected(self):
        """
        Verifica el rechazo de inyección de bytes nulos (\\x00):
          - legit.txt\\x00../../etc/passwd
          - legit.txt\\x00/etc/passwd
          - Codificación URL de null byte: legit.txt%00../../etc/passwd
        """
        null_byte_payloads = [
            "legit.txt\x00../../etc/passwd",
            "legit.txt\x00/etc/passwd",
            "subfolder/nested.txt\x00../secret.txt",
            "legit.txt%00../../etc/passwd",
            "legit.txt%00../WEB-INF/web.xml",
        ]

        for payload in null_byte_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(
                    ValueError,
                    msg=f"Fallo de seguridad: safe_join no rechazó el null byte en '{payload}'"
                ):
                    safe_join(self.base_dir, payload)

    def test_backslash_paths_rejected(self):
        """
        Verifica el rechazo de rutas con separadores de barra invertida (estilo Windows):
          - ..\\..\\..\\etc\\passwd
          - ..\\..\\Windows\\win.ini
          - subfolder\\..\\..\\secret.txt
        """
        backslash_payloads = [
            "..\\..\\..\\etc\\passwd",
            "..\\..\\Windows\\win.ini",
            "subfolder\\..\\..\\secret.txt",
            "..\\WEB-INF\\web.xml",
        ]

        for payload in backslash_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(
                    ValueError,
                    msg=f"Fallo de seguridad: safe_join no rechazó la ruta con backslashes '{payload}'"
                ):
                    safe_join(self.base_dir, payload)

    def test_positive_control_legitimate_files_allowed(self):
        """
        Control positivo: verifica que rutas legítimas ubicadas directamente
        en el directorio base SÍ se resuelven de forma correcta.
        """
        resolved_legit = safe_join(self.base_dir, "legit.txt")
        self.assertEqual(
            resolved_legit,
            self.legit_file,
            "La ruta resuelta debe coincidir con la ubicación canónica de legit.txt."
        )
        self.assertTrue(os.path.exists(resolved_legit))

        resolved_index = safe_join(self.base_dir, "index.html")
        self.assertEqual(
            resolved_index,
            self.index_file,
            "La ruta resuelta debe coincidir con la ubicación canónica de index.html."
        )
        self.assertTrue(os.path.exists(resolved_index))

    def test_positive_control_subfolder_symmetry(self):
        """
        Simetría / subcarpetas: verifica que rutas legítimas a archivos dentro
        de subcarpetas válidas también funcionan correctamente.
        """
        resolved_nested = safe_join(self.base_dir, "subfolder/nested.txt")
        self.assertEqual(
            resolved_nested,
            self.nested_file,
            "La ruta resuelta debe coincidir con la ubicación de subfolder/nested.txt."
        )
        self.assertTrue(os.path.exists(resolved_nested))

        resolved_static = safe_join(self.base_dir, "static/style.css")
        self.assertEqual(
            resolved_static,
            self.static_file,
            "La ruta resuelta debe coincidir con static/style.css."
        )
        self.assertTrue(os.path.exists(resolved_static))

    def test_edge_cases_invalid_inputs(self):
        """
        Casos límite: entradas None, tipos no soportados o cadenas vacías.
        """
        with self.assertRaises(ValueError):
            safe_join(None, "legit.txt")

        with self.assertRaises(ValueError):
            safe_join(self.base_dir, None)

        with self.assertRaises(ValueError):
            safe_join(self.base_dir, 12345)  # No es string


class TestInsecureJoinVulnerabilitySimulation(BasePathTraversalTestCase):
    """
    Simulación de vulnerabilidad: demuestra que una implementación descuidada
    que solo hace `os.path.join` sin validar es vulnerable a los mismos payloads,
    provocando que las aserciones de seguridad fallen con `AssertionError`.
    """

    def test_insecure_join_allows_path_traversal_escaping_base(self):
        """
        Demuestra que `insecure_join` permite escapar del directorio base con ../../../etc/passwd.
        Al intentar verificar mediante aserción que la ruta permanece dentro de base_dir,
        la prueba falla lanzando AssertionError.
        """
        payload = "../../../etc/passwd"
        untrusted_result = insecure_join(self.base_dir, payload)
        canonical_result = os.path.realpath(untrusted_result)

        # La aserción de seguridad exige que la ruta esté dentro de self.base_dir.
        # Como insecure_join es vulnerable, canonical_result apunta fuera (/etc/passwd),
        # por lo que self.assertTrue dispara AssertionError.
        with self.assertRaises(AssertionError):
            self.assertTrue(
                canonical_result.startswith(self.base_dir + os.sep),
                "Fallo esperado: la función insegura no evitó el escape del directorio base."
            )

    def test_insecure_join_allows_absolute_path_bypass(self):
        """
        Demuestra que en Python `os.path.join(base_dir, '/etc/passwd')` descarta por completo
        `base_dir` y devuelve directamente '/etc/passwd'.
        La aserción de que la ruta comience por `base_dir` dispara AssertionError.
        """
        untrusted_result = insecure_join(self.base_dir, "/etc/passwd")

        with self.assertRaises(AssertionError):
            self.assertTrue(
                untrusted_result.startswith(self.base_dir),
                "Fallo esperado: os.path.join descartó base_dir ante una ruta absoluta."
            )

    def test_insecure_join_fails_to_raise_value_error_on_payloads(self):
        """
        Demuestra que `insecure_join` no valida ni levanta `ValueError` ante entradas
        maliciosas. Un arnés de prueba de seguridad que espere `ValueError` fallará
        con `AssertionError: ValueError not raised`.
        """
        malicious_payloads = [
            "../../../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",
            "/etc/passwd",
            "legit.txt\x00../../etc/passwd",
            "..\\..\\..\\etc\\passwd",
        ]

        for payload in malicious_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(AssertionError):
                    # Intentar verificar que la función levanta ValueError:
                    # como insecure_join NO lo levanta, assertRaises lanza AssertionError!
                    with self.assertRaises(ValueError):
                        insecure_join(self.base_dir, payload)

    def test_insecure_join_exploits_file_read_outside_base(self):
        """
        Demuestra la explotación completa de vuln-0003: calculando la ruta relativa hacia
        un recurso confidencial exterior (WEB-INF/web.xml), `insecure_join` permite acceder
        y leer el archivo protegido. La aserción de no-filtración falla con AssertionError.
        """
        # Calcular el traversal relativo desde base_dir hasta secret_web_xml
        relative_traversal = os.path.relpath(self.secret_web_xml, self.base_dir)

        insecure_path = insecure_join(self.base_dir, relative_traversal)
        resolved_path = os.path.realpath(insecure_path)

        # Verificar que el atacante puede efectivamente leer el archivo confidencial
        with open(resolved_path, "r", encoding="utf-8") as f:
            leaked_content = f.read()

        # Si el control de acceso estuviera vigente, el contenido NO debería contener el descriptor.
        # Demostramos que la aserción de protección falla con AssertionError:
        with self.assertRaises(AssertionError):
            self.assertNotIn(
                "Altoro Mutual Deployment Descriptor",
                leaked_content,
                "Fallo esperado: se leyó exitosamente el archivo protegido fuera de base_dir."
            )


if __name__ == "__main__":
    unittest.main()
