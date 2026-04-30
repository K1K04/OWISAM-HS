import argparse
import requests
from bs4 import BeautifulSoup
import ssl
import socket
from urllib.parse import urlparse
import html
import os
from http.cookies import SimpleCookie

class SecurityReport:
    def __init__(self):
        self.findings = []
        self.score = 100
        self.risk_level = "BAJO"
        self.details = {}

    def add_finding(self, text, penalty=0):
        self.findings.append(text)
        self.score -= penalty

    def finalize(self):
        if self.score >= 80:
            self.risk_level = "BAJO"
        elif self.score >= 50:
            self.risk_level = "MEDIO"
        else:
            self.risk_level = "ALTO"

    def to_html(self, portal_name=None, fecha_hora=None):
        portal_info = f"<div class='portal'><b>Portal analizado:</b> {html.escape(portal_name) if portal_name else '-'} </div>" if portal_name else ""
        fecha_info = f"<div class='fecha'><b>Fecha y hora:</b> {fecha_hora if fecha_hora else '-'} </div>"
        html_report = f"""
        <!DOCTYPE html>
        <html lang='es'>
        <head>
            <meta charset='UTF-8'>
            <title>OWISAM-HS Security Report</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    background: #f4f6fb;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 700px;
                    margin: 40px auto;
                    background: #fff;
                    border-radius: 10px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                    padding: 32px 40px 32px 40px;
                }}
                h1 {{
                    color: #2a3b8f;
                    margin-bottom: 8px;
                }}
                .score {{
                    font-size: 1.3em;
                    margin: 18px 0 8px 0;
                }}
                .risk {{
                    font-size: 1.1em;
                    font-weight: bold;
                    color: #fff;
                    display: inline-block;
                    padding: 4px 16px;
                    border-radius: 16px;
                    background: {self._risk_color()};
                }}
                .portal, .fecha {{
                    margin: 8px 0 8px 0;
                    font-size: 1.05em;
                }}
                ul.findings {{
                    margin: 18px 0 18px 0;
                    padding-left: 22px;
                }}
                ul.findings li {{
                    margin-bottom: 8px;
                    font-size: 1.05em;
                }}
                .footer {{
                    margin-top: 32px;
                    font-size: 0.95em;
                    color: #888;
                    text-align: right;
                }}
            </style>
        </head>
        <body>
            <div class='container'>
                <h1>OWISAM-HS Security Report</h1>
                {portal_info}
                {fecha_info}
                <div class='score'><b>Security Score:</b> {self.score}/100</div>
                <div class='risk'>Nivel de riesgo: {self.risk_level}</div>
                <h2>Hallazgos</h2>
                <ul class='findings'>
                    {''.join(f'<li>{html.escape(f)}</li>' for f in self.findings)}
                </ul>
                <div class='footer'>Generado por OWISAM-HS &copy; 2026</div>
            </div>
        </body>
        </html>
        """
        return html_report

    def _risk_color(self):
        if self.risk_level == "BAJO":
            return "#4caf50"
        elif self.risk_level == "MEDIO":
            return "#ff9800"
        else:
            return "#e53935"

    def to_console(self):
        return "\n".join(self.findings) + f"\nSecurity Score: {self.score}/100\nNivel de riesgo: {self.risk_level}"

def check_captive_portal(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }
        resp = requests.get(url, allow_redirects=True, timeout=8, headers=headers)
        original = urlparse(url)
        final = urlparse(resp.url)
        # Detectar si la redirección es a una IP privada
        def is_private_ip(host):
            import ipaddress
            try:
                ip = ipaddress.ip_address(host)
                return ip.is_private
            except ValueError:
                return False
        redirected = (final.netloc.lower() != original.netloc.lower())
        redirected_to_private = False
        # Si la redirección es a una IP privada
        try:
            host = final.hostname
            if host and is_private_ip(host):
                redirected_to_private = True
        except Exception:
            pass
        # O si la página contiene indicios de login/cautividad
        captive_keywords = ["login", "portal", "captive", "access", "autenticacion", "iniciar sesion"]
        is_captive_page = any(kw in resp.text.lower() for kw in captive_keywords)
        # O si hay formulario con método POST
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        has_post_form = any(f.get("method", "get").lower() == "post" for f in forms)
        # O si hubo un código 30x en la cadena de redirecciones
        is_30x = any(h.is_redirect for h in resp.history)
        is_captive = (redirected and (redirected_to_private or is_30x)) or is_captive_page or has_post_form
        return is_captive, resp.url, resp
    except Exception as e:
        return False, None, None

def analyze_ssl(url, report):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        report.add_finding("HTTPS no habilitado.", penalty=20)
        return
    try:
        context = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    report.add_finding("Certificado SSL/TLS inválido o autofirmado.", penalty=20)
                else:
                    report.add_finding("Certificado SSL/TLS válido.")
    except Exception:
        report.add_finding("Error al validar el certificado SSL/TLS.", penalty=20)

def analyze_hsts(resp, report):
    if resp and 'Strict-Transport-Security' in resp.headers:
        report.add_finding("HSTS activo.")
    else:
        report.add_finding("Falta cabecera HSTS.", penalty=10)

def analyze_cookies(resp, report):
    cookies = resp.headers.get('Set-Cookie')
    if not cookies:
        report.add_finding("No se detectaron cookies.")
        return
    cookie = SimpleCookie()
    cookie.load(cookies)
    for morsel in cookie.values():
        if not morsel['secure']:
            report.add_finding(f"Cookie insegura: {morsel.key} sin atributo Secure.", penalty=5)
        if not morsel['httponly']:
            report.add_finding(f"Cookie insegura: {morsel.key} sin atributo HttpOnly.", penalty=5)

def analyze_auth_form(html_text, url, report):
    soup = BeautifulSoup(html_text, "html.parser")
    forms = soup.find_all("form")
    if not forms:
        report.add_finding("No se detectaron formularios de autenticación.", penalty=10)
        return
    for form in forms:
        method = form.get("method", "get").lower()
        action = form.get("action", "")
        if method != "post":
            report.add_finding("Formulario de autenticación no usa POST.", penalty=10)
        if not url.lower().startswith("https://") or (action and action.startswith("http://")):
            report.add_finding("Formulario de autenticación sin HTTPS.", penalty=20)
        if form.find("input", {"type": "password"}):
            report.add_finding("Campo de contraseña detectado.")
        if form.find("input", {"type": "captcha"}) or "captcha" in form.text.lower():
            report.add_finding("Captcha detectado en formulario.")
        # Parámetros sensibles en URL
        if "password" in action or "token" in action:
            report.add_finding("Parámetros sensibles en URL de acción del formulario.", penalty=10)
        # CSRF token
        if not (form.find("input", {"name": "csrf"}) or form.find("input", {"name": "_csrf"}) or form.find("input", {"name": "csrf_token"})):
            report.add_finding("No se detectó token CSRF en el formulario.", penalty=5)

def main():
    parser = argparse.ArgumentParser(description="OWISAM-HS: Analizador de portales cautivos y hotspots WiFi")
    parser.add_argument('--url', required=True, help='URL a analizar (ej: http://example.com)')
    parser.add_argument('--report', choices=['console', 'html'], default='console', help='Tipo de informe de salida')
    args = parser.parse_args()

    report = SecurityReport()
    # Simular búsqueda en Google para ver si hay redirección automática
    search_url = "http://www.google.com/search?q=prueba+owisam"
    is_captive_search, captive_url, captive_resp = check_captive_portal(search_url)
    if is_captive_search and captive_url and urlparse(search_url).netloc.lower() != urlparse(captive_url).netloc.lower():
        report.add_finding(f"Portal cautivo detectado automáticamente al intentar navegar: redirigido a {captive_url}", penalty=10)
        # Analizar el portal real
        final_url = captive_url
        resp = captive_resp
    else:
        # Si no hay redirección automática, analizar la URL proporcionada
        is_captive, final_url, resp = check_captive_portal(args.url)
        if is_captive:
            if final_url and urlparse(args.url).netloc.lower() != urlparse(final_url).netloc.lower():
                report.add_finding(f"Portal cautivo detectado. Redirigido a dominio diferente: {final_url}", penalty=10)
            else:
                report.add_finding("Página con indicios de portal cautivo o login detectada.", penalty=10)
        else:
            report.add_finding("No se detectó portal cautivo.")
    if resp:
        analyze_ssl(final_url, report)
        analyze_hsts(resp, report)
        analyze_cookies(resp, report)
        analyze_auth_form(resp.text, final_url, report)
    report.finalize()
    if args.report == 'html':
        from datetime import datetime
        portal_name = None
        if is_captive and final_url:
            portal_name = urlparse(final_url).netloc
        else:
            portal_name = urlparse(args.url).netloc
        fecha_hora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        out_file = os.path.join(
            os.getcwd(),
            f"owisam_hs_report_{portal_name}_{fecha_hora}.html"
        )
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(report.to_html(portal_name=portal_name, fecha_hora=fecha_hora.replace('_',' ')))
        print(f"[+] Informe HTML guardado en {out_file}")
    else:
        print(report.to_console())

if __name__ == "__main__":
    main()
