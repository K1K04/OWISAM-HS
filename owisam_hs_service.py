import sys
import time
import subprocess
import platform
import argparse
import threading
import os
from datetime import datetime

def get_active_ssid():
    if platform.system() == "Linux":
        try:
            out = subprocess.check_output(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"]).decode()
            for line in out.splitlines():
                if line.startswith("yes:"):
                    return line.split(":", 1)[1]
        except Exception:
            return None
    elif platform.system() == "Windows":
        try:
            out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"]).decode(errors="ignore")
            for line in out.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    return line.split(":", 1)[1].strip()
        except Exception:
            return None
    return None

def check_connectivity():
    # Intenta hacer ping a Google DNS
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "8.8.8.8"]
    else:
        cmd = ["ping", "-c", "1", "8.8.8.8"]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception:
        return False

def run_owisam_hs(ssid=None):
    # Simula navegación normal y detecta el portal cautivo real
    from urllib.parse import urlparse
    import requests
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"}
    try:
        resp = requests.get("http://www.google.com", allow_redirects=True, timeout=8, headers=headers)
        portal_url = resp.url
        # Si hay redirección a dominio diferente, analizar ese portal
        if urlparse(portal_url).netloc != "www.google.com":
            url = portal_url
        else:
            url = "http://www.google.com"
    except Exception:
        url = "http://www.google.com"
    fecha = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_file = f"owisam_hs_report_{ssid or 'unknown'}_{fecha}.html"
    cmd = [sys.executable, "-m", "owisam_hs.scanner", "--url", url, "--report", "html"]
    print(f"[+] Ejecutando OWISAM-HS para SSID: {ssid or 'unknown'} en URL: {url}")
    subprocess.run(cmd)
    # Renombra el último informe generado
    for f in os.listdir(os.getcwd()):
        if f.startswith("owisam_hs_report_") and f.endswith(".html") and fecha.replace(":", "-") in f:
            os.rename(f, out_file)
            print(f"[+] Informe guardado como {out_file}")
            break

def monitor_service(interval=15):
    last_ssid = None
    last_status = None
    while True:
        ssid = get_active_ssid()
        status = check_connectivity()
        if ssid != last_ssid or status != last_status:
            print(f"[+] Cambio detectado: SSID={ssid}, Conectividad={'OK' if status else 'NO'}")
            run_owisam_hs(ssid)
            last_ssid = ssid
            last_status = status
        time.sleep(interval)

def main():
    parser = argparse.ArgumentParser(description="OWISAM-HS Service - Monitor de portales cautivos multiplataforma")
    parser.add_argument('--oneshot', action='store_true', help='Solo una comprobación y salir')
    parser.add_argument('--service', action='store_true', help='Modo servicio, monitorizando cambios de red')
    parser.add_argument('--interval', type=int, default=15, help='Intervalo de comprobación en segundos (modo servicio)')
    args = parser.parse_args()

    if args.oneshot:
        ssid = get_active_ssid()
        run_owisam_hs(ssid)
    elif args.service:
        print("[+] Iniciando OWISAM-HS en modo servicio...")
        monitor_service(interval=args.interval)
    else:
        print("Usa --oneshot para una comprobación o --service para monitorizar en bucle.")

if __name__ == "__main__":
    main()
