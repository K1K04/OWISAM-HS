
# OWISAM-HS & Captive Portal Lab

OWISAM-HS es una herramienta automática para analizar la seguridad de hotspots WiFi y portales cautivos, detectando configuraciones inseguras, autenticación vulnerable y posibles riesgos de ataques Man-In-The-Middle (MITM).

Este repositorio incluye también un laboratorio de portal cautivo para prácticas de ciberseguridad y TFM.

---

## 🛰️ OWISAM-HS: Análisis de Portales Cautivos

### Características principales
- **Detección automática de portales cautivos** (redirección, formularios de login, interceptación HTTP)
- **Análisis de seguridad web**: HTTPS, certificados, HSTS, cookies, CSRF, parámetros sensibles
- **Evaluación de riesgo MITM**: downgrade HTTP, certificados autofirmados, redirecciones sospechosas
- **Sistema de puntuación de seguridad** (Security Score 0-100)
- **Generación de informes**: consola, HTML (con fecha, hora y portal analizado)
- **Modo servicio**: monitoriza cambios de red y ejecuta análisis automáticamente (Windows y Linux)

### Instalación
1. Clona el repositorio:
	```
	git clone https://github.com/tuusuario/OWISAM-HS.git
	cd OWISAM-HS
	```
2. Instala las dependencias:
	```
	pip install -r requirements.txt
	```

### Uso básico

**Escaneo manual:**
```
python -m owisam_hs.scanner --url http://example.com
```
**Informe HTML:**
```
python -m owisam_hs.scanner --url http://example.com --report html
```
**Modo servicio (monitorización automática):**
```
python owisam_hs_service.py --service
```
**Comprobación única:**
```
python owisam_hs_service.py --oneshot
```

Los informes HTML se guardan con el nombre del portal/red y la fecha, por ejemplo:
```
owisam_hs_report_FreeWiFi_Lab_2026-04-30_17-04-44.html
```

#### ¿Qué analiza OWISAM-HS?
- Presencia de portal cautivo (redirección, login, POST)
- Seguridad del formulario de autenticación (HTTPS, método, CSRF)
- Certificados SSL/TLS y HSTS
- Cookies seguras (Secure, HttpOnly)
- Parámetros sensibles en URL
- Riesgo MITM y malas prácticas

#### Ejemplo de resultado
```
OWISAM-HS Security Report
Portal analizado: 10.0.0.1
Fecha y hora: 2026-04-30 17:10:05
Security Score: 35/100
Nivel de riesgo: ALTO
Hallazgos:
- Portal cautivo detectado
- HTTPS no habilitado
- Falta cabecera HSTS
- Formulario de autenticación sin HTTPS
- No se detectó token CSRF en el formulario
```

## 🧪 Captive Portal — Laboratorio TFM Ciberseguridad

Este laboratorio permite desplegar un portal cautivo real para pruebas y formación.

### Arquitectura
```
[Cliente WiFi] → wlx98038e5c6843 (AP: 10.0.0.1)
							↓ dnsmasq (DHCP + DNS hijack)
							↓ iptables (NAT + redireccion HTTP)
							↓ Flask portal (registro nombre/email)
							↓ ens33 (192.168.20.47) → Internet
```

### Requisitos
```bash
sudo apt install hostapd dnsmasq python3-pip
pip3 install flask
```

### Uso
```bash
# Levantar todo (requiere root)
sudo bash setup.sh

# Panel de admin (desde el host atacante)
http://10.0.0.1:5000/admin?token=lab_admin_2024

# Exportar registros CSV
http://10.0.0.1:5000/admin/export?token=lab_admin_2024

# Detener y limpiar
sudo bash teardown.sh
```

### Connectivity checks interceptados
| OS         | Path                        |
|------------|-----------------------------|
| Android    | /generate_204               |
| iOS/macOS  | /hotspot-detect.html        |
| Windows    | /ncsi.txt, /connecttest.txt |
| Firefox    | /success.txt                |
| Ubuntu     | /canonical.html             |

Cuando el cliente no registrado accede a cualquiera de estas URLs, el portal se abre automáticamente.

### Flujo del ataque (documentación TFM)
1. hostapd emite SSID abierto "FreeWiFi_Lab"
2. Cliente se asocia, dnsmasq le asigna IP 10.0.0.x
3. Cliente lanza connectivity check → iptables redirige a Flask
4. Flask devuelve 302 → portal de registro
5. Cliente introduce nombre + email → se graba en SQLite
6. Cliente recibe acceso (iptables permite FORWARD)
7. Admin consulta registros en /admin

### Archivos
```
captive_portal/
├── hostapd.conf        # Configuración del AP
├── dnsmasq.conf        # DHCP + DNS hijack
├── setup.sh            # Levanta el stack
├── teardown.sh         # Limpia todo
├── portal.py           # Backend Flask
├── requirements.txt
├── templates/
│   ├── portal.html     # Formulario de registro
│   ├── success.html    # Página post-registro
│   └── admin.html      # Panel de administración
└── logs/
	 ├── registrations.db
	 └── dnsmasq.log
```

### Nota
Este laboratorio es para uso exclusivo en entornos controlados y con fines educativos/TFM. No usar contra redes o usuarios sin autorización expresa.

---
Creado por: Francisco Javier Doblado Alonso, Mario Marina Velasco
