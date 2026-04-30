git clone https://github.com/K1K04/OWISAM-HS
pip install -r requirements.txt

# OWISAM-HS

OWISAM-HS es una herramienta automática para analizar la seguridad de hotspots WiFi y portales cautivos, detectando configuraciones inseguras, autenticación vulnerable y posibles riesgos de ataques Man-In-The-Middle (MITM).

## Características principales
- **Detección automática de portales cautivos** (redirección, formularios de login, interceptación HTTP)
- **Análisis de seguridad web**: HTTPS, certificados, HSTS, cookies, CSRF, parámetros sensibles
- **Evaluación de riesgo MITM**: downgrade HTTP, certificados autofirmados, redirecciones sospechosas
- **Sistema de puntuación de seguridad** (Security Score 0-100)
- **Generación de informes**: consola, HTML (con fecha, hora y portal analizado)
- **Modo servicio**: monitoriza cambios de red y ejecuta análisis automáticamente (Windows y Linux)

## Instalación
1. Clona el repositorio:
	```
	git clone https://github.com/tuusuario/OWISAM-HS.git
	cd OWISAM-HS
	```
2. Instala las dependencias:
	```
	pip install -r requirements.txt
	```

## Uso básico

### Escaneo manual
Ejecuta un análisis sobre una URL:
```
python -m owisam_hs.scanner --url http://example.com
```
Para generar un informe HTML:
```
python -m owisam_hs.scanner --url http://example.com --report html
```

### Modo servicio (monitorización automática)
El servicio detecta cambios de red y ejecuta el análisis automáticamente:
```
python owisam_hs_service.py --service
```
Para una comprobación única:
```
python owisam_hs_service.py --oneshot
```

Los informes HTML se guardan con el nombre del portal/red y la fecha, por ejemplo:
```
owisam_hs_report_FreeWiFi_Lab_2026-04-30_17-04-44.html
```

## ¿Qué analiza OWISAM-HS?
- Presencia de portal cautivo (redirección, login, POST)
- Seguridad del formulario de autenticación (HTTPS, método, CSRF)
- Certificados SSL/TLS y HSTS
- Cookies seguras (Secure, HttpOnly)
- Parámetros sensibles en URL
- Riesgo MITM y malas prácticas

## Ejemplo de resultado
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

## Notas
- Compatible con Windows y Linux
- Uso educativo y de auditoría autorizada

---
Creado por: Francisco Javier Doblado Alonso, Mario Marina Velasco
