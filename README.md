## Análisis de Seguridad en Hotspots y Portales Cautivos

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/focus-cybersecurity-red.svg)

OWISAM-HS es una herramienta desarrollada en Python para analizar automáticamente la seguridad de hotspots WiFi y portales cautivos, detectando configuraciones inseguras, autenticación vulnerable y posibles riesgos de ataques Man-In-The-Middle (MITM).

---

# 📌 Descripción

Los portales cautivos son utilizados en redes WiFi públicas como hoteles, aeropuertos, universidades y cafeterías. Sin embargo, muchos presentan configuraciones inseguras que pueden exponer a los usuarios a:

- Robo de credenciales
- Interceptación de tráfico
- Ataques MITM
- Secuestro de sesión
- Falsificación de gateway

OWISAM-HS permite evaluar automáticamente estos riesgos y generar un informe técnico detallado.

---

# 🎯 Objetivos del Proyecto

- Detectar automáticamente la presencia de un portal cautivo.
- Analizar la seguridad del mecanismo de autenticación.
- Evaluar la protección HTTPS y certificados SSL/TLS.
- Identificar malas prácticas de seguridad web.
- Generar un informe técnico con puntuación de riesgo.

---

# 🔎 Funcionalidades

## 🛰 Detección de Portal Cautivo
- Identificación de redirecciones HTTP 302
- Comparación entre dominio solicitado y dominio redirigido
- Detección de interceptación HTTP

## 🔐 Análisis de Seguridad Web
- Verificación de uso de HTTPS
- Validación de certificado SSL/TLS
- Detección de cabecera HSTS
- Análisis de formularios de autenticación
- Verificación de método POST vs GET

## 🍪 Seguridad de Cookies
- Detección de cookies sin atributo `Secure`
- Detección de cookies sin atributo `HttpOnly`
- Identificación de parámetros sensibles en URL

## 🛡 Evaluación de Riesgo MITM
- Detección de downgrade HTTP
- Certificados autofirmados
- Redirecciones sospechosas

## 📊 Sistema de Puntuación
Genera un **Security Score (0-100)** basado en vulnerabilidades detectadas.

## 📄 Generación de Informes
- Salida en consola
- Informe en HTML
- Informe en PDF

---

# ⚙️ Instalación

## 1️⃣ Clonar repositorio

git clone https://github.com/tuusuario/OWISAM-HS.git
cd OWISAM-HS

## 2️⃣ Crear entorno virtual

python3 -m venv venv
source venv/bin/activate

## 3️⃣ Instalar dependencias

pip install -r requirements.txt

---

# 🛠 Uso

## Escaneo básico

python -m owisam_hs.scanner --url http://example.com

## Generar informe HTML

python -m owisam_hs.scanner --url http://example.com --report html

## Generar informe PDF

python -m owisam_hs.scanner --url http://example.com --report pdf

---

# 📊 Ejemplo de Resultado

OWISAM-HS Security Report
==========================

Portal detectado: SI
Redirección sospechosa: SI
HTTPS habilitado: NO
Certificado válido: NO
HSTS activo: NO
Cookies seguras: NO
CSRF token detectado: NO

Security Score: 35/100
Nivel de riesgo: ALTO

---

# ⚖️ Consideraciones Legales

Esta herramienta está diseñada exclusivamente con fines educativos y de laboratorio autorizado.
El uso contra redes sin autorización puede ser ilegal y es responsabilidad exclusiva del usuario.

---

# Creado por :
### Francisco Javier Doblado Alonso
### Mario Marina Velasco
