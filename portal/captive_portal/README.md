# Captive Portal — Laboratorio TFM Ciberseguridad

## Arquitectura

```
[Cliente WiFi] → wlx98038e5c6843 (AP: 10.0.0.1)
                     ↓ dnsmasq (DHCP + DNS hijack)
                     ↓ iptables (NAT + redireccion HTTP)
                     ↓ Flask portal (registro nombre/email)
                     ↓ ens33 (192.168.20.47) → Internet
```

## Requisitos

```bash
sudo apt install hostapd dnsmasq python3-pip
pip3 install flask
```

## Uso

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

## Connectivity checks interceptados

| OS         | Path                        |
|------------|-----------------------------|
| Android    | /generate_204               |
| iOS/macOS  | /hotspot-detect.html        |
| Windows    | /ncsi.txt, /connecttest.txt |
| Firefox    | /success.txt                |
| Ubuntu     | /canonical.html             |

Cuando el cliente no registrado accede a cualquiera de estas URLs,
el portal se abre automáticamente.

## Flujo del ataque (documentación TFM)

1. hostapd emite SSID abierto "FreeWiFi_Lab"
2. Cliente se asocia, dnsmasq le asigna IP 10.0.0.x
3. Cliente lanza connectivity check → iptables redirige a Flask
4. Flask devuelve 302 → portal de registro
5. Cliente introduce nombre + email → se graba en SQLite
6. Cliente recibe acceso (iptables permite FORWARD)
7. Admin consulta registros en /admin

## Archivos

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

## Nota

Este laboratorio es para uso exclusivo en entornos controlados
y con fines educativos/TFM. No usar contra redes o usuarios
sin autorización expresa.
