# 🔍 Nmap Output Parser

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)

**Herramienta profesional para analizar y extraer información relevante de escaneos Nmap**

[Características](#-características) •
[Instalación](#-instalación) •
[Uso](#-uso) •
[Ejemplos](#-ejemplos) •
[Contribuir](#-contribuir)

</div>

---

## 📋 Descripción

**Nmap Output Parser** es una herramienta diseñada para pentester y profesionales de ciberseguridad que necesitan analizar rápidamente los resultados de escaneos Nmap. Extrae y organiza automáticamente la información más relevante, identificando servicios críticos y generando comandos útiles para continuar con la fase de enumeración.

## ✨ Características

- 🎯 **Extracción automática** de hosts, puertos y servicios
- 🔍 **Identificación de servicios críticos** para pentesting
- 📊 **Formato visual** y fácil de leer en consola
- 🛠️ **Generación automática** de comandos Nmap para escaneos detallados
- 🔐 **Detección de sistemas operativos**
- 🚀 **Compatible** con múltiples formatos de salida de Nmap
- 💻 **Sin dependencias externas** - Solo Python 3.6+

### Servicios Críticos Identificados

La herramienta identifica automáticamente más de 20 servicios relevantes:

- **Acceso Remoto:** SSH, Telnet, RDP, VNC
- **Web:** HTTP, HTTPS, Proxies
- **Bases de Datos:** MySQL, PostgreSQL, MSSQL, MongoDB, Redis
- **Protocolos de Red:** SMB, FTP, DNS, SMTP, POP3, IMAP
- **Y muchos más...**

## 🚀 Instalación

### Requisitos

- Python 3.6 o superior
- Nmap instalado en el sistema

### Clonar el repositorio

```bash
git clone https://github.com/nm3s1s/nmap-parser.git
cd nmap-parser
chmod +x nmap_parser.py
```

### Instalación rápida

```bash
# Opción 1: Usar directamente
python3 nmap_parser.py scan.txt

# Opción 2: Mover a /usr/local/bin para uso global
sudo cp nmap_parser.py /usr/local/bin/nmap-parser
sudo chmod +x /usr/local/bin/nmap-parser
nmap-parser scan.txt
```

> **Nota:** Este script no requiere dependencias externas. No es necesario instalar colorama ni ningún paquete adicional.

## 📖 Uso

### Sintaxis básica

```bash
python3 nmap_parser.py <archivo_nmap>
```

### Opciones

```
usage: nmap_parser.py [-h] [-f FILENAME] [file]

Parser de salidas de Nmap para extraer información relevante

positional arguments:
  file                  Archivo de salida de Nmap

optional arguments:
  -h, --help            Mostrar ayuda
  -f, --file FILENAME   Archivo de salida de Nmap
```

## 💡 Ejemplos

### Ejemplo 1: Escaneo básico

```bash
# Realizar escaneo y guardar resultado
nmap -sCV 192.168.1.1 -oN scan.txt

# Analizar con la herramienta
python3 nmap_parser.py scan.txt
```

### Ejemplo 2: Pipeline directo

```bash
# Escanear y analizar en un solo comando
nmap -sCV 192.168.1.1 | tee scan.txt && python3 nmap_parser.py scan.txt
```

### Ejemplo 3: Escaneo completo de red

```bash
# Escaneo agresivo con detección de OS
nmap -sCV -O -p- --min-rate 5000 192.168.1.0/24 -oN network_scan.txt

# Analizar resultados
python3 nmap_parser.py network_scan.txt
```

### Ejemplo 4: Múltiples formatos

```bash
# Guardar en todos los formatos
nmap -sCV 192.168.1.1 -oA scan_completo

# Parsear cualquier formato
python3 nmap_parser.py scan_completo.nmap
```

## 📸 Capturas de Pantalla

### Salida de ejemplo:

```
╔═══════════════════════════════════════════════════════════╗
║           NMAP OUTPUT PARSER & ANALYZER v1.0              ║
║                  By: @nm3s1s                              ║
╚═══════════════════════════════════════════════════════════╝

[+] HOSTS ESCANEADOS
============================================================
  → 192.168.1.100

[+] PUERTOS ABIERTOS
============================================================

  [TCP]
  Puerto     Servicio        Versión
  ---------- --------------- -----------------------------------
  22         ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
  80         http            Apache httpd 2.4.41
  443        ssl/http        Apache httpd 2.4.41
  3306       mysql           MySQL 5.7.40

  Total de puertos abiertos: 4

[+] SERVICIOS INTERESANTES DETECTADOS
============================================================
  🎯 SSH (tcp/22)
     └─ Servicio: ssh
     └─ Versión: OpenSSH 8.2p1 Ubuntu 4ubuntu0.5

  🎯 HTTP (tcp/80)
     └─ Servicio: http
     └─ Versión: Apache httpd 2.4.41

  🎯 HTTPS (tcp/443)
     └─ Servicio: ssl/http
     └─ Versión: Apache httpd 2.4.41

  🎯 MySQL (tcp/3306)
     └─ Servicio: mysql
     └─ Versión: MySQL 5.7.40

[+] COMANDOS ÚTILES
============================================================

  # Escaneo detallado de puertos TCP:
  nmap -sCV -p22,80,443,3306 <target>

============================================================
[✓] Análisis completado
```

## 🗂️ Estructura del Proyecto

```
nmap-parser/
│
├── nmap_parser.py          # Script principal
├── README.md               # Este archivo
├── LICENSE                 # Licencia MIT
├── .gitignore             # Archivos ignorados por Git
│
├── examples/              # Ejemplos de uso
│   ├── example_scan.txt   # Escaneo de ejemplo
│   └── screenshots/       # Capturas de pantalla
│
└── docs/                  # Documentación adicional
    └── CHANGELOG.md       # Registro de cambios
```

## 🛠️ Roadmap

- [ ] Soporte para formato XML de Nmap
- [ ] Exportación a JSON/CSV
- [ ] Generación de informes en HTML
- [ ] Integración con bases de datos de exploits (ExploitDB)
- [ ] Búsqueda automática de CVEs
- [ ] Modo silencioso para scripts
- [ ] Comparación de múltiples escaneos
- [ ] Interfaz web opcional

## 🤝 Contribuir

Las contribuciones son bienvenidas! Si quieres mejorar esta herramienta:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

### Guías de contribución

- Mantén el código limpio y comentado
- Sigue PEP 8 para el estilo de código Python
- Añade tests si es posible
- Actualiza la documentación según sea necesario

## 📝 Formatos Soportados

La herramienta acepta los siguientes formatos de salida de Nmap:

| Formato | Extensión | Comando Nmap | Soporte |
|---------|-----------|--------------|---------|
| Normal | `.txt`, `.nmap` | `-oN` | ✅ Completo |
| Grepable | `.gnmap` | `-oG` | ✅ Completo |
| XML | `.xml` | `-oX` | 🟡 Parcial |
| Todos | `.nmap`, `.xml`, `.gnmap` | `-oA` | ✅ Completo |

## 🔧 Troubleshooting

### Error: "No se encontró el archivo"
```bash
# Asegúrate de que el archivo existe
ls -la scan.txt

# Usa la ruta completa
python3 nmap_parser.py /home/user/scans/scan.txt
```

### Error: "No se encontraron puertos abiertos"
- Verifica que el escaneo de Nmap se completó correctamente
- Asegúrate de que hay puertos abiertos en el escaneo
- Comprueba que el formato del archivo es correcto

### La herramienta no reconoce algunos servicios
- Usa el flag `-sV` en Nmap para detección de versiones
- Considera usar `-sCV` para scripts y versiones
- Algunos servicios personalizados pueden no ser identificados

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo [LICENSE](LICENSE) para más detalles.

## 👨‍💻 Autor

**Tomás** ([@nm3s1s](https://github.com/nm3s1s))

- Estudiante de ASIR
- Apasionado por Ciberseguridad y Pentesting
- En formación para CPTS, eJPTv2, CEH y OSCP

## 🙏 Agradecimientos

- A la comunidad de [HackTheBox](https://www.hackthebox.com/)
- A [Offensive Security](https://www.offensive-security.com/) por sus recursos
- A todos los contribuidores de código abierto

## 📚 Recursos Relacionados

- [Nmap Official Documentation](https://nmap.org/book/man.html)
- [Nmap NSE Scripts](https://nmap.org/nsedoc/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

<div align="center">

**⭐ Si te resulta útil, considera darle una estrella al proyecto ⭐**

Made with ❤️ by [nm3s1s](https://github.com/nm3s1s)

</div>

