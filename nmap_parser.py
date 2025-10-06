#!/usr/bin/env python3
"""
Nmap Output Parser - Extrae información relevante de escaneos Nmap
Autor: @nm3s1s
Versión: 1.0
"""

import re
import sys
import argparse
import logging
import json
import os
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import xml.etree.ElementTree as ET


class NmapParser:
    def __init__(self, filename: str, config: Optional[dict] = None):
        self.filename = filename
        self.hosts = []
        self.ports_info = defaultdict(list)
        self.content = ""
        self.config = config or {}

    def display_banner(self):
        print("\n" + "=" * 60)
        print(" NMAP OUTPUT PARSER & ANALYZER v1.0")
        print(" By: @nm3s1s")
        print("=" * 60)

    def parse_file(self):
        try:
            with open(self.filename, 'r', encoding='utf-8') as f:
                self.content = f.read()
        except Exception as e:
            print(f"[!] Error al leer el archivo: {e}")
            self.content = ""

    def parse_xml_file(self):
        try:
            tree = ET.parse(self.filename)
            root = tree.getroot()
            self.content = ET.tostring(root, encoding='unicode')
        except Exception as e:
            print(f"[!] Error al leer el archivo XML: {e}")
            self.content = ""

    def extract_hosts(self):
        self.hosts = []
        # TXT
        hosts = re.findall(r'\b(?:Nmap scan report for|Host: )\s*([\w\.-]+)', self.content)
        # XML
        if not hosts and '<host>' in self.content:
            hosts = re.findall(r'<address addr="([^"]+)"', self.content)
        self.hosts = list(set(hosts))

    def extract_ports(self):
        self.ports_info = defaultdict(list)
        # TXT: solo procesar líneas que sean puertos abiertos
        port_lines = [line for line in self.content.splitlines() if re.match(r'^\d+/(tcp|udp)\s+open\s+[\w\-]+', line)]
        port_regex = re.compile(r'^(\d+)/(tcp|udp)\s+open\s+([\w\-]+)(?:\s+(.*))?$', re.MULTILINE)
        for line in port_lines:
            match = port_regex.match(line)
            if match:
                port, proto, service, version = match.groups()
                version = version.strip() if version else "N/A"
                self.ports_info[proto].append({
                    'port': port,
                    'protocol': proto,
                    'service': service,
                    'version': version
                })
        # XML
        if '<host>' in self.content:
            xml_ports = re.findall(r'<port protocol="([^"]+)" portid="(\d+)">.*?<state state="open".*?<service name="([^"]+)"( version="([^"]+)")?', self.content, re.DOTALL)
            for proto, port, service, _, version in xml_ports:
                self.ports_info[proto].append({
                    'port': port,
                    'protocol': proto,
                    'service': service,
                    'version': version or "N/A"
                })

    def extract_os_info(self):
        os_info = re.findall(r'OS details: ([^\n]+)', self.content)
        if not os_info and '<os>' in self.content:
            os_info = re.findall(r'<osmatch name="([^"]+)"', self.content)
        return list(set(os_info))

    def get_interesting_ports(self):
        interesting_ports = set(self.config.get('interesting_ports', []))
        result = []
        for proto in self.ports_info:
            for port in self.ports_info[proto]:
                if port['port'] in interesting_ports:
                    result.append({
                        'port': port['port'],
                        'protocol': proto,
                        'service': port['service'],
                        'version': port['version'],
                        'category': port['service'].upper()
                    })
        return result

    def display_results(self, export=None, export_json=None):
        self.display_banner()
        print("\n[+] HOSTS ESCANEADOS")
        print("=" * 60)
        if self.hosts:
            for host in self.hosts:
                print(f"  → {host}")
        else:
            print("  [!] No se encontraron hosts")

        print("\n[+] PUERTOS ABIERTOS")
        print("=" * 60)
        total_ports = 0
        for protocol in ['tcp', 'udp']:
            if protocol in self.ports_info and self.ports_info[protocol]:
                print(f"\n  [{protocol.upper()}]")
                print(f"  {'Puerto':<10} {'Servicio':<15} {'Versión'}")
                print(f"  {'-'*10} {'-'*15} {'-'*35}")
                for port in sorted(self.ports_info[protocol], key=lambda x: int(x['port'])):
                    version = port['version'][:35] if port['version'] != "N/A" else "N/A"
                    print(f"  {port['port']:<10} {port['service']:<15} {version}")
                    total_ports += 1
        if total_ports == 0:
            print("  [!] No se encontraron puertos abiertos")
        else:
            print(f"\n  Total de puertos abiertos: {total_ports}")

        interesting = self.get_interesting_ports()
        if interesting:
            print("\n[+] SERVICIOS INTERESANTES DETECTADOS")
            print("=" * 60)
            categories = defaultdict(list)
            for port in interesting:
                categories[port['category']].append(port)
            for category in sorted(categories.keys()):
                ports = categories[category]
                for port in ports:
                    print(f"  🎯 {category} ({port['protocol'].upper()}/{port['port']})")
                    print(f"     └─ Servicio: {port['service']}")
                    if port['version'] != "N/A":
                        print(f"     └─ Versión: {port['version']}")
                    print()

        os_info = self.extract_os_info()
        if os_info:
            print("[+] DETECCIÓN DE SISTEMA OPERATIVO")
            print("=" * 60)
            for os in os_info:
                print(f"  → {os}")

        print("=" * 60)
        print("\n[+] COMANDOS ÚTILES")
        print("=" * 60)
        tcp_ports = [p['port'] for p in self.ports_info.get('tcp', [])]
        if tcp_ports:
            ports_list = ','.join(sorted(tcp_ports, key=int))
            print(f"\n  # Escaneo detallado de puertos TCP:")
            print(f"  nmap -sCV -p{ports_list} <target>")
        udp_ports = [p['port'] for p in self.ports_info.get('udp', [])]
        if udp_ports:
            ports_list = ','.join(sorted(udp_ports, key=int))
            print(f"\n  # Escaneo detallado de puertos UDP:")
            print(f"  nmap -sUV -p{ports_list} <target>")
        print("\n" + "=" * 60)
        print("[✓] Análisis completado\n")

    def export_html(self, filename):
        # ...implementación de exportación HTML...
        pass

    def export_markdown(self, filename):
        # ...implementación de exportación Markdown...
        pass

    # Puedes agregar aquí otros métodos de exportación y utilidades

def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    # Leer configuración
    config = {}
    if os.path.exists('config.json'):
        with open('config.json', 'r', encoding='utf-8') as f:
            config = json.load(f)
    parser = argparse.ArgumentParser(
        description='Parser profesional de salidas de Nmap para extraer y exportar información relevante',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Ejemplos de uso:
  python3 nmap_parser.py -f scan.txt
  python3 nmap_parser.py -f scan1.txt -f scan2.txt --export resultado.txt --export-json resultado.json --export-html resultado.html --export-md resultado.md
  nmap -sCV 192.168.1.1 | tee scan.txt && python3 nmap_parser.py -f scan.txt
        '''
    )
    parser.add_argument('-f', '--file', dest='filenames', required=True, nargs='+', help='Archivo(s) de salida de Nmap')
    parser.add_argument('--export', dest='export', help='Exportar resultados a archivo de texto')
    parser.add_argument('--export-json', dest='export_json', help='Exportar resultados a archivo JSON')
    parser.add_argument('--export-html', dest='export_html', help='Exportar resultados a archivo HTML')
    parser.add_argument('--export-md', dest='export_md', help='Exportar resultados a archivo Markdown')
    parser.add_argument('--xml', action='store_true', help='Procesar archivos XML de Nmap')
    args = parser.parse_args()
    all_hosts = []
    all_ports_info = defaultdict(list)
    all_os_info = []
    all_interesting = []
    for filename in args.filenames:
        nmap_parser = NmapParser(filename, config)
        try:
            if args.xml or filename.endswith('.xml'):
                nmap_parser.parse_xml_file()
            else:
                nmap_parser.parse_file()
        except Exception as e:
            print(f"[!] {e}")
            continue
        nmap_parser.extract_hosts()
        nmap_parser.extract_ports()
        all_hosts.extend(nmap_parser.hosts)
        for proto, plist in nmap_parser.ports_info.items():
            all_ports_info[proto].extend(plist)
        all_os_info.extend(nmap_parser.extract_os_info())
        all_interesting.extend(nmap_parser.get_interesting_ports())
        nmap_parser.display_results(export=args.export, export_json=args.export_json)
        if args.export_html:
            nmap_parser.export_html(args.export_html)
        if args.export_md:
            nmap_parser.export_markdown(args.export_md)
    # Si se analizaron varios archivos, mostrar resumen global
    if len(args.filenames) > 1:
        print("\n[RESUMEN GLOBAL DE TODOS LOS ARCHIVOS]")
        print("=" * 60)
        print(f"Total de hosts: {len(all_hosts)}")
        print(f"Total de puertos abiertos: {sum(len(all_ports_info[p]) for p in all_ports_info)}")
        print(f"Total de servicios interesantes: {len(all_interesting)}")
        if all_os_info:
            print(f"Sistemas operativos detectados: {', '.join(set(all_os_info))}")

if __name__ == "__main__":
    main()
