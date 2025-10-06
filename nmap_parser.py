#!/usr/bin/env python3
"""
Nmap Output Parser - Extrae información relevante de escaneos Nmap
Autor: @nm3s1s
Versión: 1.0
"""

import re
import sys
import argparse
from typing import Dict, List, Tuple
from collections import defaultdict

class NmapParser:
    def __init__(self, filename: str):
        self.filename = filename
        self.hosts = []
        self.ports_info = defaultdict(list)
        
    def parse_file(self) -> None:
        """Lee y parsea el archivo de salida de Nmap"""
        try:
            with open(self.filename, 'r', encoding='utf-8', errors='ignore') as f:
                self.content = f.read()
        except FileNotFoundError:
            print(f"[!] Error: No se encontró el archivo '{self.filename}'")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error al leer el archivo: {e}")
            sys.exit(1)
    
    def extract_hosts(self) -> List[str]:
        """Extrae las IPs/hosts escaneados"""
        host_pattern = r'Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?'
        matches = re.findall(host_pattern, self.content)
        
        for hostname, ip in matches:
            if hostname:
                self.hosts.append(f"{ip} ({hostname})")
            else:
                self.hosts.append(ip)
        
        return self.hosts
    
    def extract_ports(self) -> Dict:
        """Extrae información de puertos, servicios y versiones"""
        port_pattern = r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.+?))?(?=\n|$)'
        matches = re.findall(port_pattern, self.content)
        
        for port, protocol, state, service, version in matches:
            if state == "open":
                version_clean = version.strip() if version else "N/A"
                self.ports_info[protocol].append({
                    'port': port,
                    'state': state,
                    'service': service,
                    'version': version_clean
                })
        
        return self.ports_info
    
    def extract_os_info(self) -> List[str]:
        """Extrae información del sistema operativo"""
        os_pattern = r'(?:OS details|Running|Aggressive OS guesses):\s*(.+?)(?=\n[A-Z]|\n\n|$)'
        os_matches = re.findall(os_pattern, self.content, re.MULTILINE)
        return [os.strip() for os in os_matches if os.strip()]
    
    def get_interesting_ports(self) -> List[Dict]:
        """Identifica puertos de servicios interesantes para pentesting"""
        interesting_services = {
            '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP',
            '53': 'DNS', '80': 'HTTP', '110': 'POP3', '111': 'RPCbind',
            '135': 'MSRPC', '139': 'NetBIOS', '143': 'IMAP', '443': 'HTTPS',
            '445': 'SMB', '993': 'IMAPS', '995': 'POP3S', '1433': 'MSSQL',
            '3306': 'MySQL', '3389': 'RDP', '5432': 'PostgreSQL',
            '5900': 'VNC', '6379': 'Redis', '8080': 'HTTP-Proxy',
            '8443': 'HTTPS-Alt', '27017': 'MongoDB'
        }
        
        interesting = []
        for protocol in self.ports_info:
            for port_data in self.ports_info[protocol]:
                port = port_data['port']
                if port in interesting_services:
                    port_data['category'] = interesting_services[port]
                    port_data['protocol'] = protocol
                    interesting.append(port_data)
        
        return interesting

    def display_banner(self):
        """Muestra el banner de la herramienta"""
        banner = """
╔═══════════════════════════════════════════════════════════╗
║           NMAP OUTPUT PARSER & ANALYZER v1.0              ║
║                      By: @nm3s1s                          ║
╚═══════════════════════════════════════════════════════════╝
        """
        print(banner)

    def display_results(self):
        """Muestra los resultados formateados"""
        self.display_banner()
        
        # Mostrar hosts encontrados
        print("\n[+] HOSTS ESCANEADOS")
        print("=" * 60)
        if self.hosts:
            for host in self.hosts:
                print(f"  → {host}")
        else:
            print("  [!] No se encontraron hosts")
        
        # Mostrar todos los puertos abiertos
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
        
        # Mostrar puertos interesantes
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
        
        # Mostrar información del OS
        os_info = self.extract_os_info()
        if os_info:
            print("[+] DETECCIÓN DE SISTEMA OPERATIVO")
            print("=" * 60)
            for os in os_info:
                print(f"  → {os}")
        
        # Generar comando de copia rápida
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

def main():
    parser = argparse.ArgumentParser(
        description='Parser de salidas de Nmap para extraer información relevante',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Ejemplos de uso:
  python3 nmap_parser.py scan.txt
  python3 nmap_parser.py -f nmap_output.nmap
  nmap -sCV 192.168.1.1 | tee scan.txt && python3 nmap_parser.py scan.txt
        '''
    )
    
    parser.add_argument('file', nargs='?', help='Archivo de salida de Nmap')
    parser.add_argument('-f', '--file', dest='filename', help='Archivo de salida de Nmap')
    
    args = parser.parse_args()
    
    filename = args.file or args.filename
    
    if not filename:
        parser.print_help()
        print("\n[!] Error: Debes especificar un archivo de entrada")
        sys.exit(1)
    
    # Crear instancia del parser
    nmap_parser = NmapParser(filename)
    
    # Parsear el archivo
    nmap_parser.parse_file()
    
    # Extraer información
    nmap_parser.extract_hosts()
    nmap_parser.extract_ports()
    
    # Mostrar resultados
    nmap_parser.display_results()

if __name__ == "__main__":
    main()
