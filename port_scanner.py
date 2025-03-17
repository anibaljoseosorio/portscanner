"""Escáner de puertos avanzado con multi-hilo, servicios y colores.

Este módulo escanea puertos en un host, identifica servicios y guarda los resultados.
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import queue
from colorama import init, Fore, Style

# Inicializar colorama para colores en la consola
init()

# Diccionario ampliado de puertos comunes y sus servicios
COMMON_PORTS = {
    7: "Echo", 20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 69: "TFTP", 80: "HTTP", 110: "POP3",
    123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt"
}


def scan_port(host, port, result_queue):
    """Escanea un puerto específico en un host y guarda el resultado en una cola.

    Args:
        host (str): Dirección IP o nombre del host.
        port (int): Número del puerto a escanear.
        result_queue (Queue): Cola para almacenar puertos abiertos.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "Desconocido")
            result_queue.put((port, service))
            print(
                f"{Fore.GREEN}[+] Puerto {port} abierto ({service}){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Puerto {port} cerrado{Style.RESET_ALL}")
    except socket.gaierror:
        error_msg = f"[!] Error: El host {host} no es válido o no se puede resolver."
        print(f"{Fore.YELLOW}{error_msg}{Style.RESET_ALL}")
        sys.exit(1)
    except socket.error as e:
        print(
            f"{Fore.YELLOW}[!] Error al escanear el puerto {port}: {e}{Style.RESET_ALL}")


def validate_host(host):
    """Valida que el host sea alcanzable resolviendo su IP.

    Args:
        host (str): Dirección IP o nombre del host.
    Returns:
        bool: True si el host es válido, False si no.
    """
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        error_msg = f"[!] Error: El host {host} no es válido o no se puede resolver."
        print(f"{Fore.YELLOW}{error_msg}{Style.RESET_ALL}")
        return False


def get_user_input():
    """Solicita parámetros al usuario de forma interactiva."""
    prompt = "Ingrese el host a escanear (ej. 127.0.0.1 o scanme.nmap.org): "
    host = input(prompt).strip()
    if not validate_host(host):
        sys.exit(1)

    while True:
        try:
            start_port = int(
                input("Ingrese el puerto inicial (1-65535): ").strip())
            end_port = int(
                input("Ingrese el puerto final (1-65535): ").strip())
            if 1 <= start_port <= end_port <= 65535:
                break
            print(
                f"{Fore.YELLOW}[!] Error: Los puertos deben estar entre 1 y 65535,")
            print(
                f"y el inicio debe ser menor o igual al fin.{Style.RESET_ALL}")
        except ValueError:
            print(
                f"{Fore.YELLOW}[!] Error: Los puertos deben ser números enteros.{Style.RESET_ALL}")

    return host, start_port, end_port


def main():
    """Función principal para ejecutar el escáner de puertos."""
    if len(sys.argv) < 4:
        print(f"{Fore.CYAN}[*] Modo interactivo activado.{Style.RESET_ALL}")
        host, start_port, end_port = get_user_input()
    else:
        host = sys.argv[1]
        if not validate_host(host):
            sys.exit(1)
        try:
            start_port = int(sys.argv[2])
            end_port = int(sys.argv[3])
        except ValueError:
            print(
                f"{Fore.YELLOW}[!] Error: Los puertos deben ser números enteros.{Style.RESET_ALL}")
            sys.exit(1)

        if start_port < 1 or end_port < start_port or end_port > 65535:
            print(
                f"{Fore.YELLOW}[!] Error:Los puertos deben estar entre 1 y 65535,{Style.RESET_ALL}")
            print(
                f"{Fore.YELLOW} y el inicio debe ser menor o igual al fin.{Style.RESET_ALL}")
            sys.exit(1)

    start_msg = f"[*] Iniciando escaneo en {host} desde el puerto {start_port}"
    start_msg += f" hasta {end_port}"
    print(f"{Fore.CYAN}{start_msg}{Style.RESET_ALL}")
    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{Fore.CYAN}[*] Inicio: {start_time}{Style.RESET_ALL}")

    # Cola para almacenar puertos abiertos y servicios
    result_queue = queue.Queue()

    # Usar ThreadPoolExecutor para limitar el número de hilos
    max_threads = 50  # Ajustable según el sistema
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, host, port, result_queue)

    # Obtener puertos abiertos de la cola
    open_ports = []
    while not result_queue.empty():
        open_ports.append(result_queue.get())

    end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{Fore.CYAN}[*] Escaneo finalizado: {end_time}{Style.RESET_ALL}")
    if open_ports:
        print(
            f"{Fore.GREEN}[+] Puertos abiertos encontrados:{Style.RESET_ALL}")
        for port, service in open_ports:
            print(f"    - Puerto {port}: {service}")
        # Guardar resultados en un archivo
        with open("open_ports.txt", "w", encoding="utf-8") as f:
            f.write(f"Host: {host}\n")
            f.write(f"Rango: {start_port}-{end_port}\n")
            f.write("Puertos abiertos:\n")
            for port, service in open_ports:
                f.write(f"  - Puerto {port}: {service}\n")
        print(
            f"{Fore.GREEN}[+] Resultados guardados en 'open_ports.txt'{Style.RESET_ALL}")
    else:
        no_ports_msg = "[+] No se encontraron puertos abiertos en el rango especificado."
        print(f"{Fore.GREEN}{no_ports_msg}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
