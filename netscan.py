#!/usr/bin/env python3
"""
netscan.py
Um scanner de rede simples pra rodar no Kali.

O que ele faz:
  - acha sua rede local sozinho (sem precisar digitar o CIDR)
  - lista os dispositivos conectados (IP, MAC, hostname)
  - faz ping sweep pra ver quem tá ativo
  - escaneia portas TCP e tenta pegar o banner do serviço

Só funciona em cima da rede/host que você tem autorização pra testar.
Nada aqui foi pensado pra derrubar nada, é só reconhecimento mesmo.

Não precisa instalar nada além do Python 3 (só stdlib).
"""

import argparse
import ipaddress
import socket
import subprocess
import sys
import threading
import queue
import time
from datetime import datetime

# cores do terminal (só duas, pra não poluir)
class C:
    RESET = "\033[0m"
    NEON_GREEN = "\033[1;38;5;46m"   # verde neon - só pro "NEGUIN" do banner
    DARK_BLUE = "\033[1;38;5;25m"    # azul escuro - resto de tudo


# Arte "BY NEGUIN" em bloco grande (fonte 7x7)
BY_NEGUIN_ART = r"""
██████   ██   ██    ██   ██  ███████   ██████  ██   ██  ███████  ██   ██
██   ██  ██   ██    ███  ██  ██       ██       ██   ██     █     ███  ██
██   ██   ██ ██     ████ ██  ██       ██       ██   ██     █     ████ ██
██████     ███      ██ ████  █████    ██  ███  ██   ██     █     ██ ████
██   ██     █       ██  ███  ██       ██   ██  ██   ██     █     ██  ███
██   ██     █       ██   ██  ██       ██   ██  ██   ██     █     ██   ██
██████      █       ██   ██  ███████   ██████   █████   ███████  ██   ██
"""

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]


def print_banner():
    print(C.NEON_GREEN + BY_NEGUIN_ART + C.RESET)
    print(C.DARK_BLUE + "   scanner de rede - host discovery + port scan" + C.RESET)
    print()


# Detecção automática da rede local
def get_local_ip():
    """Descobre o IP local usado para sair à internet (não gera tráfego real)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_local_network():
    """
    Tenta detectar a rede local (CIDR) automaticamente usando `ip route`.
    Retorna algo como '192.168.1.0/24' ou None se não conseguir.
    """
    try:
        out = subprocess.run(["ip", "-o", "-f", "inet", "route", "show"],
                              capture_output=True, text=True, timeout=3)
        local_ip = get_local_ip()
        for line in out.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            cidr = parts[0]
            if "/" not in cidr:
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if ipaddress.ip_address(local_ip) in net:
                return str(net)
    except Exception:
        pass

    # Fallback: assume /24 a partir do IP local
    local_ip = get_local_ip()
    try:
        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(net)
    except Exception:
        return None


# Tabela ARP - MAC address dos dispositivos
def get_arp_table():
    """
    Lê a tabela ARP do sistema (dispositivos já vistos na rede local).
    Retorna dict {ip: mac}.
    """
    arp_map = {}

    # Tenta 'ip neigh' (padrão moderno no Kali)
    try:
        out = subprocess.run(["ip", "neigh"], capture_output=True,
                              text=True, timeout=3)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[2] == "lladdr":
                ip, mac = parts[0], parts[4]
                arp_map[ip] = mac.upper()
    except Exception:
        pass

    # Fallback: comando 'arp -n'
    if not arp_map:
        try:
            out = subprocess.run(["arp", "-n"], capture_output=True,
                                  text=True, timeout=3)
            for line in out.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3 and ":" in parts[2]:
                    arp_map[parts[0]] = parts[2].upper()
        except Exception:
            pass

    return arp_map


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def list_devices(network_cidr, max_threads=50, timeout=1):
    """
    Lista os dispositivos ativos na rede: IP, MAC e hostname (quando disponível).
    Faz ping sweep primeiro (para popular a tabela ARP) e depois lê a tabela.
    """
    print(C.DARK_BLUE + f"[*] Rede detectada/alvo: {network_cidr}\n" + C.RESET)
    active_hosts = host_discovery(network_cidr, max_threads=max_threads,
                                   timeout=timeout)

    print(C.DARK_BLUE + "[*] Consultando tabela ARP para obter endereços MAC...\n" + C.RESET)
    time.sleep(0.5)  # dá um tempinho pro kernel popular a tabela ARP
    arp_map = get_arp_table()

    devices = []
    for ip in active_hosts:
        mac = arp_map.get(ip, "desconhecido")
        hostname = resolve_hostname(ip)
        devices.append((ip, mac, hostname))

    # Também inclui entradas da ARP table que não responderam ao ping
    # mas já estavam na tabela (ex: dispositivos que bloqueiam ICMP)
    known_ips = {d[0] for d in devices}
    for ip, mac in arp_map.items():
        if ip not in known_ips:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(network_cidr, strict=False):
                    hostname = resolve_hostname(ip)
                    devices.append((ip, mac, hostname))
            except ValueError:
                continue

    devices.sort(key=lambda d: ipaddress.ip_address(d[0]))

    print(C.DARK_BLUE + "=" * 70 + C.RESET)
    print(C.DARK_BLUE + "DISPOSITIVOS NA REDE".center(70) + C.RESET)
    print(C.DARK_BLUE + "=" * 70 + C.RESET)
    print(C.DARK_BLUE + f"{'IP':<16}{'MAC Address':<20}{'Hostname':<30}" + C.RESET)
    print(C.DARK_BLUE + "-" * 70 + C.RESET)
    for ip, mac, hostname in devices:
        print(f"{ip:<16}{mac:<20}{hostname:<30}")
    print(C.DARK_BLUE + "-" * 70 + C.RESET)
    print(C.DARK_BLUE + f"Total: {len(devices)} dispositivo(s) encontrado(s)\n" + C.RESET)

    return devices


# Ping sweep - descoberta de hosts ativos
def ping_host(ip, timeout=1):
    """Retorna True se o host responder ao ping (ICMP), usando o ping do SO."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False


def host_discovery(network_cidr, max_threads=50, timeout=1):
    """Varre uma faixa CIDR (ex: 192.168.1.0/24) e retorna hosts ativos."""
    try:
        net = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError as e:
        print(C.DARK_BLUE + f"[!] Rede inválida: {e}" + C.RESET)
        return []

    hosts_to_scan = list(net.hosts())
    active_hosts = []
    lock = threading.Lock()
    q = queue.Queue()
    for h in hosts_to_scan:
        q.put(h)

    def worker():
        while not q.empty():
            try:
                ip = q.get_nowait()
            except queue.Empty:
                return
            if ping_host(ip, timeout=timeout):
                with lock:
                    active_hosts.append(str(ip))
                    print(C.DARK_BLUE + f"    [+] Host ativo: {ip}" + C.RESET)
            q.task_done()

    print(C.DARK_BLUE + f"[*] Iniciando ping sweep em {network_cidr} "
          f"({len(hosts_to_scan)} hosts)...\n" + C.RESET)

    threads = []
    for _ in range(min(max_threads, len(hosts_to_scan) or 1)):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    print(f"\n[*] Descoberta concluída. {len(active_hosts)} host(s) ativo(s).\n")
    return sorted(active_hosts, key=lambda x: ipaddress.ip_address(x))


# Port scan + banner grabbing
def grab_banner(sock):
    try:
        sock.settimeout(1.0)
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip()
    except Exception:
        return ""


def scan_port(ip, port, timeout=0.7):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "desconhecido"
                banner = grab_banner(s)
                return (port, service, banner)
    except Exception:
        pass
    return None


def port_scan(ip, ports=None, max_threads=100, timeout=0.7):
    if ports is None:
        ports = COMMON_PORTS

    open_ports = []
    lock = threading.Lock()
    q = queue.Queue()
    for p in ports:
        q.put(p)

    print(C.DARK_BLUE + f"[*] Escaneando {len(ports)} porta(s) em {ip}...\n" + C.RESET)

    def worker():
        while not q.empty():
            try:
                port = q.get_nowait()
            except queue.Empty:
                return
            res = scan_port(ip, port, timeout=timeout)
            if res:
                with lock:
                    open_ports.append(res)
                    port_n, service, banner = res
                    banner_info = f" | banner: {banner}" if banner else ""
                    print(C.DARK_BLUE + f"    [+] Porta {port_n}/tcp aberta "
                          f"({service}){banner_info}" + C.RESET)
            q.task_done()

    threads = []
    for _ in range(min(max_threads, len(ports))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    open_ports.sort(key=lambda x: x[0])
    print(f"\n[*] Scan de portas concluído em {ip}. "
          f"{len(open_ports)} porta(s) aberta(s).\n")
    return open_ports


# Main / CLI
def parse_port_range(port_str):
    """Aceita formatos como '80', '1-1000', '22,80,443'."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="netscan.py - scanner de rede simples, uso ético/autorizado apenas"
    )
    parser.add_argument(
        "-t", "--target",
        help="IP único ou rede CIDR (ex: 192.168.1.10 ou 192.168.1.0/24). "
             "Se omitido junto com --list-devices, a rede local é detectada "
             "automaticamente.",
        default=None,
    )
    parser.add_argument(
        "-l", "--list-devices",
        action="store_true",
        help="Lista os dispositivos conectados na rede (IP, MAC, hostname). "
             "Detecta a rede local automaticamente se -t não for informado.",
    )
    parser.add_argument(
        "-p", "--ports",
        help="Portas a escanear (ex: '22,80,443' ou '1-1000'). "
             "Padrão: lista de portas comuns.",
        default=None,
    )
    parser.add_argument(
        "--discover-only",
        action="store_true",
        help="Apenas descobre hosts ativos na rede (não escaneia portas).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Número máximo de threads (padrão: 100).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.7,
        help="Timeout por conexão/ping em segundos (padrão: 0.7).",
    )

    args = parser.parse_args()

    if not args.target and not args.list_devices:
        parser.error("informe -t/--target, ou use -l/--list-devices para "
                      "detectar a rede automaticamente.")

    start_time = datetime.now()
    print(C.DARK_BLUE + f"[*] Início: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n" + C.RESET)

    # Confirmação de autorização
    confirm = input(
        "[!] Confirme que você tem autorização para escanear esta rede/alvo (s/N): "
    ).strip().lower()
    if confirm != "s":
        print(C.DARK_BLUE + "[!] Operação cancelada. Use apenas em redes/alvos autorizados." + C.RESET)
        sys.exit(0)

    # Modo: listar dispositivos na rede (auto-detecção se -t não informado)
    if args.list_devices:
        network_cidr = args.target or get_local_network()
        if not network_cidr:
            print(C.DARK_BLUE + "[!] Não foi possível detectar a rede local automaticamente. "
                  "Informe manualmente com -t 192.168.1.0/24" + C.RESET)
            sys.exit(1)
        list_devices(network_cidr, max_threads=args.threads,
                     timeout=args.timeout)
        elapsed = (datetime.now() - start_time).total_seconds()
        print(C.DARK_BLUE + f"[*] Tempo total: {elapsed:.2f}s" + C.RESET)
        print(C.DARK_BLUE + "[*] Finalizado.\n" + C.RESET)
        return

    targets = []

    # Se for rede CIDR, faz descoberta de hosts primeiro
    is_network = "/" in args.target
    if is_network:
        targets = host_discovery(args.target, max_threads=args.threads,
                                  timeout=args.timeout)
    else:
        targets = [args.target]

    if args.discover_only:
        print(C.DARK_BLUE + "[*] Finalizado (modo somente descoberta)." + C.RESET)
        return

    ports = parse_port_range(args.ports) if args.ports else COMMON_PORTS

    results = {}
    for ip in targets:
        results[ip] = port_scan(ip, ports=ports, max_threads=args.threads,
                                 timeout=args.timeout)

    # Resumo final
    print(C.DARK_BLUE + "=" * 60 + C.RESET)
    print(C.DARK_BLUE + "RESUMO FINAL".center(60) + C.RESET)
    print(C.DARK_BLUE + "=" * 60 + C.RESET)
    for ip, open_ports in results.items():
        print(C.DARK_BLUE + f"\nHost: {ip}" + C.RESET)
        if not open_ports:
            print("  Nenhuma porta aberta encontrada.")
        else:
            for port, service, banner in open_ports:
                banner_info = f" - {banner}" if banner else ""
                print(f"  {port}/tcp\t{service}{banner_info}")

    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n[*] Tempo total: {elapsed:.2f}s")
    print(C.DARK_BLUE + "[*] Finalizado.\n" + C.RESET)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrompido pelo usuário.")
        sys.exit(1)
