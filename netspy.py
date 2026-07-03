#!/usr/bin/env python3
"""
NetSpy - Утилита сетевого сканирования и мониторинга.
Возможности:
  - многопоточное TCP-сканирование портов
  - простой UDP-пинг (обнаружение ICMP Port Unreachable)
  - мониторинг доступности узлов с логированием
Зависимости: scapy, tqdm
"""

import argparse
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import sr1, IP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


def scan_port(target_ip: str, port: int, timeout: float = 1.0) -> int | None:
    """Проверить TCP-порт. Возвращает порт, если открыт, иначе None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def tcp_scan(target_ip: str, ports: range, workers: int = 50) -> list[int]:
    """Многопоточное TCP-сканирование с прогресс-баром."""
    open_ports = []
    total = len(ports)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, target_ip, port): port for port in ports}
        if TQDM_AVAILABLE:
            progress = tqdm(as_completed(futures), total=total, desc="TCP scanning", unit="port")
        else:
            progress = as_completed(futures)
        for future in progress:
            port = future.result()
            if port is not None:
                open_ports.append(port)
    return sorted(open_ports)


def udp_ping(target_ip: str, port: int = 33434, timeout: float = 2.0) -> bool:
    """
    Отправить UDP-дейтаграмму на указанный порт и ожидать ICMP Port Unreachable.
    Возвращает True, если узел ответил (значит порт закрыт/узел доступен).
    """
    if not SCAPY_AVAILABLE:
        print("Ошибка: для UDP-пинга требуется scapy. Установите: pip install scapy")
        return False
    packet = IP(dst=target_ip) / UDP(dport=port)
    reply = sr1(packet, timeout=timeout, verbose=0)
    if reply is None:
        print(f"[!] Нет ответа от {target_ip} (возможно, открыт порт или фильтр)")
        return False
    if reply.haslayer(ICMP):
        icmp_type = reply[ICMP].type
        icmp_code = reply[ICMP].code
        if icmp_type == 3 and icmp_code == 3:
            print(f"[+] {target_ip} ответил ICMP Port Unreachable (узел доступен)")
            return True
    print(f"[*] Получен неожиданный ответ от {target_ip}: {reply.summary()}")
    return False


def monitor_hosts(hosts: list[str], interval: int = 5, logfile: str = "monitor.log"):
    """Пинговать список хостов и записывать статус в лог."""
    print(f"Мониторинг {len(hosts)} хостов (интервал {interval}с). Лог: {logfile}")
    with open(logfile, "a", encoding="utf-8") as log:
        log.write(f"\n--- Мониторинг запущен {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
    try:
        while True:
            for host in hosts:
                try:
                    if sys.platform == "win32":
                        cmd = ["ping", "-n", "1", "-w", "2000", host]
                    else:
                        cmd = ["ping", "-c", "1", "-W", "2", host]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    status = "UP" if result.returncode == 0 else "DOWN"
                except Exception:
                    status = "ERROR"
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                message = f"{timestamp} | {host} | {status}"
                print(message)
                with open(logfile, "a", encoding="utf-8") as log:
                    log.write(message + "\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nМониторинг остановлен.")


def main():
    parser = argparse.ArgumentParser(description="NetSpy - сетевой сканер и мониторинг")
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Режим работы")

    # TCP scan
    tcp_parser = subparsers.add_parser("scan", help="TCP-сканирование портов")
    tcp_parser.add_argument("target", help="IP-адрес цели")
    tcp_parser.add_argument("-p", "--ports", default="1-1024", help="Диапазон портов, напр. 1-1024")
    tcp_parser.add_argument("-w", "--workers", type=int, default=50, help="Количество потоков")

    # UDP ping
    udp_parser = subparsers.add_parser("udp", help="UDP-пинг")
    udp_parser.add_argument("target", help="IP-адрес цели")
    udp_parser.add_argument("--port", type=int, default=33434, help="Порт назначения (по умолчанию 33434)")

    # Monitor
    mon_parser = subparsers.add_parser("monitor", help="Мониторинг доступности")
    mon_parser.add_argument("hosts", nargs="+", help="Список хостов для мониторинга")
    mon_parser.add_argument("-i", "--interval", type=int, default=5, help="Интервал опроса в секундах")
    mon_parser.add_argument("-l", "--log", default="monitor.log", help="Лог-файл")

    args = parser.parse_args()

    if args.mode == "scan":
        target = args.target
        try:
            start, end = map(int, args.ports.split("-"))
        except ValueError:
            print("Неверный формат диапазона портов. Используй: начальный-конечный")
            sys.exit(1)
        ports = range(start, end + 1)
        print(f"Сканируем TCP {target} порты {start}-{end}...")
        open_ports = tcp_scan(target, ports, args.workers)
        if open_ports:
            print(f"Открытые порты на {target}: {', '.join(map(str, open_ports))}")
        else:
            print("Открытых портов не найдено.")

    elif args.mode == "udp":
        target = args.target
        print(f"UDP-пинг {target}:{args.port}...")
        udp_ping(target, args.port)

    elif args.mode == "monitor":
        print(f"Запуск мониторинга для: {', '.join(args.hosts)}")
        monitor_hosts(args.hosts, args.interval, args.log)


if __name__ == "__main__":
    main()