import socket
import subprocess
import psutil
import nmap

ip_address = input("Enter IP Address to Scan: ")


def check_host_reachability(ip_address):
    result = subprocess.run(
        ['ping', '-c', '1', ip_address], capture_output=True)
    return result.returncode == 0


def scan_open_ports(ip_address):
    open_ports = []
    try:
        scanner = nmap.PortScanner()
        scan_results = scanner.scan(ip_address, arguments='-p 1-65535')
        for port in scan_results['scan'][ip_address]['tcp']:
            if scan_results['scan'][ip_address]['tcp'][port]['state'] == 'open':
                open_ports.append(port)
    except nmap.PortScannerError:
        pass

    return open_ports


def get_running_processes(ip_address):
    running_processes = []
    try:
        for process in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                connections = process.connections(kind='inet')
                if any(conn.raddr and conn.raddr.ip == ip_address for conn in connections):
                    process_info = {
                        'pid': process.info['pid'],
                        'name': process.info['name'],
                        'cmdline': process.info['cmdline'],
                        'username': process.info['username'],
                    }
                    running_processes.append(process_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except psutil.Error:
        pass

    return running_processes


if check_host_reachability(ip_address):
    print(ip_address, 'is reachable.')
else:
    print(ip_address, 'is not reachable.')

open_ports = scan_open_ports(ip_address)
if open_ports:
    print(f"Open ports on {ip_address}:")
    for port in open_ports:
        print(port)

running_processes = get_running_processes(ip_address)
if running_processes:
    print(f"Running processes on {ip_address}:")
    for process in running_processes:
        print(process)
