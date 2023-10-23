import psutil

# ip_address = input("Enter an IP Address to Scan: ")


def getRunningProcessed():
    listOfProcObjects = []
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
            pinfo['vms'] = proc.memory_info().vms / (1024 * 1024)
            listOfProcObjects.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    listOfProcObjects = sorted(
        listOfProcObjects, key=lambda procObj: procObj['vms'], reverse=True)
    return listOfProcObjects


print("Running Processes: ", getRunningProcessed())


# import psutil


# def get_running_processes(ip_address):
#     running_processes = []
#     try:
#         for process in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
#             try:
#                 connections = process.connections()
#                 for conn in connections:
#                     print(conn.status)
#                     if conn.status == psutil.CONN_ESTABLISHED and conn.raddr.ip == ip_address:
#                         process_info = {
#                             'pid': process.info['pid'],
#                             'name': process.info['name'],
#                             'cmdline': process.info['cmdline'],
#                             'username': process.info['username'],
#                         }
#                         running_processes.append(process_info)
#                         break
#             except psutil.AccessDenied:
#                 pass
#     except psutil.Error:
#         pass

#     return running_processes


# ip_address = '172.17.62.25'  # IP address to monitor

# running_processes = get_running_processes(ip_address)
# if running_processes:
#     print(f"Running processes associated with {ip_address}:")
#     for process in running_processes:
#         print(process)
# else:
#     print("No running processes found.")
