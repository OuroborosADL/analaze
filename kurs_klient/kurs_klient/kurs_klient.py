import socket
import psutil
from cryptography.fernet import Fernet
from datetime import datetime
import time
import uuid
import re
import subprocess
import os
   
port = 5050
ip_server = "192.168.56.1"
address = (ip_server, port)
mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(address)


def load_key():
    key = open('crypto.key', 'rb').read()
    return key


def send(msg):
    f = Fernet(load_key())
    encrypted_msg = f.encrypt(msg.encode('utf8'))
    client.send(encrypted_msg)


send(f'u|{mac}')
connected = True
while connected:
    seconds_of_now_time = datetime.now().second
    time.sleep(1)
    if seconds_of_now_time == 0:
        psscript = """
$t = Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace "root/wmi"

$t.CurrentTemperature
"""
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        cmd = ['powershell.exe', '-Command',  psscript]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, startupinfo=si)
        tmp = proc.stdout.readline()
        celsius = int(tmp) / 10 - 273.15
        cpu_temperature = round(celsius, 2)
        send(f'u|{mac}|Процент загруженности процессора {psutil.cpu_percent()},Температура процессора {cpu_temperature},Процент загруженности памяти {psutil.virtual_memory()[2]}')