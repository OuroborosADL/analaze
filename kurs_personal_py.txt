import sys
import socket
from cryptography.fernet import Fernet
import getpass
import uuid
import re

port = 5050
ip_server = "192.168.56.1"
address = (ip_server, port)
mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(address)


def load_key():
    key = open('crypto.key', 'rb').read()
    return key


def recieve(conn):    
    key = Fernet(load_key())
    encrypted_msg = conn.recv(65536)
    decrypted_msg = key.decrypt(encrypted_msg)
    decrypted_msg = decrypted_msg.decode('utf8')
    if decrypted_msg == 'Вы были отключены':
        print(decrypted_msg)
        return 'exit'
    if ("Введите пароль" not in decrypted_msg) and (decrypted_msg != "Повторите пароль"):
        print(decrypted_msg)
    else:
        return 'passwd'
    if 'Логин или пароль неверный' not in decrypted_msg:
        return False
    else:
        return True
    


def send(msg):
    key = Fernet(load_key())
    encrypted_msg = key.encrypt(msg.encode('utf8'))
    client.send(encrypted_msg)

send(f'p|{mac}')
recieve(client)

enter = True
while enter:
    client_message = input()
    send(f'p|{mac}|{client_message}')
    recieve(client)
    client_message = getpass.getpass(prompt='Введите пароль: ')
    send(f'p|{mac}|{client_message}')
    enter = recieve(client)
    if enter == False:
        connected = True
        break
    else:
        connected = False

while connected:
    client_message = input()
    send(f'p|{mac}|{client_message}')
    msg = recieve(client)    
    if msg == 'exit':
        connected = False
        client.close()
    elif msg == 'passwd':
        client_message = getpass.getpass(prompt='Введите пароль: ')
        send(f'p|{mac}|{client_message}')
        second_msg = recieve(client)
        if second_msg == 'passwd':
            client_message = getpass.getpass(prompt='Повторите пароль: ')
            send(f'p|{mac}|{client_message}')
            recieve(client)