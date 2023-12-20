import socket
import threading
import queue
from cryptography.fernet import Fernet
import hashlib as hash
from peewee import *
from datetime import datetime, timedelta
import secrets
import string
import smtplib


port = 5050
ip_server = socket.gethostbyname(socket.gethostname())
address = (ip_server, port)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(address)

def write_key_connect():
    key = Fernet.generate_key()
    with open('connect.key', 'wb') as key_file:
        key_file.write(key)

def load_key_connect():
    key = open('connect.key', 'rb').read()
    return key

def read_data_connect():
    f = Fernet(load_key_connect())
    with open('connect.txt', 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data).decode('utf8')
    return decrypted_data

connect_data = read_data_connect().split("|")
connect = PostgresqlDatabase(connect_data[0], user=connect_data[1], password=connect_data[2], host='127.0.0.1', port=int(connect_data[3]))


class BaseModel(Model):
    class Meta:
        database = connect


class Users(BaseModel):
    id_user = IntegerField(column_name='id_user', primary_key=True)
    fio = TextField(column_name='fio', null=False)
    role = TextField(column_name='role', null=False)
    email = TextField(column_name='email', null=False)
    user_login = TextField(column_name='login', null=False)
    user_password = TextField(column_name='password', null=False)
    salt = TextField(column_name='salt', null=False)

    class Meta:
        table_name = 'users'


class PcMacAddress(BaseModel):
    id_pc = IntegerField(column_name='id_pc', primary_key=True)
    mac_address = TextField(column_name='mac_address', null=False)

    class Meta:
        table_name = 'pc_mac_address'


class PcInformation(BaseModel):
    id_information = IntegerField(column_name='id_information', primary_key=True)
    number_pc = ForeignKeyField(PcMacAddress, column_name='number_pc', null=False)
    cpu_utilization = FloatField(column_name='cpu_utilization_percents', null=False)
    cpu_temperature = FloatField(column_name='cpu_temperature', null=False)
    ram_utilization = FloatField(column_name='ram_utilization_percents', null=False)
    datetime_information = DateTimeField(column_name='datetime_information', null=False)

    class Meta:
        table_name = 'pc_information'


class UsersConnections(BaseModel):
    id_connection = IntegerField(column_name='id_connection', primary_key=True)
    user = ForeignKeyField(Users, column_name='user', null=False)
    pc = ForeignKeyField(Users, column_name='pc', null=False)
    datetime_connection = DateTimeField(column_name='datetime_connection', null=False)

    class Meta:
        table_name = 'users_connections'


def write_key():
    key = Fernet.generate_key()
    with open('crypto.key', 'wb') as key_file:
        key_file.write(key)

def load_key():
    key = open('crypto.key', 'rb').read()
    return key

def encrypt():
    f = Fernet(load_key_connect())
    with open('connect.txt', 'rb') as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open('connect.txt', 'wb') as file:
        file.write(encrypted_data)

def recv(conn):
    f = Fernet(load_key())
    encrypted_msg = conn.recv(1024)
    decrypted_msg = f.decrypt(encrypted_msg).decode('utf8')
    msg = decrypted_msg.split("|")
    return msg

def send(msg, conn):
    f = Fernet(load_key())
    encrypted_msg = f.encrypt(msg.encode('utf8'))
    conn.send(encrypted_msg)

def generate_salt():
    letters_and_digits = string.ascii_letters + string.digits
    salt = ''.join(secrets.choice(letters_and_digits) for i in range(10))
    return salt

class User():

    def __init__(self, login, password, salt, conn):
        self.login = login
        self.password = hash.sha512(password.encode('utf8')).hexdigest()
        self.salt = salt
        self.conn = conn


    def autentification(self):
        query = Users.select().where((Users.user_login == self.login) & (Users.user_password == self.password))
        auth_user = query.dicts().execute()        
        if len(auth_user) == 0:
            return False
        else:
            self.role = auth_user[0]['role']
            return True


    def welcome(self):
        welcome_msg = f"\n����� ����������, {self.login}!"
        if self.role == '������� �������������':
            welcome_msg += f"\n������ ������:\n1 - �����������\n2 - ����������� ���������� � ��������� ��\n3 - �������� ������ ������������\n4 - �������� ���� ������������\n5 - ������� ������������\n6 - ����������� ���������� � ������������ � �������\n7 - ����������� ���� �������������\n"           
        elif self.role == '�������������':            
            welcome_msg += f"\n������ ������:\n1 - �����������\n2 - ����������� ���������� � ��������� ��\n3 - �������� ������ ������������\n"
        elif self.role == '��������':            
            welcome_msg += f"\n������ ������:\n1 - �����������\n2 - ����������� ���������� � ��������� ��\n"
        send(welcome_msg, self.conn)


    def disconnect(self):
        send("�� ���� ���������", self.conn)


    def add_user(self):
        if self.role == '��������':
            self.unknown_command()
        else:
            send("������� ������", self.conn)
            passwd = recv(self.conn)
            check_password = passwd[2] + self.salt
            if self.password == hash.sha512(check_password.encode('utf8')).hexdigest():
                send("������� ��� ������ ������������", self.conn)
                fio_new_user = recv(self.conn)
                fio_new_user_db = fio_new_user[2].lower().title()
                send("������� ����� ������ ������������", self.conn)
                email_new_user = recv(self.conn)
                send("������� ����� ������ ������������", self.conn)
                login_new_user = recv(self.conn)
                send("������� ������ ������ ������������", self.conn)
                passwd_new_user = recv(self.conn)
                send("��������� ������", self.conn)
                passwd_re_entry = recv(self.conn)
                if passwd_re_entry[2] == passwd_new_user[2]:
                    salt_new_user = generate_salt()
                    query = Users.select().limit(1).order_by(Users.id_user.desc())
                    last_id_user = query.dicts().execute()
                    if len(last_id_user) == 0:
                        new_user = Users.create(id_user=1, fio=fio_new_user_db, role='��������', email=email_new_user[2], user_login=login_new_user[2], user_password=hash.sha512(f'{passwd_new_user[2] + salt_new_user}'.encode('utf8')).hexdigest(), salt=salt_new_user)
                        new_user.save()
                    else:
                        new_user = Users.create(id_user=int(last_id_user[0]['id_user']) + 1, fio=fio_new_user_db, role='��������', email=email_new_user[2], user_login=login_new_user[2], user_password=hash.sha512(f'{passwd_new_user[2] + salt_new_user}'.encode('utf8')).hexdigest(), salt=salt_new_user)
                        new_user.save()
                    send('\n������������ ������� ��������\n������� ������� �� ������ ������\n', self.conn)
                else:
                    send('\n��������� ������ �� ���������\n������� ������� �� ������ ������\n', self.conn)
            else:
                send('\n������ �������� ������. � ������� ��������\n������� ������� �� ������ ������\n', self.conn)


    def del_user(self):
        if self.role != '������� �������������':
            self.unknown_command()
        else:
            send("������� ������", self.conn)
            passwd = recv(self.conn)
            check_password = passwd[2] + self.salt
            if self.password == hash.sha512(check_password.encode('utf8')).hexdigest():
                send("������� ��� ������������, �������� �� ������ �������", self.conn)
                fio_del_user = recv(self.conn)
                fio_del_user_db = fio_del_user[2].lower().title()                
                query_users = Users.select().where(Users.fio == fio_del_user_db)
                users_with_fio = query_users.dicts().execute()
                if len(users_with_fio) != 0:
                    if len(users_with_fio) == 1:
                        query_del_connections_user = UsersConnections.delete().where(UsersConnections.user == int(users_with_fio[0]['id_user']))
                        query_del_connections_user.execute()
                        query_del_user = Users.delete().where(Users.fio == fio_del_user_db)
                        query_del_user.execute()
                        send('������������ ������� ������\n������� ������� �� ������ ������\n', self.conn)
                    else:
                        choice_msg = '�������� ������� ������������ �� ������ (������� �����):\n'
                        for i in range(len(users_with_fio)):
                            choice_msg += f"{i+1}) {users_with_fio[i]['user_login']}\n"
                        send(choice_msg, self.conn)
                        selected_user_number = recv(self.conn)
                        try:
                            next = True
                            ex = int(selected_user_number[2])
                        except:
                            next = False
                            send('����� ������ �������\n������� ������� �� ������ ������\n', self.conn)
                        if next:
                            query_del_connections_user = UsersConnections.delete().where(UsersConnections.user == int(users_with_fio[int(selected_user_number[2])-1]['id_user']))
                            query_del_connections_user.execute()
                            query_del_user = Users.delete().where((Users.fio == fio_del_user_db) & (Users.user_login == users_with_fio[int(selected_user_number[2])-1]['user_login']))
                            query_del_user.execute()
                            send('������������ ������� ������\n������� ������� �� ������ ������\n', self.conn)
                else:
                    send("������������ � ����� ��� �� ����������\n������� ������� �� ������ ������\n", self.conn)
            else:
                send('\n������ �������� ������. � ������� ��������\n������� ������� �� ������ ������\n', self.conn)


    def user_role_change(self):
        if self.role != '������� �������������':
            self.unknown_command()
        else:
            send("������� ������", self.conn)
            passwd = recv(self.conn)
            check_password = passwd[2] + self.salt
            if self.password == hash.sha512(check_password.encode('utf8')).hexdigest():
                send("������� ��� ������������, �������� �� ������ �������� ����\n", self.conn)
                fio_user = recv(self.conn)
                fio_user_db = fio_user[2].lower().title()
                query_users = Users.select().where(Users.fio == fio_user_db)
                users_with_fio = query_users.dicts().execute()
                if len(users_with_fio) != 0:
                    if len(users_with_fio) == 1:
                        send("�������� ���� (������� �����):\n1) �������������\n2) ��������\n", self.conn)
                        new_role = recv(self.conn)
                        try:
                            if int(new_role[2]) in [1, 2]:
                                if int(new_role[2]) == 1:
                                    user_change_role = Users.update(role='�������������').where(Users.fio == fio_user_db)
                                    user_change_role.execute()
                                elif int(new_role[2]) == 2:
                                    user_change_role = Users.update(role='��������').where(Users.fio == fio_user_db)
                                    user_change_role.execute()
                                send('���� � ������� ������������ ���� ������� ��������\n������� ������� �� ������ ������\n', self.conn)
                            else:
                                send('������ ���� �� ����������. ���� �� ���� ��������\n������� ������� �� ������ ������\n', self.conn)
                        except:
                            send('������ ���� �� ����������. ���� �� ���� ��������\n������� ������� �� ������ ������\n', self.conn)
                    else:
                        choice_msg = '�������� ������� ������������ �� ������ (������� �����):\n'
                        for i in range(len(users_with_fio)):
                            choice_msg += f"{i+1}) {users_with_fio[i]['user_login']}\n"
                        send(choice_msg, self.conn)
                        selected_user_number = recv(self.conn)
                        try:
                            next = True
                            ex = int(selected_user_number[2])
                        except:
                            next = False
                            send('����� ������ �������\n������� ������� �� ������ ������\n', self.conn)
                        if next:
                            send("�������� ���� (������� �����):\n1) �������������\n2) ��������\n")
                            new_role = recv(self.conn)
                            try:
                                if int(new_role[2]) in [1, 2]:
                                    if int(new_role[2]) == 1:
                                        user_change_role = Users.update(role='�������������').where((Users.fio == fio_user_db) & (Users.user_login == users_with_fio[int(selected_user_number[2])-1]['user_login']))
                                        user_change_role.execute()
                                    elif int(new_role[2]) == 2:
                                        user_change_role = Users.update(role='��������').where((Users.fio == fio_user_db) & (Users.user_login == users_with_fio[int(selected_user_number[2])-1]['user_login']))
                                        user_change_role.execute()
                                    send('���� � ������� ������������ ���� ������� ��������\n������� ������� �� ������ ������\n', self.conn)
                                else:
                                    send('������ ���� �� ����������. ���� �� ���� ��������\n������� ������� �� ������ ������\n', self.conn)
                            except:
                                send('������ ���� �� ����������. ���� �� ���� ��������\n������� ������� �� ������ ������\n', self.conn)
                else:
                    send("������������ � ����� ��� �� ����������\n������� ������� �� ������ ������\n", self.conn)                                
            else:
                send('\n������ �������� ������. � ������� ��������\n������� ������� �� ������ ������\n', self.conn)


    def show_info_connections(self):
        if self.role == '������� �������������':
            send("������� ������", self.conn)
            passwd = recv(self.conn)
            check_password = passwd[2] + self.salt
            if self.password == hash.sha512(check_password.encode('utf8')).hexdigest():
                send('�� ������ �������� �� ������ ������� ���������� � ������������ (������� �����):\n1) id ��\n2) ��� ������������\n3) �� ���������� �������\n', self.conn)
                selected_num = recv(self.conn)
                try:
                    next = True
                    ex = int(selected_num[2])
                except:
                    next = False
                    send('������� ��� ������ �������\n������� ������� �� ������ ������\n', self.conn)
                if next:
                    if int(selected_num[2]) in [1, 2, 3]:
                        if int(selected_num[2]) == 1:
                            send('������� id ��', self.conn)
                            num_pc = recv(self.conn)
                            try:
                                next = True
                                pc = int(num_pc[2])
                            except:
                                next = False
                                send('\nId �� ��� ������ �������\n������� ������� �� ������ ������\n', self.conn)
                            if next:
                                query_info_pc_connections = UsersConnections.select().where(UsersConnections.pc == int(num_pc[2]))
                                info_pc_connections = query_info_pc_connections.dicts().execute()
                                if len(info_pc_connections) == 0:
                                    send('\n�� ���������������� ����������� � �� � ����� id\n������� ������� �� ������ ������\n', self.conn)
                                else:                                        
                                    info_msg = ''
                                    for connection in info_pc_connections:
                                        query_fio = Users.select().where(Users.id_user == int(connection['user']))
                                        fio = query_fio.dicts().execute()
                                        info_msg += f'\n��� ������������: {fio[0]["fio"]}\n���� � ����� �����������: {connection["datetime_connection"]}\n'
                                        info_msg += '----------------------------------------------------------------'
                                    send(f'{info_msg}\n������� ������� �� ������ ������\n', self.conn)
                        elif int(selected_num[2]) == 2:
                            send("\n������� ��� ������������", self.conn)
                            fio_user = recv(self.conn)
                            fio_user_db = fio_user[2].lower().title()
                            query_user = Users.select().where(Users.fio == fio_user_db).limit(1)
                            user_with_fio = query_user.dicts().execute()
                            id_user = int(user_with_fio[0]['id_user'])
                            query_info_user_connections = UsersConnections.select().where(UsersConnections.user == id_user)
                            info_user_connections = query_info_user_connections.dicts().execute()
                            if len(info_user_connections) == 0:
                                send('\n�� ���������������� ����������� � �� � ������� ������������\n������� ������� �� ������ ������\n', self.conn)
                            else:
                                info_msg = ''
                                for connection in info_user_connections:
                                    info_msg += f'\nID ��: {connection["pc"]}\n���� � ����� �����������: {connection["datetime_connection"]}\n'
                                    info_msg += '----------------------------------------------------------------'
                                send(f'{info_msg}\n������� ������� �� ������ ������\n', self.conn)
                        elif int(selected_num[2]) == 3:
                            send("\n�������� ���������� ������� (������� �����):\n1) �� �����\n2) �� ������\n3) �� ����\n", self.conn)
                            select_num = recv(self.conn)
                            try:
                                next = True
                                pc = int(select_num[2])
                            except:
                                next = False
                                send('\n���������� ������� ��� ������ �������\n������� ������� �� ������ ������\n', self.conn)
                            if next:
                                if int(select_num[2]) in [1, 2, 3]:
                                    if int(select_num[2]) == 1:                                            
                                        diff = timedelta(31)                                            
                                    elif int(select_num[2]) == 2:
                                        diff = timedelta(7)
                                    elif int(select_num[2]) == 3:
                                        diff = timedelta(1)
                                    now = datetime.today()
                                    date = now - diff
                                    query_info_date_connections = UsersConnections.select().where(UsersConnections.datetime_connection > date)
                                    info_date_connections = query_info_date_connections.dicts().execute()
                                    info_msg = ''
                                    for connection in info_date_connections:
                                        query_fio_user = Users.select().where(Users.id_user == int(connection['user']))
                                        fio_user = query_fio_user.dicts().execute()
                                        info_msg += f'\nID ��: {connection["pc"]}\n��� ������������: {fio_user[0]["fio"]}\n���� � ����� �����������: {connection["datetime_connection"]}\n'
                                        info_msg += '----------------------------------------------------------------'
                                    send(f'{info_msg}\n������� ������� �� ������ ������\n', self.conn)
                                else:
                                    send('\n���������� ������� ��� ������ �������\n������� ������� �� ������ ������\n', self.conn)
                    else:
                        send('������� ��� ������ �������\n������� ������� �� ������ ������\n', self.conn)
            else:
                send('\n������ �������� ������. � ������� ��������\n������� ������� �� ������ ������\n', self.conn)
        else:
            self.unknown_command()


    def show_info_pc(self):
        send('������� id ��', self.conn)
        num_pc = recv(self.conn)
        try:
            next = True
            pc = int(num_pc[2])
        except:
            next = False
            send('Id �� ��� ������ �������\n������� ������� �� ������ ������\n', self.conn)
        if next:
            query_info_pc = PcInformation.select().where(PcInformation.number_pc == int(num_pc[2]))
            info_pc = query_info_pc.dicts().execute()
            if len(info_pc) == 0:
                send('�� � ����� id �� ����������\n������� ������� �� ������ ������\n', self.conn)
            else:
                info_msg = f'������������� ����������: {info_pc[0]["cpu_utilization"]}%\n����������� ����������: {info_pc[0]["cpu_temperature"]}��\n������������� ����������� ������: {info_pc[0]["ram_utilization"]}%\n���� � ����� ����� ����������: {info_pc[0]["datetime_information"]}\n'
                send(info_msg, self.conn)


    def show_users(self):
        if self.role == '������� �������������':
            send("������� ������", self.conn)
            passwd = recv(self.conn)
            check_password = passwd[2] + self.salt
            if self.password == hash.sha512(check_password.encode('utf8')).hexdigest():
                send('����� ������������� �� ������ ������� (������� �����):\n1) ��������������\n2) ���������\n3) ���\n', self.conn)
                selected_num = recv(self.conn)
                try:
                    next = True
                    ex = int(selected_num[2])
                except:
                    next = False
                    send('����� ��� ������ �������\n������� ������� �� ������ ������\n', self.conn)
                if next:
                    if int(selected_num[2]) in [1, 2, 3]:
                        if int(selected_num[2]) == 1:
                            query_users_admin = Users.select().where(Users.role == '�������������')
                            users_admin = query_users_admin.dicts().execute()
                            if len(users_admin) == 0:
                                send('\n������������� � ����� "�������������" ���\n������� ������� �� ������ ������\n', self.conn)
                            else:                                        
                                info_msg = ''
                                for admin in users_admin:
                                    info_msg += f'\nId ������������: {admin["id_user"]}\n��� ������������: {admin["fio"]}\n����: {admin["role"]}\n�����: {admin["email"]}\n'
                                    info_msg += '----------------------------------------------------------------'
                                send(f'{info_msg}\n������� ������� �� ������ ������\n', self.conn)
                        elif int(selected_num[2]) == 2:
                            query_users_operator = Users.select().where(Users.role == '��������')
                            users_operator = query_users_operator.dicts().execute()
                            if len(users_operator) == 0:
                                send('\n������������� � ����� "��������" ���\n������� ������� �� ������ ������\n', self.conn)
                            else:                                        
                                info_msg = ''
                                for operator in users_operator:
                                    info_msg += f'\nId ������������: {operator["id_user"]}\n��� ������������: {operator["fio"]}\n����: {operator["role"]}\n�����: {operator["email"]}\n'
                                    info_msg += '----------------------------------------------------------------'
                                send(f'{info_msg}\n������� ������� �� ������ ������\n', self.conn)
                        elif int(selected_num[2]) == 3:
                            query_users = Users.select().where((Users.role == '�������������') | (Users.role == '��������'))
                            users = query_users.dicts().execute()
                            if len(users) == 0:
                                send('\n������������� � ����� "�������������" � "��������" ���\n������� ������� �� ������ ������\n', self.conn)
                            else:                                        
                                info_msg = ''
                                for user in users:
                                    info_msg += f'\nId ������������: {user["id_user"]}\n��� ������������: {user["fio"]}\n����: {user["role"]}\n�����: {user["email"]}\n'
                                    info_msg += '----------------------------------------------------------------'
                                send(f'{info_msg}\n������� ������� �� ������ ������\n', self.conn)
                    else:
                        send('����� ��� ������ �������\n������� ������� �� ������ ������\n', self.conn)
            else:
                send('\n������ �������� ������. � ������� ��������\n������� ������� �� ������ ������\n', self.conn)
        else:
            self.unknown_command()


    def unknown_command(self):
        if self.role == '������� �������������':
            send('������� ����������� �������\n������ ������:\n1 - �����������\n2 - ����������� ���������� � ��������� ��\n3 - �������� ������ ������������\n4 - �������� ���� ������������\n5 - ������� ������������\n6 - ����������� ���������� � ������������ � �������\n7 - ����������� ���� �������������\n', self.conn)
        elif self.role == '�������������':
            send('������� ����������� �������\n������ ������:\n1 - �����������\n2 - ����������� ���������� � ��������� ��\n3 - �������� ������ ������������\n', self.conn)
        elif self.role == '��������':
            send('������� ����������� �������\n������ ������:\n1 - �����������\n2 - ����������� ���������� � ��������� ��\n', self.conn)    


def send_email(message, to_addr):
    server = 'smtp.mail.ru'
    user = 'example_api@mail.ru'
    password = 'LkybB53PjruzpkPAjnFi'

    sender = 'example_api@mail.ru'
    subject = '���������� ����������� � ��' 

    body = "\r\n".join((f"From: {user}", f"To: {to_addr}", 
           f"Subject: {subject}", message))

    mail = smtplib.SMTP_SSL(server)
    mail.login(user, password)
    mail.sendmail(sender, to_addr, body.encode('utf8'))
    mail.quit()


def handle_client(conn, q):
    connected = True
    while connected:
        try:
            msg = recv(conn)
            if msg:
                q.put((conn, msg))
                if msg[0] == "u":
                    if len(msg) == 2:
                        query = PcMacAddress.select()
                        all_pc = query.dicts().execute()
                        all_mac_address = [all_pc[i]['mac_address'] for i in range(len(all_pc))]
                        if msg[1] not in all_mac_address:
                            query = PcMacAddress.select().limit(1).order_by(PcMacAddress.id_pc.desc())
                            last_id_pc = query.dicts().execute()
                            if len(last_id_pc) == 0:
                                new_pc = PcMacAddress.create(id_pc=1, mac_address=f'{msg[1]}')
                                new_pc.save()
                            else:
                                new_pc = PcMacAddress.create(id_pc=int(last_id_pc[0]['id_pc']) + 1, mac_address=f'{msg[1]}')
                                new_pc.save()
                    elif len(msg) == 3:
                        query_id_pc = PcMacAddress.select().where(PcMacAddress.mac_address == msg[1])
                        result_query = query_id_pc.dicts().execute()
                        id_pc = int(result_query[0]['id_pc'])
                        query_id_info = PcInformation.select()
                        all_pc = query_id_info.dicts().execute()
                        all_num_pc = [int(all_pc[i]['number_pc']) for i in range(len(all_pc))]
                        info = msg[2].split(',')
                        info_cpu_percent = round(float(info[0].split()[-1]), 2)
                        info_cpu_temperature = round(float(info[1].split()[-1]), 2)
                        info_ram_percent = round(float(info[2].split()[-1]), 2)
                        if info_cpu_percent > 70 or info_cpu_temperature > 70 or info_ram_percent > 90:
                            query_admin_email = Users.select().where(Users.role == '������� �������������').limit(1)
                            admin_email = query_admin_email.dicts().execute()
                            msg_to_email = f'� �� � id = {id_pc} ��������� ���������� ��������� ������������ �������:'
                            if info_cpu_percent > 80:
                                msg_to_email += f'\n������������� ���������� ({info_cpu_percent}%)'
                            if info_cpu_temperature > 70:
                                msg_to_email += f'\n����������� ���������� ({info_cpu_temperature}��)'
                            if info_ram_percent > 90:
                                msg_to_email += f'\n������������� ����������� ������ ({info_ram_percent}%)'
                            send_email(msg_to_email, admin_email[0]['email'])
                        datetime_info = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        if id_pc in all_num_pc:
                            query_update_info = PcInformation.update(cpu_utilization_percents=info_cpu_percent, cpu_temperature=info_cpu_temperature, ram_utilization_percents=info_ram_percent, datetime_information=datetime_info).where(PcInformation.number_pc == id_pc)
                            query_update_info.execute()
                        else:        
                            query_id_info = PcInformation.select().limit(1).order_by(PcInformation.id_information.desc())
                            result_query = query_id_info.dicts().execute()
                            if len(result_query) == 0:
                                new_info = PcInformation.create(id_information=1, number_pc=id_pc, cpu_utilization_percents=info_cpu_percent, cpu_temperature=info_cpu_temperature, ram_utilization_percents=info_ram_percent, datetime_information=datetime_info)
                                new_info.save()
                            else:
                                new_info = PcInformation.create(id_information=int(result_query[0]['id_information']) + 1, number_pc=id_pc, cpu_utilization_percents=info_cpu_percent, cpu_temperature=info_cpu_temperature, ram_utilization_percents=info_ram_percent, datetime_information=datetime_info)
                                new_info.save()
                elif msg[0] == "p":
                    if len(msg) == 2:
                        query = PcMacAddress.select()
                        all_pc = query.dicts().execute()
                        all_mac_address = [all_pc[i]['mac_address'] for i in range(len(all_pc))]
                        if msg[1] not in all_mac_address:
                            query = PcMacAddress.select().limit(1).order_by(PcMacAddress.id_pc.desc())
                            last_id_pc = query.dicts().execute()
                            if len(last_id_pc) == 0:
                                new_pc = PcMacAddress.create(id_pc=1, mac_address=msg[1])
                                new_pc.save()
                            else:
                                new_pc = PcMacAddress.create(id_pc=int(last_id_pc[0]['id_pc'])+1, mac_address=msg[1])
                                new_pc.save()
                        count_attempts = 3
                        send("������� �����", conn)
                        while count_attempts > 0:
                            login = recv(conn)
                            if login:
                                send("������� ������", conn)
                                passwd = recv(conn)
                                if passwd:                       
                                    login_salt = Users.select().where(Users.user_login == login[2])
                                    user_salt = login_salt.dicts().execute()
                                    if len(user_salt) == 0:
                                        if count_attempts != 1:
                                            send("����� ��� ������ ��������. ���������� �����.\n\n������� �����", conn)
                                        count_attempts -= 1
                                    else:                                        
                                        pass_with_salt = passwd[2] + user_salt[0]['salt']
                                        user = User(login[2], pass_with_salt, user_salt[0]['salt'], conn)
                                        if user.autentification():
                                            break
                                        else:
                                            if count_attempts != 1:
                                                send("����� ��� ������ ��������. ���������� �����.\n\n������� �����", conn)
                                            count_attempts -= 1                                          
                        
                        if count_attempts == 0:
                            send("�� ��������� ���������� ������� �����.\n\n�� ���� ���������", conn)
                            conn.close()
                        else:                            
                            user.welcome()
                            query_user = Users.select().where((Users.user_login == user.login) & (Users.user_password == user.password))
                            user_id = query_user.dicts().execute()
                            query_id_pc = PcMacAddress.select().where(PcMacAddress.mac_address == msg[1])
                            id_pc = query_id_pc.dicts().execute()
                            query = UsersConnections.select().limit(1).order_by(UsersConnections.id_connection.desc())
                            last_id_connection = query.dicts().execute()
                            datetime_info = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            if len(last_id_connection) == 0:
                                new_connection = UsersConnections.create(id_connection=1, user=int(user_id[0]['id_user']), pc=int(id_pc[0]['id_pc']), datetime_connection=datetime_info)
                                new_connection.save()
                            else:
                                new_connection = UsersConnections.create(id_connection=int(last_id_connection[0]['id_connection'])+1, user=int(user_id[0]['id_user']), pc=int(id_pc[0]['id_pc']), datetime_connection=datetime_info)
                                new_connection.save()
                    elif len(msg) == 3:
                        message = msg[2]
                        if message == "1":
                            user.disconnect()
                            connected = False
                        elif message == "2":
                            user.show_info_pc()
                        elif message == "3":
                            user.add_user()
                        elif message == "4":
                            user.user_role_change()
                        elif message == "5":
                            user.del_user()
                        elif message == "6":
                            user.show_info_connections()
                        elif message == "7":
                            user.show_users()
                        else:
                            user.unknown_command()

        except:
            pass

    conn.close()

def start():
    print(f'������ �������: {ip_server}')
    server.listen()
    while True:
        conn, addr = server.accept()
        q = queue.Queue()
        thread = threading.Thread(target=handle_client, args=(conn, q))
        thread.start()
        print(f"���������� �������� �����������: {threading.activeCount() - 6}")
    connect.close()

start()