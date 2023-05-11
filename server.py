from __future__ import annotations
import time
import http.server
import json
import hashlib
import random
import sqlite3
from models import User, Chat, Message

from pyargon2 import hash

db = sqlite3.connect(':memory:')
def init_db():
    tables = [
    '''
    CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_name TEXT,
            password TEXT
            )
    ''',
    '''
    CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT
            )
    ''',
    '''
    CREATE TABLE IF NOT EXISTS chats_users (
            chatid INTEGER,
            userid INTEGER
            )
    ''',
    '''
    CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author INTEGER,
            chat INTEGER,
            text TEXT,
            created_utc INTEGER
            )
    ''',
    '''
    CREATE TABLE IF NOT EXISTS logged (
        userid INTEGER,
        expires INTEGER,
        cookie INTEGER
        )
    '''
    ]
    cur = db.cursor()
    for table in tables:
        cur.execute(table)
    db.commit()
    cur.close()

class Message_factory:
    @staticmethod
    def id_get(id):
        cr = db.cursor()
        cr.execute('SELECT author, chat, text, created_utc FROM messages WHERE id=?', (id,))
        author, chat, text, created_utc = cr.fetchone()
        cr.close()
        return Message(id, author, chat, text, created_utc)

class Chat_factory:
    @staticmethod
    def create_chat(name, user):
        cr = db.cursor()
        cr.execute('INSERT INTO chats (user_name) values(?)', (name,))
        chat_id = cr.lastrowid
        if not chat_id: return
        cr.execute('INSERT INTO chats_users (userid, chatid) values(?, ?)', (user.id, chat_id))
        db.commit()
        cr.close()
        chat = Chat(id=chat_id, name=name)
        Chat_factory.update_users(chat)
        return chat

    @staticmethod
    def add_user(chat, user):
        cr = db.cursor()
        cr.execute('INSERT INTO chats_users (userid, chatid) values(?, ?)', (user.id, chat.id))
        db.commit()
        cr.close()

    @staticmethod
    def id_get(id):
        cr = db.cursor()
        cr.execute('SELECT name, FROM chats WHERE id=?', (id,))
        name = cr.fetchone()[0]
        cr.close()
        chat = Chat(id, name)
        Chat_factory.update_messages(chat)
        Chat_factory.update_users(chat)
        return 

    @staticmethod
    def update_users(chat):
        cr = db.cursor()
        cr.execute('SELECT userid FROM chats_users WHERE chatid=?', (chat.id,))
        chat.users = [User_Factory.get_logged(i[0]) for i in cr.fetchall()]
        cr.close()
        return chat

    @staticmethod
    def update_messages(chat, limit=15):
        cr = db.cursor()
        cr.execute('SELECT id, author, text, created_utc  FROM messages WHERE chat=? ORDER BY created_utc DESC LIMIT ?', (chat.id, limit)) 
        chat.messages = [Message(id=i[0], author=i[1], chat=chat, text=i[2], created_utc=i[3]) for i in cr.fetchall()]
        cr.close()
        return chat


class User_Factory:
    @staticmethod
    def new_user_obj(id, name, password):
        user = User(id=id, name=name, password=password)
        User_Factory.update_chats(user)
        User_Factory.update_cookie(user)
        return user

    @staticmethod
    def update_chats(user):
        cr = db.cursor()
        cr.execute('SELECT chatid FROM chats_users WHERE userid=?', (user.id,))
        user.chats = [i[0] for i in cr.fetchall()]
        cr.close()
        return user

    @staticmethod
    def update_cookie(chat):
        cr = db.cursor()
        expires = int(time.time())
        cr.execute('SELECT cookie, expires FROM logged WHERE userid=? and expires>? ORDER BY expires DESC', (chat.id, expires))
        if (res := cr.fetchone()):
            chat.cookie, chat.cookie_expire = res
        cr.close()
        return chat

    @staticmethod
    def id_login(id):
        cr = db.cursor()
        cr.execute('SELECT user_name, password FROM users WHERE id=?', (id,))
        name, password = cr.fetchone()
        cr.close()
        return User_Factory.new_user_obj(id, name, password)
    
    @staticmethod
    def name_login(name):
        cr = db.cursor()
        cr.execute('SELECT id, password FROM users WHERE user_name=?', (name,))
        id, password = cr.fetchone()
        cr.close()
        return User_Factory.new_user_obj(id, name, password)
    
    @staticmethod
    def get_new_cookie(user):
        cookie = random.randint(100000, 999999)
        cr = db.cursor()
        cr.execute('INSERT INTO logged (userid, expires, cookie) values(?, ?, ?)', (user.id, time.time()+3600, cookie))
        db.commit()
        cr.close()
        user.cookie = cookie
        return user

    @staticmethod
    def get_logged(cookie):
        cr = db.cursor()
        cr.execute('SELECT userid FROM logged WHERE cookie=? and timestamp>? ORDER BY timestamp DESC', (cookie,))
        id = cr.fetchone()[0]
        cr.close()
        return User_Factory.id_login(id)

    @staticmethod
    def login(user_name, password):
        user = User_Factory.name_login(name=user_name)
        password = User_Factory.hash(password, user.id)
        if user.password == password:
            return User_Factory.get_new_cookie(user)

    @staticmethod
    def verify_user_name_exists(user_name):
        cr = db.cursor()
        cr.execute('select count(*) from users where user_name=?', (user_name,))
        count = cr.fetchone()[0]
        cr.close()
        if count:
            return True
        return False

    @staticmethod
    def hash(password, salt):
        salt = hashlib.sha512(f'{salt}'.encode('utf-8')).digest()
        return hash(password, str(salt))

    @staticmethod
    def create_account(user_name, password):
        cr = db.cursor()
        cr.execute('INSERT INTO users (user_name) values(?)', (user_name,))
        id = cr.lastrowid
        password_h = User_Factory.hash(password, id)
        cr.execute('UPDATE users SET password=? WHERE id=?', (password_h, id))
        db.commit()
        cr.close()
        user = User_Factory.new_user_obj(id, user_name, password_h)
        return User_Factory.get_new_cookie(user)

class User_factory_request_adpater:
    @staticmethod
    def create_user(data):
        if User_Factory.verify_user_name_exists(data['user_name']):
            return {'created': False, 'reason':'username already exists'}
        user = User_Factory.create_account(data['user_name'], data['password'])
        return {'created': True, 'user': user.to_dict()}

    @staticmethod
    def login(data):
        try:
            user = User_Factory.login(data['user_name'], data['password'])
            if user:
                return {'login':True, 'user':user.to_dict()}
            return {'login':False}
        except:
            return {'login':False}

    @staticmethod
    def get_from_cookie(cookie):
        return User_Factory.get_logged(cookie)

# Define a simple HTTP request handler
class RequestHandler(http.server.BaseHTTPRequestHandler):

    # Define the response headers
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    # Handle POST requests
    def do_POST(self):

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        post_data_dict = json.loads(post_data)
        cookie = post_data_dict.get('cookie')

        if (executer := post_paths_not_logged.get(self.path)):
            response = executer(post_data_dict)

        elif (executer := post_paths_logged.get(self.path)) and cookie:
            user = User_factory_request_adpater.get_from_cookie(cookie)
            response = executer(post_data_dict, user)

        else:
            self.send_response(404)
            return

        self._set_headers()
        json_data = json.dumps(response).encode('utf-8')
        self.wfile.write(json_data)

        # # Set the response headers
        # self._set_headers()
        # print('path:', self.path)
        #
        # # Set the JSON response data
        # data = {"message": "Hello, World!"}
        # json_data = json.dumps(data).encode('utf-8')
        #
        # # Write the response data
        # self.wfile.write(json_data)

if __name__ == '__main__':
    post_paths_not_logged:dict = {'/create_account': User_factory_request_adpater.create_user, '/login': User_factory_request_adpater.login}
    post_paths_logged:dict = {}

    init_db()
    # Define the server address and port
    server_address = ('', 8000)
    
    # Create an HTTP server with the defined request handler
    httpd = http.server.HTTPServer(server_address, RequestHandler)
    
    # Start the server
    print('Starting server...')
    httpd.serve_forever()
