import hashlib
import requests
from models import Message, User, Chat

def message_from_dict(d:dict)->Message:
    return Message(d['id'], d['author'], None, d['text'], d['created_utc'])
def user_from_dict(d:dict)->User:
    return User(d['id'], d['name'], None, [chats_from_dict(chat) for chat in d['chats']], d['cookie'])
def chats_from_dict(d:dict)->Chat:
    return Chat(d['id'], d['name'], [message_from_dict(message) for message in d['messages']])

class Client:
    def __init__(self) -> None:
        self.root_link = 'http://localhost:8000'
        self.session = requests.Session()

    def hash(self, user_name, password):
        return str(hashlib.sha512(f'{user_name}{password}'.encode('utf-8')).digest())

    def create_account(self, user_name:str, password:str):
        m = self.hash(user_name, password)
        r = self.session.post(f'{self.root_link}/create_account', json={'user_name':user_name, 'password':m})
        r = r.json()
        if r['created']:
            print(r['user'])
            self.user = user_from_dict(r['user'])
            print('account created successfully')
            return
        print('account name already exists')

    def create_chat(self, name):
        if not self.user: return
        r = self.session.post(f'{self.root_link}/create_chat', json={'name': name, 'cookie': self.user.cookie})
        r = r.json()
        if r['created']:
            print(r['chat'])
            chat = chats_from_dict(r['chat'])
            self.user.chats.append(chat) 
            self.chat = chat
            print('chat created successfully')
            return
        print('chat not created successfully')
    
    def enterchat(self, chat):
        if not self.user: return
        self.chat = self.user.chats[chat]

    def send_message(self, text):
        if not self.user: return
        r = self.session.post(f'{self.root_link}/send_message', json={'cookie':self.user.cookie, 'author': self.user.id, 'text':text, 'chat':self.chat.id})
        r = r.json()
        if r['created']:
            print(r['message'])
            self.chat.messages.append(message_from_dict(r['message']))
            return
        print('message failed to send')

    def logar(self, user_name:str, password:str):
        m = self.hash(user_name, password)
        r = self.session.post(f'{self.root_link}/login', json={'user_name':user_name, 'password':m})
        r = r.json()
        print(r)
        if r['login']:
            print(r['user'])
            self.user = user_from_dict(r['user'])
            print('logged in successfully')
            return
        print('couldn\'t log in')

    def add_user(self, userid):
        r = self.session.post(f'{self.root_link}/add_user', json={'cookie':self.user.cookie, 'userid':userid, 'chatid':self.chat.id})
        r = r.json()
        print(r)

    def get_users(self):
        r = self.session.post(f'{self.root_link}/get_users', json={'cookie':self.user.cookie})
        r = r.json()
        print(r)

    def get_msgs(self):
        r = self.session.post(f'{self.root_link}/get_messages', json={'cookie':self.user.cookie, 'chatid':self.chat.id})
        r = r.json()
        print(r)

if __name__ == "__main__":
    client = Client()
    client.create_account('fernando', 'asdf')
    client.create_account('pedro', 'asdf')
    client.logar('pedro', 'asdf')
    client.get_users()
    client.create_chat('chat')
    client.add_user(1)
    client.send_message('ola fernando!')
    client.logar('fernando', 'asdf')
    client.send_message('ola pedro!')
    client.get_msgs()
