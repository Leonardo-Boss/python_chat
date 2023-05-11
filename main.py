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
        self.pessoa = None
        self.chat_ativo = None
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

    def logar(self, user_name:str, password:str):
        m = self.hash(user_name, password)
        r = self.session.post(f'{self.root_link}/login', json={'user_name':user_name, 'password':m})
        r = r.json()
        if r['login']:
            print(r['user'])
            self.user = user_from_dict(r['user'])
            print('logged in successfully')
            return
        print('couldn\'t log in')

    def deslogar(self):
        self.pessoa = None
        self.chat_ativo = None

    def abrir_chat(self, chat_name):
        self.chat_ativo = chat_name

if __name__ == "__main__":
    client = Client()
    client.create_account('pedro', 'asdf')
    client.logar('pedro', 'asdf')
