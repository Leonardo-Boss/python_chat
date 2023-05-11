from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class Message:
    id:int
    author:str
    chat:Chat|None
    text:str
    created_utc:int

    def to_dict(self):
        return {'id': self.id, 'author': self.author, 'text': self.text, 'created_utc': self.created_utc}

@dataclass
class User:
    id:int
    name:str
    password:str|None
    chats:list[Chat] = field(default_factory=lambda :[])
    cookie:int|None = field(default_factory=lambda :None)

    def to_dict(self):
       return {'id': self.id, 'name': self.name, 'chats':[chat.to_dict() for chat in self.chats], 'cookie':self.cookie}

@dataclass
class Chat:
    id:int
    name:str
    messages:list[Message] = field(default_factory=lambda:[])

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'messages':[message.to_dict() for message in self.messages]}
