# python_chat

## Requisitos
a porta 8000 deve estar livre, caso queira trocar a porta basta modificar no link na linha 14 do arquivo client.py e a porta na linha 346 do arquivo server.py 

python 3.10+

bibliotecas python:
- pyargon2
- requests

para instalar as bibliotecas necessárias do python basta usar
`pip install -r requirements.txt`

## Uso
rode `python server.py`
em outro terminal rode
`python client.py`

## patterns usados
O Factory pattern pode ser encontrado em varios locais do código, na criação dos objeto no servidor usando as classes terminadas em `Factory`, na criação dos objetos no cliente usando as funções começadas em `from_dict`. Adapter pattern foi usado no server.py para adaptar as requisições da classe Request_handler e as outras classes. Nas classes Chat, Message, User foi usado Composition

codigo disponivel em https://github.com/Leonardo-Boss/python_chat
