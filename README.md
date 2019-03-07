# cChat
chat messaging app implementation for Network Protocol Design course

Syntax:
 .\cchat.py  -server <ip> <port>
  Starts a server listener
 .\cchat.py  -client <ip> <port> <message>
  Sends a message to ip:port

Sample server usage:
python .\cchat.py -server localhost 5005

Sample client usage:
python .\cchat.py -client localhost 5005 hello
