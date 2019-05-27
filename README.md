# cChat
chat messaging app implementation for Network Protocol Design course

Syntax:  
 pyhton cchat.py \<ip\> \<port\> \<longid\> \<nickname\> \[ \<neighbour host\> \<neighbour port\> \<neighbour longid\> ]...
  Starts a chat server

Sample server usage (only single host):  
python .\cchat.py localhost 5005 0101010102020202 jimmy

Sample server usage (circle of 4 hosts):
First node
python .\cchat.py localhost 5001 1111111111111111 11 localhost 5004 4444444444444444 localhost 5002 2222222222222222
Second node
python .\cchat.py localhost 5002 2222222222222222 22 localhost 5001 1111111111111111 localhost 5003 3333333333333333
Third node
python .\cchat.py localhost 5003 3333333333333333 33 localhost 5002 2222222222222222 localhost 5004 4444444444444444
Fourth node
python .\cchat.py localhost 5004 4444444444444444 44 localhost 5001 1111111111111111 localhost 5003 3333333333333333

Inside server program, terminal keyboard input can be used. Following commands are possible
/exit - exits the messaging node
/help - this help message
/list - list all destinations, with nicknames
/debugon - turn debugging on
/debugoff - turn debugging off
/routes - print routing table
/forward - print forwarding table
/distance - print distance table
\<message\> - send message to all destinations
\<nick\> \<message\> - send message to \<nick\>, for example /joe Hello!")



