# cChat
chat messaging app implementation for Network Protocol Design course

Syntax:<br/>  
pyhton cchat.py \<ip\> \<port\> \<longid\> \<nickname\> \[ \<neighbour host\> \<neighbour port\> \<neighbour longid\> ]...<br/>
Starts a chat server<br/>

Sample server usage (only single host):<br/>  
python .\cchat.py localhost 5005 0101010102020202 jimmy<br/>

Sample server usage (circle of 4 hosts):<br/>
First node<br/>
python .\cchat.py localhost 5001 1111111111111111 11 localhost 5004 4444444444444444 localhost 5002 2222222222222222<br/>
Second node<br/>
python .\cchat.py localhost 5002 2222222222222222 22 localhost 5001 1111111111111111 localhost 5003 3333333333333333<br/>
Third node<br/>
python .\cchat.py localhost 5003 3333333333333333 33 localhost 5002 2222222222222222 localhost 5004 4444444444444444<br/>
Fourth node<br/>
python .\cchat.py localhost 5004 4444444444444444 44 localhost 5001 1111111111111111 localhost 5003 3333333333333333<br/>

Inside server program, terminal keyboard input can be used. Following commands are possible<br/>
 /exit - exits the messaging node<br/>
 /help - this help message<br/>
 /list - list all destinations, with nicknames<br/>
 /routes - get all routes<br/>
 /forward - get forwarding table<br/>
 /distance - get distance table<br/>
 /self - het self longid<br/>
 /debugon - turn debugging on<br/>
 /debugoff - turn debugging off<br/>
 /routes - print routing table<br/>
 /forward - print forwarding table<br/>
 /distance - print distance table<br/>
 \<message\> - send message to all destinations<br/>
 \<nick\> \<message\> - send message to \<nick\>, for example /joe Hello!")<br/>



