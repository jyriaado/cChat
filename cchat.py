"""
gitlab : https://gitlab.cs.ttu.ee/taroja/itc8061

keepalive server :
193.40.103.97 -- urr.k-space.ee
port: 31337
GPG: 80078218B43B0E90

Send keepalive to the server with this ID as DSTID, it will respond ACK.

"""

import sys
import socket
import select
import time
import json
import threading

packet_header_length=20
packet_limit=100
payload_limit=packet_limit-packet_header_length
debug=1

class Packet:
    packet_version = 0
    packet_type = 0
    packet_flags = 0
    session_id = 0
    seq = 0
    source = bytes()
    destination = bytes()
    data = bytes()

    #packet_type is byte
    #seq,total int
    #data bytes
    def __init__(self, packet_type, packet_flags, source, destination, session_id, seq, data):
        self.packet_type = packet_type
        self.packet_flags = packet_flags
        self.session_id = session_id
        self.seq = seq
        self.source = source
        self.destination = destination
        self.data = data

    #init with data (bytes)
    @classmethod
    def init_with_data(self, data):
        #parse the data
        #print("packet length:",len(data))
        if (len(data)>=packet_header_length):
            first_byte = int.from_bytes(data[0:1], byteorder='big')
            packet_version = ((first_byte & 0xC0) >> 6)
            packet_type = ((first_byte & 0x38) >> 3)
            packet_flags = first_byte & 0x07
            session_id = int.from_bytes(data[17:18], byteorder='big')
            seq = int.from_bytes(data[18:20], byteorder='big')
            source = data[1:9]
            destination = data[9:17]
            length = int.from_bytes(data[9:10], byteorder='big')
            payload = data[20:]
            return Packet(packet_type,packet_flags, source, destination, session_id, seq, payload)
        else:
            raise Exception("cannot parse packet, as it is too short:",len(data))    

    def encode(self):
        b=bytearray()
        b.append( (self.packet_version << 6) | (self.packet_type << 3) | self.packet_flags )
        b.extend(self.source)
        b.extend(self.destination)
        b.extend(self.session_id.to_bytes(1, byteorder='big'))
        b.extend(self.seq.to_bytes(2, byteorder='big'))
        b.extend(self.data)

        return bytes(b) 

    def get_ack_packet(self):
        return Packet(self.packet_type, 0x04, self.destination, self.source, self.session_id, self.seq, bytes())       

    def __str__(self):
        return "version:"+hex(self.packet_version)+"\n"+\
            "type:"+hex(self.packet_type)+"\n"+\
                "flags:"+hex(self.packet_flags)+"\n"\
                    +"session_id:"+hex(self.session_id)+"\n"\
                        +"seq:"+hex(self.seq)+"\n"\
                            +"source:"+print_hex(self.source)+"\n"\
                                +"destination:"+print_hex(self.destination)+"\n"\
                                    +"data:"+print_hex(self.data)+"\n"
        
class PacketCollection:

    session_id=0
    packet_type=0
    source=bytes()
    destination=bytes()
    data=bytes()

    #keepalive
    #route_update
    #requestFullRoutingTable
    #reponseFullRoutingTable
    #sendIdentity
    #groupMessage
    #userMessage
    #binaryMessage
    def __init__(self, packet_type, source, destination, session_id, data):
        self.session_id=session_id
        self.packet_type=packet_type
        self.source=source
        self.destination=destination
        self.data=data

    @classmethod
    def init_with_packets(self, packets):
        #assemble the packets into one message
        first_single=self.find_packet_with_flags(self,0x03,packets)
        first_packet=self.find_packet_with_flags(self,0x01,packets)
        last_packet=self.find_packet_with_flags(self,0x02,packets)
        if (first_single!=None):
            return PacketCollection(first_single.packet_type, first_single.source, first_single.destination, first_single.session_id, first_single.data)
        elif (first_packet!=None and last_packet!=None):
            #find if middle packets are there
            next_packet=first_packet
            total_seq=last_packet.seq
            cur_seq=next_packet.seq
            packetdata=bytearray()
            while (cur_seq<total_seq and next_packet!=None):
                #print("cur_seq:",cur_seq)
                #print("total_seq:",total_seq)
                cur_seq=next_packet.seq
                packetdata.extend(next_packet.data)
                next_packet=self.find_next_packet(self,cur_seq,packets)

            if (cur_seq==total_seq):
                #we have all the packets!
                return PacketCollection(first_packet.packet_type, first_packet.source, first_packet.destination, first_packet.session_id, bytes(packetdata))
            else: 
                raise Exception("not all packets are available!")
        else:
            raise Exception("not all packets are available!")
        

    def find_next_packet(self, seq, packets):
        #find packet with certain flags
        returnValue=None
        for packet in packets:
            if ((packet.packet_flags==0x00 or packet.packet_flags==0x02) and len(packet.data)+seq==packet.seq):
                returnValue=packet
                break
        return returnValue

    def find_packet_with_flags(self, flags, packets):
        #find packet with certain flags
        returnValue=None
        for packet in packets:
            if (packet.packet_flags==flags):
                returnValue=packet
                break
        return returnValue

    def split_packets(self, packet_type, source, destination, session_id, data):
        packets=[]

        #if debug==1:
        #    print("split_packets destination:"+str(destination))

        #check for length of data, split to data segments
        data_segments=[]
        packet_no=1                
            
        while (packet_no*payload_limit<len(data)):
            data_segments.append(data[(packet_no-1)*payload_limit:packet_no*payload_limit])
            packet_no+=1
            
        data_segments.append(data[(packet_no-1)*payload_limit:])

        #create the formatted object 
        seq=0
        for i,data_segment in enumerate(data_segments):
            flags=0
            if (len(data_segments)==1):
                flags=0x03
            elif (len(data_segments)>1 and i==0):
                flags=0x01
            elif (len(data_segments)>1 and i==(len(data_segments)-1)):
                flags=0x02
            else:
                flags=0x00

            seq+=len(data_segment)
            packets.append(Packet(packet_type, flags, source, destination, session_id, seq, data_segment))
        
        return packets    

    def get_packets(self):
        return self.split_packets(self.packet_type, self.source, self.destination, self.session_id, self.data)

    def get_collection(self):
        if (self.packet_type==0x00):
            return KeepaliveMessage(self.source, self.destination, self.session_id)
        if (self.packet_type==0x01):
            return RouteUpdateMessage(False, self.source, self.destination, self.session_id, self.data)
        if (self.packet_type==0x02):
            return RequestFullRouteUpdateMessage(self.source, self.destination, self.session_id)
        if (self.packet_type==0x03):
            return RouteUpdateMessage(True, self.source, self.destination, self.session_id, self.data)
        if (self.packet_type==0x04):
            return SendIdentityMessage(self.source, self.destination, self.session_id, self.data)
        #if (self.packet_type==0x05):
        #    return GroupMessage(self.source, self.destination, self.session_id, self.data)
        if (self.packet_type==0x06):
            return ScreenMessage(self.source, self.destination, self.session_id, self.data)
        if (self.packet_type==0x07):
            return BinaryMessage(self.source, self.destination, self.session_id, self.data)


class KeepaliveMessage (PacketCollection):

    def __init__(self, source, destination, session_id):
        super().__init__(0x00,source,destination,session_id,bytes())

class RouteUpdateMessage (PacketCollection):

    routes=[]

    def __init__(self, isFull, source, destination, session_id, route_data):

        if (type(route_data) is bytes):
            no_routes = len(route_data) % 10
            for i in range(no_routes):
                self.routes.append((route_data[i*10:i*10+8],int.from_bytes(route_data[i*10+8:i*10+10])))
            super().__init__((0x03 if isFull else 0x01),source,destination,session_id,route_data)
            
        elif (type(route_data) is list):
            #let's compile the data
            self.routes=route_data
            routedata=bytearray()
            for route in self.routes:
                routedata.append(route[0])
                routedata.append(route[1].to_bytes(2, byteorder='big'))
            super().__init__((0x03 if isFull else 0x01),source,destination,session_id,bytes(routedata))

        else:
            raise Exception("for route_update data should contain the routes [(destination cost)] or is bytes()")
        

class RequestFullRouteUpdateMessage (PacketCollection):

    def __init__(self, source, destination, session_id):
        super().__init__(0x02,source,destination,session_id,bytes())


class SendIdentityMessage (PacketCollection):

    nickname=""

    def __init__(self, source, destination, session_id, nickname_data):

        if (type(nickname_data) is str):
            self.nickname=nickname_data
            json_string="{\"ID\" : \""+print_hex(source)+"\", \"responseRequired\" : \"true\", \"name\" : \""+nickname_data+"\"}"
            super().__init__(0x04,source,destination,session_id,json_string.encode())
        elif (type(nickname_data) is bytes):
            json_string = nickname_data.decode("utf-8")
            if debug==1:
                print("parsing json:"+json_string)
            json_dict=json.loads(json_string)
            self.nickname=json_dict["name"]
            super().__init__(0x04,source,destination,session_id,nickname_data)
        else:
            raise Exception("nickname_data must be type string or bytes()")


class ScreenMessage (PacketCollection):
    message=""

    def __init__(self, source, destination, session_id, message_data):

        if (type(message_data) is str):
            self.message=message_data
            super().__init__(0x06,source,destination,session_id,message_data.encode())
        elif (type(message_data) is bytes):
            self.message = message_data.decode("utf-8")
            super().__init__(0x06,source,destination,session_id,message_data)
        else:
            raise Exception("message_data must be type string or bytes()")


class BinaryMessage (PacketCollection):

    def __init__(self, source, destination, session_id, message_data):

        if (type(message_data) is bytes):
            super().__init__(0x07,source,destination,session_id,message_data)
        else:
            raise Exception("data must be type bytes()")


class PacketManager:
    routing_manager=None
    #destination openSessions
    receive_sessions={}
    #destination session_id
    send_sessions={}
    nickname="default"
    longid=bytes()
    keepalive_stop=False
    keepalive_interval=10

    def __init__(self,routing_manager,longid,nickname):
        self.routing_manager=routing_manager 
        self.nickname=nickname
        self.longid=longid
        #start keepalive thread
        thread = threading.Thread(target=self.thread_function_send_keepalive)   
        thread.start()
        #thread.join()
    
    def add(self, packet):

        #session_id packetlist
        open_sessions={}
        if packet.destination in self.receive_sessions:
            open_sessions=self.receive_sessions[packet.destination]
        else:
            self.receive_sessions[packet.destination]=open_sessions
            
        packet_list=[]
        if packet.session_id in open_sessions:       
            packet_list = open_sessions[packet.session_id]
        else:
            open_sessions[packet.session_id]=packet_list

        #add packet to the list
        packet_list.append(packet)

        #verify if session is complete
        is_complete=False
        packet_collection=None
        try:
            packet_collection=PacketCollection.init_with_packets(packet_list).get_collection()
            is_complete=True
        except Exception as error:
            print(error)
            is_complete=False
            if (str(error)!="not all packets are available!"):
                raise error

        #check the completed packetcollection
        if is_complete==True:
            #print("Session complete")
            if type(packet_collection)==KeepaliveMessage:
                if debug==1:
                    print("KeepaliveMessage received from: "+print_hex(packet_collection.source))
                #self.routing_manager.send(KeepaliveMessage(None,\
                #    packet_collection.source,\
                #    self.get_send_session_id(packet_collection.source)))
            elif type(packet_collection)==RouteUpdateMessage:
                for route in packet_collection.routes:
                    print("route: "+print_hex(route[0])+" hops:"+str(route[1]))
                print("RouteUpdateMessage received from: "+print_hex(packet_collection.source)+\
                    " data:"+print_hex(packet_collection.data))
            elif type(packet_collection)==RequestFullRouteUpdateMessage:
                print("RequestFullRouteUpdateMessage received from: "+print_hex(packet_collection.source))             
                #dest hop  
                print("blah")
                message=RouteUpdateMessage(True, self.longid,\
                    packet_collection.source,\
                    self.get_send_session_id(packet_collection.source),\
                    self.routing_manager.get_routing_table())
                self.routing_manager.send(message.get_packets(),packet_collection.source)
                print("blah")
                print("RouteUpdateMessage sent to: "+print_hex(packet_collection.source)+" data:"+print_hex(message.data))  
            elif type(packet_collection)==SendIdentityMessage:
                print("SendIdentityMessage received from: "+print_hex(packet_collection.source)+\
                    " nickname:"+packet_collection.nickname)
            elif type(packet_collection)==ScreenMessage:
                print("ScreenMessage received from: "+print_hex(packet_collection.source)+\
                    " message: "+packet_collection.message)
            elif type(packet_collection)==BinaryMessage:
                print("BinaryMessage received from:"+print_hex(packet_collection.source)+\
                    "data:"+packet_collection.data)
        else:
            if debug==1:
                print("Session not complete")

    def get_send_session_id(self, destination):
        session_id=None
        if destination in self.send_sessions:
            session_id=self.send_sessions[destination]+1
        else:
            session_id=0
        self.send_sessions[destination] = session_id
        return session_id

    # hello
    # /nick hello
    def send_text(self, text):
        #text=input('Enter text: ')
        #nickname=input('Enter receiver nickname: ')
        
        if text[0] == "/":
            #check if nick available, (example: /bob Hey bob!)
            #separator is first space
            slashnick=text.split(" ", 1)
            nick=slashnick[0][1:]
            availableNick=False
            if availableNick == True:
                try:
                    #check if nickname exists (destination <> nickname connection)
                    #if yes, availableNick = True
                    test=1
                except ValueError:
                    print("This nickname is not available!") #print list of available nicknames?
        else:
            #send text to all destinations///group message?
            for destination in self.routing_manager.get_all_destinations():
                #compose packet
                m=ScreenMessage(self.longid, destination, self.get_send_session_id(destination), text)
                print("ScreenMessage sent to: "+print_hex(destination)+" text:"+text)
                #send
                routing_manager.send(m.get_packets(), destination)

        
    def request_routing_update(self, destination):       
        self.routing_manager.send(\
            RequestFullRouteUpdateMessage(\
                self.longid,\
                destination,\
                self.get_send_session_id(destination)).get_packets(),destination)
        print("RequestFullRouteUpdateMessage sent to: "+print_hex(destination))

    def request_send_identity(self,destination):
        self.routing_manager.send(\
            SendIdentityMessage(\
                self.longid,\
                destination,\
                self.get_send_session_id(destination),\
                self.nickname).get_packets(),destination)
        print("SendIdentityMessage sent to: "+print_hex(destination)+" nickname:"+self.nickname+" id:"+print_hex(self.longid))

    def thread_function_send_keepalive(self):
        while not self.keepalive_stop:
            list_destinations = self.routing_manager.get_neighbour_destinations()
            if debug==1:
                print("thread_function_send_keepalive destinations:",list_destinations)
            for destination in list_destinations:
                self.routing_manager.send(KeepaliveMessage(None, destination, self.get_send_session_id(destination)).get_packets(),destination)
                if debug==1:
                    print("KeepaliveMessage sent to: "+print_hex(destination))
            time.sleep(self.keepalive_interval) 

class Node(object):

    def __init__(self, node):
        self.node = node
        #self.node_id = id(self)
        self.list = []
        self.pre_node = None
        self.distance = sys.maxsize
  
        
class Edge(object):
    
    def __init__(self, weight, start, end):
        self.weight = weight
        self.start = start
        self.end = end
    
    
class Path(object):
    def path(self, node_list, edge_list, start):
        start.distance = 0
        for i in range(0, len(node_list) - 1):
            for x in edge_list:
                u = x.start
                v = x.end
                distance2 = u.distance + x.weight
                if distance2 < v.distance:
                    v.distance = distance2
                    v.preNode = u

    def getpath(self, target):
        n = target
        next_node = []
        while n is not None:
            next_node.append(n.node)
            n = n.pre_node
        forwared_to = next_node[len(next_node) - 2]
        return forward_to
  

class RoutingManager:
    
    send_receive = None
    packet_manager = None

    def __init__(self, send_receive, longid):
        
        self.send_receive = send_receive
        self.id = longid #pgp_id
        self.routingTable = []
        self.neighbors = []
        self.routingTable.append({'DESTINATIONID': self.id, 'NEXTHOPID': self.id, 'HOPCOUNT': 0})

    def set_packet_manager(self, packet_manager):
        self.packet_manager = packet_manager

    def add(self, packet):
        #do something with packet
        #print("parsing:",packet)
        nodeid=packet.destination
        hops=1
        #self.neighbors.append({'DESTINATIONID': nodeid, 'Weight': hops})
        if nodeid not in [r['DESTINATIONID'] for r in self.routingTable]:
            self.routingTable.append({'DESTINATIONID': nodeid, 'NEXTHOPID': nodeid, 'HOPCOUNT': 1})
        else:
            for my_row in self.routingTable:
                if my_row['DESTINATIONID'] == nodeid:
                    my_row['HOPCOUNT'] = 1
                    my_row['NEXTHOPID'] = nodeid
        if packet.destination == self.id:
            self.packet_manager.add(packet)
        else:
            destinationlist = [n['DESTINATIONID'] for n in self.routingTable]
            nextlist = [n['NEXTHOPID'] for n in self.routingTable]
            nodes = list(dict.fromkeys(destinationlist + nextlist))
            listofNodes = []
            for i in nodes:
                x = Node(i)
                listofNodes.append(x)
            listofEdges = []
            for row in self.routingTable:
                for i in listofNodes:
                    if row['DESTINATIONID'] == i.node:
                        for j in listofNodes:
                            if row['NEXTHOPID'] == j.node:
                                y = Edge(row['HOPCOUNT'], i, j)
                                listofEdges.append(y)
            p = Path()
            p.path(listofNodes, listofEdges, listofNodes[0])
            for i in listofNodes:
                if i.node == nodeid:
                    targetNode = i
            nextHopNodeId = p.getpath(targetNode)
            port = get_neighbour_for_destination(nextHopNodeId)
            #find next hop for packet.destination
            #find the host_port for next hop
            host_port : packet.destination in self.neighbors
            self.send_receive.send(packet, port)
                    
    def updateRoutingTable(self, packet):
        
        routingTableReceived = json.loads(packet.data)
        for row in routingTableReceived:
            if row['DESTINATIONID'] not in [r['DESTINATIONID'] for r in self.routingTable]:
                if row['NEXTHOPID'] != self.id:
                    self.routingTable.append(
                        {'DESTINATIONID': row['DESTINATIONID'], 'NEXTHOPID': packet.id, 'HOPCOUNT': row['HOPCOUNT'] + 1})
            else:
                for my_row in self.routingTable:
                    if my_row['DESTINATIONID'] == row['DESTINATIONID']:
                        if row['HOPCOUNT'] + 1 < my_row['HOPCOUNT']:
                            my_row['HOPCOUNT'] = row['HOPCOUNT'] + 1
                            my_row['NEXTHOPID'] = packet.id
        for row in self.routingTable:
            if row['DESTINATIONID'] not in [r['DESTINATIONID'] for r in routingTableReceived]:
                if row['NEXTHOPID'] == packet.id:
                    self.routingTable.remove(row)

    def add_neighbour(self,host_port, longid):
        self.neighbors.append({'DESTINATIONID': longid, 'Weight': 1, 'HOST_PORT': host_port})
        self.packet_manager.request_routing_update(longid) 
        self.packet_manager.request_send_identity(longid)

    def get_all_destinations(self):
        return [n['DESTINATIONID'] for n in self.neighbors]

    def get_neighbour_for_destination(self, destination):
        neighbours=[n['HOST_PORT'] for n in self.neighbors if n['DESTINATIONID']==destination]

        if (len(neighbours)>0):
            return neighbours[0]
        else:
            return None

    def get_neighbour_destinations(self):
        destinations=[]
        for row in self.neighbors:
            destinations.append(row['DESTINATIONID'])
        return destinations

    def send(self, packet, destination):
        #print("sending packet:"+str(packet)+" to destination:"+print_hex(destination))
        self.send_receive.send(packet,self.get_neighbour_for_destination(destination))

    def remove_neighbour(self,nodeid):
        for row in self.neighbors:
            if row['DESTINATIONID'] == nodeid:
                self.neighbors.remove(row)
        for row in self.routingTable:
            if (row['DESTINATIONID'] == nodeid and row['NEXTHOPID'] == self.id) \
                    or (row['DESTINATIONID'] == self.id and row['NEXTHOPID'] == nodeid):
                self.routingTable.remove(row)

    def get_routing_table(self):
        return_table=list()
        for n in self.routingTable:
            destination=n['DESTINATIONID']
            hopcount=n['HOPCOUNT']
            return_table.append((destination,hopcount))
        return return_table

class Keyboard(threading.Thread):

    send_receive=None
    stop_keyboard=False

    def __init__(self,send_receive):
        threading.Thread.__init__(self)
        self.send_receive=send_receive

    def run(self):
        global debug
        while not self.stop_keyboard:
            print("Type /help for a list of commands")
            kbd_input = input("> ")
            if (kbd_input == "/debugon"):
                debug=1
                #print("debug:",debug)
            if (kbd_input == "/debugoff"):
                debug=0
                #print("debug:",debug)
            if (kbd_input == "/exit"):
                break
            if (kbd_input == "/help"):
                print ("/exit - exits the messaging client")
                print ("/help - this help message")
                print ("/list - list all destinations, with nicknames")
                print ("/debugon - turn debugging on")
                print ("/debugoff - turn debugging off")
                print ("<message> - send message to all destinations")
                print ("/<nick> <message> - send message to <nick, for example /joe Hello!")
            if (kbd_input != ""):
                self.send_receive.keyboard(kbd_input)
        self.send_receive.exit()

    def exit(self):
        self.stop_keyboard=True

class SendAndReceive:

    #ack interval is 5 seconds
    resend_interval=5000 
    keepalive_max_interval=40000
    host_port=("localhost", 5000)
    long_id=bytes().fromhex("0101010102020202")
    nickname="joe"
    send_buffer=[]
    kbd_buffer=[]
    #dictionary (destination, session_id, seq) = (packet, timestamp)
    ack_buffer={}
    #dictionary destination = timestap
    keepalive_buffer={}
    do_exit=False

    def __init__(self, host_port, long_id, nickname):
        self.host_port=host_port
        self.long_id=long_id
        self.nickname=nickname

    def set_routing_manager(self,routing_manager):
        self.routing_manager=routing_manager

    def set_packet_manager(self,packet_manager):
        self.packet_manager=packet_manager        

    #packet is of type Packet
    #neighbour is tuple (host port)
    def send (self, packet, neighbour):
        if (type(packet)==list):
            for single in packet:
                self.send_buffer.append((single, neighbour))
        else:
            self.send_buffer.append((packet, neighbour))

    def keyboard(self, kbd_input):
        self.kbd_buffer.append(kbd_input)

    def exit(self):
        print ("Exiting, please wait up to ",str(self.packet_manager.keepalive_interval)+"s")
        self.do_exit=True
        self.packet_manager.keepalive_stop=True

    def start(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(self.host_port)
        #sock.listen(10)

        while not self.do_exit:
            time.sleep(.1)
            #check for keyboard input
            while (len(self.kbd_buffer)>0):
                kbd_input = self.kbd_buffer.pop(0)
                self.packet_manager.send_text(kbd_input)
                #print("Keyboard input:",kbd_input)

            #check for packets for resend
            timestamp=int(round(time.time() * 1000))

            #resend the packets that have not been acked in self.resend_interval
            resend_infos=[self.ack_buffer[packet_info] \
                for packet_info in self.ack_buffer \
                if (timestamp - self.ack_buffer[packet_info][1]) > self.resend_interval ]
            for resend_info in resend_infos:
                if debug==1:
                    print("resending packet to destination:"+print_hex(resend_info[0].destination)+\
                        " diff:"+str(timestamp - resend_info[1]))
                self.routing_manager.send(resend_info[0],resend_info[0].destination)
            
            #drop connection, if keepalive is not acked in resend_max_interval
            drop_destinations=[destination \
                for destination in self.keepalive_buffer \
                if (timestamp - self.keepalive_buffer[destination]) > self.keepalive_max_interval]
            for drop_destination in drop_destinations:
                print("dropping neighbour destination:"+print_hex(drop_destination))
                del self.keepalive_buffer[drop_destination]
                self.routing_manager.remove_neighbour(drop_destination)
                #remove all packets drom ack buffer for destination
                #remove_packets = [packet_info \
                #    for packet_info in self.ack_buffer \
                #    if packet_info[0] == drop_destination]
                #for remove_packet in remove_packets:
                #    del self.ack_buffer[remove_packet]

            connections = [sock]
            recv,write,err = select.select(connections,connections,connections)

            for s in recv:
                try:
                    msg = s.recv(4096)
                    #print("Recieved data:",print_hex(msg))
                    packet = Packet.init_with_data(msg)
                    if debug==1:
                        print("Recieved packet:",packet)
                    #see if this is ack packet
                    if (packet.packet_flags==0x04):
                        #see if it is an keepalive ack, remove antry from keepalive buffer for destination
                        if (packet.packet_type==0x00):
                            del self.keepalive_buffer[packet.source]
                        else:
                            #this normal is ack packet, lets see if this packet is in ack_buffer and remove
                            if (packet.source, packet.session_id, packet.seq) in self.ack_buffer:
                                del self.ack_buffer[(packet.source, packet.session_id, packet.seq)]
                    else:
                        #ack sent packet
                        self.routing_manager.send(packet.get_ack_packet(),packet.source)
                        #add to routing manager for processing
                        routing_manager.add(packet)
                except Exception as error:
                    if debug==1:
                        print("Error recv:",error)
                        if (debug==1 and str(error)=="can only concatenate str (not \"list\") to str"):
                            raise error
                        elif (debug==1 and str(error)=="list index out of range"):
                            raise error

            for s in write:
                while (len(self.send_buffer)>0):
                    (packet, neighbour) = self.send_buffer.pop(0)
                    if (packet.source==None):
                        packet.source=self.long_id
                    if debug==1:
                        print("Sending packet:",packet,"to:",neighbour)

                    #add packet with timestamp to ack buffer (so that if ack is not received, packet is resent)
                    #we do not add ack packets to ack buffer, add keepalive to keepalive buffer
                    if packet.packet_flags!=0x04:
                        if (packet.packet_type==0x00):
                            if packet.destination not in self.keepalive_buffer:
                                self.keepalive_buffer[packet.destination]=int(round(time.time() * 1000))
                        else:
                            self.ack_buffer[(packet.destination, packet.session_id, packet.seq)] = \
                                (packet, int(round(time.time() * 1000)))

                    #send the packet
                    try:
                        if (neighbour!=None):
                            sent = s.sendto(packet.encode(), neighbour)
                        else:
                            print("No route to:"+print_hex(packet.destination))
                        #print("Sent bytes:",sent,"to",neighbour)
                    except Exception as error:
                        if debug==1:
                            print("Error send:",error)
            for s in err:
                print("Error with a socket")
                s.close()
                connections.remove(s)


def help():
    print ("Syntax:")
    print ("",sys.argv[0]," <host> <port> <longid> <nickname> [ <neighbour host> <neighbour port> <neighbour longid> ]... ")
    print ("Example")
    print ("",sys.argv[0]," localhost 5005 0101010102020202 jimmy")

print ("length:",str(len(sys.argv)))
print ("argv:",sys.argv)

def print_hex(data_bytes):
    
    msg=""
    if (type(data_bytes)==bytes and len(data_bytes)>0):
        msg=''.join(['{:02x}'.format(b) for b in data_bytes])
    elif len(data_bytes)>0:
        print("Wrong type for print_hex:"+str(type(data_bytes)))

    return msg 

#neighbor can be set only on command line
if (len(sys.argv)>=5):

    if (len(bytes().fromhex(sys.argv[3]))==8):
        send_receive=SendAndReceive((sys.argv[1], int(sys.argv[2])), bytes().fromhex(sys.argv[3]), sys.argv[4])
        routing_manager=RoutingManager(send_receive, bytes().fromhex(sys.argv[3]))
        packet_manager=PacketManager(routing_manager, bytes().fromhex(sys.argv[3]), sys.argv[4])
        routing_manager.set_packet_manager(packet_manager)
        send_receive.set_routing_manager(routing_manager)
        send_receive.set_packet_manager(packet_manager)
        keyboard = Keyboard(send_receive)
        keyboard.daemon = True

        try:

            if (len(sys.argv)>=8 and len(sys.argv) % 3 == 2):
                for i in range(5,len(sys.argv),3):
                    print("adding neighbour host:"+sys.argv[i]+" port:"+sys.argv[i+1]+" longid:"+sys.argv[i+2])
                    if (len(bytes().fromhex(sys.argv[i+2]))==8):
                        routing_manager.add_neighbour((sys.argv[i], int(sys.argv[i+1])),bytes().fromhex(sys.argv[i+2]))
                    else:
                        print("longid must be 8 bytes:"+sys.argv[i+2])

            keyboard.start()

            send_receive.start()

        except Exception as error:
            send_receive.exit()
            keyboard.exit()
            raise error


    else:
        print("longid must be 8 bytes:"+sys.argv[3])

else:
    help()
