import sys
import socket
import select
import time
import json

packet_header_length=20
packet_limit=100
payload_limit=packet_limit-packet_header_length

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
        if (len(data)>=packet_header_length):
            first_byte = int.from_bytes(data[0:1])
            self.packet_version = ((first_byte & 0xC0) >> 6)
            self.packet_type = ((first_byte & 0x38) >> 3)
            self.packet_flags = first_byte & 0x07
            self.session_id = int.from_bytes(data[17:18])
            self.seq = int.from_bytes(data[18:20])
            self.source = int.from_bytes(data[1:9])
            self.destination = int.from_bytes(data[9:17])
            length = int.from_bytes(data[9:10])
            self.data = data[20:]
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
    #screenMessage
    #screenMessageEcho
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
            self.session_id=first_single.session_id
            self.packet_type=first_single.packet_type
            self.source=first_single.source
            self.destination=first_single.destination
            self.data=first_single.data
        elif (first_packet!=None and last_packet!=None):
            #find if middle packets are there
            next_packet=first_packet
            total_seq=last_packet.seq
            cur_seq=next_packet.seq
            packetdata=bytearray()
            while (cur_seq<total_seq and next_packet!=None):
                packetdata.append(next_packet.data)
                next_packet=self.find_next_packet(self,cur_seq,packets)
                cur_seq=next_packet.seq
            if (cur_seq==total_seq):
                #we have all the packets!
                self.session_id=first_packet.session_id
                self.packet_type=first_packet.packet_type
                self.source=first_packet.source
                self.destination=first_packet.destination
                self.data=bytes(packetdata)
            else: 
                raise Exception("not all packets are available!")
        else:
            raise Exception("not all packets are available!")

    def find_next_packet(self, seq, packets):
        #find packet with certain flags
        returnValue=None
        for packet in packets:
            if (packet.packet_flags==0x00 and len(packet.data)+seq==packet.seq):
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
                self.routes.append(route_data[i*10:i*10+8],(int.from_bytes(route_data[i*10+8:i*10+10])))
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
            super().__init__(0x04,source,destination,session_id,
            "{ID:\""+source.hex()+"\", responseRequired=false, name:\""+self.nickname+"\"".encode())
        elif (type(nickname_data) is bytes):
            json_string = nickname_data.decode("utf-8")
            self.nickname = json.loads(json_string)["name"]
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

    def __init__(self,routing_manager):
        self.routing_manager=routing_manager


class RoutingManager:
    send_receive=None
    packet_manager=None

    def __init__(self,send_receive):
        self.send_receive=send_receive

    def set_packet_manager(self,packet_manager):
        self.packet_manager=packet_manager

    def add(self,packet):
        #do something with packet
        test=1

class SendAndReceive:

    host_port=("localhost", 5000)
    longId=bytes().fromhex("0101010102020202")
    nickname="joe"
    send_buffer=[]

    def __init__(self, host_port, longId, nickname):
        self.host_port=host_port
        self.longId=longId
        self.nickname=nickname

    def set_routing_manager(self,routing_manager):
        self.routing_manager=routing_manager

    #packet is of type Packet
    #neighbour is tuple (host port)
    def send (self,packet, neighbour):
        if (type(packet)==list):
            for single in packet:
                self.send_buffer.append((single, neighbour))
        else:
            self.send_buffer.append((packet, neighbour))

    def start(self):

        sock = socket.socket(socket.AF_INET, # Internet 
            socket.SOCK_DGRAM) # UDP
        sock.bind(self.host_port)
        sock.listen(10)

        connections = [sock]

        while True:
            time.sleep(.1)
            recv,write,err = select.select(connections,connections,connections)

            for socket in recv:
                msg = socket.recv(4096).decode("UTF-8")
                print("Recieved message from a socket, message was: "+msg.hex())
                routing_manager.add(Packet.init_with_data(msg))

            for socket in write:
                while (len(self.send_buffer)>0):
                    (packet, neighbour) = self.send_buffer.pop(0)
                    socket.sendto(packet.encode(), neighbour)

            for socket in err:
                print("Error with a socket")
                socket.close()
                connections.remove(socket)

def help():
    print ("Syntax:")
    print ("",sys.argv[0]," <host> <port> <longid> <nickname>")
    print ("Example")
    print ("",sys.argv[0]," localhost 5005 0101010102020202 jimmy")

print ("length:",str(len(sys.argv)))
print ("argv:",sys.argv)

if (len(sys.argv)==5):

    send_receive=SendAndReceive((sys.argv[1], sys.argv[2]), bytes().fromhex(sys.argv[3]), sys.argv[4])
    routing_manager=RoutingManager(send_receive)
    packet_manager=PacketManager(routing_manager)
    routing_manager.set_packet_manager(packet_manager)
    send_receive.set_routing_manager(routing_manager)
    send_receive.start()

else:
    help()
