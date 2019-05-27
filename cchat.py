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
import traceback
import random

packet_header_length = 20
packet_limit = 100
payload_limit = packet_limit - packet_header_length
debug = 0

#main packet class, can convert data to packet and vice versa
class Packet:
    packet_version = 0
    packet_type = 0
    packet_flags = 0
    session_id = 0
    seq = 0
    source = bytes()
    destination = bytes()
    data = bytes()

    # packet_type is byte
    # seq,total int
    # data bytes
    def __init__(self, packet_type, packet_flags, source, destination, session_id, seq, data):
        self.packet_type = packet_type
        self.packet_flags = packet_flags
        self.session_id = session_id
        self.seq = seq
        self.source = source
        self.destination = destination
        self.data = data

    # init packet fields with data (bytes)
    @classmethod
    def init_with_data(self, data):
        # parse the data
        # print("packet length:",len(data))
        if (len(data) >= packet_header_length):
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
            return Packet(packet_type, packet_flags, source, destination, session_id, seq, payload)
        else:
            raise Exception("cannot parse packet, as it is too short:", len(data))

    #encode packet fields to data
    def encode(self):
        b = bytearray()
        b.append((self.packet_version << 6) | (self.packet_type << 3) | self.packet_flags)
        b.extend(self.source)
        b.extend(self.destination)
        b.extend(self.session_id.to_bytes(1, byteorder='big'))
        b.extend(self.seq.to_bytes(2, byteorder='big'))
        b.extend(self.data)

        return bytes(b)

    #get ack packet out of standard packet
    def get_ack_packet(self):
        return Packet(self.packet_type, 0x04, self.destination, self.source, self.session_id, self.seq, bytes())

    #string representation
    def __str__(self):
        return "version:" + hex(self.packet_version) + "\n" + \
               "type:" + hex(self.packet_type) + "\n" + \
               "flags:" + hex(self.packet_flags) + "\n" \
               + "session_id:" + hex(self.session_id) + "\n" \
               + "seq:" + hex(self.seq) + "\n" \
               + "source:" + print_hex(self.source) + "\n" \
               + "destination:" + print_hex(self.destination) + "\n" \
               + "data:" + print_hex(self.data) + "\n"


#PacketCollection is a group of packets that represent a single message (like ScreenMessage)
#there are methods to get a list of packets and also to get a certain message (like ScreenMessage) 
#from list of packets
class PacketCollection:
    session_id = 0
    packet_type = 0
    source = bytes()
    destination = bytes()
    data = bytes()

    def __init__(self, packet_type, source, destination, session_id, data):
        self.session_id = session_id
        self.packet_type = packet_type
        self.source = source
        self.destination = destination
        self.data = data

    #init with packet list
    @classmethod
    def init_with_packets(self, packets):
        # assemble the packets into one message
        first_single = self.find_packet_with_flags(self, 0x03, packets)
        first_packet = self.find_packet_with_flags(self, 0x01, packets)
        last_packet = self.find_packet_with_flags(self, 0x02, packets)
        if (first_single != None):
            return PacketCollection(first_single.packet_type, first_single.source, first_single.destination,
                                    first_single.session_id, first_single.data)
        elif (first_packet != None and last_packet != None):
            # find if middle packets are there
            next_packet = first_packet
            total_seq = last_packet.seq
            cur_seq = next_packet.seq
            packetdata = bytearray()
            while (cur_seq < total_seq and next_packet != None):
                # print("cur_seq:",cur_seq)
                # print("total_seq:",total_seq)
                cur_seq = next_packet.seq
                packetdata.extend(next_packet.data)
                next_packet = self.find_next_packet(self, cur_seq, packets)

            if (cur_seq == total_seq):
                # we have all the packets!
                return PacketCollection(first_packet.packet_type, first_packet.source, first_packet.destination,
                                        first_packet.session_id, bytes(packetdata))
            else:
                raise Exception("not all packets are available!")
        else:
            raise Exception("not all packets are available!")

    def find_next_packet(self, seq, packets):
        # find packet with certain flags
        returnValue = None
        for packet in packets:
            if ((packet.packet_flags == 0x00 or packet.packet_flags == 0x02) and len(packet.data) + seq == packet.seq):
                returnValue = packet
                break
        return returnValue

    def find_packet_with_flags(self, flags, packets):
        # find packet with certain flags
        returnValue = None
        for packet in packets:
            if (packet.packet_flags == flags):
                returnValue = packet
                break
        return returnValue

    #generate a list of packets, based on data. The data can be longer so it will automatically
    #get certain number of packets
    def split_packets(self, packet_type, source, destination, session_id, data):
        packets = []

        # check for length of data, split to data segments
        data_segments = []
        packet_no = 1

        while (packet_no * payload_limit < len(data)):
            data_segments.append(data[(packet_no - 1) * payload_limit:packet_no * payload_limit])
            packet_no += 1

        data_segments.append(data[(packet_no - 1) * payload_limit:])

        # create the formatted object
        seq = 0
        for i, data_segment in enumerate(data_segments):
            flags = 0
            if (len(data_segments) == 1):
                flags = 0x03
            elif (len(data_segments) > 1 and i == 0):
                flags = 0x01
            elif (len(data_segments) > 1 and i == (len(data_segments) - 1)):
                flags = 0x02
            else:
                flags = 0x00

            seq += len(data_segment)
            packets.append(Packet(packet_type, flags, source, destination, session_id, seq, data_segment))

        return packets

    #get a list of packets
    def get_packets(self):
        return self.split_packets(self.packet_type, self.source, self.destination, self.session_id, self.data)

    #get a certain message
    def get_collection(self):
        if (self.packet_type == 0x00):
            return KeepaliveMessage(self.source, self.destination, self.session_id)
        if (self.packet_type == 0x01):
            return RouteUpdateMessage(False, self.source, self.destination, self.session_id, self.data)
        if (self.packet_type == 0x02):
            return RequestFullRouteUpdateMessage(self.source, self.destination, self.session_id)
        if (self.packet_type == 0x03):
            return RouteUpdateMessage(True, self.source, self.destination, self.session_id, self.data)
        if (self.packet_type == 0x04):
            return SendIdentityMessage(self.source, self.destination, self.session_id, self.data)
        # if (self.packet_type==0x05):
        #    return GroupMessage(self.source, self.destination, self.session_id, self.data)
        if (self.packet_type == 0x06):
            return ScreenMessage(self.source, self.destination, self.session_id, self.data)
        if (self.packet_type == 0x07):
            return BinaryMessage(self.source, self.destination, self.session_id, self.data)

class KeepaliveMessage(PacketCollection):

    def __init__(self, source, destination, session_id):
        super().__init__(0x00, source, destination, session_id, bytes())


class RouteUpdateMessage(PacketCollection):
    routes = []

    def __init__(self, isFull, source, destination, session_id, route_data):

        if (type(route_data) is bytes):
            no_routes = len(route_data) % 10
            for i in range(no_routes):
                self.routes.append((route_data[i * 10:i * 10 + 8], int.from_bytes(route_data[i * 10 + 8:i * 10 + 10])))
            super().__init__((0x03 if isFull else 0x01), source, destination, session_id, route_data)

        elif (type(route_data) is list):
            # let's compile the data
            self.routes = route_data
            routedata = bytearray()
            for route in self.routes:
                routedata.extend(route[0])
                routedata.extend(route[1].to_bytes(2, byteorder='big'))
            super().__init__((0x03 if isFull else 0x01), source, destination, session_id, bytes(routedata))

        else:
            raise Exception("for route_update data should contain the routes [(destination cost)] or is bytes()")


class RequestFullRouteUpdateMessage(PacketCollection):

    def __init__(self, source, destination, session_id):
        super().__init__(0x02, source, destination, session_id, bytes())


class SendIdentityMessage(PacketCollection):
    nickname = ""

    def __init__(self, source, destination, session_id, nickname_data):

        # print("SendIdentityMessage: source:"+print_hex(source)+" destination:"+print_hex(destination)+" nickname data:"+print_hex(nickname_data))

        if (type(nickname_data) is str):
            self.nickname = nickname_data
            json_string = "{\"ID\" : \"" + print_hex(
                source) + "\", \"responseRequired\" : \"true\", \"name\" : \"" + nickname_data + "\"}"
            super().__init__(0x04, source, destination, session_id, json_string.encode())
        elif (type(nickname_data) is bytes):
            json_string = nickname_data.decode("utf-8")
            if debug == 1:
                print("parsing json:" + json_string)
            json_dict = json.loads(json_string)
            self.nickname = json_dict["name"]
            super().__init__(0x04, source, destination, session_id, nickname_data)
        else:
            raise Exception("nickname_data must be type string or bytes()")


class ScreenMessage(PacketCollection):
    message = ""

    def __init__(self, source, destination, session_id, message_data):

        if (type(message_data) is str):
            self.message = message_data
            super().__init__(0x06, source, destination, session_id, message_data.encode())
        elif (type(message_data) is bytes):
            self.message = message_data.decode("utf-8")
            super().__init__(0x06, source, destination, session_id, message_data)
        else:
            raise Exception("message_data must be type string or bytes()")


class BinaryMessage(PacketCollection):

    def __init__(self, source, destination, session_id, message_data):

        if (type(message_data) is bytes):
            super().__init__(0x07, source, destination, session_id, message_data)
        else:
            raise Exception("data must be type bytes()")

#packet manager handles the main logic of the program, i.e what to do with incoming messages
#it also handles the session_id for different destinations.
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
    destlist=set()

    def __init__(self,routing_manager,longid,nickname):
        self.routing_manager=routing_manager 
        self.nickname=nickname
        self.longid=longid
        #start keepalive thread
        thread = threading.Thread(target=self.thread_function_send_keepalive)   
        thread.start()
        # thread.join()

    #incoming packets are sent here
    def add(self, packet):

        # session_id packetlist
        open_sessions = {}
        if packet.destination in self.receive_sessions:
            open_sessions = self.receive_sessions[packet.destination]
        else:
            self.receive_sessions[packet.destination] = open_sessions

        packet_list = []
        if packet.session_id in open_sessions:
            packet_list = open_sessions[packet.session_id]
        else:
            open_sessions[packet.session_id] = packet_list

        # add packet to the list
        packet_list.append(packet)

        # verify if session is complete
        is_complete = False
        packet_collection = None
        try:
            packet_collection = PacketCollection.init_with_packets(packet_list).get_collection()
            is_complete = True
            del open_sessions[packet.session_id]

        except Exception as error:
            print(error)
            is_complete = False
            if (str(error) != "not all packets are available!"):
                raise error

        # check the completed packetcollection
        #have a logic, based on incoming message type
        if is_complete == True:
            # print("Session complete")
            if type(packet_collection) == KeepaliveMessage:
                if debug == 1:
                    print("KeepaliveMessage received from: " + print_hex(packet_collection.source))
                # self.routing_manager.send(KeepaliveMessage(None,\
                #    packet_collection.source,\
                #    self.get_send_session_id(packet_collection.source)))
            elif type(packet_collection) == RouteUpdateMessage:
                for route in packet_collection.routes:
                    print("route: " + print_hex(route[0]) + " hops:" + str(route[1]))
                print("RouteUpdateMessage received from: " + print_hex(packet_collection.source) + \
                      " data:" + print_hex(packet_collection.data))
                # make the table compatible and compare to our version
                no_routes = len(packet_collection.data) // 10
                routing_table = []
                for i in range(no_routes):
                    routing_table.append({"DESTINATIONID": packet_collection.data[i * 10:i * 10 + 8], \
                                          "NEXTHOPID": packet_collection.source, \
                                          "HOPCOUNT": int.from_bytes(packet_collection.data[i * 10 + 8:i * 10 + 10],\
                                              byteorder='big')})
                if len(routing_table)>0:
                    #compare routing tables
                    self.routing_manager.compare_tables(routing_table)
                else:
                    #if route update message is empty, remove all routes via source
                    self.routing_manager.remove_node(packet_collection.source)

            elif type(packet_collection) == RequestFullRouteUpdateMessage:
                print("RequestFullRouteUpdateMessage received from: " + print_hex(packet_collection.source))
                # dest hop
                self.request_send_routing_update(True, \
                    packet_collection.source, \
                        self.routing_manager.get_routing_table())
            elif type(packet_collection) == SendIdentityMessage:
                print("SendIdentityMessage received from: " + print_hex(packet_collection.source) + \
                      " nickname:" + packet_collection.nickname)
                self.destlist.add((packet_collection.source, packet_collection.nickname))
                if debug == 1:
                    print("Source and Nickname added to /list")
            elif type(packet_collection) == ScreenMessage:
                print("ScreenMessage received from: " + print_hex(packet_collection.source) + \
                      " message: " + packet_collection.message)
            elif type(packet_collection) == BinaryMessage:
                print("BinaryMessage received from:" + print_hex(packet_collection.source) + \
                      "data:" + packet_collection.data)
        else:
            if debug == 1:
                print("Session not complete")

    #print all the destinations with nicknames
    def print_destlist(self):
        #check if destination list in routing manager has been updated.
        list_destinations=self.routing_manager.get_all_destinations()
        newlist=set()
        for pair in self.destlist:
            for destination in list_destinations:
                if pair[0] == destination:
                    newlist.add(pair)
        self.destlist=newlist
        #print the list
        print("Destination Nickname")
        for row in self.destlist:
            print(print_hex(row[0]),row[1])
            #print("{: >20} {: >20}".format(*row))
    
    #get session id for a particular destination
    def get_send_session_id(self, destination):
        session_id = None
        if destination in self.send_sessions:
            session_id = self.send_sessions[destination] + 1
            if session_id == 256:
                session_id = 0
        else:
            session_id = 0
        self.send_sessions[destination] = session_id
        return session_id

    #send a text message, as input from keyboard
    def send_text(self, text):
        if text == "/list":
                self.print_destlist()
        elif text[0] == "/" and text not in ('/help','/debugon','/debugoff','/exit'):
            #separator for nickname is first space
            givenNick=(text.split(" ", 1))[0][1:]
            destination=None
            availableNick=False
            #check if nickname is available in destlist
            for pair in self.destlist:
                testNick = pair[1]
                if testNick == givenNick:
                    availableNick = True
                    destination = pair[0] 
            if availableNick == False:
                print(givenNick + " is not available! Use /list for available nicknames")
            else:
                # compose packet
                m = ScreenMessage(self.longid, destination, self.get_send_session_id(destination), text)
                print("ScreenMessage sent to: " + givenNick + " destination: " + print_hex(
                    destination) + " text: " + text[(len(givenNick) + 2):])
                # send
                routing_manager.send(m.get_packets(), destination)
        else:
            # send text to all destinations
            for destination in self.routing_manager.get_all_destinations():
                m = ScreenMessage(self.longid, destination, self.get_send_session_id(destination), text)
                print("ScreenMessage sent to: " + print_hex(destination) + " text:" + text)
                routing_manager.send(m.get_packets(), destination)

    #send a RouteUpdateMessage
    def request_send_routing_update(self, isFull, destination, routes):
        message = RouteUpdateMessage(isFull, self.longid, \
                                destination, \
                                self.get_send_session_id(destination), \
                                routes)
        self.routing_manager.send(message.get_packets(), destination)
        print("RouteUpdateMessage sent to: " + print_hex(destination) + " data:" + print_hex(
            message.data))

    #send a RequestFullRoutingUpdateMessage
    def request_send_fullrouting_update(self, destination):
        self.routing_manager.send( \
            RequestFullRouteUpdateMessage( \
                self.longid, \
                destination, \
                self.get_send_session_id(destination)).get_packets(), destination)
        print("RequestFullRouteUpdateMessage sent to: " + print_hex(destination))

    #send identity message
    def request_send_identity(self, destination):
        self.routing_manager.send( \
            SendIdentityMessage( \
                self.longid, \
                destination, \
                self.get_send_session_id(destination), \
                self.nickname).get_packets(), destination)
        print("SendIdentityMessage sent to: " + print_hex(
            destination) + " nickname:" + self.nickname + " id:" + print_hex(self.longid))

    #this thread function is executed periodically by a thread to generate keepalive messages
    #with neighbours
    def thread_function_send_keepalive(self):
        while not self.keepalive_stop:
            list_destinations = self.routing_manager.get_neighbour_destinations()
            if debug == 1:
                print("thread_function_send_keepalive destinations:", list_destinations)
            for destination in list_destinations:
                self.routing_manager.send(
                    KeepaliveMessage(None, destination, self.get_send_session_id(destination)).get_packets(),
                    destination)
                if debug == 1:
                    print("KeepaliveMessage sent to: " + print_hex(destination))
            time.sleep(self.keepalive_interval)

# class Node,
# Each node in the network will be initialized and added to a list of nodes
# Later it will be used to find the best forwarding table
class Node(object):

    def __init__(self, node): # Node class constructor
        self.node = node # node name(id)
        self.list = []
        self.pre_node = None # if the node is connected to a previous node
        self.distance = sys.maxsize # distance is set to max according to Bellman-Ford algorithm


# Class Edge,
# Each node is connected to at least one other node,
# class edge connect these nodes together and put them in a list
# it will be used in Bellman-ford to find the path
class Edge(object):

    def __init__(self, weight, start, end):
        self.weight = weight # hop-count weight
        self.start = start # starting node
        self.end = end # destination node

# Class Path,
# this class connect and find the path to all nodes
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
                    v.pre_node = u

    # This is the Bellman-Ford function that the program can send the destination and it returns the forwarding table
    def getpath(self, target):
        n = target
        next_node = []
        while n is not None:
            next_node.append(n.node)
            n = n.pre_node
        forward_to = next_node[len(next_node) - 2]
        return forward_to

# Class Routing Manager,
# This class manages the routing table, neighbors tables
class RoutingManager:
    send_receive = None
    packet_manager = None
    forwarding_table = {}
    distance_table={}

    def __init__(self, send_receive, longid):

        self.send_receive = send_receive
        self.id = longid  # pgp_id of my node
        self.routingTable = [] # initializing routingTable
        self.neighbors = [] # initializing neighbors table
        self.routingTable.append({'DESTINATIONID': self.id, 'NEXTHOPID': self.id, 'HOPCOUNT': 0}) # adding my node to the routing table with hop count 0
        #generate new forwarding table after route update
        self.bellman_ford()

    def set_packet_manager(self, packet_manager):
        self.packet_manager = packet_manager

    #generate forwarding and distance table
    def bellman_ford(self):
        #print("routingTable:",self.routingTable)
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
                            y = Edge(row['HOPCOUNT'], j, i)
                            listofEdges.append(y)

        p = Path()
        p.path(listofNodes, listofEdges, listofNodes[0])
        self.forwarding_table={}
        self.distance_table={}
        for i in listofNodes:
            self.forwarding_table[i.node] = p.getpath(i)
            self.distance_table[i.node] = i.distance
            #print("node:",i.node," next:",self.forwarding_table[i.node]," distance:",self.distance_table[i.node])

    # The add function, for incoming packets
    def add(self, packet):
        # do something with packet
        # print("parsing:",packet)        
        if packet.destination == self.id:
            self.packet_manager.add(packet)
        else:
            if packet.destination in self.forwarding_table:
                destination = self.forwarding_table[packet.destination]
                print("Forwarding:",print_hex(packet.destination),"-->",print_hex(destination))
                self.send(packet,destination)
            else:
                print("No route to host:"+print_hex(packet.destination))

    # add_neighbour, adds neighbour to the niegbours table and update the routing table
    def add_neighbour(self, host_port, longid):

        print("Add neighbour:",print_hex(longid))
        if longid not in [r['DESTINATIONID'] for r in self.routingTable]:
            self.routingTable.append({'DESTINATIONID': longid, 'NEXTHOPID': self.id, 'HOPCOUNT': 1})
        else:
            for my_row in self.routingTable:
                if my_row['DESTINATIONID'] == longid:
                    my_row['HOPCOUNT'] = 1
                    my_row['NEXTHOPID'] = self.id
        #generate new forwarding table after route update
        self.bellman_ford()

        self.neighbors.append({'DESTINATIONID': longid, 'Weight': 1, 'HOST_PORT': host_port})
        self.packet_manager.request_send_fullrouting_update(longid)
        self.packet_manager.request_send_identity(longid)
        
        #send update to neighbours also regarding addition
        for destination in self.get_neighbour_destinations():
            if destination!=longid:
                self.packet_manager.request_send_routing_update(False, \
                    destination, [(longid,1)])

    # get_all_destinations, returns all destinations in routing table
    def get_all_destinations(self):
        destinations = set()
        [destinations.add(n['DESTINATIONID']) for n in self.routingTable if n['DESTINATIONID'] != self.id]
        return destinations

    # get_neighbour_for_destination, returns a neighbours connected to a destination from neighbours table
    def get_neighbour_for_destination(self, destination):
        neighbours = [n['HOST_PORT'] for n in self.neighbors if n['DESTINATIONID'] == destination]

        if (len(neighbours) > 0):
            return neighbours[0]
        else:
            return None

    # get_neighbour_destinations, returns all neighbours destinations from niegbours table
    def get_neighbour_destinations(self):
        destinations = []
        for row in self.neighbors:
            destinations.append(row['DESTINATIONID'])
        return destinations

    def send(self, packet, destination):
        # print("sending packet:"+str(packet)+" to destination:"+print_hex(destination))
        if destination in self.get_neighbour_destinations():
            self.send_receive.send(packet, self.get_neighbour_for_destination(destination))
        else:
            if destination in self.forwarding_table:
                new_destination = self.forwarding_table[destination]
                distance = self.distance_table[destination]
                print("forwarding:"+print_hex(destination)+"-->"+print_hex(new_destination)+"("+str(distance)+")")
                self.send_receive.send(packet,self.get_neighbour_for_destination(new_destination))
            else:
                self.send_receive.send(packet,None)

    # remove_node, remove node from neighbors table (if exists) and routing table and all its connected routing table
    def remove_node(self, nodeid):
        print("removing node:",nodeid)
        new_neighbours=[]
        for row in self.neighbors:
            if row['DESTINATIONID'] != nodeid:
                new_neighbours.append(row)
        self.neighbors=new_neighbours
        new_routingTable=[]
        for row in self.routingTable:
            if (row['DESTINATIONID'] != nodeid and row['NEXTHOPID'] != nodeid):
                new_routingTable.append(row)
        self.routingTable=new_routingTable
        #generate new forwarding table after route update
        self.bellman_ford()
        #send also update to neighbours regarding removal
        for destination in self.get_neighbour_destinations():
            if destination!=nodeid:
                self.packet_manager.request_send_routing_update(False, \
                    destination, [(nodeid,0xFFFF)])

    # get_routing_table, returns destinations and hop count for all routingtable and put them in a set
    def get_routing_table(self):
        return_table = list()
        for destination in self.distance_table:
            hopcount = self.distance_table[destination]
            return_table.append((destination, hopcount))
        return return_table

    # compare_tables, this method is used to compare 2 routing tables, our node current routing table, 
    # and the table (or update records) received from a new node
    # it updates the routing table to get the optimized route 
    def compare_tables(self, table):
        updates= [] #updates for other neighbours
        newtable = []
        for row in self.routingTable:
            if row['DESTINATIONID'] == self.id:
                newtable.append(
                    {'DESTINATIONID': row['DESTINATIONID'], 'NEXTHOPID': row['NEXTHOPID'], 'HOPCOUNT': row['HOPCOUNT']})
                break
        temptable = table
        for row in self.routingTable:
            temp = False
            for row2 in table:
                if row['DESTINATIONID'] == row2['DESTINATIONID'] \
                    and row['NEXTHOPID'] == row2['NEXTHOPID']:
                    temp = True
                    if row2['HOPCOUNT']==0xFFFF:
                        updates.append(row2)
                    elif row['HOPCOUNT'] <= row2['HOPCOUNT']:
                        newtable.append(row)
                    else:
                        newtable.append(row2)
                        updates.append(row2)
                    temptable.remove(row2)
            if temp is False and row not in newtable:
                newtable.append(row)
        newentries=[]
        for row in temptable:
            if row not in newtable and row['HOPCOUNT']!=0xFFFF:
                newtable.append(row)
                newentries.append(row)
                updates.append(row)
        self.routingTable = newtable
        #generate new forwarding table after route update
        self.bellman_ford()
        #for new entries, ask also host identity
        for row in newentries:
            if row['DESTINATIONID']!=self.id:
                self.packet_manager.request_send_identity(row['DESTINATIONID'])
        #send updates to neighbours, about remove/add/update
        routes=[]
        for update in updates:
            destination=update['DESTINATIONID']
            if (update['HOPCOUNT']==0xFFFF):
                routes.append((destination,0xFFFF))
            else:
                routes.append((destination,self.distance_table[destination]))
        if len(routes)>0:
            for destination in self.get_neighbour_destinations():
                self.packet_manager.request_send_routing_update(False,destination,routes)

#class to manager keyboard input
class Keyboard(threading.Thread):
    send_receive = None
    stop_keyboard = False
    packet_manager = None

    def __init__(self, send_receive):
        threading.Thread.__init__(self)
        self.send_receive = send_receive

    def run(self):
        global debug
        while not self.stop_keyboard:
            print("Type /help for a list of commands")
            kbd_input = input("> ")
            if (kbd_input == "/debugon"):
                debug = 1
                # print("debug:",debug)
            elif (kbd_input == "/debugoff"):
                debug = 0
                # print("debug:",debug)
            elif (kbd_input == "/exit"):               
                break
            elif (kbd_input =="/routes"):
                print("Destination","Nexthop","Hopcount")
                for route in self.send_receive.routing_manager.routingTable:
                    print (print_hex(route['DESTINATIONID']),\
                        print_hex(route['NEXTHOPID']),\
                        route['HOPCOUNT'])
            elif (kbd_input =="/forward"):
                print("Destination","NextHop")
                for destination in self.send_receive.routing_manager.forwarding_table:
                    print (print_hex(destination),\
                        print_hex(self.send_receive.routing_manager.forwarding_table[destination]))
            elif (kbd_input =="/distance"):
                print("Destination","Distance")
                for destination in self.send_receive.routing_manager.distance_table:
                    print (print_hex(destination),\
                        str(self.send_receive.routing_manager.distance_table[destination]))
            elif (kbd_input =="/bf"):
                self.send_receive.routing_manager.bellman_ford()
            elif (kbd_input =="/self"):
                print("self longid:",print_hex(self.send_receive.long_id))
            elif (kbd_input == "/help"):
                print("/exit - exits the messaging client")
                print("/help - this help message")
                print("/list - list all destinations, with nicknames")
                print("/routes - list all routes")
                print("/forward - list forwarding table")
                print("/distance - list distance table")
                print("/self - print self longid")
                print("/debugon - turn debugging on")
                print("/debugoff - turn debugging off")
                print("<message> - send message to all destinations")
                print("/<nick> <message> - send message to <nick, for example /joe Hello!")
            elif (kbd_input != ""):
                self.send_receive.keyboard(kbd_input)
        self.send_receive.exit()

    def exit(self):
        self.stop_keyboard = True

#general class to manage sending and receiving, acks
class SendAndReceive:
    # ack interval is 5 seconds
    resend_interval = 5000
    keepalive_max_interval = 40000
    host_port = ("localhost", 5000)
    long_id = bytes().fromhex("0101010102020202")
    nickname = "joe"
    send_buffer = [] #the main send buffer, (packet, (host port)) tuples will be put here
    kbd_buffer = [] #keyboard input is put here
    ack_buffer = {} # ack dictionary (destination, session_id, seq) = (packet, timestamp)
    keepalive_buffer = {} #keepalive dictionary destination = timestap
    do_exit = False
    neighbours = {} #neighbour configuration dictionary, in case we have a neighbour drop and then wake up

    def __init__(self, host_port, long_id, nickname):
        self.host_port = host_port
        self.long_id = long_id
        self.nickname = nickname

    def set_routing_manager(self, routing_manager):
        self.routing_manager = routing_manager

    def set_packet_manager(self, packet_manager):
        self.packet_manager = packet_manager

    # main send method, just append to buffer
    def send(self, packet, neighbour):
        if (type(packet) == list):
            for single in packet:
                self.send_buffer.append((single, neighbour))
        else:
            self.send_buffer.append((packet, neighbour))

    #input from keyboard
    def keyboard(self, kbd_input):
        self.kbd_buffer.append(kbd_input)

    #exit is called from Keyboard classs, when /exit is typed
    def exit(self):
        #announce exit to neighbours
        for destination in routing_manager.get_neighbour_destinations():
            self.packet_manager.request_send_routing_update(True, \
                    destination, \
                        list())
    
        print("Exiting, please wait up to ", str(self.packet_manager.keepalive_interval) + "s")
        self.do_exit = True
        self.packet_manager.keepalive_stop = True

    #the main server program loop starts here
    def start(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(self.host_port)
        # sock.listen(10)

        while not self.do_exit:
            time.sleep(.1)
            # check for keyboard input
            while (len(self.kbd_buffer) > 0):
                kbd_input = self.kbd_buffer.pop(0)
                self.packet_manager.send_text(kbd_input)
                # print("Keyboard input:",kbd_input)

            # check for packets for resend
            timestamp = int(round(time.time() * 1000))

            # resend the packets that have not been acked in self.resend_interval
            resend_infos = [self.ack_buffer[packet_info] \
                            for packet_info in self.ack_buffer \
                            if (timestamp - self.ack_buffer[packet_info][1]) > self.resend_interval]
            for resend_info in resend_infos:
                if debug == 1:
                    print("resending packet to destination:" + print_hex(resend_info[0].destination) + \
                          " diff:" + str(timestamp - resend_info[1]))
                self.routing_manager.send(resend_info[0], resend_info[0].destination)

            # drop connection, if keepalive is not acked in resend_max_interval
            drop_destinations = [destination \
                                 for destination in self.keepalive_buffer \
                                 if (timestamp - self.keepalive_buffer[destination]) > self.keepalive_max_interval]
            for drop_destination in drop_destinations:
                print("dropping neighbour destination:" + print_hex(drop_destination))
                del self.keepalive_buffer[drop_destination]
                self.routing_manager.remove_node(drop_destination)
                # remove all packets drom ack buffer for destination
                remove_packets = [packet_info \
                    for packet_info in self.ack_buffer \
                    if packet_info[0] == drop_destination]
                for remove_packet in remove_packets:
                    del self.ack_buffer[remove_packet]
                # remove also packets for destination in send buffer
                remove_packets = [packet_info for packet_info in self.send_buffer \
                    if packet_info[0].destination==drop_destination]
                for remove_packet in remove_packets:
                    self.send_buffer.remove(remove_packet)

            connections = [sock]
            recv, write, err = select.select(connections, connections, connections)

            for s in recv:
                try:
                    #receive data
                    msg = s.recv(4096)
                    # print("Recieved data:",print_hex(msg))
                    packet = Packet.init_with_data(msg)
                    if debug == 1:
                        print("Recieved packet:", packet)
                    # see if this is ack packet
                    if (packet.packet_flags == 0x04):
                        # see if it is an keepalive ack, remove antry from keepalive buffer for destination
                        if (packet.packet_type == 0x00):
                            del self.keepalive_buffer[packet.source]
                        else:
                            # this normal is ack packet, lets see if this packet is in ack_buffer and remove
                            if (packet.source, packet.session_id, packet.seq) in self.ack_buffer:
                                del self.ack_buffer[(packet.source, packet.session_id, packet.seq)]
                    else:
                        #see if neighbour is back
                        if (packet.source in self.neighbours and \
                            self.routing_manager.get_neighbour_for_destination(packet.source))==None:
                            self.routing_manager.add_neighbour(self.neighbours[packet.source], packet.source)
                        # ack sent packet
                        self.routing_manager.send(packet.get_ack_packet(), packet.source)
                        # add to routing manager for processing
                        routing_manager.add(packet)
                except ConnectionResetError:
                    pass #skip the connection errors from printing on screen, in case neighbour lost
                except Exception as error:
                    print("Error recv:", error)
                    if debug==1:
                        traceback.print_exc()

            for s in write:
                #write data to socket
                while (len(self.send_buffer) > 0):
                    (packet, neighbour) = self.send_buffer.pop(0)
                    if (packet.source == None):
                        packet.source = self.long_id
                    if debug == 1:
                        print("Sending packet:", packet, "to:", neighbour)

                    # add packet with timestamp to ack buffer (so that if ack is not received, packet is resent)
                    # we do not add ack packets to ack buffer, add keepalive to keepalive buffer
                    if packet.packet_flags != 0x04:
                        if (packet.packet_type == 0x00):
                            if packet.destination not in self.keepalive_buffer:
                                self.keepalive_buffer[packet.destination] = int(round(time.time() * 1000))
                        else:
                            self.ack_buffer[(packet.destination, packet.session_id, packet.seq)] = \
                                (packet, int(round(time.time() * 1000)))

                    # send the packet
                    try:
                        if (neighbour != None):
                            sent = s.sendto(packet.encode(), neighbour)
                        else:
                            print("No route to:" + print_hex(packet.destination))
                    except Exception as error:
                        print("Error send:", error)
                        if debug==1:
                            traceback.print_exc()

            for s in err:
                print("Error with a socket")
                if debug==1:
                        traceback.print_exc()
                s.close()
                connections.remove(s)


def help():
    print("Syntax:")
    print("", sys.argv[0],
          " <host> <port> <longid> <nickname> [ <neighbour host> <neighbour port> <neighbour longid> ]... ")
    print("Example")
    print("", sys.argv[0], " localhost 5005 0101010102020202 jimmy")


print("length:", str(len(sys.argv)))
print("argv:", sys.argv)

#helper function to print the bytes
def print_hex(data_bytes):
    msg = ""
    if (type(data_bytes) == bytes and len(data_bytes) > 0):
        msg = ''.join(['{:02x}'.format(b) for b in data_bytes])
    elif len(data_bytes) > 0:
        print("Wrong type for print_hex:" + str(type(data_bytes)))

    return msg

# neighbor can be set only on command line
# parse command line
if (len(sys.argv) >= 5):

    if (len(bytes().fromhex(sys.argv[3])) == 8):

        #initialize all classes
        send_receive = SendAndReceive((sys.argv[1], int(sys.argv[2])), bytes().fromhex(sys.argv[3]), sys.argv[4])
        routing_manager = RoutingManager(send_receive, bytes().fromhex(sys.argv[3]))
        packet_manager = PacketManager(routing_manager, bytes().fromhex(sys.argv[3]), sys.argv[4])
        routing_manager.set_packet_manager(packet_manager)
        send_receive.set_routing_manager(routing_manager)
        send_receive.set_packet_manager(packet_manager)
        keyboard = Keyboard(send_receive)
        keyboard.daemon = True

        #parse neighbours from command line
        try:

            if (len(sys.argv) >= 8 and len(sys.argv) % 3 == 2):
                for i in range(5, len(sys.argv), 3):
                    host = sys.argv[i]
                    port = sys.argv[i + 1]
                    longid = sys.argv[i + 2]
                    print("adding neighbour host:" + host + " port:" + port + " longid:" + longid)
                    ipaddress = socket.gethostbyname_ex(host)
                    longidbytes = bytes().fromhex(longid)
                    if (len(longidbytes) == 8):
                        host_port = (host, int(port))
                        send_receive.neighbours[longidbytes]=host_port
                        routing_manager.add_neighbour(host_port,longidbytes)
                    else:
                        print("longid must be 8 bytes:" + sys.argv[i + 2])

            keyboard.start()

            #start the main loop
            send_receive.start()

        except Exception as error:
            send_receive.exit()
            keyboard.exit()
            raise error


    else:
        print("longid must be 8 bytes:" + sys.argv[3])

else:
    help()
