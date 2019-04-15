
import sys
import socket


def server(ip, port):

    sock = socket.socket(socket.AF_INET, # Internet
        socket.SOCK_DGRAM) # UDP
    sock.bind((ip, int(port)))

    while True:
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        print ("received message:", data.decode(), "addr:", addr)
        #send back echo
        sock.sendto(data, addr)
        print ("sent message:", data.decode(), "addr:", addr)

def client_send(ip, port, message, timeout):

    print ("UDP target IP:", ip)
    print ("UDP target port:", port)
    print ("message:", message)
 
    sock = socket.socket(socket.AF_INET, # Internet
        socket.SOCK_DGRAM) # UDP
    sock.sendto(message.encode(), (ip, int(port)))

    #now wait 30s for an answer
    print ("waiting for an answer on:",sock.getsockname())
    sock.settimeout(timeout)
    data, addr = sock.recvfrom(1024)
    print ("received message:", data.decode(), "addr:", addr)

def help():
    print ("Syntax:")
    print ("",sys.argv[0]," -server <ip> <port>")
    print ("  Starts a server listener")
    print ("",sys.argv[0]," -client <ip> <port> <message> ")
    print ("  Sends a message to ip:port")

#print ("length:",str(len(sys.argv)))
#print ("argv:",sys.argv)

else:
    help()
