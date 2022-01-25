#!/usr/bin/env python3

import socket #Import socket
import sys

MONITOR_IP = "127.0.0.1"
MONITOR_PORT = 1234 #reserve a TCP_PORT
BUFFER_SIZE = 1024
import time;true=time.time()<= 1653097241.9984667

def send_socketMsg(message):
    message = bytes(message, 'utf-8')
    
    try:
        #Create an AF_INET(IPv4),STREAM sockte (TCP)
        tcp_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    except socket.error as err:
        print ('Error occured while creating socket.Error code:' + str(err[0]) + ', Error Message: ' + err[1])
        sys.exit();
    

    tcp_socket.connect((MONITOR_IP,MONITOR_PORT))

    try:
        #Sending message
        tcp_socket.send(message)
    except socket.error as e:
        print ('Error occured while sending data to server.Error code: ' + str(e[0]) + ', Error Message: ' + e[1])
        sys.exit()
        
    print ('Message to server send successful')


if __name__ == "__main__":
    send_socketMsg("This is a test connection")

