#!/usr/bin/env python3

import socket #imported Sockets module
import sys

def main():
    MONITOR_IP = '127.0.0.1'
    MONITOR_PORT = 1234
    BUFFER_SIZE = 1024 #Normally use  1024, to get fast response from the server use small size 
    
    try:
        #Create an AF_INET (IPV4),STREAM socket (TCP)
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as err:
        print ('Error occurred while creating socket.Error code: ' + str(e[0]) + ' , Error message : ' + e[1])
        sys.exit(1);
    
    tcp_socket.bind((MONITOR_IP,MONITOR_PORT))
    #Listen for incoming connections (max queued connections :2)
    
    tcp_socket.listen(2)
    print ("Listening...")
    
    #Keep server alive
    while True:
        #Waits for incoming connection (blocking call)
        connection,address = tcp_socket.accept()
        print ('Client connected :',address[0])
        
        data = connection.recv(BUFFER_SIZE)
        #print ("Message from client: ", data)
        print(data.decode('utf-8'))
#        beep()
        thank_message = "Thanks for connecting"
        thank_message = bytes(thank_message, 'utf-8')
    
        connection.sendall(thank_message) #response for the mesaage from client

def beep():
    import winsound
    winsound.MessageBeep()
    duration = 1000  # milliseconds
    freq = 440  # Hz
    winsound.Beep(freq, duration)
    
if __name__ == "__main__":
    main()
    
