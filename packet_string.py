import re
from scapy.all import *

from Rule import *



def packetString(pkt):
    """Construct the human-readable string corresponding to the packet, from IP header to Application data."""

    out = ""
    if (IP in pkt):
        out += ipString(pkt[IP])
    elif (IPv6 in pkt):
        # TODO
        pass
    if (TCP in pkt):
        out += tcpString(pkt[TCP]) + '/n'
    elif (UDP in pkt):
        out += udpString(pkt[UDP])+'/n'
    return out

def matchedPacketString(pkt, rule):
    """Construct the human-readable string corresponding to the matched packet, from IP header to Application data, with matched fields in red."""

    out = ""
    if (IP in pkt):
        # IP Header
        out += matchedIpString(pkt[IP], rule)
    elif (IPv6 in pkt):
        # TODO
        pass
    if (TCP in pkt):
        # TCP Header
        out += matchedTcpString(pkt[TCP], rule)
    elif (UDP in pkt):
        out += matchedUdpString(pkt[UDP], rule)
    return out

def unmatched(key, message):
    # Each string in ciphertext represents a column in the grid.
    ciphertext = [''] * key

    # Loop through each column in ciphertext.
    for col in range(key):
        pointer = col

        # Keep looping until pointer goes past the length of the message.
        while pointer < len(message):
            # Place the character at pointer in message at the end of the
            # current column in the ciphertext list.
            ciphertext[col] += message[pointer]

            # move pointer over
            pointer += key

    # Convert the ciphertext list into a single string value and return it.
    return ''.join(ciphertext)

