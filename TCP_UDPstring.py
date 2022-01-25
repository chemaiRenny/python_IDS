import re
from scapy.all import *
from enum import Enum

from Rule import *

URG = 0x20


def tcpString(tcp):
        """Construct the human-readable string corresponding to the TCP header."""

        out = "[TCP Header]" + "\n"
        out += "\t Source Port: " + str(tcp.sport) + "\n"
        out += "\t Destination Port: " + str(tcp.dport) + "\n"
        out += "\t Sequence Number: " + str(tcp.seq) + "\n"
        out += "\t Acknowledgment Number: " + str(tcp.ack) + "\n"
        out += "\t Data Offset: " + str(tcp.dataofs) + "\n"
        out += "\t Reserved: " + str(tcp.reserved) + "\n"
        out += "\t Flags: " + tcp.underlayer.sprintf("%TCP.flags%") + "\n"
        out += "\t Window Size: " + str(tcp.window) + "\n"
        out += "\t Checksum: " + str(tcp.chksum) + "\n"
        if (tcp.flags & URG):
            out += "\t Urgent Pointer: " + str(tcp.window) + "\n"
        if (tcp.dataofs > 5):
            out += "\t Options: " + str(tcp.options) + "\n"
        return out

def matchedTcpString(tcp, rule):
    """Construct the human-readable string corresponding to the matched TCP header, with matched fields in red."""

    out = "[TCP Header]" + "\n"
    if (hasattr(rule.srcPorts, "listPorts") and len(rule.srcPorts.listPorts) == 1):
        out += "\t Source Port: " + str(tcp.sport)  + "\n"
    else:
        out += "\t Source Port: " + str(tcp.sport) +"\n"
    if (hasattr(rule.dstPorts, "listPorts") and len(rule.dstPorts.listPorts) == 1):
        out += "\t Destination Port: " + str(tcp.dport) + "\n"
    else:
        out +=  "\t Destination Port: " + str(tcp.dport) + "\n"
    if (hasattr(rule, "seq")):
        out += "\t Sequence Number: " + str(tcp.seq) + "\n"
    else:
        out += "\t Sequence Number: " + str(tcp.seq)  +"\n"
    if (hasattr(rule, "ack")):
        out += "\t Acknowledgment Number: " + str(tcp.ack)+ "\n"
    else:
        out += "\t Acknowledgment Number: " + str(tcp.ack)  + "\n"
    out += "\t Data Offset: " + str(tcp.dataofs) + "\n"
    out += "\t Reserved: " + str(tcp.reserved) + "\n"
    if (hasattr(rule,"flags")):
        out += "\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%") + "\n"
    else:
        out +="\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%") + "\n"
    out += "\t Window Size: " + str(tcp.window) + "\n"
    out += "\t Checksum: " + str(tcp.chksum) + "\n"
    if (tcp.flags & URG):
        out += "\t Urgent Pointer: " + str(tcp.window) + "\n"
    if (tcp.dataofs > 5):
        out += "\t Options: " + str(tcp.options) + "\n"
    return out



#UDP

def udpString(udp):
    """Construct the human-readable string corresponding to the UDP header."""

    out = "[UDP Header]" + "\n"
    out += "\t Source Port: " + str(udp.sport) + "\n"
    out += "\t Destination Port: " + str(udp.dport) + "\n"
    out += "\t Length: " + str(udp.len) + "\n"
    out += "\t Checksum: " + str(udp.chksum) + "\n"
    return out

def matchedUdpString(udp, rule):
    """Construct the human-readable string corresponding to the UDP header, with matched fields in red."""

    out = "[UDP Header]" + "\n"
    if (hasattr(rule.srcPorts, "listPorts") and len(rule.srcPorts.listPorts) == 1):
        out += "\t Source Port: " + str(udp.sport) + "\n"
    else:
        out += "\t Source Port: " + str(udp.sport)+ "\n"
    if (hasattr(rule.dstPorts, "listPorts") and len(rule.dstPorts.listPorts) == 1):
        out +=  "\t Destination Port: " + str(udp.dport)  + "\n"
    else:
        out +=  "\t Destination Port: " + str(udp.dport) + "\n"
    out += "\t Length: " + str(udp.len) + "\n"
    out += "\t Checksum: " + str(udp.chksum) + "\n"
    return out

#HTTP
HTTPcommands = ["GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"]
def isHTTP(pkt):
    if (TCP in pkt and pkt[TCP].payload):
        data = str(pkt[TCP].payload)
        words = data.split('/')
        if (len(words) >= 1 and words[0].rstrip() == "HTTP"):
            return True
            
        words = data.split(' ')
        if (len(words) >= 1 and words[0].rstrip() in HTTPcommands):
            return True
        else:
            return False
    else:
        return False
files=["main.py","sniff.py","login.py","client.py","ip_string.py",'make_rules.py','packet_string.py','read_file.py','Rule.py','server.py','syntax_check.py','TCP_UDPstring.py']

