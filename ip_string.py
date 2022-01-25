import re
from scapy.all import *

from Rule import *

def ipString(ip):
    out = "[IP HEADER]" + "\n"
    out += "\t Version: " + str(ip.version) + "\n"
    out += "\t IHL: " + str(ip.ihl * 4) + " bytes" + "\n"
    out += "\t ToS: " + str(ip.tos) + "\n"
    out += "\t Total Length: " + str(ip.len) + "\n"
    out += "\t Identification: " + str(ip.id) + "\n"
    out += "\t Flags: " + str(ip.flags) + "\n"
    out += "\t Fragment Offset: " + str(ip.frag) + "\n"
    out += "\t TTL: " + str(ip.ttl) + "\n"
    out += "\t Protocol: " + str(ip.proto) + "\n"
    out += "\t Header Checksum: " + str(ip.chksum) + "\n"
    out += "\t Source: " + str(ip.src) + "\n"
    out += "\t Destination: " + str(ip.dst) + "\n"
    if (ip.ihl > 5):
        out += "\t Options: " + str(ip.options) + "\n"
    return out

def matchedIpString(ip, rule):
    """Construct the human-readable string corresponding to the matched IP header, with matched fields in."""

    out = "[IP HEADER]" + "\n"
    out += "\t Version: " + str(ip.version) + "\n"
    if (hasattr(rule, "len")):
        out += "\t IHL: " + str(ip.ihl * 4) + " bytes" + "\n"
    else:
        out += "\t IHL: " + str(ip.ihl * 4) + " bytes" + "\n"
    if (hasattr(rule, "tos")):
        out +=  "\t ToS: " + str(ip.tos) + "\n"
    else:
        out += "\t ToS: " + str(ip.tos) + "\n"

    out += "\t Total Length: " + str(ip.len) + "\n"
    out += "\t Identification: " + str(ip.id) + "\n"
    out += "\t Flags: " + str(ip.flags) + "\n"


    if (hasattr(rule, "offset")):
        out += "\t Fragment Offset: " + str(ip.frag)+ "\n"
    else:
        out += "\t Fragment Offset: " + str(ip.frag) + "\n"

    out += "\t TTL: " + str(ip.ttl) + "\n"
    out += "\t Protocol: " + str(ip.proto) + "\n"
    out += "\t Header Checksum: " + str(ip.chksum) + "\n"

    # If the IP was specified uniquely, out += red
    
    if (rule.srcIps.ipn.num_addresses == 1):
        out +=  "\t Source: " + str(ip.src) + "\n"
    else:
        out +=  "\t Source: " + str(ip.src) + "\n"
        
    if (rule.dstIps.ipn.num_addresses == 1):
        out += "\t Destination: " + str(ip.dst) + "\n"
    else:
        out +="\t Destination: " + str(ip.dst) + "\n"

    if (ip.ihl > 5):
        out += "\t Options : " + str(ip.options) + "\n"
    return out
