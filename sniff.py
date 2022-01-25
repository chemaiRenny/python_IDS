from scapy.all import *
from threading import Thread
import logging
import pprint
from datetime import datetime

from Rule import * 
import read_file 
import client

class Sniffer():
    def __init__(self, ruleList):
        Thread.__init__(self)
        self.stopped = False
        self.ruleList = ruleList

    def stop(self):
        self.stopped = True

    def stopfilter(self, x):
        return self.stopped

    def inPacket(self, pkt):
        for rule in self.ruleList:
            # Check all rules
            # print "checking rule"
            matched = rule.match(pkt)
            if (matched):
                current_time=str(datetime.now()).split('.')[0]
                logMessage = current_time +'\n'+rule.getMatchedMessage(pkt)
                logging.warning(logMessage)
                try:
                    client.send_socketMsg(rule.getMatchedPrintMessage(pkt))
                except ConnectionRefusedError:
                    import time
                    print("Server Not Connected")
                    time.sleep(1)
                    pass
                print(rule.getMatchedPrintMessage(pkt))

    def run(self):
        print ("Packet Sniffing started")
        sniff(prn=self.inPacket, filter="", store=0, stop_filter=self.stopfilter)
        print ("Done sniffing packets")



