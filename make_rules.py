#!/usr/bin/env python3

import os
from sys import exit

def makeRules():
    exploited_ports = "21,22,23,25,69,445,6666,5357,135,139,80,443"
    rules = """
    alert tcp 192.168.0.143 %s -> any any (msg:'Attempted Intrusion')
    alert udp 192.168.0.143 %s -> any any (msg:'Attempted Intrusion')
    
"""%(exploited_ports,exploited_ports)
    rules=rules.strip()
    if not os.path.exists("rules"):
        os.system("mkdir rules")
        
    if  os.path.exists("rules/default_rules.txt"):
        userInput=input("The file 'default_rules.txt' already exists.Do you wish to overwrite it? (y) or (n) \n>>> ")
        if userInput.strip().upper().startswith("N"):
            pass
        else:
            with open("rules/default_rules.txt","w") as f:
                f.write(rules)
                f.close()
    else:
        with open("rules/default_rules.txt","w") as f:
                f.write(rules)
                f.close()

if __name__ == "__main__":
    makeRules()
    print("File saved to default_rules.txt")

