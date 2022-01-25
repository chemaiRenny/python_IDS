from Rule import *

def read(filename):
    l = list()
    with open (filename, 'r') as f:
        ruleErrorCount = 0
        for  line in f:
            try:
                rule = Rule(line)
                l.append(rule)
            except ValueError as err:
                ruleErrorCount += 1
                print (err)

    return l, ruleErrorCount



