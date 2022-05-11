# -*- coding: utf-8 -*-

from util import countMsgs,verifyMsg,retrieveMsgContent
from ethernet import retrieveEthernet, type_ethernet
from ip import retrieveIP, proto
from udp import retrieveUDP
from dhcp import retrieveDHCP
from dns import retrieveDNS
import sys

#MAIN
def analyse(path):
    original_stdout = sys.stdout
    f1= open(path[:len(path)-4]+"-result.txt", 'w')
    try:
        with open(path,'r') as f:
          sys.stdout = f1
          lines = f.readlines()               #lecture du fichier
          n, nbException = countMsgs(lines)   #count frames in the text file
          for i in range(1,n+1):
              print("****************************************************************")
              print("Trame {} :\n".format(i))
              msg = verifyMsg(lines,i,n)          #verify and return the message
              #
              if msg!=None and len(msg)>0:
                content = retrieveMsgContent(msg) #retrieve msg content
                pos1, ethertype= retrieveEthernet(content)    #Analyse ethernet frame
                if (ethertype=="0800"):
                  pos2, protocol2 = retrieveIP(content,pos1)    #Analyse IP packet
                  if protocol2=="11":
                    pos3, protocol3 = retrieveUDP(content,pos2) #Analyse UDP segment
                    if protocol3=="dhcp":
                        retrieveDHCP(content,pos3)      #Analyse DHCP Header
                    if protocol3=="dns":
                        retrieveDNS(content,pos3)      #Analyse DNS Header """
                  else:
                      try:
                          print("\nCette trame encapsule un segment {}".format(proto[protocol2]))
                      except:
                          print("\nCette trame n'encapsule pas un datagramme UDP")
                else:
                    try:
                        print("\nCette trame encapsule le protocol ",type_ethernet[ethertype])
                    except:
                        print("\nCette trame n'encapsule pas un paquet IP")
          sys.stdout = original_stdout
          f1.close()
    except :
        print("error")
    finally:
        sys.stdout = original_stdout
        f1.close()
"""
try:
    analyse("trace.txt")
except FileNotFoundError:
    print("Wrong file or file path")
"""
