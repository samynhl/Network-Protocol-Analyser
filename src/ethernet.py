# -*- coding: utf-8 -*-
"""
Created on Wed Oct 27 10:39:09 2021

@author: PC
"""
from util import to_mac, hex_to_int

type_ethernet = {"6000":"DEC",
                 "6009":"DEC",
                 "0600":"XNS",
                 "0800":"IPV4",
                 "0806":"ARP",
                 "8019":"DOMAIN",
                 "8035":"RARP",
                 "809B":"AppleTalk",
                 "8100":"802.1Q",
                 "86DD":"IPV6"}
                 #0027

#Analyseur de trame ethernet (entête)
def retrieveEthernet(content):
  #initialisation
  adr_destination = to_mac(content[0:6])
  adr_source=to_mac(content[6:12])
  ether_type=""
  pos = 14
  for el in content[12:14]:
    ether_type=ether_type + el
  print("Ethernet Frame Analysis -")
  if adr_destination=="ff:ff:ff:ff:ff:ff":
    print("\tTarget MAC Adress       :",adr_destination,"(broadcast)")
  else:
    print("\tTarget MAC Adress       :",adr_destination)
  print("\tSender MAC Adress       :",adr_source)
  try:
    print("\tEthernet Type           :",type_ethernet[ether_type],ether_type)
  except:
    print("\tEthernet Type           :", ether_type)
  if ether_type=="8100":
    vlanprio = ""
    vlanid = ""
    ethertype_ = ""
    tag = content[14:16]
    m1=bin(hex_to_int(tag[0],16))[2:]
    for i in range(0,8-len(m1)):
      m1 = "0" + m1
    m2=bin(hex_to_int(tag[1],16))[2:]
    for i in range(0,8-len(m2)):
      m2 = "0" + m2

    vlanprio = m1[0:3]                  #Vlan priority 3 bits
    cfi = m1[3:4]   
    vlanid = m1[4:] + m2                #canonical format indication 1 bit
    for el in content[16:18]:           #vlan identifier 12 bits
      ethertype_=ethertype_ + el
    pos = 18
    print("\tVlan Analysis")
    print("\t\tVlan Priority     :",int("0b"+vlanprio,2), vlanprio)
    print("\t\tCFI               :", cfi)
    print("\t\tVlan Identifier   :",int("0b"+vlanid,2), vlanid)
    try:
      print("\tEthernet Type     :",type_ethernet[ethertype_],ethertype_)
    except:
      print("\tEthernet Type     :",ethertype_)
      ether_type = ethertype_
  #return the position in which the frame header ends
  #and the transport layer's protocol
  return pos, ether_type