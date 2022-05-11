# -*- coding: utf-8 -*-
"""
Created on Sun Nov 21 15:39:23 2021

@author: PC
"""
from util import hex_to_int

#Analyseur de segment UDP
def retrieveUDP(content,pos):
  #initialisation
  port_source = ""   #16 bits
  for el in content[pos:pos+2]:
    port_source=port_source+el
  port_destination= "" #16 bits
  for el in content[pos+2:pos+4]:
    port_destination= port_destination+el
  longueur= ""     #16 bits
  for el in content[pos+4:pos+6]:
    longueur= longueur + el
  checksum = ""      #16 bits
  for el in content[pos+6:pos+8]:
    checksum = checksum + el
  #Affichage
  print("\nUDP Protocol Segment Analysis -")
  print("\tport source             :", "0x"+port_source, "(",hex_to_int(port_source),")")
  print("\tport destination        :", "0x"+port_destination, "(",hex_to_int(port_destination),")")
  print("\tTotal length            :", hex_to_int(longueur),"octets")
  print("\tchecksum                :", "0x"+checksum,)
  application=""
  if hex_to_int(port_destination) in (67,68):
      print("\n\tThis segment encapsulates a DHCP message")
      application = "dhcp"
  if hex_to_int(port_source)==53 or hex_to_int(port_destination)==53:
      print("\n\tThis segment encapsulates a DNS message")
      application = "dns"
  return pos+8, application