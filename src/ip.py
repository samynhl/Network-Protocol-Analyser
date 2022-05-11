# -*- coding: utf-8 -*-
"""
Created on Sun Nov 21 15:37:57 2021

@author: PC
"""
from util import to_ip, hex_to_int

proto={"01":"ICMP",
       "06":"TCP",
       "11":"UDP",}

options={"00":"(end of options list EOOL)",
         "01":"no operation NOP",
         "07":"(record route RR)",
         "68":"(time stamp TS)",
         "131":"(loose source route LSR)",
         "137":"(strict source route SSR)"}

#Analyseur de paquet IP (entête)
def retrieveIP(content, pos):
  #initialisation
  version = content[pos][0]
  ihl= content[pos][1]
  Tos = content [pos+1]
  length= ""
  for el in content [pos+2:pos+4]:
    length=length+el
  ident = ""
  for el in content [pos+4:pos+6]:
    ident=ident+el
  frag_offset=""

  tag = content[pos+6:pos+8]
  m1=bin(int("0x"+tag[0],16))[2:]
  for i in range(0,8-len(m1)):
    m1 = "0" + m1
  m2=bin(int("0x"+tag[1],16))[2:]
  for i in range(0,8-len(m2)):
    m2 = "0" + m2
  DF = m1[0]
  MF = m1[1]
  R = m1[2] 
  frag_offset = m1[3:] + m2
  ttl= content[pos+8]
  protocol=content[pos+9]
  checksum=""
  for el in content [pos+10:pos+12]:
    checksum=checksum+el
  sourceIP = to_ip(content[pos+12:pos+16])
  destIP = to_ip(content[pos+16:pos+20])
  #Affichage de l'entête sans options
  print("\nInternet Protocol Packet Analysis -")
  print("\tIP version              :", version)
  print("\tIP header length        :", hex_to_int(ihl)*4,"octets")
  print("\tToS                     :", "0x"+Tos,"(", hex_to_int(Tos),")")
  print("\tTotal length            :", hex_to_int(length),"octets")
  print("\tIdentification          :", "0x"+ident, "(", hex_to_int(ident),")")
  print("\tDon't Fragment          :", DF)
  print("\tMore Fragment           :", MF)
  print("\tR register              :", R)
  print("\tFragment Offset         :", "0x"+frag_offset,"(",int("0b"+frag_offset,2),")")
  print("\tTime to leave TTL       :","0x"+ttl,"(", hex_to_int(ttl),")")
  print("\tProtocol                :","0x"+protocol,"(", proto[protocol],")")
  print("\tchecksum                :","0x"+checksum)
  print("\tIP source adress        :",sourceIP)
  print("\tIP target adress        :",destIP)
  #Vérification des options
  n = hex_to_int(ihl)*4
  if n==20:
    print ("\theader without options, options length 0")
  else:
    print("\toptions length          :", n - 20,"bytes")
    type_opt = content[pos+20]
    longueur= content[pos+21]
    ptr = content[pos+22]   
    print("\t\ttype            :","0x"+type_opt,options[type_opt])
    print("\t\tlongueur        :","0x"+longueur,"(",hex_to_int(longueur),")")
    print("\t\tptr             :","0x"+ptr)
    padding = (hex_to_int(longueur)-2)%4
    print("\t\tpadding         :",padding)
    icmp_type = ""
    if type_opt=="07":
      icmp_type = content[pos+60]
      if icmp_type=="08":
          print("\t\tICMP Echo request")

      else:
          if icmp_type=="00":
              print("\t\tICMP Echo reply")
              k = pos+23
              for i in range((hex_to_int(longueur)-2)//4):
                  if to_ip(content[k:k+4])==sourceIP:
                      print("\t\t\t Target ip :"+to_ip(content[k:k+4]))
                  else:
                      if to_ip(content[k:k+4])==destIP:
                          print("\t\t\t Targer ip :"+to_ip(content[k:k+4]))
                      else:
                          print("\t\t\t Router ip :"+to_ip(content[k:k+4]))
                  k=k+4
  return pos+n, protocol