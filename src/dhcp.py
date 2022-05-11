# -*- coding: utf-8 -*-
"""
Created on Sun Nov 21 15:46:51 2021

@author: PC
"""
from util import to_ip, hex_to_int
options={"00":"Padding",
         "01":"Subnet Mask",
         "51":"IP adress lease time",
         "52":"option overload",
         "53":"DHCP message type",
         "54":"DHCP server identifier",
         "55":"Parameter request list",
         "56":"Message",
         "57":"Maximum dhcp message size",
         "58":"Renewal time value",
         "59":"Rebinding time value",
         "61":"Client Identifier",
         "ff":"END",}

#Analyseur de l'entête DHCP
def retrieveDHCP(content,pos):
  #initialisation
  op = content[pos]   #1 oct
  htype = content[pos+1]
  hlen = content[pos+2]
  hops = content[pos+3]
  xid = "".join(el for el in content[pos+4:pos+8])
  secs = "".join(el for el in content[pos+8:pos+10])
  flags = "".join(el for el in content[pos+10:pos+12])
  ciaddr = to_ip(content[pos+12:pos+16])
  yiaddr = to_ip(content[pos+16:pos+20])
  siaddr = to_ip(content[pos+20:pos+24])
  giaddr = to_ip(content[pos+24:pos+28])
  chaddr = "".join(el for el in content[pos+28:pos+44])
  sname = "".join(el for el in content[pos+44:pos+108])
  filen = "".join(el for el in content[pos+108:pos+236])
  magic_cookie = "".join(el for el in content[pos+236:pos+240])
  #affichage
  print("\nDHCP frame analysis -")
  print("\toperation               :", op, "(",int("0x"+op,16),")")
  print("\thardware adress         :", htype, "(",int("0x"+htype,16),")")
  print("\thardware length         :", int("0x"+hlen,16),"octets")
  print("\thops                    :", "0x"+hops)
  print("\tclient identifier       :","0x", xid, "(",int("0x"+xid,16),")")
  print("\ttimer                   :", int("0x"+secs,16), "secondes")
  print("\tflags                   :", flags, "(",int("0x"+flags,16),")")
  print("\tclient ip adress        :", ciaddr)
  print("\tfuture client ip adress :", yiaddr)
  print("\tserver ip adress        :", siaddr)
  print("\tgateway adress          :", giaddr)
  print("\tclient hardware adress  :", chaddr)
  #print("\tserver name     :", "0x",sname)
  #print("\tboot file :", "0x", filen)
  print("\tmagic cookie :", "0x", magic_cookie)
  
  #DHCP options
  print("\tDHCP options          :")
  k = pos+240
  type_opt = ""
  leng = ""
  option_content=""
  while True:
      type_opt = content[k]
      if type_opt=="ff":
          #print(hex_to_int(type_opt))
          break
      leng = content[k+1]
      if type_opt=="61":
          option_content=to_ip(content[k+2:k+2+hex_to_int(leng)])
      else:
          for el in content[k+2:k+2+hex_to_int(leng)]:
              option_content = option_content + el
      try:
          print("\t\tOption :",hex_to_int(type_opt), options[str(hex_to_int(type_opt))])
          print("\t\t\tLength  :",hex_to_int(leng))
          
          print("\t\t\tContent :",option_content)
      except:
          pass
      k = k+ 2 + hex_to_int(leng)
      option_content=""
  return pos