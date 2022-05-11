# -*- coding: utf-8 -*-
"""
compression du paquet dns : 
    lire les champs qui indiquent la longueur de la section
    compteur pour chaque section, il faut lire le nombre de messages indiqué avant
    se rappeler des adresses début du messages dns
    se rappeler des noms utilisés (ils seront utilisés lors de la compression)
"""

from util import hex_to_int,to_ip, to_ip6
import codecs

list_hexa = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
rr_types = {1:"A",28:"AAAA",5:"CNAME",2:"NS",15:"MX"}
#Analyseur de l'entête DHCP
def retrieveDNS(content,pos):
  #pos représente le début du message dns
  start = pos
  #initialisation
  id = "".join(el for el in content[pos:pos+2])   #16bits
  #Bits de controle
  control = "".join(el for el in content[pos+2:pos+4])
  m = bin(int("0x"+control,16))[2:]
  for i in range(0,16-len(m)):
    m  = "0" + m
  qr = m[0]       #1 bit, request or response
  opcode = m[1:5]
  aa = m[5]
  tc = m[6]
  rd = m[7]
  ra = m[8]
  zero = m[9]
  ad = m[10]
  cf = m[11]
  rcode = m[12:16]
  
  #nombre de messages de chaque section
  nbQuestions = hex_to_int("".join(el for el in content[pos+4:pos+6]))
  nbReponses =  hex_to_int("".join(el for el in content[pos+6:pos+8]))
  nbAutorites = hex_to_int("".join(el for el in content[pos+8:pos+10]))
  nbAdditionnels = hex_to_int("".join(el for el in content[pos+10:pos+12]))
      
  #Affichage
  print("\nDNS Protocol Analysis -")
  print("\tIdentifiant             :", "0x"+id)
  print("\tControl                 :", "0x"+control)
  print("\t\tQr     = ",qr)
  print("\t\topcode = ",opcode)
  print("\t\taa     = ",aa)
  print("\t\ttc     = ",tc)
  print("\t\trd     = ",rd)
  print("\t\tra     = ",ra)
  print("\t\tzero   = ",zero)
  print("\t\tad     = ",ad)
  print("\t\tcd     = ",cf)
  print("\t\trcode  = ",rcode)
  print("\n\tQuestions                :",nbQuestions)
  print("\tRéponses                 :",nbReponses)
  print("\tAutorités                :",nbAutorites)
  print("\tAdditionnels             :",nbAdditionnels)
  
  #Section Questions
  pos = pos+13
  print("\n\tsection questions :")
  for i in range(nbQuestions):
      qname = read_name(content, pos,start)
      pos += len(qname)+1
      qtype = "".join(el for el in content[pos:pos+2])
      qclass = "".join(el for el in content[pos+2:pos+4])
      pos+=4
      #print(qname, qtype, qclass)
      print("\t\tqname   : ",qname)
      print("\t\tqtype   : ",qtype)
      print("\t\tqclass  : ",qclass)
  #Section Réponses
  if nbReponses>0:
      print("\n\tsection réponses :")
  for i in range(nbReponses):
      name ,type,classe,m,rdata, pos = read_response(content, pos,start)
      #print(name ,type,classe,rdata)
      print("\t\t***********")
      print("\t\tréponse ",i+1)
      print("\t\tname    : ",name)
      print("\t\ttype    : ",rr_types[hex_to_int(type)])
      print("\t\tclasse  : ","0x"+classe,"(internet)")
      print("\t\trdata   : ",rdata)
  #Section Autorités
  if nbAutorites>0:
      print("\n\tsection autorités :")
  for i in range(nbAutorites):
      name ,type,classe,m,rdata, pos = read_response(content, pos,start)
      print("\t\t***********")
      print("\t\tname    : ",name)
      print("\t\ttype    : ",rr_types[hex_to_int(type)])
      print("\t\tclasse  : ","0x"+classe,"(internet)")
      print("\t\trdata   : ",rdata)  
  #Section Additionnels
  if nbAdditionnels>0:
      print("\n\tsection additionnels :")
  for i in range(nbAdditionnels):
      name ,type,classe,m,rdata, pos = read_response(content, pos,start)
      print("\t\t***********")
      print("\t\tname    : ",name)
      print("\t\ttype    : ",rr_types[hex_to_int(type)])
      print("\t\tclasse  : ","0x"+classe, "(internet)")
      print("\t\trdata   : ",rdata)  
def read_name(content,pos,start):
    name=""
    if content[pos]=="00":
        return ""
    else:
        if hex_to_int(content[pos][0])>11:
            m = bin(int("0x"+"".join(el for el in content[pos:pos+2]),16))[4:] #A revoir
            m1 = int("0b"+m,2)
            name+= read_name(content,start+m1,start)
        else:
            if hex_to_int(content[pos])<30:
                name+="."
            else:
                name+=read_name2(content, pos, 1)
            name+= read_name(content, pos+1, start)
    
    return name

def read_name2(content,pos,taille):
    name=""
    for i in range(taille):
        byte = content[pos+i]
        if byte=="00":
            break
        if hex_to_int(content[pos][0])>11:
            break
        name += byte
    binary_str = codecs.decode(name, "hex")
    str(binary_str,'utf-8')
    return str(binary_str,'utf-8')

def read_response(content,pos,start):
    name,pos = read_section_name(content, pos,start)
    type = "".join(el for el in content[pos:pos+2])

    classe = "".join(el for el in content[pos+2:pos+4])
    #ttl = "".join(el for el in content[pos+4:pos+8])
    rdata_length= "".join(el for el in content[pos+8:pos+10])
    
    m = hex_to_int(rdata_length)
    rdata = ""
    
    if hex_to_int(type) in [5,2,15]:
        #print(rr_types[hex_to_int(type)],read_data_name(content, pos+10, m, start))
        rdata = read_data_name(content, pos+10, m, start)
    else:
        if hex_to_int(type)==1:
            #print(rr_types[hex_to_int(type)],to_ip(content[pos+10:pos+14]))
            rdata = to_ip(content[pos+10:pos+14])
        else:
            if hex_to_int(type)==28:
                #print(rr_types[hex_to_int(type)],to_ip6(content[pos+10:pos+26]))
                rdata = to_ip6(content[pos+10:pos+26])
            else:
                for i in range(m):
                    rdata+=content[pos+10+i]
    pos+=10+m
    return name ,type,classe,m,rdata, pos  

def read_section_name(content,pos,start):
    name=""
    byte = content[pos][0]
    while True:
        if hex_to_int(content[pos][0])>11:
            byte = "".join(el for el in content[pos:pos+2])
            m = bin(int("0x"+byte,16))[4:] #A revoir
            m1 = int("0b"+m,2)
            name += read_name(content, start+m1+1,start)
            pos +=2
        else:
            name += read_name2(content, pos+1,hex_to_int(content[pos]))
            pos += len(name)+1
        if content [pos]=="00":
            break
        else:
            name+="."
    return name,pos

def read_data_name(content,pos,length,start):
    name=""
    byte = content[pos][0]
    k=0
    while True:
        if hex_to_int(content[pos][0])>11:
            byte = "".join(el for el in content[pos:pos+2])
            m = bin(int("0x"+byte,16))[4:] #A revoir
            m1 = int("0b"+m,2)
            name += read_name(content, start+m1+1,start)
            pos +=2
            k+=2
        else:
            name += read_name2(content, pos+1,hex_to_int(content[pos]))
            k+= hex_to_int(content[pos])+1
            pos += hex_to_int(content[pos])+1
        if k==length:
            break
        else:
            name+="."
    return name