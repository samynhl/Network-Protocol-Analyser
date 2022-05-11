# -*- coding: utf-8 -*-
"""
Created on Wed Oct 27 10:36:23 2021

@author: PC
"""
#DATA STRUCTURES
#Ethernet
list_hexa = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
                 
#UTIL FUNCTIONS
#Verify whether a hexa word is valid or not (contains hexa characters)
def isValid(word):
  for c in word:
    if c.lower() not in list_hexa:
      return False
  return True

#count number of messages in a file (by the number of 0000 offset)
def countMsgs(lines):
  cpt = 0
  nbException = 0
  for line in lines:
    if line!="\n":
      offset = line.split()[0]
      try:
        offset = line.split()[0]
      except:
        print("exception")
        nbException = nbException+1
      if offset=="0000" and len(line)>7:
        cpt = cpt +1
  
  print("Number of frames of the file:",cpt)
  return cpt,nbException

#retrieve message number n from text file
def retrieveMsg(lines, n):
  cpt = 0
  msg = []
  for line in lines:
    if line!="\n":
      try:
        offset = line.split()[0]
      except:
        pass
      if offset=="0000":
        cpt = cpt +1
      if cpt == n:
        if len(line.strip())>8:
          msg.append(line)
      else: 
        if cpt>n:
          break
  return msg

#clean the message from endline characters
def clean(msg):
  msgout = []
  for line in msg:
    line = line.split(" ")
    b = False
    for i in range(len(line)-2):
      if line[i]=="" and line[i+1]=="":
        msgout.append(line[:i])
        b = True
        break
    if line[len(line)-1][len(line[len(line)-1])-1]=="\n" and b == False:
      line[len(line)-1] = line[len(line)-1][:len(line[len(line)-1])-1]
      msgout.append(line)
  return msgout

#retrieve msg content
def retrieveMsgContent(msg):
  msgout = []
  msg_ = msg
  for line in msg_:
    for i in line[1:]:
      msgout.append(i)
  return msgout

#verify if the sum of bytes and the current offset is equal to the next offset
#verify if all bytes are well written in hexa
def verifyMsg(lines,numsg, n):
  if numsg>n:
    #print("Frame number out of frames range 1 -",n)
    return None
  check = True
  msg_ = retrieveMsg(lines, numsg)
  msg = clean(msg_)
  offset = "0000" #init with first line offset
  try:
    taille = len(msg[0][2:])
  except:
    print(msg)
  k = 0
  #afficher le message
  for line in msg:
    line.pop(1) #remove the space
    taille_ligne = len(line[1:])
    offset_ligne = line[0]
    if k>0:
      n = sumh(offset, taille)
      if n == hex(int("0x"+offset_ligne,16)):
        #print(n, "||", offset_ligne,"=> valid lign")
        offset = offset_ligne
        taille = taille_ligne
        for el in line[1:]:
          if isValid(el)==False or len(el)!=2:
            print("************************************************************")
            print("Invalid caracter '", el,"'" , "in lign", k+1,"of frame", numsg)
            check = False
            break
      else:
        print("************************************************************")
        print("Invalid lign", k+1,"of frame", numsg)
        return None
    else:
        for el in line[1:]:
          if isValid(el)==False or len(el)!=2:
            print("************************************************************")
            print("Invalid caracter '", el,"'" , "in lign", k+1,"of frame", numsg)
            check = False
            break
    k=k+1
    #print(line, "off:",offset_ligne,"Taille:",taille_ligne)
  #affichage
  if check==True:
    #print("Message",numsg, "Succesfully Verified and ready to analyse !\n")
    return msg
  else:
    return None

#sum in hexa
def sumh(offset, taille):
  return hex(int("0x"+offset,16)+taille)

#show message
def show(msg):
  for line in msg:
    print(line)

#compose ip adress
def to_ip(chaine):
    adr=""
    for el in chaine:
      adr=adr+str(int("0x"+el,16))+"."
    adr = adr[:len(adr)-1]
    return adr

#compose ipv6 adress
def to_ip6(chaine): #chaine est une chaine de 16 octet
    adr=""
    k=0
    while k!=len(chaine):
        adr += str(chaine[k]+chaine[k+1])+":"
        k+=2
    adr = adr[:len(adr)-1]
    return adr

#compose mac adress
def to_mac(chaine):
    adr=""
    for el in chaine:
      adr=adr+el+":"
    adr = adr[:len(adr)-1]
    return adr

def hex_to_int(hexnumber):
    return int("0x"+hexnumber,16)

def check_user_input(input):
    try:
        int(input)
        return True
    except ValueError:
        return False
    
#test
#chaine = ["20","01","ab","cd","22","34","a1","2c","20","01","ab","cd","22","34","a1","2c"]
#print(to_ip6(chaine))