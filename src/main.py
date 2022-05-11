# -*- coding: utf-8 -*-
"""
Created on Wed Oct 27 10:35:51 2021

@author: PC
"""
from control import analyse
from util import countMsgs,verifyMsg,retrieveMsgContent, check_user_input
from ethernet import retrieveEthernet
from ip import retrieveIP
from udp import retrieveUDP
from dhcp import retrieveDHCP
from dns import retrieveDNS
import sys, os
              
def main(path,k):
    print("Fichier résultat créé dans le repertoire \n", path[:len(path)-4],"\n")
    with open(path,'r') as f:
          lines = f.readlines()               #lecture du fichier
          n, nbException = countMsgs(lines)   #count frames in the text file
          msg = verifyMsg(lines,k,n)          #verify and return the message
          msg1 = msg
          #
          protocol2 = ""
          protocol3 = ""
          if msg!=None and len(msg)>0:
            content = retrieveMsgContent(msg) #retrieve msg content
            pos1, ethertype= retrieveEthernet(content)    #Analyse ethernet frame
            if (ethertype=="0800"):
              pos2, protocol2 = retrieveIP(content,pos1)    #Analyse IP packet
              if protocol2=="11":
                pos3, protocol3 = retrieveUDP(content,pos2) #Analyse UDP segment
                #pos = retrieveDHCP(content,pos)
                if protocol3=="dhcp":
                    retrieveDHCP(content,pos3)      #Analyse DHCP Header
                if protocol3=="dns":
                    retrieveDNS(content,pos3)      #Analyse DNS Header """

            #menu du programme principal
            while True:
                print("\n\t**************************************")
                print("\tMenu")
                print("\t\t1- Afficher les octets du la trame")
                print("\t\t2- Afficher Trame Ethernet")
                print("\t\t3- Afficher Paquet IP")
                if protocol2=="11":
                    print("\t\t4- Afficher Segment UDP")
                    if protocol3=="dhcp" or protocol3=="dns":
                        print("\t\t5- Afficher "+ protocol3)
                print("\t\t9- Choisir une autre trame")
                print("\t\t0- Exit")
                print("\t**************************************")
                try:
                    n = input("\tEntrer votre choix: ")       
                except:
                    print("Entrée invalide, veuillez réessayer")  
                if check_user_input(n):
                    if int(n)==2:
                        retrieveEthernet(content)    #Analyse ethernet frame
                    if int(n)==3:
                        retrieveIP(content,pos1)   #Analyse ip packet
                    if int(n)==4:
                        retrieveUDP(content,pos2)   #Analyse ip packet
                    if int(n)==5:
                        if protocol3=="dhcp":
                            retrieveDHCP(content,pos3)      #Analyse DHCP Header
                        if protocol3=="dns":
                            retrieveDNS(content,pos3)
                    if int(n)==1:
                        for line in msg1:
                            ch=""
                            for el in line:
                                ch+=el+" "
                            print("\t\t",ch)
                    if int(n)==9:
                        return 1
                    if int(n)==0:
                        return 0
                else:
                    print("Entrée invalide, veuillez réessayer")
                    

#Execution du main
try:
    #fname = gui_fname() ligne qui pose problème
    fname = input("Donner le chemin vers le fichier: ") #ligne rajoutée
    analyse(fname)
    while True:
        try:
            k = input("Choisir le numéro de message à analyser, choisir 0 pour quitter: ")
        except:
            print("Entrée invalide, veuillez réessayer")  
        if check_user_input(k):
            if int(k) == 0:
                break
            else:
                a = main(fname,int(k))
                if a==0:
                    break
        else :
            print("Entrée invalide, veuillez réessayer")
except FileNotFoundError:
    print("Wrong file or file path")
except KeyboardInterrupt:
    print('Interrupted')
    try:
        sys.exit(0)
    except SystemExit:
        os._exit(0)
