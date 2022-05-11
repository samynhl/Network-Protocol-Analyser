***********************************************************************************
Description de la structure du code:
***********************************************************************************
Ce document décrit la structure du code de notre analyseur de protocoles
internet offline.

Le code de notre analyseur de protocoles internet est organisé en modules étant
donné qu’on a opté pour une approche procédurale pour le développement de
ce projet.
Le choix de l’approche procédurale est selon nous, le plus adapté à ce projet
de sa nature qui se penche plus vers le traitement de texte (chaine de caractères).
Concernant le choix du langage de programmation, nous avons opté pour
le langage Python, ce dernier est puissant avec tout ce qui est traitement du
texte et la manipulation de fichiers, c’est aussi le meuilleur langage pour une
approche procédurale.
Pour l’affichage de résultat de notre analyseur, ce dernier se fait en mode
console (terminal).

De vue globale, le code du projet se compose de 08 modules: un module
utilitaire (util.py), 05 modules relatifs aux protocoles à analyser (ethernet,ip,
udp, dhcp, dns), un module de controle et enfin un module main qui a pour rôle
l’execution du programme et l’affichage du menu principal.

Dans ce document nous allons décrire la structure du code, la description de
chaque module ainsi que la manière dont le projet s’exécute comme un tout.
**********************************************************************************
Découpage modulaire
**********************************************************************************
Module 1 : Util.py
Ce module contient plusieurs fonctions utilitaires qui vont servir les autres modules
du programme, ces fonctions permettent essentiellement le traitement du
texte, la vérification de la validité d’une trame et de chaque caractère qu’elle
contient, des conversions utiles (par exemple chaine en adresse ip; chaine en
adresse mac ..)
Les fonctions de ce module sont:
 	isValid() : retourne vrai si un caractère est en hexadécimal.
 	countMsgs(), clean() : compte le nombre de messages du fichier, et enlève
			les caractères de fin de ligne.
 	verifyMsg() : vérifie si la taille des lignes d’un message correspond 
			à l’offset annoncé au début du message
 	retrieveMsg() : retourne le message i du fichier indiqué en paramètre.
 	retrieveMsgContent() : retourne le contenu du message sous la forme d’une
			liste
 	sumh(), toip(), toip6(), tomac(), hextoint(), checkuserinput()

Module 2 : ethernet.py
Ce module contient la fonction retrieveEthernet qui, comme son nom l’indique,
extrait du paquet d’octets l’entête du protocole de couche 2 ethernet.
Cette fonction lit séquentiellement les champs du paquet (liste d’octets) passés
en entrée, et extrait les champs : adresse destination, adresse source, type
ethernet.
Si le champs type ethernet extrait auparavant indique qu’il y a un vlan, la
fontion affiche également les informations qui lui sont liées.
Cette fonction retourne la position dans laquelle elle s’est arrêtée (afin que le
protocole ip puisse continuer l’analyse), ainsi que le type du protocole de couche
supérieure que cette trame encapsule.(ip dans notre cas).

Module 3 : ip.py
Ce module contient la fonction retrieveIP qui, comme son nom l’indique, extrait
du paquet d’octets l’entête du protocole de couche 3 Ip.
Cette fonction lit séquentiellement les champs du paquet (liste d’octets) passés
en entrée à partir de la position ou s’est arrêtée la trame ethernet, et extrait 
les différents champs du paquet IP.
Si le paquet contient des options, la fontion affiche également les différents
champs de ces dernières, et traite en particulier le cas de l’option record route
vu en cours.
Cette fonction retourne la position dans laquelle elle s’est arrêtée (afin que le
protocole udp puisse continuer l’analyse), ainsi que le type du protocole de
couche supérieure que ce paquet encapsule (tcp, udp,icmp).

Module 4 : udp.py
Ce module contient la fonction retrieveUDP qui, comme son nom l’indique, extrait
du paquet d’octets l’entête du protocole de couche 4 UDP (User Datagram
Protocol).
Cette fonction lit séquentiellement les champs du segment (liste d’octets) passés
en entrée à partir de la position ou s’est arrêté le paquet IP, et extrait les
différents champs du datagramme UDP (port source, port destination, longueur,
checksum).
Cette fonction retourne la position dans laquelle elle s’est arrêtée, ainsi que le
type du protocole de la couche applicative que ce datagramme encapsule.

Module 5 : dhcp.py
Ce module contient la fonction retrieveDHCP qui, comme son nom l’indique,
extrait du paquet d’octets l’entête du protocole de la couche application DHCP
(Dynamic Host Configuration Protocol).
Cette fonction lit séquentiellement les champs du segment (liste d’octets) passés
en entrée à partir de la position ou s’est arrêté le datagramme DHCP, et extrait
les différents champs de l’entête DHCP, ainsi que les options s’il y en a.

Module 6 : dns.py
Ce module contient la fonction retrieveDNS qui, comme son nom l’indique,
extrait du paquet d’octets l’entête du protocole de la couche application DNS
(Domain Name Server).
Cette fonction lit séquentiellement les champs du segment (liste d’octets) passés
en entrée à partir de la position ou s’est arrêté le paquet IP, et extrait les
différents champs de l’entête DNS.
Cette fonction traite également la compression de noms utilisée par DNS (dans
le but de réduire la taille des données envoyées).
En plus de la fonction retrieveDNS, le module dns.py contient également les
fonctions suivantes:
 readresponse() : retourne les champs de la section réponse, autorité et
	additionnels.
 readname() : lit le nom de section, si un nom est compréssé (par ex C032),
	lit récursivement le nom dans le même paquet.
 readdataname()

Module 7 : control.py
Ce module contient la fonction Analyse qui a pour role l’analyse de tout
les messages contenus dans le fichier et retourner l’analyse sous forme d’un
fichier .txt formaté créé dans le même répertoire que le fichier trace.
Pour l’idée de ce module :
– Parcourir tout les messages du fichier trace de l’entrée
– Pour chaque message (suite d’octets), le module utilise les fonctions
du module util.py pour enlever les caractères de fin de chaines, vérifier
s’il est valide (ie tout ses caractères sont en hexadécimal ainsi que la
longueur des lignes avec l’offset suivant, puis extraire le contenu de
ce message afin d’entamer l’analyse.
– Le contenu de la suite d’octets représentant le message étant prêt
à être analysé, le module exécute séquentiellement le module ethernet.
py, ip.py, udp.py, dns.py (ou dhcp.py).
– le module control.py exporte les résultats de tout les modules vers
un fichier result.txt comme indiqué dans le cahier des charges.

Module 8 : main.py
Ce module contient la fonction main qui exécute la fonction analyse, ainsi
que l’affichage du menu principal de notre analyseur.
***********************************************************************************
Fonctionnement du code.
***********************************************************************************
A l’exécution de la fonction main du projet, cette dernière va créer -grâce
à la fonction analyse- un fichier résultat avec le suffixe "-result" dans son
nom dans le même repertoire que le fichier source de l’entrée, ce fichier
contient l’analyse protocolaire de toutes les trams du fichiers trace.
De plus, la fonction main fait appel au programme analyse avec un numéro
de trame pour afficher l’analyse de cette trame ainsi que le menu principal
dans la console.
