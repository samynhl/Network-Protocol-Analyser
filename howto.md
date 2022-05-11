-----------------------------------------------------------------------------------
MANUEL D'UTILISATION ANALYSEUR DE PROTOCOLES INTERNET
-----------------------------------------------------------------------------------
Pour exécuter l'analyseur de protocoles internet, Vous devez suivre 
les étapes suivre :

o Placez vous dans le repertoire contenant le programme main.exe et le lancer.

o Un dialogue de fichiers s'affiche, vous devez préciser le fichier .txt trace
contenant les octets du message à afficher.
	
o Vous devez maintenant indiquer le numéro de la séquence d'octets (ou message)
à analyser.

o Le programme doit afficher toute l'analyse du message selectionné ainsi qu'un
menu pour la les différentes options.

o Le menu principal contient différentes options selon les protocoles présents
dans le message. Pour un message contenant tout les protocoles (ie ethernet,ip-
udp-dns ou dhcp), la forme du menu principal ressemblerai à celle ci:

	******************************************
	Menu
		1- Afficher les octets du la trame
		2- Afficher Trame Ethernet
		3- Afficher Paquet IP
		4- Afficher Segment UDP
		5- Afficher dns
		0- Exit
	******************************************
	Entrer votre choix: 

où pour chaque option est associé un numéro qu'il suffit de le faire entrer 
pour exécuter cette option.

o Pour choisir une autre trame, cliquer sur 9

o Pour quitter le programme, cliquer sur 0
