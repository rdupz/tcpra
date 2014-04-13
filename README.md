#tcpra
TCP Reordering Analysis
#===
Ce programme analyse des traces TCP capturées afin de trouver les paquets TCP qui sont reçu en mauvais ordre, et le “retard” de ces paquets.
#----
#Installation

Dépendances : *libpcap* *libpcap-dev*

Se placer dans le repertoire contenant la makefile et taper `make`.
Cette commande va générer un binaire executable nommé `tcpra`.

#Utilisation

```
tcpra [OPTIONS] [FILE]
	
	DESCRIPTION:
	Le programme prend en paramètre un fichier de capture au format .pcap.
	Pour un fichier name.pcap passé en argument, tcpra génère un fichier
	name.csv dans le même repertoire que name.pcap.
	Le fichier name.csv contient les informations relatives au problèmes 
	d'ordre de la capture suivant le format :

	identifiant_du_paquet1,retard_du_paquet1
	...,...
	identifiant_du_paquetN,retard_du_paquetN



	OPTIONS:
	
	-m maxlate
		Spécifie le retard maximum d'un paquet avant qu'il soit considéré comme perdu et abandonné.
		Par défaut, le retard maximum est de 10000.
	-w
		Demande au programme de générer un fichier "pcapnamefile".lost contenant la liste des paquets considérés comme perdus.
```

#Implémentation
Le programme utilise la bibliothèque *pcap.h* pour lire les paquets de la trame à analyser.
Puisque les fonctions de cette bibliothèque ne permettent pas de revenir en arrière durant la lecture, nous avons choisis, plutôt que d’ouvrir plusieurs fois la même trame à l’exécution, de stocker les informations utiles des paquets dans une liste.
En effet, pour chaque paquet, le programme vérifie qu’il est valide, puis sauvegarde dans une structure son numéro de séquence ainsi que le numero de séquence attendue pour le paquet suivant. La structure correspondant est ajoutée à la suite de la liste.
Une fois tous les paquets ajoutés à la liste, le calcul des retards commence. Pour chaque paquet de séquence *seqcurrent*, si la séquence du paquet suivant *seqnext* ne correspond pas à la séquence *seqexpected* attendue, on compte le nombre de paquets parcourus avant de trouver le paquet défini par *seqexpected*. Ce dernier trouvé, on l’efface et cherche à partir de *seqcurrent* le paquet qui doit suivre *seqexpected* défini par la séquence *seqexpected2*. Et ceci jusqu’à ce que *seqexpectedN* = *seqnext*. On peut ensuite changer de *seqcurrent* en avançant dans la liste, tout en effaçant l’ancien *seqcurrent* pour nettoyer la liste.

Il arrive cependant que le paquet recherché ne soit pas présent du tout dans la trame capturée. Ceci entraîne donc une recherche assez longue puisque parcourant la totalité des paquets restant. On choisit donc de limiter la recherche aux *maxlate* paquets suivants. Les pires retards que l’on a pu observés étaient de l’ordre de 200 paquets, mais on a quand même choisi un maxlate par défaut de 10000, ce qui constitue un bon compromis entre performance et justesse de l’algorithme.
Le programme offre la possibilité, avec l’option -w, d’écrire dans un fichier ‘.lost’ les paquets considérés comme perdus car non trouvés durant la recherche (soit parce qu’il ne sont pas du tout présents dans la trame, soit parce que leur retard est supérieur à *maxlate*).

###Précisions quant au format des trames
Les trames analysées par le programme doivent avoir l’extension ‘.pcap’. Les paquets dont l’ordre sera analysé sont ceux dont la destination est la même que celle du premier paquet SYN-ACK de la trame et dont le payload n’est pas nul.
En d’autres termes, le programme détecte l’IP qui va recevoir les données en cherchant le destinataire du premier paquet SYN-ACK de la trame. Il se concentre ensuite uniquement sur les paquets qui lui sont destinés. De plus, il ignore les paquets ne contenant aucune charge utile.
