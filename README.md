# Teaching-HEIGVD-SRX-2022-Laboratoire-Snort

**Ce travail de laboratoire est à faire en équipes de 2 personnes**

**ATTENTION : Commencez par créer un Fork de ce repo et travaillez sur votre fork.**

Clonez le repo sur votre machine. Vous pouvez répondre aux questions en modifiant directement votre clone du README.md ou avec un fichier pdf que vous pourrez uploader sur votre fork.

**Le rendu consiste simplement à répondre à toutes les questions clairement identifiées dans le text avec la mention "Question" et à les accompagner avec des captures. Le rendu doit se faire par une "pull request". Envoyer également le hash du dernier commit et votre username GitHub par email au professeur et à l'assistant**

## Table de matières

[Introduction](#introduction)

[Echéance](#echéance)

[Démarrage de l'environnement virtuel](#démarrage-de-lenvironnement-virtuel)

[Communication avec les conteneurs](#communication-avec-les-conteneurs)

[Configuration de la machine IDS et installation de Snort](#configuration-de-la-machine-ids-et-installation-de-snort)

[Essayer Snort](#essayer-snort)

[Utilisation comme IDS](#utilisation-comme-un-ids)

[Ecriture de règles](#ecriture-de-règles)

[Travail à effectuer](#exercises)

[Cleanup](#cleanup)


## Echéance

Ce travail devra être rendu au plus tard, **le 29 avril 2022 à 08h30.**


## Introduction

Dans ce travail de laboratoire, vous allez explorer un système de détection contre les intrusions (IDS) dont l'utilisation es très répandue grâce au fait qu'il est gratuit et open source. Il s'appelle [Snort](https://www.snort.org). Il existe des versions de Snort pour Linux et pour Windows.

### Les systèmes de détection d'intrusion

Un IDS peut "écouter" tout le traffic de la partie du réseau où il est installé. Sur la base d'une liste de règles, il déclenche des actions sur des paquets qui correspondent à la description de la règle.

Un exemple de règle pourrait être, en langage commun : "donner une alerte pour tous les paquets envoyés par le port http à un serveur web dans le réseau, qui contiennent le string 'cmd.exe'". En on peut trouver des règles très similaires dans les règles par défaut de Snort. Elles permettent de détecter, par exemple, si un attaquant essaie d'éxecuter un shell de commandes sur un serveur Web tournant sur Windows. On verra plus tard à quoi ressemblent ces règles.

Snort est un IDS très puissant. Il est gratuit pour l'utilisation personnelle et en entreprise, où il est très utilisé aussi pour la simple raison qu'il est l'un des systèmes IDS des plus efficaces.

Snort peut être exécuté comme un logiciel indépendant sur une machine ou comme un service qui tourne après chaque démarrage. Si vous voulez qu'il protège votre réseau, fonctionnant comme un IPS, il faudra l'installer "in-line" avec votre connexion Internet.

Par exemple, pour une petite entreprise avec un accès Internet avec un modem simple et un switch interconnectant une dizaine d'ordinateurs de bureau, il faudra utiliser une nouvelle machine éxecutant Snort et placée entre le modem et le switch.


## Matériel

Vous avez besoin de votre ordinateur avec Docker et docker-compose. Vous trouverez tous les fichiers nécessaires pour générer l'environnement pour virtualiser ce labo dans le projet que vous avez cloné.


## Démarrage de l'environnement virtuel

Ce laboratoire utilise docker-compose, un outil pour la gestion d'applications utilisant multiples conteneurs. Il va se charger de créer un réseaux virtuel `snortlan`, la machine IDS, un client avec un navigateur Firefox, une machine "Client" et un conteneur Wireshark directement connecté à la même interface réseau que la machine IDS. Le réseau LAN interconnecte les autres 3 machines (voir schéma ci-dessous).

![Plan d'adressage](images/docker-snort.png)

Nous allons commencer par lancer docker-compose. Il suffit de taper la commande suivante dans le répertoire racine du labo, celui qui contient le fichier [docker-compose.yml](docker-compose.yml). Optionnelement vous pouvez lancer le script [up.sh](scripts/up.sh) qui se trouve dans le répertoire [scripts](scripts), ainsi que d'autres scripts utiles pour vous :

```bash
docker-compose up --detach
```

Le téléchargement et génération des images prend peu de temps.

Les images utilisées pour les conteneurs client et la machine IDS sont basées sur l'image officielle Kali. Le fichier [Dockerfile](Dockerfile) que vous avez téléchargé contient les informations nécessaires pour la génération de l'image de base. [docker-compose.yml](docker-compose.yml) l'utilise comme un modèle pour générer ces conteneurs. Les autres deux conteneurs utilisent des images du groupe LinuxServer.io. Vous pouvez vérifier que les quatre conteneurs sont crées et qu'ils fonctionnent à l'aide de la commande suivante.

```bash
docker ps
```

## Communication avec les conteneurs

Afin de simplifier vos manipulations, les conteneurs ont été configurées avec les noms suivants :

- IDS
- Client
- wireshark
- firefox

Pour accéder au terminal de l’une des machines, il suffit de taper :

```bash
docker exec -it <nom_de_la_machine> /bin/bash
```

Par exemple, pour ouvrir un terminal sur votre IDS :

```bash
docker exec -it IDS /bin/bash
```

Optionnelement, vous pouvez utiliser les scripts [openids.sh](scripts/openids.sh), [openfirefox.sh](scripts/openfirefox.sh) et [openclient.sh](scripts/openclient.sh) pour contacter les conteneurs.

Vous pouvez bien évidemment lancer des terminaux communiquant avec toutes les machines en même temps ou même lancer plusieurs terminaux sur la même machine. ***Il est en fait conseillé pour ce laboratoire de garder au moins deux terminaux ouverts sur la machine IDS en tout moment***.


### Configuration de la machine Client et de firefox

Dans un terminal de votre machine Client et de la machine firefox, taper les commandes suivantes :

```bash
ip route del default
ip route add default via 192.168.220.2
```

Ceci configure la machine IDS comme la passerelle par défaut pour les deux autres machines.


## Configuration de la machine IDS et installation de Snort

Pour permettre à votre machine Client de contacter l'Internet à travers la machine IDS, il faut juste une petite règle NAT par intermédiaire de nftables :

```bash
nft add table nat
nft 'add chain nat postrouting { type nat hook postrouting priority 100 ; }'
nft add rule nat postrouting meta oifname "eth0" masquerade
```

Cette commande `iptables` définit une règle dans le tableau NAT qui permet la redirection de ports et donc, l'accès à l'Internet pour la machine Client.

On va maintenant installer Snort sur le conteneur IDS.

La manière la plus simple c'est d'installer Snort en ligne de commandes. Il suffit d'utiliser la commande suivante :

```
apt update && apt install snort
```

Ceci télécharge et installe la version la plus récente de Snort.

Il est possible que vers la fin de l'installation, on vous demande de fournir deux informations :

- Le nom de l'interface sur laquelle snort doit surveiller - il faudra répondre ```eth0```
- L'adresse de votre réseau HOME. Il s'agit du réseau que vous voulez protéger. Cela sert à configurer certaines variables pour Snort. Vous pouvez répondre ```192.168.220.0/24```.


## Essayer Snort

Une fois installé, vous pouvez lancer Snort comme un simple "sniffer". Pourtant, ceci capture tous les paquets, ce qui peut produire des fichiers de capture énormes si vous demandez de les journaliser. Il est beaucoup plus efficace d'utiliser des règles pour définir quel type de trafic est intéressant et laisser Snort ignorer le reste.

Snort se comporte de différentes manières en fonction des options que vous passez en ligne de commande au démarrage. Vous pouvez voir la grande liste d'options avec la commande suivante :

```
snort --help
```

On va commencer par observer tout simplement les entêtes des paquets IP utilisant la commande :

```
snort -v -i eth0
```

**ATTENTION : le choix de l'interface devient important si vous avez une machine avec plusieurs interfaces réseau. Dans notre cas, vous pouvez ignorer entièrement l'option ```-i eth0```et cela devrait quand-même fonctionner correctement.**

Snort s'éxecute donc et montre sur l'écran tous les entêtes des paquets IP qui traversent l'interface eth0. Cette interface reçoit tout le trafic en provenance de la machine "Client" puisque nous avons configuré le IDS comme la passerelle par défaut.

Pour arrêter Snort, il suffit d'utiliser `CTRL-C` (**attention** : en ligne générale, ceci fonctionne si vous patientez un moment... Snort est occupé en train de gérer le contenu du tampon de communication et cela qui peut durer quelques secondes. Cependant, il peut arriver de temps à autres que Snort ne réponde plus correctement au signal d'arrêt. Dans ce cas-là, il faudra utiliser `kill` depuis un deuxième terminal pour arrêter le process).


## Utilisation comme un IDS

Pour enregistrer seulement les alertes et pas tout le trafic, on execute Snort en mode IDS. Il faudra donc spécifier un fichier contenant des règles.

Il faut noter que `/etc/snort/snort.config` contient déjà des références aux fichiers de règles disponibles avec l'installation par défaut. Si on veut tester Snort avec des règles simples, on peut créer un fichier de config personnalisé (par exemple `mysnort.conf`) et importer un seul fichier de règles utilisant la directive "include".

Les fichiers de règles sont normalement stockes dans le répertoire `/etc/snort/rules/`, mais en fait un fichier de config et les fichiers de règles peuvent se trouver dans n'importe quel répertoire de la machine.

Par exemple, créez un fichier de config `mysnort.conf` dans le repertoire `/etc/snort` avec le contenu suivant :

```
include /etc/snort/rules/icmp2.rules
```

Ensuite, créez le fichier de règles `icmp2.rules` dans le repertoire `/etc/snort/rules/` et rajoutez dans ce fichier le contenu suivant :

`alert icmp any any -> any any (msg:"ICMP Packet"; sid:4000001; rev:3;)`

On peut maintenant éxecuter la commande :

```
snort -c /etc/snort/mysnort.conf
```

Vous pouvez maintenant faire quelques pings depuis votre "Client" et regarder les résultas dans le fichier d'alertes contenu dans le repertoire `/var/log/snort/`.


## Ecriture de règles

Snort permet l'écriture de règles qui décrivent des tentatives de exploitation de vulnérabilités bien connues. Les règles Snort prennent en charge à la fois, l'analyse de protocoles et la recherche et identification de contenu.

Il y a deux principes de base à respecter :

* Une règle doit être entièrement contenue dans une seule ligne
* Les règles sont divisées en deux sections logiques : (1) l'entête et (2) les options.

L'entête de la règle contient l'action de la règle, le protocole, les adresses source et destination, et les ports source et destination.

L'option contient des messages d'alerte et de l'information concernant les parties du paquet dont le contenu doit être analysé. Par exemple:

```
alert tcp any any -> 192.168.220.0/24 111 (content:"|00 01 86 a5|"; msg: "mountd access";)
```

Cette règle décrit une alerte générée quand Snort trouve un paquet avec tous les attributs suivants :

* C'est un paquet TCP
* Emis depuis n'importe quelle adresse et depuis n'importe quel port
* A destination du réseau identifié par l'adresse 192.168.220.0/24 sur le port 111

Le text jusqu'au premier parenthèse est l'entête de la règle.

```
alert tcp any any -> 192.168.220.0/24 111
```

Les parties entre parenthèses sont les options de la règle:

```
(content:"|00 01 86 a5|"; msg: "mountd access";)
```

Les options peuvent apparaître une ou plusieurs fois. Par exemple :

```
alert tcp any any -> any 21 (content:"site exec"; content:"%"; msg:"site
exec buffer overflow attempt";)
```

La clé "content" apparait deux fois parce que les deux strings qui doivent être détectés n'apparaissent pas concaténés dans le paquet mais a des endroits différents. Pour que la règle soit déclenchée, il faut que le paquet contienne **les deux strings** "site exec" et "%".

Les éléments dans les options d'une règle sont traités comme un AND logique. La liste complète de règles sont traitées comme une succession de OR.

## Informations de base pour le règles

### Actions :

```
alert tcp any any -> any any (msg:"My Name!"; content:"Skon"; sid:1000001; rev:1;)
```

L'entête contient l'information qui décrit le "qui", le "où" et le "quoi" du paquet. Ça décrit aussi ce qui doit arriver quand un paquet correspond à tous les contenus dans la règle.

Le premier champ dans le règle c'est l'action. L'action dit à Snort ce qui doit être fait quand il trouve un paquet qui correspond à la règle. Il y a six actions :

* alert - générer une alerte et écrire le paquet dans le journal
* log - écrire le paquet dans le journal
* pass - ignorer le paquet
* drop - bloquer le paquet et l'ajouter au journal
* reject - bloquer le paquet, l'ajouter au journal et envoyer un `TCP reset` si le protocole est TCP ou un `ICMP port unreachable` si le protocole est UDP
* sdrop - bloquer le paquet sans écriture dans le journal

### Protocoles :

Le champ suivant c'est le protocole. Il y a trois protocoles IP qui peuvent être analysés par Snort : TCP, UDP et ICMP.


### Adresses IP :

La section suivante traite les adresses IP et les numéros de port. Le mot `any` peut être utilisé pour définir "n'import quelle adresse". On peut utiliser l'adresse d'une seule machine ou un block avec la notation CIDR.

Un opérateur de négation peut être appliqué aux adresses IP. Cet opérateur indique à Snort d'identifier toutes les adresses IP sauf celle indiquée. L'opérateur de négation est le `!`.

Par exemple, la règle du premier exemple peut être modifiée pour alerter pour le trafic dont l'origine est à l'extérieur du réseau :

```
alert tcp !192.168.220.0/24 any -> 192.168.220.0/24 111
(content: "|00 01 86 a5|"; msg: "external mountd access";)
```

### Numéros de Port :

Les ports peuvent être spécifiés de différentes manières, y-compris `any`, une définition numérique unique, une plage de ports ou une négation.

Les plages de ports utilisent l'opérateur `:`, qui peut être utilisé de différentes manières aussi :

```
log udp any any -> 192.168.220.0/24 1:1024
```

Journaliser le traffic UDP venant d'un port compris entre 1 et 1024.

--

```
log tcp any any -> 192.168.220.0/24 :6000
```

Journaliser le traffic TCP venant d'un port plus bas ou égal à 6000.

--

```
log tcp any :1024 -> 192.168.220.0/24 500:
```

Journaliser le traffic TCP venant d'un port privilégié (bien connu) plus grand ou égal à 500 mais jusqu'au port 1024.


### Opérateur de direction

L'opérateur de direction `->`indique l'orientation ou la "direction" du trafique.

Il y a aussi un opérateur bidirectionnel, indiqué avec le symbole `<>`, utile pour analyser les deux côtés de la conversation. Par exemple un échange telnet :

```
log 192.168.220.0/24 any <> 192.168.220.0/24 23
```

## Alertes et logs Snort

Si Snort détecte un paquet qui correspond à une règle, il envoie un message d'alerte ou il journalise le message. Les alertes peuvent être envoyées au syslog, journalisées dans un fichier text d'alertes ou affichées directement à l'écran.

Le système envoie **les alertes vers le syslog** et il peut en option envoyer **les paquets "offensifs" vers une structure de repertoires**.

Les alertes sont journalisées via syslog dans le fichier `/var/log/snort/alerts`. Toute alerte se trouvant dans ce fichier aura son paquet correspondant dans le même repertoire, mais sous le fichier `snort.log.xxxxxxxxxx` où `xxxxxxxxxx` est l'heure Unix du commencement du journal.

Avec la règle suivante :

```
alert tcp any any -> 192.168.220.0/24 111
(content:"|00 01 86 a5|"; msg: "mountd access";)
```

un message d'alerte est envoyé à syslog avec l'information "mountd access". Ce message est enregistré dans `/var/log/snort/alerts` et le vrai paquet responsable de l'alerte se trouvera dans un fichier dont le nom sera `/var/log/snort/snort.log.xxxxxxxxxx`.

Les fichiers log sont des fichiers binaires enregistrés en format pcap. Vous pouvez les ouvrir avec Wireshark ou les diriger directement sur la console avec la commande suivante :

```
tcpdump -r /var/log/snort/snort.log.xxxxxxxxxx
```

Vous pouvez aussi utiliser des captures Wireshark ou des fichiers snort.log.xxxxxxxxx comme source d'analyse por Snort.

## Exercices

**Réaliser des captures d'écran des exercices suivants et les ajouter à vos réponses.**

### Essayer de répondre à ces questions en quelques mots, en réalisant des recherches sur Internet quand nécessaire :

**Question 1: Qu'est ce que signifie les "preprocesseurs" dans le contexte de Snort ?**

---

Les préprocesseurs sont des modules d’extension pour arranger ou modifier les paquets de données avant que le moteur de détection n’intervienne. Certains préprocesseurs détectent aussi des anomalies
dans les entêtes des paquets et génèrent alors des alertes.

---

**Question 2: Pourquoi êtes vous confronté au WARNING suivant `"No preprocessors configured for policy 0"` lorsque vous exécutez la commande `snort` avec un fichier de règles ou de configuration "fait-maison" ?**

---

Car nous n'avons pas configuré de préprocesseur dans notre configuration "fait-maison"

---

--

### Trouver du contenu :

Considérer la règle simple suivante:

alert tcp any any -> any any (msg:"Mon nom!"; content:"Rubinstein"; sid:4000015; rev:1;)

**Question 3: Qu'est-ce qu'elle fait la règle et comment ça fonctionne ?**

---

Pour tous les paquets tcp de partout à partout, il donne l'alert "Mon nom!" lorsque le contenu "Rubinstein" est détecté

---

Utiliser nano pour créer un fichier `myrules.rules` sur votre répertoire home (```/root```). Rajouter une règle comme celle montrée avant mais avec votre text, phrase ou mot clé que vous aimeriez détecter. Lancer Snort avec la commande suivante :

```
sudo snort -c myrules.rules -i eth0
```

**Question 4: Que voyez-vous quand le logiciel est lancé ? Qu'est-ce que tous ces messages affichés veulent dire ?**

---

**Réponse :**  

Message affiché
```
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/root/myrules.rules"
Tagged Packet Limit: 256
Log directory = /var/log/snort

+++++++++++++++++++++++++++++++++++++++++++++++++++
Initializing rule chains...
1 Snort rules read
    1 detection rules
    0 decoder rules
    0 preprocessor rules
1 Option Chains linked into 1 Chain Headers
+++++++++++++++++++++++++++++++++++++++++++++++++++

+-------------------[Rule Port Counts]---------------------------------------
|             tcp     udp    icmp      ip
|     src       0       0       0       0
|     dst       0       0       0       0
|     any       1       0       0       0
|      nc       0       0       0       0
|     s+d       0       0       0       0
+----------------------------------------------------------------------------

+-----------------------[detection-filter-config]------------------------------
| memory-cap : 1048576 bytes
+-----------------------[detection-filter-rules]-------------------------------
| none
-------------------------------------------------------------------------------

+-----------------------[rate-filter-config]-----------------------------------
| memory-cap : 1048576 bytes
+-----------------------[rate-filter-rules]------------------------------------
| none
-------------------------------------------------------------------------------

+-----------------------[event-filter-config]----------------------------------
| memory-cap : 1048576 bytes
+-----------------------[event-filter-global]----------------------------------
+-----------------------[event-filter-local]-----------------------------------
| none
+-----------------------[suppression]------------------------------------------
| none
-------------------------------------------------------------------------------
Rule application order: pass->drop->sdrop->reject->alert->log
Verifying Preprocessor Configurations!

[ Port Based Pattern Matching Memory ]
+-[AC-BNFA Search Info Summary]------------------------------
| Instances        : 1
| Patterns         : 1
| Pattern Chars    : 8
| Num States       : 8
| Num Match States : 1
| Memory           :   1.62Kbytes
|   Patterns       :   0.05K
|   Match Lists    :   0.09K
|   Transitions    :   1.09K
+-------------------------------------------------
pcap DAQ configured to passive.
Acquiring network traffic from "eth0".
Reload thread starting...
Reload thread started, thread 0x7f0237887640 (29)
Decoding Ethernet

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.15.1 GRE (Build 15125) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.10.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11

Commencing packet processing (pid=28)

```

On peut noter les informations pertinentes suivantes:
- Snort fonctionne en mode IDS
- Snort est lancé avec le fichier de règles `myrules.rules`
- Les logs sont stockés dans `/var/log/snort`
- Il y a une règle définie
    - C'est une règle de détection
    - Elle vérifie les paquets entrants et sortant de type TCP
- Il n'y a pas de filtre
- Il n'y a pas de préprocesseur

---

Aller à un site web contenant dans son text la phrase ou le mot clé que vous avez choisi (il faudra chercher un peu pour trouver un site en http... Si vous n'y arrivez pas, vous pouvez utiliser [http://neverssl.com](http://neverssl.com) et modifier votre votre règle pour détecter un morceau de text contenu dans le site).

Pour accéder à Firefox dans son conteneur, ouvrez votre navigateur web sur votre machine hôte et dirigez-le vers [http://localhost:4000](http://localhost:4000). Optionnellement, vous pouvez utiliser wget sur la machine client pour lancer la requête http ou le navigateur Web lynx - il suffit de taper ```lynx neverssl.com```. Le navigateur lynx est un navigateur basé sur text, sans interface graphique.

**Question 5: Que voyez-vous sur votre terminal quand vous chargez le site depuis Firefox ou la machine Client ?**

---

**Réponse :**  
Le terminal nous affiche simplement le message suivant répété plusieurs fois :
```
WARNING: No preprocessors configured for policy 0.
```

Il indique ceci car il n'y a pas de préprocesseur configuré pour la règle.

---

Arrêter Snort avec `CTRL-C`.

**Question 6: Que voyez-vous quand vous arrêtez snort ? Décrivez en détail toutes les informations qu'il vous fournit.**

---

**Réponse :**  
En faisant un `CTRL-C` dans le terminal, le processus s'arrête mais n'affiche rien. Il faut refaire une requête depuis le client pour que le terminal mettre l'affichage à jour.
Une fois l'affichage à jour, il affiche ceci :

```bash
===============================================================================
Run time for packet processing was 40.46377 seconds
Snort processed 121 packets.
Snort ran for 0 days 0 hours 0 minutes 40 seconds
   Pkts/sec:            3
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       4096000
  Bytes in mapped regions (hblkhd):      30265344
  Total allocated space (uordblks):      3348160
  Total free space (fordblks):           747840
  Topmost releasable block (keepcost):   590400
===============================================================================
Packet I/O Totals:
   Received:          126
   Analyzed:          121 ( 96.032%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            5 (  3.968%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:          121 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:          121 (100.000%)
       Frag:            0 (  0.000%)
       ICMP:            0 (  0.000%)
        UDP:            9 (  7.438%)
        TCP:          112 ( 92.562%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:           55 ( 45.455%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:          121
===============================================================================
Action Stats:
     Alerts:            8 (  6.612%)
     Logged:            8 (  6.612%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          121 ( 96.032%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
```
Ce tableau présente les statistiques des traitements et effectués lorsque Snort fonctionnait. Ici nous voyons que 8 alertes ont été levées et mises dans les logs.

---


Aller au répertoire /var/log/snort. Ouvrir le fichier `alert`. Vérifier qu'il y ait des alertes pour votre text choisi.

**Question 7: A quoi ressemble l'alerte ? Qu'est-ce que chaque élément de l'alerte veut dire ? Décrivez-la en détail !**

---

**Réponse :**
Voici un exemple d'alerte :

Règle : `alert tcp any any -> any any (msg:"HEIG-VD detected"; content:"HEIG-VD"; sid:4000015; rev:1;)`

```bash
[**] [1:4000015:1] HEIG-VD detected [**]
[Priority: 0]
04/29-08:55:10.970647 193.134.220.45:80 -> 192.168.220.3:52066
TCP TTL:36 TOS:0x0 ID:50279 IpLen:20 DgmLen:1500
***AP*** Seq: 0x1AFF6DDA  Ack: 0x46243E63  Win: 0xFFFF  TcpLen: 20
```
La première ligne indique l'identifiant de la règle (sid) et sa version (1), ainsi que le message d'alerte.<br>
La deuxième ligne indique la priorité, ici la priorité par défaut.<br>
La troisième ligne indique la date de l'alerte ainsi que les IP source et destination. Ici, la source est le serveur web qui a répondu en envoyant une page qui contenait les mots clefs qui ont levé l'alerte. A noter que l'année de l'alerte n'est pas précisée.

---


--

### Detecter une visite à Wikipedia

Ecrire deux règles qui journalisent (sans alerter) chacune un message à chaque fois que Wikipedia est visité **SPECIFIQUEMENT DEPUIS VOTRE MACHINE CLIENT OU DEPUIS FIREFOX**. Chaque règle doit identifier quelle machine à réalisé la visite. Ne pas utiliser une règle qui détecte un string ou du contenu. Il faudra se baser sur d'autres paramètres.

**Question 8: Quelle est votre règle ? Où le message a-t'il été journalisé ? Qu'est-ce qui a été journalisé ?**

---

**Réponse :**  

```
var WIKIPEDIA_IP 91.198.174.192
var CLIENT_IP 192.168.220.3
var FIREFOX_IP 192.168.220.4
var WEB_PORTS [80,443]

log tcp $CLIENT_IP any -> any $WEB_PORTS (msg:"Connexion à wikipedia depuis la machine client"; sid:400000001; rev:1;)
log tcp $FIREFOX_IP any -> any $WEB_PORTS (msg:"Connexion à wikipedia depuis la machine firefox"; sid:400000002; rev:1;)
```
Notre règle journalise les connexions à Wikipedia depuis la machine client et depuis la machine firefox.
Elle utilise l'adresse du site wikipedia.org.

Le message ne sera pas journalisé dans les logs, mais il est quand même utile pour comprendre ce que fait la règle.
Dans les logs on peut simplement voir qu'il y a eu un accès à wikipedia depuis la machine client ou firefox:
(on peut afficher le contenu du fichier avec `tcpdump -r /var/log/snort/snort.log.1651225023`)

Voici le contenu du fichier de log dans "/var/log/snort/snort.log.1651225023":

``` 
reading from file /var/log/snort/snort.log.1651225023, link-type EN10MB (Ethernet), snapshot length 1514
09:37:12.333483 IP Client.snortlan.47836 > text-lb.esams.wikimedia.org.https: Flags [R], seq 4171324781, win 0, length 0
09:37:12.333499 IP Client.snortlan.47836 > text-lb.esams.wikimedia.org.https: Flags [R], seq 4171324781, win 0, length 0
09:37:12.440697 IP Client.snortlan.47838 > text-lb.esams.wikimedia.org.https: Flags [R], seq 4097727664, win 0, length 0
09:37:12.441379 IP Client.snortlan.47838 > text-lb.esams.wikimedia.org.https: Flags [R], seq 4097727664, win 0, length 0
```
On voit les logs qui indiquent que qu'une connexion à Wikipedia depuis `client` a été détectée.

````
reading from file /var/log/snort/snort.log.1651768073, link-type EN10MB (Ethernet), snapshot length 1514
16:28:28.981143 IP firefox.snortlan.59760 > text-lb.esams.wikimedia.org.https: Flags [R], seq 870898746, win 0, length 0
````
On voit les logs qui indiquent que qu'une connexion à Wikipedia depuis `firefox` a été détectée.




---

--

### Détecter un ping d'un autre système

Ecrire une règle qui alerte à chaque fois que votre machine IDS **reçoit** un ping depuis une autre machine (n'import laquelle des autres machines de votre réseau). Assurez-vous que **ça n'alerte pas** quand c'est vous qui **envoyez** le ping depuis l'IDS vers un autre système !
**Question 9: Quelle est votre règle ?**

---

**Réponse :**  
```
var LOCAL_NET 192.168.220.0/24
var LOCALHOST 192.168.220.2
alert icmp $LOCAL_NET any -> $LOCALHOST any (msg:"Ping from local network detected"; itype:8; sid:4000003; rev:1;)
```
---


**Question 10: Comment avez-vous fait pour que ça identifie seulement les pings entrants ?**

---

**Réponse :**
Nous avons limité l'alerte à le demande d'echo en ajoutant `itype:8`. Ainsi, aucune alerte n'est levée lors d'une réponse à un ECHO envoyé par l'IDS.

---


**Question 11: Où le message a-t-il été journalisé ?**

---

**Réponse :**  
Le fichier est journalisé dans "/var/log/snort/snort.log.xxxxxx"

---

Les journaux sont générés en format pcap. Vous pouvez donc les lire avec Wireshark. Vous pouvez utiliser le conteneur wireshark en dirigeant le navigateur Web de votre hôte sur vers [http://localhost:3000](http://localhost:3000). Optionnellement, vous pouvez lire les fichiers log utilisant la commande `tshark -r nom_fichier_log` depuis votre IDS.

**Question 12: Qu'est-ce qui a été journalisé ?**

---

**Réponse :**  
Uniquement les règles commançant par `log` ont été journalisées.

---

--

### Detecter les ping dans les deux sens

Faites le nécessaire pour que les pings soient détectés dans les deux sens.

**Question 13: Qu'est-ce que vous avez fait pour détecter maintenant le trafic dans les deux sens ?**

---

**Réponse :**  

Il faut changer le type de flèche dans la règle. Remplacer `->` par `<>`

```
var LOCAL_NET 192.168.220.0/24
var LOCALHOST 192.168.220.2
alert icmp $LOCAL_NET any <> $LOCALHOST any (msg:"Ping from local network detected"; itype:8; sid:4000003; rev:1;)
```

---


--

### Detecter une tentative de login SSH

Essayer d'écrire une règle qui alerte qu'une tentative de session SSH a été faite depuis la machine Client sur l'IDS.

**Question 14: Quelle est votre règle ? Montrer la règle et expliquer en détail comment elle fonctionne.**

---

**Réponse :**  

```
var CLIENT 192.168.220.3
var IDS 192.168.220.2
alert tcp $CLIENT any -> $IDS 22 (msg:"SSH connexion attempt detected"; sid:40000004; rev:1;)
```
La règle détecte les tentatives de connexion SSH depuis la machine client vers l'IDS. Plus précisément, on se base ici sur le numéro de port qu'écoute ssh pour détecter des tentatives de connexion.

> pour que cette règle fonctionne nous avons dû ajouter l'option `-k none` au lancement de snort pour désactiver le "checksum mode"

---


**Question 15: Montrer le message enregistré dans le fichier d'alertes.**

---

**Réponse :** 

```
[**] [1:40000005:1] SSH connexion attempt detected [**]
[Priority: 0] 
05/05-20:22:45.618181 192.168.220.3:51646 -> 192.168.220.2:22
TCP TTL:64 TOS:0x10 ID:44221 IpLen:20 DgmLen:60 DF
******S* Seq: 0x70D27C9D  Ack: 0x0  Win: 0xFAF0  TcpLen: 40
TCP Options (5) => MSS: 1460 SackOK TS: 1059687740 0 NOP WS: 7 
```

---



--

### Analyse de logs

Depuis l'IDS, servez-vous de l'outil ```tshark```pour capturer du trafic dans un fichier. ```tshark``` est une version en ligne de commandes de ```Wireshark```, sans interface graphique.

Pour lancer une capture dans un fichier, utiliser la commande suivante :

```
tshark -w nom_fichier.pcap
```

Générez du trafic depuis le deuxième terminal qui corresponde à l'une des règles que vous avez ajoutées à votre fichier de configuration personnel. Arrêtez la capture avec ```Ctrl-C```.

**Question 16: Quelle est l'option de Snort qui permet d'analyser un fichier pcap ou un fichier log ?**

---

**Réponse :**  
On peut utiliser l'option `-r` pour lire un fichier pcap ou un fichier log, en utilisant la synthaxe suivante :

```
snort -r <fileName>.{pcap|log}
```

---

Utiliser l'option correcte de Snort pour analyser le fichier de capture Wireshark que vous venez de générer.

**Question 17: Quel est le comportement de Snort avec un fichier de capture ? Y-a-t'il une différence par rapport à l'analyse en temps réel ?**

---

**Réponse :**  
On peut utiliser les 2 modes pour faire de l'analyse de fichier de capture :
- Mode sniffer (sans règles) sur un fichier de capture <br>
  `snort -r <fichier>` <br>
  Snort affiche simplement les paquets envoyés dans la console. mais ne génère aucun log.
- Mode IDS sur un fichier de capture: <br>
  `snort -c <règles> -r <fichier>` <br>
  Snort agit comme en temps réel:
  - Le fichier de capture est analysé et les alertes sont affichées dans la console
  - les alertes et les logs sont enregistrés dans des fichiers.


---

**Question 18: Est-ce que des alertes sont aussi enregistrées dans le fichier d'alertes?**

---

**Réponse :**  
Oui, comme dit avant, en utilisant le mode IDS avec l'option `-c`

---

--

### Contournement de la détection

Faire des recherches à propos des outils `fragroute` et `fragrouter`.

**Question 19: A quoi servent ces deux outils ?**

---

**Réponse :**  

`fragroute`:
Cet outil permet d'intercepter et de modifier le trafic sortant à destination d'un hôte spécifique. Il est utilisé pour contourner les firwall et les IDSs. A la base, cet outil a été développé dans le but de tester plus en profondeur les infrastructures réseau. `fragroute` permet par exemple de tester le bon fonctionnement d'un firewall statfull ou les timout de réassemblage des paquets par les IDS.

`fragrouter`:
C'est un framework ayant permettant de faire du contournement de systèmes de protections tels que les firewall et les IDS.

---


**Question 20: Quel est le principe de fonctionnement ?**

---

**Réponse :**

Ces outils utilisent la fragmentation IP pour tromper les IDS et les firewall. L'idée est de forcer artificiellement la fragmentation des paquets IP en morceaux plus petit, tel que le prévoit le protocole IP si le paquet IP rencontre un MTU trop petit sur son chemin. Cette fonctionnalité a été pensée à la base pour permettre le transit des données à travers des réseaux hétérogènes. Cependant, certains firewall et les IDS mal configurés ne gèrent pas correctement ces fragments de paquets IP. Dans ce cas, il est possible de contourner les règles de protection que ces équipements sont sensés assurer. <br>
`fragroute` utilise différentes méthodes : retransmission des fragments IP dans un ordre aléatoire, suppression de fragments, retransmission avec différentes tailles de fragments ou encore duplication de fragments. A noter que les fragments sont eux-mêmes des paquets IP valident.

---


**Question 21: Qu'est-ce que le `Frag3 Preprocessor` ? A quoi ça sert et comment ça fonctionne ?**

---

**Réponse :**

`Frag3 Preprocessor` détecte si des fragments IP transitent par le réseau. Il les garde en mémoire afin de les assembler et reformer le paquet IP original. L'IDS peut ensuite les analyser correctement et réagir en fonction des règles comme cela est attendu.


---


L'utilisation des outils ```Fragroute``` et ```Fragrouter``` nécessite une infrastructure un peu plus complexe. On va donc utiliser autre chose pour essayer de contourner la détection.

L'outil nmap propose une option qui fragmente les messages afin d'essayer de contourner la détection des IDS. Générez une règle qui détecte un SYN scan sur le port 22 de votre IDS.


**Question 22: A quoi ressemble la règle que vous avez configurée ?**

---

**Réponse :**
```
var IDS 192.168.220.2
alert tcp any any -> $IDS 22 (msg:"SYN packet detected on SSH port"; flags:S; sid:40000005; rev:1;)
```
---


Ensuite, servez-vous du logiciel nmap pour lancer un SYN scan sur le port 22 depuis la machine Client :

```
nmap -sS -p 22 192.168.220.2
```
Vérifiez que votre règle fonctionne correctement pour détecter cette tentative.

Ensuite, modifiez votre commande nmap pour fragmenter l'attaque :

```
nmap -sS -f -p 22 --send-eth 192.168.220.2
```

**Question 23: Quel est le résultat de votre tentative ?**

---

**Réponse :**  
Avec l'option `-f` nmap fragmente les paquets envoyés.
Snort ne détecte alors plus le SYN scan.

---


Modifier le fichier `myrules.rules` pour que snort utiliser le `Frag3 Preprocessor` et refaire la tentative.


**Question 24: Quel est le résultat ?**

---

**Réponse :**  
Cette fois-ci la règle fonctionne et une alerte est lancée.

```
[**] [1:40000005:1] SSH connexion attempt detected [**]
[Priority: 0] 
05/05-20:10:17.727376 192.168.220.3:44031 -> 192.168.220.2:22
TCP TTL:46 TOS:0x0 ID:6208 IpLen:20 DgmLen:44
******S* Seq: 0x22BB80F  Ack: 0x0  Win: 0x400  TcpLen: 24
TCP Options (1) => MSS: 1460 

[**] [1:40000003:1] SYN packet detected on SSH port [**]
[Priority: 0] 
05/05-20:10:17.727376 192.168.220.3:44031 -> 192.168.220.2:22
TCP TTL:46 TOS:0x0 ID:6208 IpLen:20 DgmLen:44
******S* Seq: 0x22BB80F  Ack: 0x0  Win: 0x400  TcpLen: 24
TCP Options (1) => MSS: 1460 

```

---


**Question 25: A quoi sert le `SSL/TLS Preprocessor` ?**

---

**Réponse :**  
C'est un préprocesseur qui détecte les paquets chiffrés avec SSL/TLS avant que snort ne commence de les inspecter. Cela serait inutile car il est impossible de lire leur contenu.

---


**Question 26: A quoi sert le `Sensitive Data Preprocessor` ?**

---

**Réponse :**  
C'est un préprocesseur qui détecte les paquets contenant des informations personnelles sensibles. Ces données peuvent être des informations bancaires, des emails, numéros sociaux (américains) etc.
Il est possible de déclancher des alertes et de masquer une partie des données.

---

### Conclusion


**Question 27: Donnez-nous vos conclusions et votre opinion à propos de snort**

---

**Réponse :**  
Snort est un outil très pratique pour détecter des comportements suspects sur un réseau. Il demande un certain temps d'apprentissage bien que la syntaxe ne soit pas spécialement compliquée. Finalement, le plus compliqué doit être d’imaginer toutes les règles qui permettent de détecter les attaques de manière la plus exhaustive possible. Ce sont elles qui rendent Snort réellement puissant.

---

### Cleanup

Pour nettoyer votre système et effacer les fichiers générés par Docker, vous pouvez exécuter le script [cleanup.sh](scripts/cleanup.sh). **ATTENTION : l'effet de cette commande est irréversible***.


<sub>This guide draws heavily on http://cs.mvnu.edu/twiki/bin/view/Main/CisLab82014</sub>

