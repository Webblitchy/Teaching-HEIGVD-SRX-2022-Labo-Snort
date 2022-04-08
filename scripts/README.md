# Scripts pour le labo IDS

Ce repertoire contient des scripts qui automatisent certaines parties du setup (et le nettoyage) pour l'environnement de virtualisation du labo.

Il est conseillé de faire le travail manuellement mais si vous avez besoin de refaire le travail ou de recommencer à partir de zéro, ceci peut peut-être vous aider.

### Client
ip route del default
ip route add default via 192.168.220.2


### Firefox
ip route del default
ip route add default via 192.168.220.2



### IDS
nft add table nat
nft 'add chain nat postrouting { type nat hook postrouting priority 100 ; }'
nft add rule nat postrouting meta oifname "eth0" masquerade
apt install snort
echo "include /etc/snort/rules/icmp2.rules" > /etc/snort/mysnort.conf
echo "alert icmp any any -> any any (msg:"ICMP Packet"; sid:4000001; rev:3;)" > /etc/snort/rules/icmp2.rules
