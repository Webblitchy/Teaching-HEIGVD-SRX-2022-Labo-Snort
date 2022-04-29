FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install net-tools iptables nftables iputils-ping iproute2 wget netcat-openbsd ssh nano traceroute tcpdump lynx nmap tshark -y

# Modify `sshd_config`
RUN sed -i s/#PermitRootLogin.*/PermitRootLogin\ yes/ /etc/ssh/sshd_config
RUN sed -i s/#PermitEmptyPasswords.*/PermitEmptyPasswords\ yes/ /etc/ssh/sshd_config
RUN sed -ri 's/^UsePAM.*/UsePAM no/' /etc/ssh/sshd_config

# Delete root password (set as empty)
RUN passwd -d root

RUN apt install snort -y

# COPY setupIDS.sh /opt/setupIDS.sh

# WORKDIR /opt

# RUN chmod +x setupIDS.sh
# RUN ./setupIDS.sh
#USER 0

#RUN ["/bin/bash", "-c", "nft add table nat"]
# RUN nft add table nat
#RUN nft 'add chain nat postrouting { type nat hook postrouting priority 100 ; }'
#RUN nft add rule nat postrouting meta oifname "eth0" masquerade