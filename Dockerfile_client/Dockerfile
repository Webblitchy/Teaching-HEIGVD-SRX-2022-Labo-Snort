FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install net-tools iptables nftables iputils-ping iproute2 wget netcat-openbsd ssh nano traceroute tcpdump lynx nmap tshark -y

# Modify `sshd_config`
RUN sed -i s/#PermitRootLogin.*/PermitRootLogin\ yes/ /etc/ssh/sshd_config
RUN sed -i s/#PermitEmptyPasswords.*/PermitEmptyPasswords\ yes/ /etc/ssh/sshd_config
RUN sed -ri 's/^UsePAM.*/UsePAM no/' /etc/ssh/sshd_config

#RUN ip route del default
#RUN ip route add default via 192.168.220.2

# Delete root password (set as empty)
RUN passwd -d root
