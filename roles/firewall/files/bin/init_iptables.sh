#!/bin/sh
for fichier in /usr/local/etc/utilserv/firewall/*.conf ; do
  . "$fichier"
  ports_tcp="$ports_tcp $p_tcp"
  ports_udp="$ports_udp $p_udp"
done

#Types ICMP V6 à autoriser, cf. https://tools.ietf.org/html/rfc4890#section-4.4 & https://en.wikipedia.org/wiki/ICMPv6#Types_of_ICMPv6_messages
icmpV6_type="1 2 3 4 133 134 135 136 137 141 142 148 149" # Types ICMPv6 séparés par un espace
icmp_V6_local="130 131 132 143 151 152 153"

# Interdit toute connexion entrante 
iptables -P INPUT DROP
iptables -P FORWARD DROP
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP

#Autorise toute connexion sortante
ip6tables -P OUTPUT ACCEPT
iptables -P OUTPUT ACCEPT

#Interdire les paquets invalides
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP

#Autoriser lo
iptables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT

#Ne pas casser les connexions établies
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Interdire les paquets non conformes
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Dropper les faux lo
iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
ip6tables -A INPUT -s ::1/128 ! -i lo -j DROP

# Bloquer broadcast, multicast et anycast en v4
iptables -A INPUT -m addrtype --dst-type BROADCAST -j DROP
iptables -A INPUT -m addrtype --dst-type MULTICAST -j DROP
iptables -A INPUT -m addrtype --dst-type ANYCAST -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP

# 6 pings/sec/source maxi, et loggué une seule fois
iptables -N ICMPFLOOD
iptables -A ICMPFLOOD -m recent --set --name ICMP --rsource
iptables -A ICMPFLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP --rsource --rttl -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "iptables[ICMP-flood]: "
iptables -A ICMPFLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP --rsource --rttl -j DROP
iptables -A ICMPFLOOD -j ACCEPT
ip6tables -N ICMPFLOOD
ip6tables -A ICMPFLOOD -m recent --set --name ICMP --rsource
ip6tables -A ICMPFLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP --rsource --rttl -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "iptables[ICMP-flood]: "
ip6tables -A ICMPFLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP --rsource --rttl -j DROP
ip6tables -A ICMPFLOOD -j ACCEPT

# Ouverture des ports personnalisés
for i in $ports_tcp; do
  iptables -A INPUT -p tcp --dport "$i" -j ACCEPT
  ip6tables -A INPUT -p tcp --dport "$i" -j ACCEPT
done
for i in $ports_udp; do
  iptables -A INPUT -p udp --dport "$i" -j ACCEPT
  ip6tables -A INPUT -p udp --dport "$i" -j ACCEPT
done

# Autoriser des paquets ICMP importants
# Cf. https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 3 -j ACCEPT 
iptables -A INPUT -p icmp --icmp-type 11 -j ACCEPT

# Autoriser les types ICMP IPv6 d'après RFC 4890.
for i in $icmpV6_type; do
   ip6tables -A INPUT -p ipv6-icmp --icmpv6-type "$i"   -j ACCEPT
done
for i in $icmp_V6_local; do
  ip6tables -A INPUT -s fe80::/10 -p ipv6-icmp --icmpv6-type "$i" -j ACCEPT
done

# Autoriser le ping avec la règle prédéfinie
iptables -A INPUT -p icmp --icmp-type 8  -m conntrack --ctstate NEW -j ICMPFLOOD
ip6tables -A INPUT -p ipv6-icmp --icmpv6-type 128 -j ICMPFLOOD

# Ne pas logguer les réponses tardives des serveurs de nom
iptables -A INPUT -p udp --sport 53 -j DROP
ip6tables -A INPUT -p udp --sport 53 -j DROP

# Good practise is to explicately reject AUTH traffic so that it fails fast.
# Il est conseillé de rejeter explicitement le traffic AUTH pour qu'il soit rapidement en erreur
iptables -A INPUT -p tcp --dport 113 --syn -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset
ip6tables -A INPUT -p tcp --dport 113 --syn -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset

# Pour éviter de flooder les logs
iptables -A INPUT -m limit --limit 1/second --limit-burst 100 -j LOG --log-prefix "iptables[DOS]: "
ip6tables -A INPUT -m limit --limit 1/second --limit-burst 100 -j LOG --log-prefix "iptables[DOS]: "

for regle in /usr/local/etc/utilserv/firewall/conf.d/*.conf; do
  . "$regle"
done
echo "L'activation des règles de pare-feu a été effectuée [OK]"
