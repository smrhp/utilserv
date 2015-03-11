#!/bin/sh
 
echo -n "Réinitialisation des règles du firewall..."
 
# Remet la police par défaut à ACCEPT
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT
 
# Remet les polices par défaut pour la table NAT
iptables -t nat -P PREROUTING ACCEPT
iptables -t nat -P POSTROUTING ACCEPT
iptables -t nat -P OUTPUT ACCEPT
 
# Vide (flush) toutes les règles existantes
iptables -F
iptables -t nat -F 
iptables -t mangle -Z
ip6tables -F
ip6tables -t mangle -Z
 
# Efface toutes les chaînes qui ne sont pas à défaut dans la table filter et nat
iptables -X
iptables -t nat -X
iptables -t mangle -X
ip6tables -X
ip6tables -t mangle -X
 
echo " [OK]"

