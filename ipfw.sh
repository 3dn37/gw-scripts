#!/bin/bash
######### VALUES #############################################################
nat_interfaces='eth1'
nat_ip="91.229.59.100" #nat_ip="91.229.59.26-91.229.59.30"
int_if="eth3"
ext_if="ifb0"

iptables='/usr/sbin/iptables'
ip6tables='/usr/sbin/ip6tables'
sysctl='/sbin/sysctl'
modprobe='/sbin/modprobe'
ifconfig='/sbin/ifconfig'
ipset='/usr/sbin/ipset'
tc='/usr/sbin/tc'
ethtool='/sbin/ethtool'

######### CLEAR TABLES #######################################################
# зачищаем таблицы
#iptables -F FORWARD
$iptables -F -t filter
$iptables -F -t mangle
$iptables -F -t nat

$iptables -F accept_internal_services
$iptables -X accept_internal_services

$ipset -F allowed_users
$ipset -X allowed_users

$ipset -F allowed_serv
$ipset -X allowed_serv

$ipset -F my_nets
$ipset -X my_nets

$ipset -F my_inets
$ipset -X my_inets

# Чистим очереди от предыдущих данных
$tc qdisc del dev $ext_if root
$tc qdisc del dev $int_if root

######### SYSTEM SETTINGS ####################################################
# пропускать транзитный трафик (/etc/sysctl.conf)
$sysctl net.ipv4.ip_forward=1

# подключаем виртуальный интерфейс чтобы шейпить исходящий трафик
$modprobe ifb
$ifconfig ifb0 up

# передаем весь трафик с внутреннего интерфейса на виртуальный для шейпа
$tc qdisc add dev $int_if ingress
$tc filter add dev $int_if parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev $ext_if

# enable ipv4
$iptables -P FORWARD ACCEPT
$iptables -P INPUT ACCEPT

# disable ipv6
$ip6tables -P FORWARD DROP
$ip6tables -P INPUT DROP

######### UP INTERFACES ######################################################
$ifconfig $ext_if up
$ifconfig $int_if up

for iface in ${nat_interfaces}
do
    $ifconfig $iface up
done

######### ACCEPT_INTERNAL_SERVICES ###########################################
# создаем таблицу бесплатных сервисов
$iptables -N accept_internal_services
# разрешаем трафик на днс
#iptables -A accept_internal_services -d 10.1.1.10 -p udp -m multiport --dport 53 -j ACCEPT
#iptables -A accept_internal_services -d 10.1.2.10 -p udp -m multiport --dport 53 -j ACCEPT
# разрешаем трафик на сайт idep.ru
$iptables -A accept_internal_services -d 91.229.59.56 -p tcp --dport 80 -j ACCEPT
# и страницу статистики
$iptables -A accept_internal_services -d 91.229.59.56 -p tcp --dport 443 -j ACCEPT
# на сайт medi-a.ru (medialiance)
$iptables -A accept_internal_services -d 77.246.96.109 -p tcp --dport 80 -j ACCEPT
$iptables -A accept_internal_services -d 77.246.96.108 -p tcp --dport 80 -j ACCEPT
$iptables -A accept_internal_services -d 77.246.96.99 -p tcp --dport 80 -j ACCEPT
$iptables -A accept_internal_services -p udp --dport 123 -j ACCEPT
$iptables -A accept_internal_services -p udp --sport 123 -j ACCEPT
$iptables -A accept_internal_services -d 77.246.96.123 -p tcp --dport 80 -j ACCEPT
$iptables -A accept_internal_services -d 77.246.96.118 -p tcp -j ACCEPT

# разрешаем трафик c днс
#iptables -A accept_internal_services -s 10.1.1.10 -j ACCEPT
#iptables -A accept_internal_services -s 10.1.2.10 -j ACCEPT
# разрешаем трафик c сайта idep.ru и страницы статистики
$iptables -A accept_internal_services -s 91.229.59.56 -j ACCEPT
# с сайта medi-a.ru (medialiance)
$iptables -A accept_internal_services -s 77.246.96.109 -j ACCEPT
$iptables -A accept_internal_services -s 77.246.96.108 -j ACCEPT
$iptables -A accept_internal_services -s 77.246.96.99 -j ACCEPT
$iptables -A accept_internal_services -s 89.221.207.113 -j ACCEPT
$iptables -A accept_internal_services -s 77.246.96.123 -j ACCEPT
$iptables -A accept_internal_services -s 77.246.96.118 -j ACCEPT
# действие по умолчанию
$iptables -A accept_internal_services -j RETURN

######### ALLOWED_USERS ######################################################
# создаем таблицу работающих пользователей
$ipset -N allowed_users hash:ip
#$ipset -A allowed_users 192.168.0.245
#$ipset -A allowed_users 192.168.5.245
#$ipset -A allowed_users 91.229.59.245

######### ALLOWED_SERV #######################################################
# создаем таблицу работающих серверов
$ipset -N allowed_serv hash:ip
$ipset -A allowed_serv 10.10.10.5
#$ipset -A allowed_serv 91.229.59.1
$ipset -A allowed_serv 91.229.59.6
$ipset -A allowed_serv 192.168.0.4

######### NUESTROS REDS ######################################################
# создаем таблицу наших подсетей
$ipset -N my_nets hash:net
$ipset -A my_nets 192.168.0.0/24
$ipset -A my_nets 192.168.5.0/24
$ipset -A my_nets 10.10.10.0/24
$ipset -A my_nets 91.229.59.0/24
$ipset -A my_nets 172.20.20.0/24

######### NUESTROS INTERNAL REDS #############################################
# создаем таблицу наших подсетей
$ipset -N my_inets hash:net
$ipset -A my_inets 192.168.0.0/24
$ipset -A my_inets 192.168.5.0/24
$ipset -A my_inets 10.10.10.0/24
$ipset -A my_inets 172.20.20.0/24

######### FORWARD ############################################################
# проверяем кому из юзверей можно иметь инет
$iptables -A FORWARD -j NETFLOW
$iptables -A FORWARD -m set --match-set allowed_users src -j ACCEPT
$iptables -A FORWARD -m set --match-set allowed_users dst -j ACCEPT
$iptables -A FORWARD -m set --match-set allowed_serv src -j ACCEPT
$iptables -A FORWARD -m set --match-set allowed_serv dst -j ACCEPT

# кто не прошел - разрешаем попасть на разрешенные сервисы
$iptables -A FORWARD -m set --match-set my_nets src -j accept_internal_services
$iptables -A FORWARD -m set --match-set my_nets dst -j accept_internal_services

# действие по умолчанию - в лес
$iptables -A FORWARD -j DROP

######### POSTROUTING ########################################################
######### SHAPING ############################################################
$iptables -t mangle -A PREROUTING -i $int_if -j IPMARK --addr src --and-mask 0xffff --or-mask 0x10000
$iptables -t mangle -A POSTROUTING -o $int_if -j IPMARK --addr dst --and-mask 0xffff --or-mask 0x10000

######### NAT ################################################################
for iface in ${nat_interfaces}
do
    $iptables -t nat -A POSTROUTING -m set --match-set my_inets src -o $iface -j SNAT --to-source $nat_ip
done

# создадим корневой обработчик очереди на интерфейсе
$tc qdisc add dev $int_if root handle 1: htb
$tc qdisc add dev $ext_if root handle 1: htb

#$tc class add dev $ext_if parent 1:0 classid 1:1 htb rate 1gbit burst 15k
#$tc class add dev $int_if parent 1:0 classid 1:1 htb rate 4gbit burst 15k

# Добавляем фильтр fw (без параметров помещает пакет по указанными при помощи ipmark parent:classid в нужный класс.)
$tc filter add dev $ext_if parent 1: protocol ip fw
$tc filter add dev $int_if parent 1: protocol ip fw
# tc filter show dev em1

$ethtool -G eth0 tx 4096
$ethtool -G eth0 rx 4096
$ethtool -G eth1 tx 4096
$ethtool -G eth1 rx 4096

/bin/echo 131072 > /sys/module/nf_conntrack/parameters/hashsize
/usr/sbin/sysctl -p


#########################################################
# SAMPLE CLIENT 1
# 192.168.136.1 -> 8801 (88: 136 hex; 01 - 1 hex)
# echo "obase=16; 136" | bc #88
# 5.245  05f5
#########################################################
# tc class show dev em0
# tc class delete dev eth0 parent 1:0 classid 1:0541
#
#tc class replace dev $ext_if parent 1: classid 1:8801 htb rate 1024kbit
#tc class replace dev $int_if parent 1: classid 1:8801 htb rate 2048kbit

#$tc class replace dev $int_if parent 1:0 classid 1:05f5 htb rate 30mbit
#$tc class replace dev $ext_if parent 1:0 classid 1:05f5 htb rate 30mbit

#
#########################################################
# SAMPLE CLIENT 2
# 192.168.136.2 -> 8802 (88: 136 hex; 02 - 2 hex)
#########################################################
#tc class replace dev $ext_if parent 1: classid 1:8802 htb rate 4090kbit
#tc class replace dev $int_if parent 1: classid 1:8802 htb rate 8192kbit

#$tc class replace dev $ext_if parent 1: classid 1:0542 htb rate 3072kbit
#$tc class replace dev $int_if parent 1: classid 1:0542 htb rate 3072kbit

# cat /proc/net/ip_tables_targets
# cat /proc/net/ip_tables_names

# apt-get install ipset xtables-addons-source xtables-addons-common xtables-addons-dkms
#
# aptitude update
# aptitude install module-assistant xtables-addons-source xtables-addons-common
# m-a prepare
# m-a auto-install xtables-addons-source
# depmod -a

