#!/bin/sh
set -e
. /lib/functions/network.sh
. /usr/share/libubox/jshn.sh

host=`uci get owmp.server.host`
port=`uci get owmp.server.port`
server_http_api='http://'$host':'$port'/'
api_version='0.2.2'

rand() {
    num=`head /dev/urandom | tr -dc "0123456789" | head -c2`
    if [ "$num" -gt "50" ]; then
        num=$((num - 50))
    fi
    echo $num
}
tmp=`rand`
echo 'sleep '$tmp
sleep $tmp

network_get_mac() {
    local iface="$1"
    network_get_device ifname $iface
    local cmd="ifconfig "$ifname" | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'"
    local tmp=$(eval $cmd)
    echo ${tmp//:/}
    return $?
}
lan_mac=$(network_get_mac lan)
echo $lan_mac
r=`curl -sH 'Accept: application/json; version='$api_version -A 'HiAC/0.1.0 (Linux; OpenWrt 14.07; Hiwifi_J1S/HC6361)' $server_http_api'devices/'$lan_mac'/config/wireless'`
echo $r
json_load "$r"
json_select device
json_get_var channel channel
json_get_var txpower txpower
echo "$channel"
echo "$txpower"

wifi_need_restart=0
old_channel=`uci get wireless.radio0.channel`
if [ $old_channel != $channel ]; then
    uci set wireless.radio0.channel=$channel
    wifi_need_restart=1
fi
old_txpower=`uci get wireless.radio0.txpwr`
if [ $old_txpower != $txpower ]; then
    uci set wireless.radio0.txpwr=$txpower
    wifi_need_restart=1
fi

json_select ..
json_select iface
json_get_var ssid ssid
json_get_var encryption encryption

old_ssid=`uci get wireless.master.ssid`
if [ $old_ssid != $ssid ]; then
    uci set wireless.master.ssid=$ssid
    wifi_need_restart=1
fi
old_encryption=`uci get wireless.master.encryption`
if [ $old_encryption != $encryption ]; then
    uci set wireless.master.encryption=$encryption
    wifi_need_restart=1
fi

if [ $wifi_need_restart -eq 1 ]; then
    uci commit wireless
    echo 'wifi restarting'
    wifi
fi

r=`curl -sH 'Accept: application/json; version='$api_version -A 'HiAC/0.1.0 (Linux; OpenWrt 14.07; Hiwifi_J1S/HC6361)' $server_http_api'devices/'$lan_mac'/config/shadow'`
echo $r
json_load "$r"
json_get_var password password
echo "$password"

echo 'password changing'
echo -e "$password\n$password" | (passwd root)

r=`curl -sH 'Accept: application/json; version='$api_version -A 'HiAC/0.1.0 (Linux; OpenWrt 14.07; Hiwifi_J1S/HC6361)' $server_http_api'devices/'$lan_mac'/config/wifidog'`
echo $r
json_load "$r"
json_select auth_server
json_get_var hostname hostname
json_get_var path path
echo "$hostname"
echo "$path"

wifidog_need_restart=0
old_hostname=`uci get wifidog.authserver.Hostname`
if [ $old_hostname != $hostname ]; then
    uci set wifidog.authserver.Hostname=$hostname
    wifidog_need_restart=1
fi

old_path=`uci get wifidog.authserver.Path`
if [ $old_path != $path ]; then
    uci set wifidog.authserver.Path=$path
    wifidog_need_restart=1
fi

json_select ..
json_select domain_whitelist
local i=1
domain_whitelist=''
while json_get_type type $i && [ "$type" = string ]; do
    json_get_var tmp "$((i++))"
    echo $tmp
    domain_whitelist=`echo $domain_whitelist $tmp`
done
echo "$domain_whitelist"
old_domain_whitelist=`uci get wifidog.hostlist.host`
if [ "$old_domain_whitelist" != "$domain_whitelist" ]; then
    uci delete wifidog.hostlist.host
    i=1
    while json_get_type type $i && [ "$type" = string ]; do
        json_get_var tmp "$((i++))"
        echo $tmp
        uci add_list wifidog.hostlist.host=$tmp
    done
    wifidog_need_restart=1
fi

json_select ..
json_select ip_whitelist
i=1
ip_whitelist=''
while json_get_type type $i && [ "$type" = string ]; do
    json_get_var tmp "$((i++))"
    echo $tmp
    ip_whitelist=`echo $ip_whitelist $tmp`
done
echo "$ip_whitelist"
old_ip_whitelist=`uci get wifidog.iplist.ip`
if [ "$old_ip_whitelist" != "$ip_whitelist" ]; then
    uci delete wifidog.iplist.ip
    i=1
    while json_get_type type $i && [ "$type" = string ]; do
        json_get_var tmp "$((i++))"
        echo $tmp
        uci add_list wifidog.iplist.ip=$tmp
    done
    wifidog_need_restart=1
fi

if [ $wifidog_need_restart -eq 1 ]; then
    uci commit wifidog
    echo 'wifidog restarting'
    /etc/init.d/wifidog restart
fi

# because network maybe restart, so we should change network at the end 
r=`curl -sH 'Accept: application/json; version='$api_version -A 'HiAC/0.1.0 (Linux; OpenWrt 14.07; Hiwifi_J1S/HC6361)' $server_http_api'devices/'$lan_mac'/config/network'`
echo $r
json_load "$r"
json_select wan
json_get_var proto proto
json_get_var username username
json_get_var password password
echo "$proto"
echo "$username"
echo "$password"

network_need_restart=0
old_proto=`uci get network.wan.proto`
if [ $old_proto != $proto ]; then
    uci set network.wan.proto=$proto
    uci set network.wan.username=$username
    uci set network.wan.password=$password
    network_need_restart=1
fi
if [ $old_proto = "pppoe" ]; then
    old_username=`uci get network.wan.username`
    if [ $old_username != $username ]; then
        uci set network.wan.username=$username
        network_need_restart=1
    fi
    old_password=`uci get network.wan.password`
    if [ $old_password != $password ]; then
        uci set network.wan.password=$password
        network_need_restart=1
    fi
fi

if [ $network_need_restart -eq 1 ]; then
    uci commit network
    echo 'network restarting'
    /etc/init.d/network restart
fi
