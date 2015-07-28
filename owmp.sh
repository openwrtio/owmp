#!/bin/sh
version='0.4.0'

. /lib/functions/network.sh
. /usr/share/libubox/jshn.sh

host=`uci get owmp.server.host`
port=`uci get owmp.server.port`
api_version=`uci get owmp.server.version`
server_http_api='http://'$host':'$port'/'

distrib_revision=`cat /etc/openwrt_release | grep DISTRIB_REVISION | awk -F'"' '{print $2}'`

rand() {
    num=`head /dev/urandom | tr -dc "0123456789" | head -c2`
    if [ "$num" -gt "50" ]; then
        num=$((num - 50))
    fi
    echo $num
}
tmp=`rand`
echo '---------------------'
echo 'sleep '$tmp
sleep $tmp

network_get_mac() {
    local iface="$1"
    network_get_device ifname $iface
    local cmd="ifconfig "$ifname" | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'"
    local tmp=`eval $cmd`
    echo ${tmp//:/}
    return $?
}
lan_mac=`network_get_mac lan`
echo $lan_mac
oui=${lan_mac:0:6}

r=`curl -sH "'Accept: application/json; version="$api_version"'" -A "'owmp/"$version" (Linux; OpenWrt $distrib_revision)'" $server_http_api'devices/'$lan_mac'/config/wireless'`
echo $r
json_load "$r"
if [ $? -ne 0 ]; then
    echo 'error: json_load error'
    exit 1
fi
json_select device
if [ $? -ne 0 ]; then
    echo 'error: json_select error'
    exit 1
fi
json_get_var channel channel
json_get_var txpower txpower
json_get_var disabled disabled
echo "$channel"
echo "$txpower"
echo "$disabled"

# todo: read define from make menuconfig
wifi_txpower='txpower'
case $oui in
    # youku
    '54369B')
        wifi_device='mt7620'
        wifi_iface='@wifi-iface[1]'
    ;;
    # gee ralink
    # todo: j1 ar71xx
    'D4EE07')
        wifi_device='radio0'
        wifi_iface='master'
        wifi_txpower='txpwr'
    ;;
esac

wifi_need_restart=0
cmd="uci get wireless.$wifi_device.channel"
old_channel=`eval $cmd`
if [ $old_channel != $channel ]; then
    uci set wireless.$wifi_device.channel=$channel
    wifi_need_restart=1
fi

cmd="uci get wireless.$wifi_device.disabled"
old_disabled=`eval $cmd`
if [ "$old_disabled" != "$disabled" ]; then
    uci set wireless.$wifi_device.disabled=$disabled
    wifi_need_restart=1
fi

cmd="uci get wireless.$wifi_device.$wifi_txpower"
old_txpower=`eval $cmd`
if [ "$old_txpower" != "$txpower" ]; then
    uci set wireless.$wifi_device.$wifi_txpower=$txpower
    wifi_need_restart=1
fi

json_select ..
json_select iface
if [ $? -ne 0 ]; then
    echo 'error: json_select error'
    exit 1
fi
json_get_var ssid ssid
json_get_var encryption encryption

cmd="uci get wireless.$wifi_iface.ssid"
old_ssid=`eval $cmd`
if [ "$old_ssid" != "$ssid" ]; then
    uci set wireless.$wifi_iface.ssid=$ssid
    wifi_need_restart=1
fi

cmd="uci get wireless.$wifi_iface.encryption"
old_encryption=`eval $cmd`
if [ "$old_encryption" != "$encryption" ]; then
    uci set wireless.$wifi_iface.encryption=$encryption
    wifi_need_restart=1
fi

if [ $wifi_need_restart -eq 1 ]; then
    uci commit wireless
    echo '---------------------'
    echo 'wifi restarting'
    wifi
fi

r=`curl -sH "Accept: application/json; version=$api_version" -A "owmp/$version (Linux; OpenWrt $distrib_revision)" $server_http_api'devices/'$lan_mac'/config/wifidog'`
echo $r
json_load "$r"
if [ $? -ne 0 ]; then
    echo 'error: json_load error'
    exit 1
fi
json_select auth_server
if [ $? -ne 0 ]; then
    echo 'error: json_select error'
    exit 1
fi
json_get_var hostname hostname
json_get_var path path
echo "$hostname"
echo "$path"

wifidog_need_commit=0
wifidog_need_restart=0
if [ -f /etc/config/wifidog ]; then
    old_hostname=`uci get wifidog.authserver.Hostname`
    if [ x"$old_hostname" != x"$hostname" ]; then
        echo 'hostname is diff'
        uci set wifidog.authserver.Hostname=$hostname
        wifidog_need_commit=1
        wifidog_need_restart=1
    fi

    old_path=`uci get wifidog.authserver.Path`
    if [ x"$old_path" != x"$path" ]; then
        echo 'path is diff'
        uci set wifidog.authserver.Path=$path
        wifidog_need_commit=1
        wifidog_need_restart=1
    fi
else
    old_gatewayid=`grep "^GatewayID " /etc/wifidog.conf | awk '{print $2}'`
    if [ "$old_gatewayid" != "$lan_mac" ]; then
        echo 'GatewayID '$lan_mac >> /etc/wifidog.conf
        wifidog_need_restart=1
    fi
    old_hostname=`grep "^    Hostname" /etc/wifidog.conf | awk '{print $2}'`
    if [ "$old_hostname" == "" ]; then
        echo 'AuthServer {' >> /etc/wifidog.conf
        echo '    Hostname '$hostname >> /etc/wifidog.conf
        echo '    Path '$path >> /etc/wifidog.conf
        echo '}' >> /etc/wifidog.conf
    else
        if [ $old_hostname != $hostname ]; then
            sed -i "|Hostname $old_hostname|Hostname $hostname|g" /etc/wifidog.conf
            wifidog_need_restart=1
        fi

        old_path=`grep "^    Path" /etc/wifidog.conf | awk '{print $2}'`
        if [ $old_path != $path ]; then
            sed -i "|Path $old_hostname|Hostname $hostname|g" /etc/wifidog.conf
            wifidog_need_restart=1
        fi
    fi
fi

json_select ..
json_select domain_whitelist
if [ $? -ne 0 ]; then
    echo 'error: json_select error'
    exit 1
fi
local i=1
domain_whitelist=''
while json_get_type type $i && [ "$type" = string ]; do
    json_get_var tmp "$((i++))"
    domain_whitelist=`echo $domain_whitelist $tmp`
done
echo 'domain_whitelist: '
echo "$domain_whitelist"

json_select ..
json_select ip_whitelist
if [ $? -ne 0 ]; then
    echo 'error: json_select error'
    exit 1
fi
i=1
ip_whitelist=''
while json_get_type type $i && [ "$type" = string ]; do
    json_get_var tmp "$((i++))"
    ip_whitelist=`echo $ip_whitelist $tmp`
done
echo 'ip_whitelist: '
echo "$ip_whitelist"

if [ -f /etc/config/wifidog ]; then
    old_domain_whitelist=`uci get wifidog.hostlist.host`
    if [ "$old_domain_whitelist" != "$domain_whitelist" ]; then
        echo "domain_whitelist is diff"
        uci delete wifidog.hostlist.host
        i=1
        for domain in $domain_whitelist; do
            uci add_list wifidog.hostlist.host=$domain
        done
        wifidog_need_commit=1
        wifidog_need_restart=1
    fi
    old_ip_whitelist=`uci get wifidog.iplist.ip`
    if [ "$old_ip_whitelist" != "$ip_whitelist" ]; then
        echo "ip_whitelist is diff"
        uci delete wifidog.iplist.ip
        for ip in $ip_whitelist; do
            uci add_list wifidog.iplist.ip=$ip
        done
        wifidog_need_commit=1
        wifidog_need_restart=1
    fi
else
    whitelist=`echo $domain_whitelist" "$ip_whitelist`
    echo 'whitelist: '
    echo "$whitelist"
    conf=`cat /etc/wifidog.conf`
    tmp=${conf#*'FirewallRuleSet global {'}
    tmp2=${tmp%%'}'*}
    tmp3=`echo "$tmp2" | grep "^    FirewallRule" | awk '{print $4}'`
    old_whitelist=`echo $tmp3`
    echo 'old_whitelist: '
    echo "$old_whitelist"
    if [ "$old_whitelist" != "$whitelist" ]; then
        start_line=`grep -n 'FirewallRuleSet global {' /etc/wifidog.conf | awk -F: '{print $1}'`
        echo $start_line
        for num in `grep -n '}' /etc/wifidog.conf  | awk -F: '{print $1}'`; do
            if [ $num -gt $start_line ]; then
                end_line=$num
                break
            fi
        done
        echo $end_line
        sed -i "$start_line,$end_line"d /etc/wifidog.conf
        echo 'FirewallRuleSet global {' >> /etc/wifidog.conf
        for domain in $domain_whitelist; do
            echo '    FirewallRule allow to '"$domain" >> /etc/wifidog.conf                       
        done             
        for ip in $ip_whitelist; do
            echo '    FirewallRule allow to '"$ip" >> /etc/wifidog.conf
        done
        echo '}' >> /etc/wifidog.conf
    fi
fi

json_select ..
json_select mac_whitelist
if [ $? -ne 0 ]; then
    echo 'error: json_select error'
    exit 1
else
    i=1
    mac_whitelist=''
    while json_get_type type $i && [ "$type" = string ]; do
        json_get_var tmp "$((i++))"
        mac_whitelist=`echo $mac_whitelist $tmp`
    done
    echo 'mac_whitelist: '
    echo "$mac_whitelist"

    if [ -f /etc/config/wifidog ]; then
        old_mac_whitelist=`uci get wifidog.maclist.mac`
        if [ "$old_mac_whitelist" != "$mac_whitelist" ]; then
            echo "mac_whitelist is diff"
            uci delete wifidog.maclist.mac
            i=1
            for mac in $mac_whitelist; do
                uci add_list wifidog.maclist.mac=$mac
            done
            wifidog_need_commit=1
            wifidog_need_restart=1
        fi
    fi
fi

if [ $wifidog_need_commit -eq 1 ]; then
    uci commit wifidog
fi

if [ $wifidog_need_restart -eq 1 ]; then
    echo '---------------------'
    echo 'wifidog stop and start'
    /etc/init.d/wifidog stop
    /etc/init.d/wifidog start
fi

r=`curl -sH "'Accept: application/json; version="$api_version"'" -A "'owmp/"$version" (Linux; OpenWrt $distrib_revision)'" $server_http_api'devices/'$lan_mac'/config/shadow'`
echo $r
json_load "$r"
if [ $? -ne 0 ]; then
    echo 'error: json_load error'
    exit 1
fi
json_get_var password password
echo "$password"

echo '---------------------'
echo 'password changing'
echo -e "$password\n$password" | (passwd root)

rm -f /tmp/owmp_command.sh
touch /tmp/owmp_command.sh
curl -sH 'Accept: application/json; version='$api_version -A 'owmp/'$version' (Linux; OpenWrt '$distrib_revision')' $server_http_api'devices/'$lan_mac'/command' -o /tmp/owmp_command.sh
if [ -s /tmp/owmp_command.sh ]; then
    echo 'clear command'
    curl -d 'command=' -sH 'Accept: application/json; version='$api_version -A 'owmp/'$version' (Linux; OpenWrt '$distrib_revision')' $server_http_api'devices/'$lan_mac'/command'
    echo 'run command start'
    sh /tmp/owmp_command.sh
    echo 'run command end'
fi

# because network maybe restart, so we should change network at the end 
r=`curl -sH "'Accept: application/json; version="$api_version"'" -A "'owmp/"$version" (Linux; OpenWrt $distrib_revision)'" $server_http_api'devices/'$lan_mac'/config/network'`
echo $r
json_load "$r"
if [ $? -ne 0 ]; then
    echo 'error: json_load error'
    exit 1
fi
json_select wan
if [ $? -ne 0 ]; then
    echo 'error: json_select error'
    exit 1
fi
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
    echo '---------------------'
    echo 'network restarting'
    /etc/init.d/network restart
fi
