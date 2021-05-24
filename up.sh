#!/bin/bash
date
IP=${1}
MACADDRESS=${2}
if [ "${IP}" == "" ]
then
    echo "no ip (abort)"
    exit 255
fi
if [ "${MACADDRESS}" == "" ]
then
    echo "no mac address (abort)"
    exit 255
fi
for i in {1..5}
do
#/bin/ip route del ${IP} > /dev/null 2>&1
echo /bin/ip route del ${IP}
done
gateway=""
macaddress_to_ip () {
    LOWER=`echo "$1" | tr '[:upper:]' '[:lower:]'`
    if [ "${LOWER}" == "e4:a8:b6:99:73:5b" ] || [ "${LOWER}" == "ISP A" ]
    then
        gateway='192.168.1.10'
        echo -n "use ISP A (${gateway}) "
    else
        gateway='192.168.1.11'
        echo -n "use ISP B (${gateway}) "
    fi
}
if [ "${IP}" = "8.8.8.8" ]
then
    macaddress_to_ip "${MACADDRESS}"
    #/bin/ip route add ${IP} via ${gateway} dev eth2
    echo /bin/ip route add ${IP} via ${gateway} dev eth2
    exit 0
elif [ "${IP}" = "8.8.4.4" ]
then
    macaddress_to_ip "${MACADDRESS}"
    #/bin/ip route add ${IP} via ${gateway} dev eth2
    echo /bin/ip route add ${IP} via ${gateway} dev eth2
    exit 0
else
    macaddress_to_ip "${MACADDRESS}"
    #/bin/ip route add ${IP} via ${gateway} dev eth2
    echo /bin/ip route add ${IP} via ${gateway} dev eth2
    exit 0
fi
exit 125
