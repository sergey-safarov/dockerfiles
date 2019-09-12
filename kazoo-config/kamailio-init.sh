#!/bin/sh


if [ "${DISABLE_NAT}" != "true" -a -z "${PUBLIC_IPV4}" ]; then
    # Calling kamailio-helper service to assign elastic IP and adjust "ip rules" on EC2 instance
    curl -s -S -X POST http://kamailio-helper.ippbx:8080/configure_pod/ | tee /tmp/curl.log | jq -j '.mapped_ip' > /tmp/pod_public_ip
    if [ $? -eq 0 ]; then
        PUBLIC_IPV4=$(cat /tmp/pod_public_ip)
        echo "Content of 'curl.log'"
        cat /tmp/curl.log | jq
    else
        PUBLIC_IPV4=$(wget -q -O - http://169.254.169.254/latest/meta-data/public-ipv4)
    fi
fi

if [ "${DISABLE_NAT}" == "true" ]; then
    curl -s -S -X POST http://kamailio-helper.ippbx:8081/configure_priv_pod/
    if [ $? -ne 0 ]; then
        echo "Error: configuration call for 'configure_priv_pod' kamailio-helper service failed"
        exit 1
    fi
    sed -e "s/ advertise .*//" \
        -i /etc/kazoo/kazoo-configs-kamailio/kamailio/local.cfg
fi

set -e

LOCAL_IPV4=$(ip -4 addr show dev eth0 | grep -o "inet [0-9.]*" | sed -e "s/inet //")
MY_HOSTNAME=$(grep "${LOCAL_IPV4}" /etc/hosts | sed -e 's/^\S*\s*//' -e 's/\s\+.*//' -e 's/.svc.cluster.local//')

sed -e "s/MY_WAN_ADDRESS 0.0.0.0/MY_WAN_ADDRESS ${PUBLIC_IPV4}/" \
    -e "s/MY_IP_ADDRESS!0.0.0.0/MY_IP_ADDRESS!${LOCAL_IPV4}/" \
    -e "s/MY_HOSTNAME!kamailio.2600hz.com/MY_HOSTNAME!${MY_HOSTNAME}/" \
    -i /etc/kazoo/kazoo-configs-kamailio/kamailio/local.cfg

if [ ! -z "${MY_AMQP_URL}" ]; then
    sed -e "s|MY_AMQP_URL!kazoo://guest:guest@127.0.0.1:5672|MY_AMQP_URL!${MY_AMQP_URL}|" \
        -i /etc/kazoo/kazoo-configs-kamailio/kamailio/local.cfg
fi

if [ ! -z "${MY_AMQP_SECONDARY_URL}" ]; then
    sed -e "/MY_AMQP_URL.*/a #!substdef \"!MY_AMQP_SECONDARY_URL!${MY_AMQP_SECONDARY_URL}!g\"" \
        -i /etc/kazoo/kazoo-configs-kamailio/kamailio/local.cfg
fi

if [ ! -z "${MY_AMQP_TERTIARY_URL}" ]; then
    sed -e "/MY_AMQP_SECONDARY_URL.*/a #!substdef \"!MY_AMQP_TERTIARY_URL!${MY_AMQP_TERTIARY_URL}!g\"" \
        -i /etc/kazoo/kazoo-configs-kamailio/kamailio/local.cfg
fi

if [ ! -z "${MY_AMQP_QUATERNARY_URL}" ]; then
    sed -e "/MY_AMQP_TERTIARY_URL.*/a #!substdef \"!MY_AMQP_QUATERNARY_URL!${MY_AMQP_QUATERNARY_URL}!g\"" \
        -i /etc/kazoo/kazoo-configs-kamailio/kamailio/local.cfg
fi

cp -R /etc/kazoo/* /mnt
