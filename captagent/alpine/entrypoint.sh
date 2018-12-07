#!/bin/sh -e

# Options, defaults.
ETHERNET_DEV=${ETHERNET_DEV:-any}
CAPTURE_HOST=${CAPTURE_HOST:-localhost}
CAPTURE_PORT=${CAPTURE_PORT:-9061}
CAPTURE_FILTER=${RTCP_PORTRANGE:-port 5060}
CAPTURE_PASSWORD=${CAPTURE_PASSWORD:-myhep}
SIP_ENABLE=${SIP_ENABLE:-true}
RTCP_ENABLE=${RTCP_ENABLE:-true}
RTCP_PORTRANGE=${RTCP_PORTRANGE:-10000-50000}
LOG_LEVEL=${LOG_LEVEL:-3}

sed -e "s:name=\"dev\" value=\"any:name=\"dev\" value=\"${ETHERNET_DEV}:" \
    -e "s:RTCP Socket\" enable=\"true:RTCP Socket\" enable=\"${RTCP_ENABLE}:" \
    -e "s:portrange 10000-50000:portrange ${RTCP_PORTRANGE}:" \
    -e "s:port 5060:${CAPTURE_FILTER}:" \
    -i /etc/captagent/socket_pcap.xml
sed -e "s:name=\"capture-host\" value=\"127.0.0.1:name=\"capture-host\" value=\"${CAPTURE_HOST}:" \
    -e "s:name=\"capture-port\" value=\"9061:name=\"capture-port\" value=\"${CAPTURE_PORT}:" \
    -e "s:name=\"capture-password\" value=\"myhep:name=\"capture-password\" value=\"${CAPTURE_PASSWWORD}:" \
    -i /etc/captagent/transport_hep.xml
sed -e "s:name=\"debug\" value=\"3:name=\"debug\" value=\"${LOG_LEVEL}:" \
    -i /etc/captagent/captagent.xml

if [ ${SIP_ENABLE} == "false" ]; then
    sed -e '/send_hep/,+3d' \
        -i /etc/captagent/captureplans/sip_capture_plan.cfg
fi

exec tini -- captagent -n
