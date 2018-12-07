![captagent](http://i.imgur.com/3kEIR.png)

# CAPTAGENT 6 Docker
Captagent may be used to capture SIP signaling with or without RTCP stats.

Also may be to capture only RTCP statistics. This usefull when SIP signaling is captured by Kamailio and RTCP statistic is captured on FreeSwitch host.

http://sipcapture.org

Supported environment variables

- `ETHERNET_DEV` on witch device need to capture. Default value `any`;
- `CAPTURE_HOST` host to send HEP packets. Default value `localhost`;
- `CAPTURE_PORT` port to send HEP packets. Default value `9061`;
- `CAPTURE_FILTER` filter to capture traffic on NIC. Default value `port 5060`. When used in systemd unit need to escape space symbols as desribed at https://www.freedesktop.org/software/systemd/man/systemd-escape.html;
- `CAPTURE_PASSWORD` authetication password for capture server. Default value `myhep`;
- `SIP_ENABLE` send SIP signaling messages to capture server. Default value `true`;
- `RTCP_ENABLE` send RTCP statistics to capture server. Default value `true`;
- `RTCP_PORTRANGE` portrange where RTP streams is possible. Default value `10000-50000`;
- `LOG_LEVEL` debug loglevel. Default value `3`;

### Pull latest
```
docker pull safarov/captagent
```

### Run latest using --net=host
```
docker run -itd --name captagent6 --net=host safarov/captagent
```

### Local Build & Test
```
git clone https://github.com/safarov/dockerfiles; cd dockerfiles/captagent/alpine
docker build --tag="captagent:local" ./
docker run --net=host -t -i captagent:local
```

### Example docker-compose
```
captagent:
  container_name: captagent
  image: safarov/captagent
  restart: always
  net: host
  environment:
    - ETHERNET_DEV=eth0
    - CAPTURE_HOST=homer.domain.com
    - CAPTURE_PORT=9060
    - CAPTURE_FILTER=port 5060
    - CAPTURE_PASSWORD=myHep
    - RTCP_ENABLE=true
    - RTCP_PORTRANGE=10000-20000
    - LOG_LEVEL=3
```

### Example systemd unit
```
[Unit]
Description=captagentontainer
After=docker.service network-online.target
Requires=docker.service


[Service]
Restart=always
TimeoutStartSec=0
ExecStartPre=-/usr/bin/docker rm -f captagent
;Space symbol must be escaped https://www.freedesktop.org/software/systemd/man/systemd-escape.html
ExecStart=/usr/bin/docker run -t \
                 --rm=true \
                 --name=captagent \
                 --network=host \
                 -e ETHERNET_DEV=eth1 \
                 -e CAPTURE_HOST=10.4.6.41 \
                 -e CAPTURE_FILTER=port\x205060\x20or\x201100 \
                 -e LOG_LEVEL=3 \
                 safarov/captagent

ExecStop=/usr/bin/docker stop captagent

[Install]
WantedBy=multi-user.target
```