# dumpcap
Container may be used in to record other container network traffic.

### Pull latest
```
docker pull safarov/dumpcap
```

### Run latest on other container
```
docker run -itd --name dumpcap --net=container:${CONTAINER_NAME} safarov/dumpcap
```

Run as systemd unit
```
systemctl add-requires dumpcap-docker@parent.service parent-docker.service
systemctl enable --now dumpcap-docker@parent.service
```

### Local Build & Test
```
git clone https://github.com/safarov/dockerfiles; cd dockerfiles/dumpcap/alpine
docker build --tag="dumpcap:local" ./
docker run --net=container:${CONTAINER_NAME} -t -i dumpcap:local
```

### Example docker-compose
```
captagent:
  container_name: dumpcap
  image: safarov/dumpcap
  restart: always
  net: container:${CONTAINER_NAME}
```

### Example systemd unit
Unit filename `dumpcap-docker@.service`
```
[Unit]
Description=dumpcap container template
After=docker.service network-online.target
Requires=docker.service


[Service]
Restart=always
TimeoutStartSec=0
ExecStartPre=-/usr/bin/docker rm -f dumpcap-%i
;Space symbol must be escaped https://www.freedesktop.org/software/systemd/man/systemd-escape.html
ExecStart=/usr/bin/docker run -t \
                --rm=true \
                --name=dumpcap-%i \
                --network=container:%i \
                -w="/dumpcap/%i" \
                -v dumpcap:/dumpcap \
                safarov/dumpcap

ExecStop=/usr/bin/docker stop dumpcap-%i

[Install]
WantedBy=multi-user.target
```