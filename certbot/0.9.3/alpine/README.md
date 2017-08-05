# General

For generation trusted certificate please execute
```
docker run -p 80:80  \
           -v /etc/letsencrypt:/etc/letsencrypt \
           safarov/certbot --rsa-key-size 4096 \
                   -m your-email@example.com \
                   -d certbot.example.com
```

Trusted certificate will placed in `/etc/letsencrypt` directory

You can generate test cerificate using command

```
docker run -p 80:80  \
           -v /etc/letsencrypt:/etc/letsencrypt \
           safarov/certbot --test-cert --rsa-key-size 4096 \
                   -m your-email@example.com \
                   -d certbot.example.com
```

# systemd unit file

For automatic certificate renewal you can create two systemd files
service file `/etc/systemd/system/certbot-docker.service`

```
[Unit]
Description=certbot container
After=docker.service network-online.target
Requires=docker.service


[Service]
Type=oneshot
IOSchedulingClass=idle
Nice=19
#One ExecStart/ExecStop line to prevent hitting bugs in certain systemd versions
ExecStart=/bin/sh -c 'docker rm -f certbot; \
          docker run -t -p 80:80 --name certbot \
                 -v /etc/letsencrypt:/etc/letsencrypt \
                 safarov/certbot renew; \
          docker rm -f certbot'

# Uncomment next commnad if you want copy new certificate to other host
#ExecStartPost=/usr/bin/rsync -e 'ssh -o "StrictHostKeyChecking=yes"' \
#                             --recursive --links /etc/letsencrypt \
#                             other-host.example.org:/etc/letsencrypt
```

And timer file `/etc/systemd/system/certbot-docker.timer`

```
[Unit]
Description=Renew certbot certificates every 15 days

[Timer]
OnBootSec=15d
OnUnitActiveSec=15m
Unit=certbot-docker.service

[Install]
WantedBy=multi-user.target
```
