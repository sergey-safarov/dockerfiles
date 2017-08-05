#!/bin/sh

if [ $#  -eq 0 ]; then
    echo "Example of call 'docker run --net host certbot --test-cert -m your-email@example.com -d certbot.example.com --rsa-key-size 4096'"
    exit 1
fi

nginx

if [ "$1"=="renew" ]; then
    certbot renew --webroot --webroot-path /usr/share/nginx/html
    rc=$?
else
    certbot certonly -n --agree-tos --webroot --webroot-path /usr/share/nginx/html $@
    rc=$?
fi

nginx -s stop

exit $rc
