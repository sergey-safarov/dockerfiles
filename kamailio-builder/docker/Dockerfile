FROM alpine:edge

RUN apk add --no-cache abuild git gcc build-base bison flex expat-dev postgresql-dev pcre-dev mariadb-dev \
    libxml2-dev curl-dev unixodbc-dev confuse-dev ncurses-dev sqlite-dev lua-dev openldap-dev \
    libressl-dev net-snmp-dev libuuid libev-dev jansson-dev json-c-dev libevent-dev linux-headers \
    libmemcached-dev rabbitmq-c-dev hiredis-dev libmaxminddb-dev libunistring-dev \
    && adduser -D build && addgroup build abuild \
    && echo "%abuild ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/abuild \
    && su - build -c "git config --global user.name 'Your Full Name'" \
    && su - build -c "git config --global user.email 'your@email.address'" \
    && su - build -c "abuild-keygen -a -i"
