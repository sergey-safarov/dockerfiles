FROM kamailio/kamailio-ci:5.1.6-alpine as build

RUN apk add git

RUN echo "Downloading core repos" \
    && mkdir /etc/kazoo \
    && git clone -b no_swarm https://github.com/sergey-safarov/kazoo-configs-kamailio.git /etc/kazoo/kazoo-configs-kamailio \
    && git clone https://github.com/sergey-safarov/kazoo-configs-freeswitch.git /etc/kazoo/kazoo-configs-freeswitch \
    && git clone https://github.com/sergey-safarov/kazoo-configs-core.git /etc/kazoo/kazoo-configs-core

RUN echo "Preparing PostgreSQL database init files" \
    && DB_ENGINE=postgres /etc/kazoo/kazoo-configs-kamailio/kamailio/db_scripts/create-kazoodb-sql.sh \
    && sed -e '/^COMMIT.*/i ALTER TABLE presentity ALTER COLUMN etag TYPE varchar(128);' \
           -e '/^COMMIT.*/i ALTER TABLE location_attrs ALTER COLUMN avalue TYPE varchar(512);' \
           -i /tmp/kamailio_initdb.sql \
    && mv /tmp/kamailio_initdb.sql /etc/kazoo/kazoo-configs-kamailio/kamailio/db_scripts
ADD kamailio-db-rows.sql /etc/kazoo/kazoo-configs-kamailio/kamailio/db_scripts/
ADD 01-kazoo-db-init.sql 02-kazoo-db-init.sh /etc/kazoo/kazoo-configs-kamailio/kamailio/db_scripts/docker-entrypoint-initdb.d/

RUN echo "Preparing kazoo config.ini" \
    && rm -f /etc/kazoo/kazoo-configs-core/core/config.ini
ADD kazoo-config.ini /etc/kazoo/kazoo-configs-core/core/config.ini

RUN echo "Preparing daemons init scripts"
ADD kamailio-init.sh /etc/kazoo/

RUN echo "Preparing FreeSwitch config" \
    && sed -i -e '/docker_ip_v4/d' /etc/kazoo/kazoo-configs-freeswitch/freeswitch/freeswitch.xml \
    && sed -i -e 's/docker_ip_v4/local_ip_v4/' /etc/kazoo/kazoo-configs-freeswitch/freeswitch/sip_profiles/sipinterface_1.xml

RUN echo "Removing .git folders from repos" \
    && rm -Rf /etc/kazoo/kazoo-configs-core/.git \
              /etc/kazoo/kazoo-configs-freeswitch/.git \
              /etc/kazoo/kazoo-configs-kamailio/.git

ADD app.py /etc/kazoo/kazoo-configs-kamailio/kamailio/


FROM alpine:edge
COPY --from=build /etc/kazoo /etc/kazoo
RUN apk --no-cache add jq curl bind-tools python3 \
    && pip3 install kubernetes awscli boto3
