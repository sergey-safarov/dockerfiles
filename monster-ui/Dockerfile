FROM alpine as build

ENV UI_VER 4.3.57
ENV UI_VOIP_VER 4.3.22
ENV UI_CALLFLOWS_VER 4.3.9
ENV UI_ACCOUNTS_VER 4.3.5
ENV UI_PBXS_VER 4.3.1
ENV UI_WEBHOOKS_VER 4.3.3
ENV UI_NUMBERS_VER 4.3.0
ENV UI_FAX_VER 4.3.3
ENV UI_VOICEMAILS_VER 4.3.2
ENV UI_CSV_VER 4.3.3

RUN apk add git npm \
    && npm install gulp -g

RUN git clone --branch ${UI_VER} https://github.com/2600hz/monster-ui.git /tmp/monster-ui \
    && git clone --branch ${UI_VOIP_VER} https://github.com/2600hz/monster-ui-voip.git /tmp/monster-ui/src/apps/voip \
    && git clone --branch ${UI_CALLFLOWS_VER} https://github.com/2600hz/monster-ui-callflows.git /tmp/monster-ui/src/apps/callflows \
    && git clone --branch ${UI_ACCOUNTS_VER} https://github.com/2600hz/monster-ui-accounts.git /tmp/monster-ui/src/apps/accounts \
    && git clone --branch ${UI_PBXS_VER} https://github.com/2600hz/monster-ui-pbxs.git /tmp/monster-ui/src/apps/pbxs \
    && git clone --branch ${UI_WEBHOOKS_VER} https://github.com/2600hz/monster-ui-webhooks.git /tmp/monster-ui/src/apps/webhooks \
    && git clone --branch ${UI_NUMBERS_VER} https://github.com/2600hz/monster-ui-numbers.git /tmp/monster-ui/src/apps/numbers \
    && git clone --branch ${UI_FAX_VER} https://github.com/2600hz/monster-ui-fax.git /tmp/monster-ui/src/apps/fax \
    && git clone --branch ${UI_VOICEMAILS_VER} https://github.com/2600hz/monster-ui-voicemails.git /tmp/monster-ui/src/apps/voicemails \
    && git clone --branch ${UI_CSV_VER} https://github.com/2600hz/monster-ui-csv-onboarding.git /tmp/monster-ui/src/apps/csv

COPY files/ /tmp

RUN git config --global user.email "you@example.com" \
    && git config --global user.name "Your Name" \
    && cd /tmp/monster-ui \
    && find /tmp/patches -maxdepth 1 -type f -name *.patch -exec git am {} \; \
    && cd /tmp/monster-ui/src/apps/accounts \
    && find /tmp/patches/accounts -maxdepth 1 -type f -name *.patch -exec git am {} \; \
    && cd /tmp/monster-ui/src/apps/callflows \
    && find /tmp/patches/callflows -maxdepth 1 -type f -name *.patch -exec git am {} \; \
    && cd /tmp/monster-ui/src/apps/csv \
    && find /tmp/patches/csv -maxdepth 1 -type f -name *.patch -exec git am {} \; \
    && cd /tmp/monster-ui/src/apps/fax \
    && find /tmp/patches/fax -maxdepth 1 -type f -name *.patch -exec git am {} \; \
    && cd /tmp/monster-ui/src/apps/numbers \
    && find /tmp/patches/numbers -maxdepth 1 -type f -name *.patch -exec git am {} \; \
    && cd /tmp/monster-ui/src/apps/pbxs \
    && find /tmp/patches/pbxs -maxdepth 1 -type f -name *.patch -exec git am {} \; \
    && cd /tmp/monster-ui/src/apps/voicemails \
    && find /tmp/patches/voicemails -maxdepth 1 -type f -name *.patch -exec git am {} \; \
    && cd /tmp/monster-ui/src/apps/voip \
    && find /tmp/patches/voip -maxdepth 1 -type f -name *.patch -exec git am {} \; \
    && cd /tmp/monster-ui/src/apps/webhooks \
    && find /tmp/patches/webhooks -maxdepth 1 -type f -name *.patch -exec git am {} \; \
    && echo "patches applied" \
    && cd /tmp/monster-ui \
    && npm install \
    && gulp build-all \
    && mkdir -p /tmp/target/etc/nginx/conf.d \
    && mkdir -p /tmp/target/var/www \
    && mkdir -p /tmp/target/run/nginx \
    && cp /tmp/entrypoint.sh /tmp/target \
    && chmod 755 /tmp/target/entrypoint.sh \
    && mkdir -p /tmp/target/etc/nginx/sites-available \
    && mkdir -p /tmp/target/etc/nginx/sites-enabled \
    && mv /tmp/local.conf /tmp/target/etc/nginx/conf.d \
    && mv /tmp/monster-ui.conf /tmp/target/etc/nginx/sites-available \
    && ln -s ../sites-available/monster-ui.conf /tmp/target/etc/nginx/sites-enabled \
    && mv dist /tmp/target/var/www/monster-ui-prod \
    && mv distDev /tmp/target/var/www/monster-ui-dev

FROM alpine
RUN apk --no-cache add nginx \
    && rm -f /etc/nginx/conf.d/default.conf

COPY --from=build /tmp/target/ /
ENTRYPOINT ["/entrypoint.sh"]
