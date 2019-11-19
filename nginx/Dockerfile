FROM alpine:edge
RUN apk --no-cache add nginx nginx-mod-http-lua-upstream lua-json4 lua5.1-uuid openssh-client \
    && mkdir -p /etc/nginx/sites-available \
    && mkdir -p /etc/nginx/sites-enabled \
    && mkdir -p /run/nginx \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
    && rm -f /etc/nginx/conf.d/default.conf \
    \
    && echo "gzip on;" > /etc/nginx/conf.d/local.conf \
    && echo "ssl_session_timeout 10m;" >> /etc/nginx/conf.d/local.conf \
    && echo "include sites-enabled/*;" >> /etc/nginx/conf.d/local.conf

STOPSIGNAL SIGTERM

CMD ["nginx", "-g", "daemon off;"]
