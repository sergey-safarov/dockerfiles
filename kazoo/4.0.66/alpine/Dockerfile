FROM alpine:3.6

RUN  apk --no-cache --allow-untrusted --repository http://217.12.247.220/repo-alpine-u search search -qe 'kazoo*' | \
           xargs apk --no-cache --allow-untrusted --repository http://217.12.247.220/repo-alpine-u add

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
