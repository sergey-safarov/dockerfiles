FROM nginx:1.17.2-alpine

ADD entrypoint.sh /
RUN apk --no-cache add certbot

ENTRYPOINT ["/entrypoint.sh"]
