FROM alpine:edge

ADD entrypoint.sh /
RUN apk --no-cache add captagent tini

STOPSIGNAL HUP
ENTRYPOINT ["/entrypoint.sh"]
#ENTRYPOINT ["tini", "--", "/entrypoint.sh"]
