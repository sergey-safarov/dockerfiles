FROM alpine:edge

RUN echo 'http://dl-cdn.alpinelinux.org/alpine/edge/testing' >> /etc/apk/repositories \
    && apk --no-cache add bird \
    && rm -f /etc/bird.conf

ADD bird.conf /etc/

ENTRYPOINT ["bird", "-f"]
