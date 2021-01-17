FROM alpine:edge

COPY  Makefile /tmp

RUN apk add make git \
    && cd /tmp \
    && apk add musl-utils musl-dev \
    && apk update muls musl-utils musl-dev \
    && git clone https://github.com/kamailio/kamailio.git \
    && cd kamailio/src \
    && make cfg
