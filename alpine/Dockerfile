FROM alpine:edge

COPY  Makefile /tmp

RUN apk add make \
    && cd /tmp \
    && apk update muls \
    && make
