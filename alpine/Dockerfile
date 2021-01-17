FROM alpine:edge

COPY  Makefile /tmp

RUN apk add make \
    && apk add musl-utils musl-dev \
    && apk update muls musl-utils musl-dev \
    && cd /tmp \
    && make

