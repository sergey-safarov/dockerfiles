FROM alpine:edge

COPY  Makefile /tmp

RUN apk add make \
    && apk update muls musl-utils musl-dev \
    && cd /tmp \
    && make

#    && apk add musl-utils musl-dev \
