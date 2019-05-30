FROM alpine:edge as build

COPY voipmonitor.conf /tmp
COPY entrypoint.sh /tmp

RUN apk add wget
RUN echo "Downloading installer" \
    && wget --no-verbose \
            --output-document=/tmp/voipmonitor.tar.gz \
            http://www.voipmonitor.org/current-stable-sniffer-static-64bit.tar.gz

RUN echo "Extracting installer" \
    && tar x -z -f /tmp/voipmonitor.tar.gz -C /tmp \
    && mv /tmp/voipmonitor-amd64-* /tmp/voipmonitor-dist

RUN echo "Installing voipmonitor" \
    && rm /tmp/voipmonitor-dist/install-script.sh \
    && cp /tmp/voipmonitor.conf /tmp/voipmonitor-dist/etc/voipmonitor.conf \
    && cp /tmp/entrypoint.sh    /tmp/voipmonitor-dist/entrypoint.sh \
    && mkdir -p /tmp/voipmonitor-dist/var/spool/voipmonitor/rrd \
    && chmod ugo+x /tmp/voipmonitor-dist/entrypoint.sh

FROM alpine:edge
COPY --from=build /tmp/voipmonitor-dist/ /
RUN apk --no-cache add rrdtool
ENTRYPOINT ["/entrypoint.sh"]


