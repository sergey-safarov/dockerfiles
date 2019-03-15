FROM alpine:edge as build
WORKDIR /scratch
RUN apk add wireshark-common \
    && ldd /usr/bin/dumpcap | sed -e 's/^.* => //' -e 's/ (.*)//' -e 's/\s\+//' -e '/^ldd$/d' > filelist \
    && echo /lib >> filelist \
    && echo /tmp >> filelist \
    && echo /usr/lib >> filelist \
    && echo /usr/bin >> filelist \
    && echo /usr/bin/dumpcap >> filelist \
    && cat filelist | xargs realpath > filelist.real \
    && cat filelist >> filelist.real \
    && sort filelist.real > filelist \
    && tar -czf scratch.tar.gz --no-recursion $(cat filelist) \
    && tar xzf scratch.tar.gz \
    && rm -f scratch.tar.gz filelist filelist.real

FROM scratch
COPY --from=build /scratch /
ENTRYPOINT ["dumpcap", "-w", "packets.pcap"]

