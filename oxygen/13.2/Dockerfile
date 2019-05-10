# This container maybe started by command
# docker run -d --rm --volume="${XAUTHORITY}:/.Xauthority:rw" --volume="${HOME}:${HOME}" -w="${HOME}" --env="HOME" --env="DISPLAY" --user="${UID}" --network host safarov/oxygen:13.2

FROM centos:7

RUN yum -y install libXext libXtst \
    && yum clean all \
    && rm -Rf /var/lib/yum/* \
    && curl http://archives.oxygenxml.com/Oxygen/Editor/InstData13.2/All/oxygen.tar.gz > /tmp/oxygen.tar.gz \
    && cd /usr/local \
    && tar xzf /tmp/oxygen.tar.gz \
    && rm -f /tmp/oxygen.tar.gz \
    && curl http://217.12.247.220/jdk-6u45-linux-x64-rpm.bin > /tmp/jdk-6u45-linux-x64-rpm.bin \
    && chmod 755 /tmp/jdk-6u45-linux-x64-rpm.bin \
    && /tmp/jdk-6u45-linux-x64-rpm.bin \
    && rm -f /tmp/jdk-6u45-linux-x64-rpm.bin

ENTRYPOINT ["/usr/local/oxygen/oxygen.sh"]
