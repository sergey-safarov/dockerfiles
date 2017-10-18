FROM centos:7.3.1611

RUN yum -y install epel-release \
    && yum-config-manager --add-repo https://download.opensuse.org/repositories/home:/lazedo:/kamailio/CentOS_7/ \
    && yum -y --nogpgcheck install iproute tcpdump kamailio* \
    && rm -f /etc/yum.repos.d/217.12.247.220_repo.repo \
    && yum clean all \
    && rm -Rf /var/cache/yum/*


ENTRYPOINT ["/usr/sbin/kamailio", "-f", "/etc/kamailio/kamailio.cfg", "-DD", "-E"]
