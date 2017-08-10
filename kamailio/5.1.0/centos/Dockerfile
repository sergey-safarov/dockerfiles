FROM centos:7.3.1611

RUN yum -y install epel-release \
    && yum-config-manager --add-repo http://217.12.247.220/repo \
    && yum -y --nogpgcheck install iproute tcpdump kamailio* \
    && rm /etc/yum.repos.d/217.12.247.220_repo.repo \
    && yum clean all \
    && rm -Rf /var/cache/yum/*


ENTRYPOINT ["/usr/sbin/kamailio", "-f", "/etc/kamailio/kamailio.cfg", "-m", "64", "-M", "8", "-DD", "-E"]
