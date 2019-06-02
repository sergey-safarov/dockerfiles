FROM debian:9

RUN apt-get update \
    && apt-get install -y gnupg2 wget git python-pip \
    && wget -O - https://files.freeswitch.org/repo/deb/freeswitch-1.8/fsstretch-archive-keyring.asc | apt-key add - \
    && wget -O - https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add - \
    && echo "deb http://files.freeswitch.org/repo/deb/freeswitch-1.8/ stretch main" > /etc/apt/sources.list.d/freeswitch.list \
    && echo "deb-src http://files.freeswitch.org/repo/deb/freeswitch-1.8/ stretch main" >> /etc/apt/sources.list.d/freeswitch.list \
    && echo "deb http://deb.nodesource.com/node_10.x stretch main" > /etc/apt/sources.list.d/nodesource.list \
    && echo "deb-src http://deb.nodesource.com/node_10.x stretch main" >> /etc/apt/sources.list.d/nodesource.list \
    && echo '{ "allow_root": true }' > /root/.bowerrc \
    && apt-get update \
    && apt-get install -y python-esl nodejs \
    && git clone https://github.com/roramirez/qpanel.git \
    && cd qpanel \
    && npm install \
    && pip install -r requirements.txt \
    && cp samples/config.ini-dist /etc/qpanel.ini \
    && ln -s /etc/qpanel.ini config.ini \
    && ./node_modules/.bin/bower install

ENTRYPOINT ["python", "/qpanel/app.py"]
