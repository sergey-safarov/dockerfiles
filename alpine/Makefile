.DEFAULT_GOAL := test

#OS := $(shell uname -s | sed -e s/SunOS/solaris/ -e s/CYGWIN.*/cygwin/ \
#		 | tr "[A-Z]" "[a-z]" | tr "/" "_")

test:
	uname -a
	git clone https://github.com/kamailio/kamailio.git
	cd kamailio/src
	make cfg
#	$(info OS variable has value $(OS))
#	apk add gcc
#	gcc -v

