.DEFAULT_GOAL := test

OS := $(shell uname -s | sed -e s/SunOS/solaris/ -e s/CYGWIN.*/cygwin/ \
		 | tr "[A-Z]" "[a-z]" | tr "/" "_")

test:
	$(info OS variable has value $(OS))
#	apk add gcc
#	gcc -v

