#!/bin/sh

RELX_REPLACE_OS_VARS=${RELX_REPLACE_OS_VARS:-true}
NODE_NAME=${NODE_NAME:-kazoo_apps}
VMARGS_PATH=${VMARGS_PATH:-/etc/kazoo/vm.args}

echo "$HOSTNAME" | grep -qF '.'
if [ $? -ne 0 ]; then
        echo "Kazoo requires configred longmode hostname. Plase configrue hostname like 'host.domain' or 'host.example.org'" > /dev/stderr
        exit 1
fi

if [ ! -f "$VMARGS_PATH" ]; then
        echo "File '$VMARGS_PATH' does not exist"
        exit 1
fi

if [ "$RELX_REPLACE_OS_VARS" ]; then
        cp /etc/kazoo/vm.args /tmp/vm.args
        cp /etc/kazoo/vm.args /tmp/vm.args.orig
        VMARGS_PATH=/tmp/vm.args
fi

if [ "$RELX_REPLACE_OS_VARS" == "true" ];then
        export RELX_REPLACE_OS_VARS
fi
export NODE_NAME
export VMARGS_PATH

trap 'kill -TERM  ${!}' SIGTERM

/opt/kazoo/bin/kazoo-4.0.0 foreground &
pid="$!"

wait $pid
