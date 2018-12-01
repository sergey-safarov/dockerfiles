#!/bin/sh

get_nic_list() {
    cat /proc/net/dev | grep -o '^.*:' | sed -e 's/^\s*//' -e 's/://' -e '/lo/d'
}

RC=0

for i in $(get_nic_list); do
    ip link set $i down
    RC=$?
    if [ ${RC} -ne 0 ]; then
        echo "error: cannot set link $i to DOWN state"
        echo "Probable need to add '--cap-add=NET_ADMIN' options to run command"
        exit ${RC}
    fi
done

exec tail -f /dev/null
