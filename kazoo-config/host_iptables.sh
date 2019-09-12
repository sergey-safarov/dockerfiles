#!/bin/sh
TIMER=${TIMER-60}

iptables_command() {
local command=$1
if [ "${command}" != "A" -a "${command}" != "C" -a "${command}" != "D" -a "${command}" != "I" ]; then
	echo "error: not supported iptables command '${command}'"
	exit 1
fi
iptables -t nat -${command} POSTROUTING -m addrtype --src-type LOCAL -m comment --comment "Removing outbound NAT for local connections" -j ACCEPT
}

add_rule() {
iptables_command "I" && echo "iptables rule added" || echo "cannot add iptables rule"
}

del_rule() {
iptables_command "D" && echo "iptables rule deleted" || echo "cannot delete iptables rule"
}

check_rule() {
iptables_command "C" &> /dev/null
}

on_exit() {
del_rule
exit 0
}

main() {
echo "checking iptables rule every ${TIMER} second"
while true; do
	if ! check_rule; then
		add_rule
	fi
	sleep ${TIMER}
done
}

trap on_exit SIGINT SIGTERM

main
