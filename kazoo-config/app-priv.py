#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
from flask import Flask, request, g, jsonify
import ipaddress

try:
    assert sys.version_info >= (3, 7)
except:
    print("Please run with Python 3.7 or higher")
    exit(1)

try:
    from kubernetes import client, config
except:
    print("Please install kubernetes - `pip3 install kubernetes`")
    exit(1)

try:
    import boto3
except:
    print("Please install boto3 - `pip3 install boto3`")
    exit(1)

try:
    import awscli.__main__ as _
except:
    print("Please install aws-cli - `pip3 install awscli`")
    exit(1)

import os
import subprocess
import re

from typing import List, Dict, Any

from kubernetes.client.models.v1_pod import V1Pod
from kubernetes.client.models.v1_object_meta import V1ObjectMeta
from kubernetes.client.models.v1_pod_list import V1PodList
from kubernetes.client.models.v1_node_list import V1NodeList
from kubernetes.client.models.v1_node import V1Node
from kubernetes.client.models.v1_stateful_set_list import V1StatefulSetList
from kubernetes.client.models.v1_stateful_set import V1StatefulSet
from kubernetes.client.rest import ApiException

if (
    not os.environ.get("AWS_ACCESS_KEY_ID")
    or not os.environ.get("AWS_SECRET_ACCESS_KEY")
    or not os.environ.get("AWS_DEFAULT_REGION")
):
    print(
        """Please setup AWS credentials.
        We expect not empty AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_DEFAULT_REGION"""
    )
    exit(1)

# Check provider credentionals
try:
    ec2 = boto3.client("ec2")
    ec2r = boto3.resource("ec2")
    ssm_client = boto3.client("ssm")

except Exception:
    print("Please setup AWS credentials")
    exit(1)

# Check kubernetes local config
try:
    config.load_incluster_config()
except:
    print("please run within cluster pod")
    exit(1)
    # config.load_kube_config()

NAMESPACE = (
    open("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
    .readlines()[0]
    .replace("\n", "")
)
v1 = client.CoreV1Api()
v1a = client.AppsV1Api()

app = Flask(__name__)

cluster_name = "ippbx"
pod_prefix = "pod-"
current_stateful_set = "proxy-priv-dc1"


@app.route("/configure_priv_pod/", methods=["POST"])
def main():
    operations_log = []

    my_ip = request.remote_addr
    operations_log.append(f"My IP: {my_ip}")

    parent_stateful_set = get_statful_set_by_ip(my_ip)
    operations_log.append(f"My statefulset: {parent_stateful_set}")

    host_ip = get_host_ip_by_pod_ip(my_ip)
    instance_id, network_interface_host, network_interface_pod = get_instance_id_by_host_ip(
        host_ip, my_ip
    )
    operations_log.append(f"Host IP: {host_ip}")
    operations_log.append(f"Instance ID: {instance_id}")

    private_ip_pool = get_private_ip_pool_from_annotation(current_stateful_set)
    operations_log.append(f"Private IP pool: {private_ip_pool}")
    if not private_ip_pool:
        return jsonify(
            {
                "error": f"error: cannot determine private IP addresses for service: {parent_stateful_set}",
                "operations_log": operations_log,
            }
        )

    # Проверка 1
    # 1) проверять наличие ipset - "ipset list %{satefulset_name}"
    # 2) если не нашли, то создавать -> " ipset create %{satefulset_name} nethash"
    # 3) если нашли, то продолжаем обработку

    ipset_results, err = execute_ssm_command(
        instance_id, f"ipset list {parent_stateful_set}"
    )
    operations_log.append(f"IP set list - {ipset_results}")

    if err:
        command = f"ipset create {parent_stateful_set} nethash"
        ipset_results, err = execute_ssm_command(instance_id, command)
        operations_log.append(f"creating ipset - {command}")
        if err:
            operations_log.append(f"IP set create errors - {err}")
        else:
            ipset_results, err = execute_ssm_command(
                instance_id, f"ipset list {parent_stateful_set}"
            )

    # Проверка 2
    # pod -> statfll set -> annotation private ip
    # to find the second running pod in the same stateful set
    # 1) в полученном результате проверяем IP адреса в списке ipset.
    # Адреса которые не входят в этот statefulset удаляем комадой вида "ipset del %{satefulset_name} %{members_pods.my_ipN}"
    # 2) добавлем для кажого "annotation private ip" что входит в этот статефулсет правило вида "ipset add %{satefulset_name} %{annotation.private_ipN}".
    # Если правило есть, то команда выдаст ошибку. Ошибку игнорируем. В принципе можно добавлять только те адреса которых нет в ipset.

    ipset_addresses = (
        ipset_results[ipset_results.index("Members:") + 1 : -1]
        if "Members:" in ipset_results
        else []
    )
    operations_log.append(f"IPset addresses - {ipset_addresses}")

    for ip in ipset_addresses:
        if ip not in private_ip_pool:
            res, err = execute_ssm_command(
                instance_id, f"ipset del {parent_stateful_set} {ip}"
            )
            operations_log.append(f"IP set del res - {res}")

    for ip in private_ip_pool:
        if ip not in ipset_addresses:
            res, err = execute_ssm_command(
                instance_id, f"ipset add {parent_stateful_set} {ip}"
            )
            operations_log.append(f"IP set add res - {res}")

    # Проверка 3
    # 1) получаем список правил iptables - "iptables-save"
    # 2) искать в нем строку "-A POSTROUTING -m comment --comment "kamailio-helper for statefulset %{satefulset_name}" -m set --match-set %{satefulset_name} src -j ACCEPT";
    # 3) если не нашли, то добавляем ее iptables -t nat -I POSTROUTING -m comment --comment "kamailio-helper for statefulset %{satefulset_name}" -m set --match-set %{satefulset_name} src -j ACCEPT
    # 4) нашли, продожаем обработку

    res, err = execute_ssm_command(instance_id, f"iptables-save")
    if err:
        operations_log.append(f"iptables resolve errors - {err}")

    iptable_res_found = False
    for r in res:
        if (
            f'-A POSTROUTING -m comment --comment "kamailio-helper for statefulset {parent_stateful_set}" -m set --match-set {parent_stateful_set} src -j ACCEPT'
            in r
        ):
            iptable_res_found = True
            operations_log.append(f"Found matching iptables rule")

    if not iptable_res_found:
        operations_log.append(f"iptables - {res}")
        command = f'iptables -t nat -I POSTROUTING -m comment --comment "kamailio-helper for statefulset {parent_stateful_set}" -m set --match-set {parent_stateful_set} src -j ACCEPT'

        res, err = execute_ssm_command(instance_id, command)
        if err:
            operations_log.append(f"iptables add errors - {err}")
        else:
            operations_log.append(f"added iptables rule - {command}")

    # current_namespace = get_namespace(current_stateful_set)

    pod_uuids, uuids_mapping = get_pods_uuids(current_stateful_set)
    operations_log.append(f"pod_uuids: {pod_uuids}")
    # not_processed_addresses = []
    for pod_uuid in pod_uuids:
        operations_log.append(f"checking annotation: {pod_uuid}")
        pod = get_pod_by_uuid(NAMESPACE, pod_uuid)
        # check if pods with uuids exists - ok, if not exits - delete
        # check the pod is part of the stateful set. if not - delete annotation
        # V1ObjectMeta
        # type: # V1ObjectMeta.owner_references

        if not pod or not any(
            [
                ref.name == current_stateful_set
                for ref in pod.metadata.owner_references
                if ref.kind == "StatefulSet"
            ]
        ):
            operations_log.append(f"removing annotation: {pod_uuid}")
            delete_annotation(pod_uuid)
        # else:
        #     if pod:
        # not_processed_addresses.append(pod.status.pod_ip)
        # operations_log.append(
        #     f"Excluding IP {pod.status.pod_ip} from configuration as already used on pod {pod.metadata.uid}")

    # 3 if k8s used one of the addresses (check in all podIPs) - exclude the IP address from checks
    # ips_to_check = [i for i in private_ip_pool if i not in not_processed_addresses]

    # for ip in private_ip_pool:
    # check if ip in k8s pods
    namespace_pods = get_pods_by_namespace(NAMESPACE)
    for pod in namespace_pods:
        if pod.status.pod_ip in private_ip_pool:
            operations_log.append(
                f"WARNING - {pod.status.pod_ip} used by pod {pod.metadata.name}. Excluding IP {pod.status.pod_ip} from statefulset IP address as already used"
            )
            private_ip_pool.remove(pod.status.pod_ip)

    ips_to_check = private_ip_pool.copy()
    for ip in private_ip_pool:
        is_used, instance_id = address_used_by_ec2_instances(ip)
        if is_used:
            operations_log.append(
                f"WARNING - IP address {ip} is used by ec2 instance {instance_id}. Excluding IP {ip} from configuration as already used"
            )
            # if used - exclude from checks
            # operations_log.append(f"Excluding IP {ip} from configuration as already used")
            ips_to_check.remove(ip)

    # 5 проверяем что pod.uid curl клиента присутстует в анотации statefulset.
    # Если есть, то возвращаем заначение анотации и заврегаем работу скрипта;

    curl_uid = get_uid_by_pod_ip(my_ip)
    if curl_uid in pod_uuids:
        curl_ext_ip = uuids_mapping[f"{pod_prefix}{curl_uid}"]
        operations_log.append(f"client uid {curl_uid} found in statefulset uids")
        return jsonify({"operations_log": operations_log, "assigned_ip": curl_ext_ip})

    # 6 no addresses left - return error
    if not ips_to_check:
        operations_log.append(f"No ips left to check")
        return jsonify({"operations_log": operations_log, "error": "No addresses left"})

    # 7 check the same for k8s instances - remove configuration
    for ip in ips_to_check:
        res = address_used_by_k8s_node(ip)
        if not res:
            operations_log.append(f"no instances found for IP {ip}")
            continue
        instance, instance_private_ip, instance_network_interface = res
        if instance:
            operations_log.append(
                f"IP address {ip} is used by instance {instance['InstanceId']}, will be removed"
            )
            # remove address from instance
            res, err = execute_ssm_command(instance["InstanceId"], "ip -4 addr show")
            if not err:
                # operations_log.append(res)
                relevant_results_row = [i for i in res if ip in i]
                if relevant_results_row:
                    # Команда на удаление адреса
                    # ip addr del {ip_address/mask} dev {device_name}
                    # Example
                    # ip addr del 19.19.19.17/30 dev eth1
                    #
                    # Команда для проверки что адреса более нет
                    # ip -4 addr show dev {device_name}
                    # Example
                    # ip -4 addr show dev eth1
                    # https://docs.aws.amazon.com/cli/latest/reference/ec2/unassign-private-ip-addresses.html
                    """    inet 192.168.100.31/24 brd 192.168.100.255 scope global dynamic noprefixroute wlp1s0"""
                    vars = relevant_results_row[0].split(" ")
                    ip_with_mask = vars[1]
                    linux_network_interface = vars[-1]

                    res, err = execute_ssm_command(
                        instance["InstanceId"],
                        f"ip addr del {ip_with_mask} dev {linux_network_interface}",
                    )

                ec2.unassign_private_ip_addresses(
                    NetworkInterfaceId=instance_network_interface,
                    PrivateIpAddresses=[instance_private_ip],
                )

                operations_log.append(
                    f"IP {ip} unassigned from {instance['InstanceId']} : {instance_network_interface}"
                )

    # 8 получить спискок всех ID сетевых карточек для instance_id на котором находится curl клиент
    interfaces_ids, instance = get_network_interfaces_by_ip(my_ip)
    # 9 по очереди начать прикреплять к каждой сетевой карточки выбраное значение IP адреса из анотации.
    # Амазон может не дать прикрепить к одной карте, пробуем прикрепить к следующей карте.
    # Если удолось выходим, если нет идем далее

    assignment_ip = ips_to_check[-1]
    for interface_id in interfaces_ids:
        # https://docs.aws.amazon.com/cli/latest/reference/ec2/assign-private-ip-addresses.html
        args = {
            "AllowReassignment": False,
            "NetworkInterfaceId": interface_id,
            "PrivateIpAddresses": [assignment_ip],
        }
        try:
            ec2.assign_private_ip_addresses(**args)
            operations_log.append(
                f"Successfully assign address {assignment_ip} to interface id {interface_id}"
            )
            add_annotation(current_stateful_set, curl_uid, assignment_ip)
            return jsonify(
                {"operations_log": operations_log, "assigned_ip": assignment_ip}
            )

        except Exception as e:
            operations_log.append(
                f"""Failed to assign address {assignment_ip} to interface id {interface_id} - {e}. 
                args - {args}"""
            )

    # 10) ишем ID сети к которой подключены первая сетевая карта kube host
    # (aws ec2 describe-network-interfaces --network-interface-ids eni-02181b7a7d962ec2b --query 'NetworkInterfaces[*].SubnetId' --output json)
    # done in get_network_interfaces_by_ip

    # 11) ищем Group привязааные к первой сетевой карте aws ec2 describe-network-interfaces --network-interface-ids eni-07a97c511712948e9 --query 'NetworkInterfaces[*].Groups' --output json
    groups = get_groups_for_first_network_interface(instance)
    operations_log.append(f"groups: {groups}")

    # 12) Получаем занятые IP адреса в локальной сети (aws ec2 describe-network-interfaces --filters "Name=subnet-id,Values=subnet-00224cfd31ac390e9" --query 'NetworkInterfaces[*].PrivateIpAddresses[*].PrivateIpAddress' --output json')
    used_ip_address = get_all_used_ip_for_subnet(instance["SubnetId"])
    operations_log.append(f"used ip addresses: {used_ip_address}")

    # 13) получаем адрес сети aws ec2 describe-subnets --subnet-ids subnet-0b59ea0b349d43697 --output json --query 'Subnets[0].CidrBlock
    subnet = get_subnet_by_id(instance["SubnetId"])
    operations_log.append(f"subnet: {subnet}")

    # 14) ищем адрес который не используется в этой сети (нужен IP калькулятор тут) и не используется в private_pool
    first_unused_ip = get_first_unused_address(subnet, used_ip_address + ips_to_check)
    operations_log.append(f"first unused ip: {first_unused_ip}")

    # 15) Создаем новую карту с адресом который только-что нашли.  Если Амазон не дал создать новую карту, то curl клиенту выводим ошибку которую я буду к клиенте обрабатывать. Мне нужно только эту ошибку подсветить;
    try:
        new_interface = ec2.create_network_interface(
            SubnetId=instance["SubnetId"],
            PrivateIpAddress=first_unused_ip,
            Groups=groups,
        )
    except Exception as e:
        operations_log.append(f"Failed to create network interface - {e}")
        return jsonify({"operations_log": operations_log})

    operations_log.append(f"new interface: {new_interface}")
    new_interface_mac = new_interface["NetworkInterface"]["MacAddress"]
    new_interface_id = new_interface["NetworkInterface"]["NetworkInterfaceId"]

    # 16) выставлем новой карте таг "helper=kamailio" https://docs.aws.amazon.com/cli/latest/reference/ec2/create-tags.html
    try:
        ec2.create_tags(
            Resources=[new_interface_id], Tags=[{"Key": "helper", "Value": "kamailio"}]
        )
    except Exception as e:
        operations_log.append(
            f"Failed to add tag to the interface {new_interface_id} - {e}"
        )
        return jsonify({"operations_log": operations_log})

    # 18) атачим новую карту в инстанс
    next_available_index = find_device_index(instance)
    try:
        attachment = ec2.attach_network_interface(
            DeviceIndex=next_available_index,
            InstanceId=instance["InstanceId"],
            NetworkInterfaceId=new_interface_id,
        )
        operations_log.append(f"attachment: {attachment}")
    except Exception as e:
        ec2.delete_network_interface(NetworkInterfaceId=new_interface_id)
        operations_log.append(
            f"Failed to add attach additional network interface - {e}"
        )
        return jsonify({"operations_log": operations_log})

    # 19) выставлем новой карте флаг DeleteOnTermination
    # https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-network-interface-attribute.html
    # res = ec2.modify_network_interface_attribute(
    #     Attachment={
    #         "AttachmentId": attachment["AttachmentId"],
    #         "DeleteOnTermination": True,
    #     },
    #     NetworkInterfaceId=new_interface_id,
    # )
    # operations_log.append(f"Result of network interface attribute modification: {res}")

    # 20) Пробуем прикрепить значение IP адреса из анотации private_pool к новой карте
    args = {
        "AllowReassignment": False,
        "NetworkInterfaceId": new_interface_id,
        "PrivateIpAddresses": [assignment_ip],
    }
    try:
        ec2.assign_private_ip_addresses(**args)
        operations_log.append(
            f"Successfully assign address {assignment_ip} to interface id {new_interface_id}"
        )

        instance_id, network_interface_host, network_interface_pod = get_instance_id_by_host_ip(
            host_ip, my_ip
        )

        # 22) через ssm на инстанце найти сетевую карту с MAC адресом новой карты ip link show
        operations_log.append(f"Executing ip link show on {instance_id}")
        res, err = execute_ssm_command(instance_id, "ip link show")
        print(err)
        network_card = find_network_card_in_ip_link_output(res, new_interface_mac)
        operations_log.append(res)
        # 23) через ssm выполнить команду ip addr add 173.21.1.105/32 dev eth2 (тут маска 32 важна)
        res, err = execute_ssm_command(
            instance_id,
            f"ip addr add {assignment_ip}/{subnet['CidrBlock'].split('/')[1]} dev {network_card}",
        )
        print(err)
        operations_log.append(res)
        # 24) через ssm выполнить команду ip rule add from {private_ip_address} table {table_index}.
        res, err = execute_ssm_command(
            instance_id,
            f"ip rule add from {assignment_ip} table {next_available_index+1}",
        )
        print(err)
        operations_log.append(res)

        # 21) в statefuleset добавить анатацию "pod-(uuid}:{assigned_private_ip}"
        add_annotation(current_stateful_set, curl_uid, assignment_ip)

        return jsonify({"operations_log": operations_log, "assigned_ip": assignment_ip})

    except Exception as e:
        operations_log.append(
            f"""Failed to assign address {assignment_ip} to interface id {new_interface_id} - {e}.
            Args - {args}"""
        )

    return jsonify(
        {
            "operations_log": operations_log,
            "error": "can't assign custom stateful set IP",
        }
    )


@app.route("/test/", methods=["POST"])
def test():
    err = ""
    uid = "3662f97a-e356-11e9-a607-0680ea3ad016"
    ip = "172.21.1.104"
    interface = "eni-0c94c7fb4183ddd45"
    subnet = {
        "AvailabilityZone": "us-west-2b",
        "AvailabilityZoneId": "usw2-az1",
        "AvailableIpAddressCount": 202,
        "CidrBlock": "172.21.1.0/24",
        "DefaultForAz": False,
        "MapPublicIpOnLaunch": True,
        "State": "available",
        "SubnetId": "subnet-00224cfd31ac390e9",
        "VpcId": "vpc-1e50277a",
        "OwnerId": "612528789372",
        "AssignIpv6AddressOnCreation": False,
        "Ipv6CidrBlockAssociationSet": [],
        "Tags": [
            {"Key": "Name", "Value": "172-VoIP-2b"},
            {"Key": "kubernetes.io/cluster/ippbx", "Value": "shared"},
            {"Key": "kubernetes.io/role/elb", "Value": ""},
            {"Key": "kubernetes.io/role/internal-elb", "Value": ""},
        ],
        "SubnetArn": "arn:aws:ec2:us-west-2:612528789372:subnet/subnet-00224cfd31ac390e9",
    }
    # instance_id = 'i-062e9e68891486d6c'
    # res, err = execute_ssm_command(instance_id, 'ip link show')
    # new_interface = ec2.create_network_interface(SubnetId='subnet-0e27feb6cc905bc08')
    res = [
        j["PrivateIpAddress"]
        for i in ec2.describe_network_interfaces()["NetworkInterfaces"]
        for j in i["PrivateIpAddresses"]
        if i["SubnetId"] == "subnet-00224cfd31ac390e9"
    ]
    return jsonify({"res": res, "err": err})


def find_network_card_in_ip_link_output(ip_link_output: List[str], mac_address: str):
    line_of_interest = 0
    for i, l in enumerate(ip_link_output):
        if mac_address in l:
            line_of_interest = i - 1
    return ip_link_output[line_of_interest].split(":")[1].strip()


def get_first_unused_address(subnet: Dict, used_ip_address: List[str]) -> str:
    network = ipaddress.ip_network(subnet["CidrBlock"])
    network_addresses = [str(i) for i in network]
    network_addresses.remove(str(network.network_address))
    network_addresses.remove(str(network.broadcast_address))
    unused_addresses = [
        i for i in network_addresses[16:] if str(i) not in used_ip_address
    ]
    return unused_addresses[0]


def get_all_used_ip_for_subnet(subnet_id: str) -> List[str]:
    # aws ec2 describe-network-interfaces --filters "Name=subnet-id,Values=subnet-00224cfd31ac390e9" --query 'NetworkInterfaces[*].PrivateIpAddresses[*].PrivateIpAddress' --output json
    # ec2_instances = ec2.describe_instances()["Reservations"]
    # instances = [j for i in ec2_instances for j in i["Instances"]]
    # address = []
    # for instance in instances:
    #     address.extend(
    #         [
    #             k["PrivateIpAddress"]
    #             for j in instance["NetworkInterfaces"]
    #             for k in j["PrivateIpAddresses"]
    #         ]
    #     )
    address = [
        j["PrivateIpAddress"]
        for i in ec2.describe_network_interfaces()["NetworkInterfaces"]
        for j in i["PrivateIpAddresses"]
        if i["SubnetId"] == subnet_id
    ]

    return address


def get_groups_for_first_network_interface(instance: Dict) -> List[str]:
    interfaces = instance["NetworkInterfaces"]
    for interface in interfaces:
        if interface["Attachment"]["DeviceIndex"] == 0:
            return [i["GroupId"] for i in interface["Groups"]]


def get_subnet_by_id(subnet_id: str) -> Dict:
    subnets = ec2.describe_subnets()["Subnets"]
    matching_subnets = [i for i in subnets if i["SubnetId"] == subnet_id]
    return matching_subnets[0]


def find_device_index(instance: dict) -> int:
    current_indexes = sorted(
        [
            i.get("Attachment").get("DeviceIndex")
            for i in instance.get("NetworkInterfaces")
        ]
    )
    for i, j in enumerate(current_indexes):
        if i + 1 == len(current_indexes):
            return j + 1
        if j + 1 != current_indexes[i + 1]:
            return j + 1


def get_uid_by_pod_ip(pod_ip: str) -> str:
    resources = get_pods_by_namespace(NAMESPACE)
    for resource in resources:
        if (
            resource.status.pod_ip == pod_ip
            and resource.metadata.labels.get("helper") == "kamailio"
        ):
            return resource.metadata.uid


def get_network_interfaces_by_ip(ip) -> (List[str], Any):
    ec2_instances = ec2.describe_instances()["Reservations"]
    instances = [j for i in ec2_instances for j in i["Instances"]]
    for instance in instances:
        instance_private_addresses = [
            k["PrivateIpAddress"]
            for j in instance["NetworkInterfaces"]
            for k in j["PrivateIpAddresses"]
        ]
        if ip in instance_private_addresses:
            return (
                [i["NetworkInterfaceId"] for i in instance["NetworkInterfaces"]],
                instance,
            )


def address_used_by_k8s_node(ip: str) -> (str, str, str):
    ec2_instances = ec2.describe_instances()["Reservations"]
    k8s_instances = [
        j
        for i in ec2_instances
        for j in i["Instances"]
        if any(
            k == {"Key": "kubernetes.io/cluster/ippbx", "Value": "owned"}
            for k in j["Tags"]
        )
    ]
    for instance in k8s_instances:
        instance_private_addresses = [
            (k["PrivateIpAddress"], j["NetworkInterfaceId"])
            for j in instance["NetworkInterfaces"]
            for k in j["PrivateIpAddresses"]
        ]

        for instance_private_ip, network_interface in instance_private_addresses:
            if ip == instance_private_ip:
                return instance, instance_private_ip, network_interface


def address_used_by_ec2_instances(ip: str) -> (bool, str):
    ec2_instances = ec2.describe_instances()["Reservations"]
    not_k8s_instances = [
        j
        for i in ec2_instances
        for j in i["Instances"]
        if all(
            k != {"Key": "kubernetes.io/cluster/ippbx", "Value": "owned"}
            for k in j["Tags"]
        )
    ]
    for instance in not_k8s_instances:
        if ip in [
            k["PrivateIpAddress"]
            for j in instance["NetworkInterfaces"]
            for k in j["PrivateIpAddresses"]
        ]:
            return True, instance["InstanceId"]

    return False, ""


def get_private_ip_pool_from_annotation(stateful_set: str) -> List[str]:
    mappings = [
        i.metadata.annotations
        for i in v1a.list_namespaced_stateful_set(NAMESPACE).items
        if i.metadata.name == stateful_set
    ]
    if not mappings:
        return [""]
    private_pool = [v for k, v in mappings[0].items() if k == "private_ip_pool"]
    return private_pool[0].split(" ")


def add_annotation(stateful_set: str, uid: str, ip: str) -> None:
    "pod-(uuid}:{assigned_private_ip}"
    annotation_key = f"pod-{uid}"
    payload = {"metadata": {"annotations": {annotation_key: ip}}}
    v1a.patch_namespaced_stateful_set(stateful_set, NAMESPACE, payload)


def get_pod_by_uuid(namespace: str, uuid: str) -> V1Pod:
    pods_list = v1.list_namespaced_pod(namespace)  # type: V1PodList
    found_pod = [i for i in pods_list.items if i.metadata.uid == uuid]
    if not found_pod:
        return None
    return found_pod[0]


def get_namespace(stateful_set: str) -> str:
    items = v1a.list_namespaced_stateful_set(NAMESPACE).items
    if not items:
        return ""
    current_ss = [
        i.metadata.namespace
        for i in v1a.list_namespaced_stateful_set(NAMESPACE).items
        if i.metadata.name == stateful_set
    ]
    if not current_ss:
        return ""
    return current_ss[0]


def get_pods_uuids(stateful_set: str) -> (List[str], Dict[str, str]):
    """# kubectl get statefulset proxy-priv-dc1 -o yaml
    # metadata: -> annotations: -> pod-*
    # extract uuid pod-{0d3ff598-d216-11e9-9062-0a778d797ff2}:
    """
    mappings = [
        i.metadata.annotations
        for i in v1a.list_namespaced_stateful_set(NAMESPACE).items
        if i.metadata.name == stateful_set
    ]
    """[{'pod-0d3ff598-d216-11e9-9062-0a778d797ff2': '172.21.1.103', 'pod-0d3ff598-d216-11e9-9062-0a778d797ff3': '172.21.1.104', 'private_ip_pool': '172.21.1.103 172.21.1.104'}]"""
    if not mappings:
        return [""]
    uuids = [
        i[len(pod_prefix) :]
        for i in list(mappings[0].keys())
        if i.startswith(pod_prefix)
    ]
    uuids_mapping = {
        i: j for i, j in list(mappings[0].items()) if i.startswith(pod_prefix)
    }
    return uuids, uuids_mapping


def delete_annotation(uuid: str) -> (str, str):
    # c = f"""kubectl patch statefulset {current_stateful_set} -p """
    annotation = f"{pod_prefix}{uuid}"
    payload = {"metadata": {"annotations": {annotation: None}}}
    v1a.patch_namespaced_stateful_set(current_stateful_set, NAMESPACE, payload)


def get_statful_set_by_ip(ip: str) -> str:
    resources = get_pods_by_namespace(NAMESPACE)
    for pod in resources:
        if pod.status.pod_ip == ip and pod.metadata.labels.get("helper") == "kamailio":
            return [
                i.name for i in pod.metadata.owner_references if i.kind == "StatefulSet"
            ][0]


def get_pods_by_namespace(namespace: str) -> List[V1Pod]:
    try:
        pods_list = v1.list_namespaced_pod(namespace)  # type: V1PodList
    except ApiException:
        print(
            f"""Pod permission not configured
            Please execute 
            kubectl create rolebinding default-view --clusterrole=view --serviceaccount={NAMESPACE}:default --namespace={NAMESPACE}"""
        )
    return [i for i in pods_list.items]


def get_host_ip_by_pod_ip(pod_ip: str) -> str:
    resources = get_pods_by_namespace(NAMESPACE)
    for resource in resources:
        if resource.status.pod_ip == pod_ip:
            return resource.status.host_ip


def get_instance_id_by_host_ip(host_ip: str, pod_ip: str) -> (str, str, str):
    nodes = get_all_nodes()
    for node in nodes:
        for addr in node.status.addresses:
            if addr.type == "InternalIP" and addr.address == host_ip:
                instance_id = node.spec.provider_id.split("/")[-1]
                instance = ec2r.Instance(instance_id)
                for network_interface_host in instance.network_interfaces_attribute:
                    if network_interface_host["PrivateIpAddress"] == host_ip:
                        for (
                            network_interface_pod
                        ) in instance.network_interfaces_attribute:
                            if any(
                                [
                                    i["PrivateIpAddress"] == pod_ip
                                    for i in network_interface_pod["PrivateIpAddresses"]
                                ]
                            ):
                                return (
                                    instance_id,
                                    network_interface_pod["NetworkInterfaceId"],
                                    network_interface_host["NetworkInterfaceId"],
                                )

    print(f"Error - no nods found for ip {host_ip}")
    exit(1)


def get_all_nodes() -> List[V1Node]:
    try:
        lst = v1.list_node()  # type: V1NodeList
    except Exception:
        print(
            f"""Pod persmission to view kubernetes host is not configred
            Please execute
            kubectl create clusterrole nodesview-role --verb=get,list,watch --resource=nodes
            kubectl create clusterrolebinding nodesview-role-binding --clusterrole=nodesview-role --serviceaccount={NAMESPACE}:default --namespace={NAMESPACE}"""
        )
        exit(1)
    return [i for i in lst.items]


def get_statefulset_public_ip_pool(
    namespace: str, parent_stateful_set: str
) -> List[str]:
    sets = v1a.list_namespaced_stateful_set(namespace)  # type: V1StatefulSetList
    for set in sets.items:  # type: V1StatefulSet
        if set.metadata.name == parent_stateful_set:
            return set.metadata.annotations.get("private_ip_pool").split()


def execute_ssm_command(instance: str, command: str) -> (List[str], str):
    response = ssm_client.send_command(
        InstanceIds=[instance],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [command]},
    )
    command_id = response["Command"]["CommandId"]
    time.sleep(0.5)
    output = ssm_client.get_command_invocation(
        CommandId=command_id, InstanceId=instance
    )

    while output["Status"] == "InProgress":
        time.sleep(2)
        output = ssm_client.get_command_invocation(
            CommandId=command_id, InstanceId=instance
        )

    if output["StatusDetails"] == "Success":
        return (
            [
                i
                for i in output["StandardOutputContent"].split("\n")
                + [(f'Executing command: "{command}" on {instance}')]
                if i
            ],
            "",
        )
    else:
        return (
            [f'Executing command: "{command}" on {instance}'],
            f'Failed to execute "{command}" on {instance}. Error - {output["StandardErrorContent"]}',
        )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082, debug=False)
