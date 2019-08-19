#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
from flask import Flask, request, g, jsonify

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

from typing import List, Dict

from kubernetes.client.models.v1_pod import V1Pod
from kubernetes.client.models.v1_pod_list import V1PodList
from kubernetes.client.models.v1_node_list import V1NodeList
from kubernetes.client.models.v1_node import V1Node
from kubernetes.client.models.v1_stateful_set_list import V1StatefulSetList
from kubernetes.client.models.v1_stateful_set import V1StatefulSet
from kubernetes.client.rest import ApiException

if not os.environ.get('AWS_ACCESS_KEY_ID') or not \
        os.environ.get('AWS_SECRET_ACCESS_KEY') or not \
        os.environ.get('AWS_DEFAULT_REGION'):
    print("""Please setup AWS credentials.
        We expect not empty AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_DEFAULT_REGION""")
    exit(1)


# NAMESPACE = 'ippbx'
NAMESPACE = open('/var/run/secrets/kubernetes.io/serviceaccount/namespace').readlines()[0].replace('\n', '')


# proxy-dc0 - need to check by IP
# PARENT_STATEFULSET = os.environ.get('PARENT_STATEFULSET')
# if not PARENT_STATEFULSET:
#     print("Please set PARENT_STATEFULSET variable")
#     exit(1)

try:
    config.load_incluster_config()
except:
    print("please run within cluster pod")
    exit(1)
    # config.load_kube_config()

app = Flask(__name__)

v1 = client.CoreV1Api()

v1a = client.AppsV1Api()

try:
    ec2 = boto3.client('ec2')
    ec2r = boto3.resource('ec2')
    ssm_client = boto3.client('ssm')

except Exception:
    print("Please setup AWS credentials")
    exit(1)


def get_ip():
    c = """ ip -4 addr show dev eth0 """
    process = subprocess.Popen(c.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    if error:
        print("Failed to get IP address - {error}")
        exit(1)
    ip = re.search('inet (.*) scope', str(output)).group(0).split(' ')[1].split('/')[0]
    if not ip:
        print("Failed to get pod IP")
        exit(1)
    return ip


def get_all_pods() -> List[V1Pod]:
    try:
        pods_list = v1.list_pod_for_all_namespaces(watch=False)  # type: V1PodList
    except ApiException:
        print(f"""Pod permission not configured
            Please execute 
            kubectl create rolebinding default-view --clusterrole=view --serviceaccount={NAMESPACE}:default --namespace={NAMESPACE}""")
        # exit(1)
    return [i for i in pods_list.items]


def get_pods_by_namespace(namespace: str) -> List[V1Pod]:
    try:
        pods_list = v1.list_namespaced_pod(namespace)  # type: V1PodList
    except ApiException:
        print(f"""Pod permission not configured
            Please execute 
            kubectl create rolebinding default-view --clusterrole=view --serviceaccount={NAMESPACE}:default --namespace={NAMESPACE}""")
        # exit(1)
    return [i for i in pods_list.items]


def get_stateful_set_pods_ip(pods) -> List[V1Pod]:
    return [i.status.pod_ip for i in pods]


def get_statful_set_by_ip(ip: str) -> str:
    resources = get_pods_by_namespace(NAMESPACE)
    pod_by_ip = [i for i in resources if i.status.pod_ip == ip][0]

    return [i.name for i in pod_by_ip.metadata.owner_references if i.kind == 'StatefulSet'][0]


def get_statefull_set_pods(parent_statefullset):
    res = []
    pods = get_pods_by_namespace(NAMESPACE)
    for pod in pods:
        if pod.metadata.owner_references:
            for ref in pod.metadata.owner_references:
                if ref.name == parent_statefullset:
                    res.append(pod)
    return res


def get_host_ip_by_pod_ip(pod_ip: str) -> str:
    resources = get_pods_by_namespace(NAMESPACE)
    for resource in resources:
        if resource.status.pod_ip == pod_ip:
            return resource.status.host_ip


def get_all_nodes() -> List[V1Node]:
    try:
        lst = v1.list_node()  # type: V1NodeList
    except Exception:
        print(f"""Pod persmission to view kubernetes host is not configred
            Please execute
            kubectl create clusterrole nodesview-role --verb=get,list,watch --resource=nodes
            kubectl create clusterrolebinding nodesview-role-binding --clusterrole=nodesview-role --serviceaccount={NAMESPACE}:default --namespace={NAMESPACE}""")
        exit(1)
    return [i for i in lst.items]


def get_instance_id_by_host_ip(host_ip: str, pod_ip: str) -> (str, str, str):
    nodes = get_all_nodes()
    for node in nodes:
        for addr in node.status.addresses:
            if addr.type == 'InternalIP' and addr.address == host_ip:
                instance_id = node.spec.provider_id.split('/')[-1]
                instance = ec2r.Instance(instance_id)
                for network_interface_host in instance.network_interfaces_attribute:
                    if network_interface_host['PrivateIpAddress'] == host_ip:
                        for network_interface_pod in instance.network_interfaces_attribute:
                            if any([i['PrivateIpAddress'] == pod_ip for i in
                                    network_interface_pod['PrivateIpAddresses']]):
                                return (instance_id,
                                        network_interface_pod['NetworkInterfaceId'],
                                        network_interface_host['NetworkInterfaceId'])

    print(f"Error - no nods found for ip {host_ip}")
    exit(1)


def get_statefulset_public_ip_pool(namespace: str, parent_stateful_set:str) -> List[str]:
    sets = v1a.list_namespaced_stateful_set(namespace)  # type: V1StatefulSetList
    for set in sets.items:  # type: V1StatefulSet
        if set.metadata.name == parent_stateful_set:
            return set.metadata.annotations.get('public_ip_pool').split()


def prepare_address_objects(pool: List[str]) -> (List[Dict], List[str]):
    res = ec2.describe_addresses()

    addresses = [address for address in res['Addresses'] if address['PublicIp'] in pool]
    inaccessible_addresses = [i for i in pool if i not in [a['PublicIp'] for a in addresses]]

    return addresses, inaccessible_addresses


def assign_address_to_instance(addresses: List[Dict], instance: str, interface: str, my_ip: str, force: bool = False
                               ) -> (str, List[str]):
    err = []
    for address in addresses:
        try:
            print(f"Trying to assign {address} to {instance} ({interface})")
            if not force:
                _ = ec2.associate_address(
                    AllocationId=address['AllocationId'],
                    NetworkInterfaceId=interface,
                    AllowReassociation=False,
                    PrivateIpAddress=my_ip)
            else:
                _ = ec2.associate_address(
                    AllocationId=address['AllocationId'],
                    NetworkInterfaceId=interface,
                    AllowReassociation=True,
                    PrivateIpAddress=my_ip)
        except Exception as e:
            err.append(f"{address['PublicIp']} - {e}")
        else:
            print(f"Successfully assigned {address} to {instance} ({interface})")
            return f"{address['PublicIp']}", err
    return None, err


def release_address(address: Dict):
    try:
        address = ec2r.VpcAddress(address['AllocationId'])
        address.association.delete()
        # _ = ec2.release_address(AllocationId=address['AllocationId'])
    except Exception as e:
        print(f"Failed to release address {address} - {e}")


def get_pods_by_instance_ip(elastic_ip_obj: Dict) -> List[V1Pod]:
    try:
        pods_list = v1.list_namespaced_pod(NAMESPACE)  # type: V1PodList
    except ApiException:
        print(f"""Pod permission not configured
            Please execute 
            kubectl create rolebinding default-view --clusterrole=view --serviceaccount={NAMESPACE}:default --namespace={NAMESPACE}""")
        exit(1)
    return [i for i in pods_list.items if i.status.pod_ip == elastic_ip_obj['PrivateIpAddress']]


def delete_pod(name):
    v1.delete_namespaced_pod(name, NAMESPACE)


def get_nodes_by_instance_id(instance: str) -> List[V1Node]:
    all_nodes = get_all_nodes()
    return [n for n in all_nodes if n.spec.provider_id.split('/')[-1] == instance]


def execute_ssm_command(instance: str, command: str, instance_id: str) -> (List[str], str):

    response = ssm_client.send_command(
        InstanceIds=[instance],
        DocumentName="AWS-RunShellScript",
        Parameters={'commands': [command]},
    )
    command_id = response['Command']['CommandId']
    time.sleep(0.5)
    output = ssm_client.get_command_invocation(
        CommandId=command_id,
        InstanceId=instance,
    )

    while output['Status'] == 'InProgress':
        time.sleep(2)
        output = ssm_client.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance,
        )

    if output['StatusDetails'] == 'Success':
        return [i for i in output['StandardOutputContent'].split('\n') + [(f'Executing command: "{command}" on {instance}')] if i], ''
    else:
        return [f'Executing command: "{command}" on {instance}'], \
               f'Failed to execute "{command}" on {instance_id}. Error - {output["StandardErrorContent"]}'


def fix_ip_routes(rules: List[str], my_ip: str, instance_id: str) -> List[str]:
    operations_log = []

    lookup_pod_ip_lines = [i for i in rules if f"from {my_ip} to" in i]
    if lookup_pod_ip_lines:
        first_number = lookup_pod_ip_lines[0].strip().split(' ')[-1].strip()
        operations_log.append(f"First number - {first_number}")
        more_lookup_pod_ip_lines = [i for i in rules if f"from {my_ip}" in i]
        delta_numbers = [i for i in
                         [i.strip().split(' ')[-1].strip()
                          for i in more_lookup_pod_ip_lines
                          if i not in lookup_pod_ip_lines]
                         if i]
        operations_log.append(f"Delta numbers: {delta_numbers}")

        for number in delta_numbers:
            out, err = execute_ssm_command(instance_id, f'ip rule del from {my_ip} to default table {number}', instance_id)
            operations_log.append(out)
            if err:
                raise Exception(err)
        out, err = execute_ssm_command(instance_id, f'ip rule add from {my_ip} to default table {first_number}', instance_id)
        operations_log.append(out)
        if err:
            raise Exception(err)
    return operations_log


def get_statful_set_addresses(parent_stateful_set) -> List[str]:
    pods = get_statefull_set_pods(parent_stateful_set)
    pod_ips = [i.status.pod_ip for i in pods]
    # host_ips = [get_host_ip_by_pod_ip(pod_ip) for pod_ip in pod_ips]
    return pod_ips


@app.route("/configure_pod/", methods=['POST'])
def main():
    mapped_ip = None
    errors = None
    operations_log = []

    # my_ip = get_ip()
    my_ip = request.remote_addr
    operations_log.append(f"My IP: {my_ip}")
    parent_stateful_set = get_statful_set_by_ip(my_ip)
    stateful_pods = get_statefull_set_pods(parent_stateful_set)
    stateful_ips = get_stateful_set_pods_ip(stateful_pods)
    operations_log.append(f"Stateful IPs: {stateful_ips}")

    if my_ip not in stateful_ips:
        return jsonify({"error": f"error: current pod is not member of {parent_stateful_set} statefulset",
                        "operations_log": operations_log})

    host_ip = get_host_ip_by_pod_ip(my_ip)
    operations_log.append(f"Host IP: {host_ip}")

    if not host_ip:
        return jsonify({"error": "error: cannot determine host IP", "operations_log": operations_log})

    instance_id, network_interface_host, network_interface_pod = get_instance_id_by_host_ip(host_ip, my_ip)
    operations_log.append(
        f"Instance ID: {instance_id}, Network interface host: {network_interface_host} Network interface pod: {network_interface_pod}")

    if not instance_id:
        return jsonify({"error": "error: cannot determine EC2 Instance-ID", "operations_log": operations_log})

    if network_interface_host != network_interface_pod:

        ip_rules, err = execute_ssm_command(instance_id, 'ip rule', instance_id)
        ip_rules_for_log = [i for i in ip_rules if f'from {my_ip} to ' in i and 'lookup main' not in i]
        if ip_rules_for_log:
            operations_log.append(f"IP rules: {ip_rules_for_log[0]}")
        else:
            operations_log.append(f"Error: no ip rules found matching the pattern")
        if err:
            operations_log.append(err)

        try:
            operations_log.append(fix_ip_routes(ip_rules, my_ip, instance_id))
        except Exception as e:
            operations_log.append(f"Failed to fix ip routes - {e}")
        if errors:
            operations_log += errors

    public_ip_pool = get_statefulset_public_ip_pool(NAMESPACE, parent_stateful_set)
    operations_log.append(f"Public IP pool: {public_ip_pool}")
    if not public_ip_pool:
        return jsonify({"error": f"error: cannot determine public IP addresses for service: {parent_stateful_set}",
                        "operations_log": operations_log})

    operations_log.append(f"EC2 host with ID {instance_id} have secondary IP address: {my_ip}.")
    operations_log.append(f"Please map with {my_ip} IP address one of this elastic IP addresses:")
    operations_log.append(f"{public_ip_pool}")

    address_objects, inaccessibles = prepare_address_objects(public_ip_pool)

    operations_log.append(f"Inaccessibles IP addresses: {inaccessibles}")

    pods = []

    for ip in address_objects:

        if ip.get('PrivateIpAddress') and ip.get('InstanceId'):
            pods = get_pods_by_instance_ip(ip)

            if not pods:
                operations_log.append(f"No pods found associated with address {ip}")
                release_address(ip)

            else:
                nodes = get_nodes_by_instance_id(ip['InstanceId'])
                if not nodes:
                    return jsonify(
                        {"error": f"No nodes found for IP address {ip}", "operations_log": operations_log})

                for node in nodes:
                    if [i.address for i in node.status.addresses if i.type == 'InternalIP'] != [pods[0].status.host_ip]:
                        operations_log.append(f"No pods found associated with address {ip}")
                        release_address(ip)
                        continue

                if pods[0].metadata.name not in [i.metadata.name for i in stateful_pods]:
                    operations_log.append(f"{pods[0].metadata.name} associated with address {ip} and not a part of stateful set")
                    release_address(ip)
                    delete_pod(pods[0].metadata.name)

                if pods[0].status.pod_ip == my_ip:
                    mapped_ip = ip['PublicIp']

    if not mapped_ip:
        mapped_ip, errors = assign_address_to_instance(address_objects, instance_id, network_interface_host, my_ip)

    if not mapped_ip and errors:
        return jsonify(
            {"error": f"Failed to assign elastic IP - {errors}", "operations_log": operations_log})

    if pods:
        if pods[0].status.host_ip == pods[0].status.pod_ip:
            pass

    operations_log.append(f"Successfully assigned IP - {mapped_ip}")

    # Проверка 1
    # 1) проверять наличие ipset - "ipset list %{satefulset_name}"
    # 2) если не нашли, то создавать -> " ipset create %{satefulset_name} nethash"
    # 3) если нашли, то продолжаем обработку

    res, err = execute_ssm_command(instance_id, f"ipset list {parent_stateful_set}", instance_id)

    operations_log.append(f"IP set list - {res}")

    if any(['The set with the given name does not exist' in i for i in err]):
        res, err = execute_ssm_command(instance_id, f"ipset create {parent_stateful_set} nethash", instance_id)
    if err:
        operations_log.append(f"IP set create errors - {err}")


    # Проверка 2
    # pod -> statfll set -> elastic ip
    # to find the second running pod in the same stateful set
    # 1) в полученном результате проверяем IP адреса (pod ip) в списке ipset.
    # Адреса которые не входят в этот statefulset удаляем комадой вида "ipset del %{satefulset_name} %{members_pods.my_ipN}"
    # 2) добавлем для кажого pod.my_private_ip что входит в этот статефулсет правило вида "ipset add %{satefulset_name} %{members_pods.my_ipN}".
    # Если правило есть, то команда выдаст ошибку. Ошибку игнорируем. В принципе можно добавлять только те адреса которых нет в  ipset.

    statful_set_addresses = get_statful_set_addresses(parent_stateful_set)
    operations_log.append(f"Stateful set addresses - {statful_set_addresses}")

    ipset_results, err = execute_ssm_command(instance_id, f"ipset list {parent_stateful_set}", instance_id)
    operations_log.append(f"IP set list - {ipset_results}")

    # if err:
    #     operations_log.append(f"IP set list resolve errors - {err}")

    ipset_addresses = ipset_results[ipset_results.index('Members:')+1:-1] if 'Members:' in ipset_results else []

    operations_log.append(f"IPset addresses - {ipset_addresses}")

    for ip in ipset_addresses:
        if ip not in statful_set_addresses:
            res, err = execute_ssm_command(instance_id, f"ipset del {parent_stateful_set} {ip}", instance_id)
            operations_log.append(f"IP set del res - {res}")

    for ip in statful_set_addresses:
        res, err = execute_ssm_command(instance_id, f"ipset add {parent_stateful_set} {ip}", instance_id)
        operations_log.append(f"IP set add res - {res}")
    # res, err = execute_ssm_command(instance_id, f"ipset add {parent_stateful_set} {my_ip}", instance_id)
    # operations_log.append(f"IP set add res - {res}")

    # Проверка 3
    # 1) получаем список правил iptables - "iptables-save"
    # 2) искать в нем строку "-A POSTROUTING -m comment --comment "kamailio-helper for statefulset %{satefulset_name}" -m set --match-set %{satefulset_name} src -j ACCEPT";
    # 3) если не нашли, то добавляем ее iptables -t nat -I POSTROUTING -m comment --comment "kamailio-helper for statefulset %{satefulset_name}" -m set --match-set %{satefulset_name} src -j ACCEPT
    # 4) нашли, продожаем обработку

    res, err = execute_ssm_command(instance_id, f"iptables-save", instance_id)
    # operations_log.append(f"iptables - {res}")
    if err:
        operations_log.append(f"iptables resolve errors - {err}")

    iptable_res_found = False
    for r in res:
        if f'-A POSTROUTING -m comment --comment \"kamailio-helper for statefulset {parent_stateful_set}\" -m set --match-set {parent_stateful_set} src -j ACCEPT' in r:
            iptable_res_found = True
            operations_log.append(f"Found matching iptables rule")

    if not iptable_res_found:
        operations_log.append(f"iptables - {res}")
        command = f'iptables -t nat -I POSTROUTING -m comment --comment \"kamailio-helper for statefulset {parent_stateful_set}\" -m set --match-set {parent_stateful_set} src -j ACCEPT'

        res, err = execute_ssm_command(instance_id, command, instance_id)
        if err:
            operations_log.append(f"iptables add errors - {err}")
        else:
            operations_log.append(f"added iptables rule - {command}")
    return jsonify({"mapped_ip": mapped_ip, "operations_log": operations_log})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
