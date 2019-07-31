#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

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

# 'ippbx'
NAMESPACE = os.environ.get('NAMESPACE')
if not NAMESPACE:
    print("Please set NAMESPACE variable")
    exit(1)

# proxy-dc0
PARENT_STATEFULSET = os.environ.get('PARENT_STATEFULSET')
if not PARENT_STATEFULSET:
    print("Please set PARENT_STATEFULSET variable")
    exit(1)

try:
    config.load_incluster_config()
except:
    print("please run within cluster pod")
    exit(1)
    # config.load_kube_config()

v1 = client.CoreV1Api()

v1a = client.AppsV1Api()

try:
    ec2 = boto3.client('ec2')
    ec2r = boto3.resource('ec2')
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
        exit(1)
    return [i for i in pods_list.items]


def get_pods_by_namespace(namespace: str) -> List[V1Pod]:
    try:
        pods_list = v1.list_namespaced_pod(namespace)  # type: V1PodList
    except ApiException:
        print(f"""Pod permission not configured
            Please execute 
            kubectl create rolebinding default-view --clusterrole=view --serviceaccount={NAMESPACE}:default --namespace={NAMESPACE}""")
        exit(1)
    return [i for i in pods_list.items]


def get_stateful_set_pods_ip(pods) -> List[V1Pod]:
    return [i.status.pod_ip for i in pods]


def get_statefull_set_pods():
    res = []
    pods = get_pods_by_namespace(NAMESPACE)
    for pod in pods:
        if pod.metadata.owner_references:
            for ref in pod.metadata.owner_references:
                if ref.name == PARENT_STATEFULSET:
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


def get_instance_id_by_host_ip(host_ip: str) -> (str, str):
    nodes = get_all_nodes()
    for node in nodes:
        for addr in node.status.addresses:
            if addr.type == 'InternalIP' and addr.address == host_ip:
                instance_id = node.spec.provider_id.split('/')[-1]
                instance = ec2r.Instance(instance_id)
                for network_interface in instance.network_interfaces_attribute:
                    if network_interface['PrivateIpAddress'] == host_ip:
                        return (instance_id, network_interface['NetworkInterfaceId'])


def get_statefulset_public_ip_pool(namespace: str) -> List[str]:
    sets = v1a.list_namespaced_stateful_set(namespace)  # type: V1StatefulSetList
    for set in sets.items:  # type: V1StatefulSet
        if set.metadata.name == PARENT_STATEFULSET:
            return set.metadata.annotations.get('public_ip_pool').split()


def prepare_address_objects(pool: List[str]) -> (List[Dict], List[str]):
    res = ec2.describe_addresses()

    addresses = [address for address in res['Addresses'] if address['PublicIp'] in pool]
    # inaccessible_addresses = [address for address in res['Addresses'] if address['PublicIp'] in pool and address not in addresses]
    inaccessible_addresses = [i for i in pool if i not in [a['PublicIp'] for a in addresses]]

    if inaccessible_addresses:
        print(f"Inaccessible addresses: {inaccessible_addresses}")
    return addresses, inaccessible_addresses


def assign_address_to_instance(addresses: List[Dict], instance: str, interface: str, my_ip: str
                               ) -> (str, List[str]):
    err = []
    for address in addresses:
        try:
            print(f"Trying to assign {address} to {instance} ({interface})")
            _ = ec2.associate_address(
                AllocationId=address['AllocationId'],
                NetworkInterfaceId=interface,
                AllowReassociation=False,
                PrivateIpAddress=my_ip)
        except Exception as e:
            err.append(f"{address['PublicIp']} - {e}")
        else:
            print(f"Successfully assigned {address} to {instance} ({interface})")
            return f"{address['PublicIp']}", err
    return None, err


def release_address(address: Dict):
    try:
        _ = ec2.release_address(AllocationId=address['AllocationId'])
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


def get_nodes_by_instance_id(instance_id: str) -> List[V1Node]:
    all_nodes = get_all_nodes()
    return [n for n in all_nodes if n.spec.provider_id.split('/')[-1] == instance_id]


if __name__ == '__main__':
    mapped_ip = None
    errors = None

    my_ip = get_ip()
    print(f"My IP: {my_ip}")
    stateful_pods = get_statefull_set_pods()
    stateful_ips = get_stateful_set_pods_ip(stateful_pods)
    print(f"Stateful IPs: {stateful_ips}")

    if my_ip not in stateful_ips:
        print(f"error: current pod is not member of {PARENT_STATEFULSET} statefulset")
        exit(1)

    host_ip = get_host_ip_by_pod_ip(my_ip)
    print(f"Host IP: {host_ip}")

    if not host_ip:
        print("error: cannot determine host IP")
        exit(1)

    instance_id, network_interface = get_instance_id_by_host_ip(host_ip)
    print(f"Instance ID: {instance_id}, Network interface: {network_interface}")
    if not instance_id:
        print("error: cannot determine EC2 Instance-ID")
        exit(1)

    public_ip_pool = get_statefulset_public_ip_pool(NAMESPACE)
    print(f"Public IP pool: {public_ip_pool}")
    if not public_ip_pool:
        print(f"error: cannot determine public IP addresses for service: {PARENT_STATEFULSET}")
        exit(1)

    print(f"EC2 host with ID {instance_id} have secondary IP address: {my_ip}.")
    print(f"Please map with {my_ip} IP address one of this elastic IP addresses:")
    print(f"{public_ip_pool}")

    address_objects, inaccessibles = prepare_address_objects(public_ip_pool)

    print(f"Inaccessibles IP addresses: {inaccessibles}")

    for ip in address_objects:

        if ip['PrivateIpAddress'] and ip['InstanceId']:
            pods = get_pods_by_instance_ip(ip)

            if not pods:
                print(f"No pods found associated with address {ip}")
                release_address(ip)

            else:
                nodes = get_nodes_by_instance_id(ip['InstanceId'])
                if not nodes:
                    print(f"No nodes found for IP address {ip}")
                    exit(1)

                for node in nodes:
                    if [i.address for i in node.status.addresses if i.type == 'InternalIP'] != [pods[0].status.host_ip]:
                        print(f"No pods found associated with address {ip}")
                        release_address(ip)
                        continue

                # if not pods returned -> deallocate
                # if we have a name -> check owner of the pod
                # if part of statefull set -> do nothing
                # if nod internal ip == my internal ip -> return the ip in question and end the script
                # if not a part of statefull set -> deallocate + restart (delete pod)

                if pods[0].metadata.name not in [i.metadata.name for i in stateful_pods]:
                    print(f"{pods[0].metadata.name} associated with address {ip} and not a part of stateful set")
                    release_address(ip)
                    delete_pod(pods[0].metadata.name)

                if pods[0].status.pod_ip == my_ip:
                    mapped_ip = ip['PublicIp']

    address_objects, inaccessibles = prepare_address_objects(public_ip_pool)

    if not mapped_ip:
        mapped_ip, errors = assign_address_to_instance(
            address_objects, instance_id, network_interface, my_ip)

    if not mapped_ip and errors:
        print(f"Failed to assign elastic IP - {errors}")
        exit(1)

    print(f"Successfully assigned IP - {mapped_ip}")

    with open('/tmp/pod_public_ip', 'wt') as f:
        print(mapped_ip, file=f)

    print("Public IP saved to file /tmp/pod_public_ip")
