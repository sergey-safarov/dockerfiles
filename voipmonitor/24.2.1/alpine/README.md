# General

start container

docker run -it -e TOKEN=yyyyyyy safarov/voipmonitor


Supported environment vars

TOKEN - token for voipmonitor cloud service
SENSOR_ID - sensor_id for cloud service
CLOUD - cloud type where we know how configre natalias option. Now supported `AWS` values for Amazon EC2 cloud.


Will be added environment vars

- NIC
- PORTS
- RINGSIZE
- HEAPSIZE
- CALLTIMEOUT

