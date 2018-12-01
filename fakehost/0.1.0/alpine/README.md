# General

Purpose of cotainer is crete DNS record on docker embeded DNS server.
Goal is reached by creating contained and shutdowning all NIC interfaces.
IP address and DNS name may be assigned to other container.

To start container
```
docker run -rm=true  \
           --name fakehost \
           --network myoverlay \
           --network-alias prodhost.myoverlay \
           --cap-add=NET_ADMIN \
           safarov/fakehost \
```
