Image designed for replication routes from main linux route table into `2, 3, 4, 5` route tables.

This feature useful Kubernetes nodes customisation inside Amazon EKS cloud. We use for this direct assigment of elastic IP to pods.

Example to `yaml` file.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: bird
  labels:
    app: bird
spec:
  selector:
    matchLabels:
      app: bird
  template:
    metadata:
      labels:
        app: bird
    spec:
      hostNetwork: true
      containers:
      - name: bird
        image: safarov/bird
        securityContext:
          capabilities:
            add: ["NET_ADMIN"]
```
