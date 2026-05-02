# Kubernetes Deployment for InventoryApp

This directory contains Kubernetes manifests for deploying InventoryApp in a production Kubernetes cluster.

## Architecture

```
┌─────────────────────────────────────┐
│         Ingress (NGINX)             │
│      inventoryapp.example.com       │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│     Service: inventoryapp-web       │
│         LoadBalancer                │
└───────────────┬─────────────────────┘
                │
        ┌───────┴───────┐
        ▼               ▼
┌──────────────┐  ┌──────────────┐
│ Pod: web-1   │  │ Pod: web-2   │
│ (3 replicas) │  │ (3 replicas) │
└──────┬───────┘  └──────┬───────┘
       │                 │
       └────────┬────────┘
                │
        ┌───────┴────────┐
        ▼                ▼
┌───────────────┐  ┌──────────────┐
│ PostgreSQL    │  │   Redis      │
│ StatefulSet   │  │  Deployment  │
└───────────────┘  └──────────────┘
```

## Prerequisites

- Kubernetes cluster (v1.24+)
- kubectl configured
- Helm (optional, for easier management)
- Persistent Volume provisioner
- SSL certificates (for HTTPS)

## Quick Start

### 1. Create Namespace

```bash
kubectl create namespace inventoryapp
kubectl config set-context --current --namespace=inventoryapp
```

### 2. Create Secrets

```bash
# Generate secret key
SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')

# Create secret
kubectl create secret generic inventoryapp-secrets \
  --from-literal=SECRET_KEY=$SECRET_KEY \
  --from-literal=DATABASE_PASSWORD=your-db-password \
  --from-literal=REDIS_PASSWORD=your-redis-password
```

### 3. Deploy PostgreSQL

```bash
kubectl apply -f postgres-pvc.yaml
kubectl apply -f postgres.yaml
```

### 4. Deploy Redis

```bash
kubectl apply -f redis.yaml
```

### 5. Deploy Application

```bash
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

### 6. Setup Ingress

```bash
# Edit ingress.yaml with your domain
kubectl apply -f ingress.yaml
```

## Files Description

### Core Resources

- **deployment.yaml**: Main application deployment
- **service.yaml**: Service definitions
- **configmap.yaml**: Application configuration
- **secrets.yaml.template**: Secret template (copy to secrets.yaml)

### Database

- **postgres-pvc.yaml**: PostgreSQL persistent volume claim
- **postgres.yaml**: PostgreSQL StatefulSet
- **postgres-service.yaml**: PostgreSQL service

### Cache

- **redis.yaml**: Redis deployment
- **redis-service.yaml**: Redis service

### Networking

- **ingress.yaml**: Ingress rules for external access
- **network-policy.yaml**: Network policies (optional)

### Monitoring (Optional)

- **servicemonitor.yaml**: Prometheus ServiceMonitor
- **grafana-dashboard.json**: Grafana dashboard

## Configuration

### Environment Variables

Edit `configmap.yaml` to configure:

```yaml
data:
  FLASK_ENV: "production"
  DATABASE_URL: "postgresql://inventoryapp:password@postgres:5432/inventoryapp"
  REDIS_URL: "redis://redis:6379/0"
  # ... other configs
```

### Scaling

```bash
# Scale web pods
kubectl scale deployment inventoryapp-web --replicas=5

# Autoscaling
kubectl autoscale deployment inventoryapp-web \
  --min=3 --max=10 --cpu-percent=70
```

### Resource Limits

Adjust in `deployment.yaml`:

```yaml
resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
  limits:
    memory: "2Gi"
    cpu: "2000m"
```

## Persistent Storage

### Storage Classes

Recommended storage classes:
- **Fast SSD**: For PostgreSQL (high IOPS)
- **Standard**: For uploads and backups

```yaml
storageClassName: fast-ssd  # or gp3, pd-ssd, etc.
```

### Backup Strategy

```bash
# Backup PostgreSQL
kubectl exec -it postgres-0 -- pg_dump -U inventoryapp inventoryapp > backup.sql

# Restore
kubectl exec -i postgres-0 -- psql -U inventoryapp inventoryapp < backup.sql
```

## Monitoring

### Health Checks

Application provides:
- Liveness probe: `/health`
- Readiness probe: `/health`

### Logs

```bash
# View logs
kubectl logs -f deployment/inventoryapp-web

# Stream logs from all pods
kubectl logs -f -l app=inventoryapp-web
```

### Metrics

If Prometheus is installed:

```bash
kubectl apply -f servicemonitor.yaml
```

## SSL/TLS

### Using cert-manager

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create issuer (edit with your email)
kubectl apply -f cert-issuer.yaml

# Certificate will be auto-generated via ingress annotation
```

### Manual Certificate

```bash
kubectl create secret tls inventoryapp-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key
```

## High Availability

### Database HA

For production, use managed PostgreSQL:
- AWS RDS
- Google Cloud SQL
- Azure Database for PostgreSQL

Update `DATABASE_URL` in configmap.

### Redis HA

For high availability Redis:

```bash
# Deploy Redis Sentinel
kubectl apply -f redis-ha.yaml
```

## Security

### Network Policies

```bash
kubectl apply -f network-policy.yaml
```

Restricts:
- PostgreSQL: Only accessible from web pods
- Redis: Only accessible from web pods
- Web: Exposed via ingress only

### Pod Security

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  readOnlyRootFilesystem: true
```

### Secrets Management

Consider using:
- **Sealed Secrets**: For GitOps
- **External Secrets Operator**: For AWS Secrets Manager, etc.
- **HashiCorp Vault**: For enterprise secrets

## Updates

### Rolling Update

```bash
# Update image
kubectl set image deployment/inventoryapp-web \
  web=inventoryapp:v2.2.0

# Or apply updated deployment
kubectl apply -f deployment.yaml
```

### Rollback

```bash
# View rollout history
kubectl rollout history deployment/inventoryapp-web

# Rollback to previous version
kubectl rollout undo deployment/inventoryapp-web

# Rollback to specific revision
kubectl rollout undo deployment/inventoryapp-web --to-revision=2
```

## Troubleshooting

### Pod Not Starting

```bash
# Describe pod
kubectl describe pod <pod-name>

# Check events
kubectl get events --sort-by=.metadata.creationTimestamp

# View logs
kubectl logs <pod-name>
```

### Database Connection Issues

```bash
# Test PostgreSQL connection
kubectl run -it --rm debug --image=postgres:16 --restart=Never -- \
  psql -h postgres -U inventoryapp

# Check service DNS
kubectl run -it --rm debug --image=busybox --restart=Never -- \
  nslookup postgres
```

### Performance Issues

```bash
# Check resource usage
kubectl top pods
kubectl top nodes

# Get detailed metrics
kubectl describe node <node-name>
```

## Cost Optimization

### Right-sizing

```bash
# Monitor actual usage
kubectl top pods

# Adjust requests/limits based on actual usage
```

### Spot Instances

Use node affinity for non-critical workloads:

```yaml
affinity:
  nodeAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      preference:
        matchExpressions:
        - key: node.kubernetes.io/instance-type
          operator: In
          values:
          - spot
```

## Production Checklist

- [ ] SSL certificates configured
- [ ] Secrets properly encrypted
- [ ] Database backups automated
- [ ] Monitoring and alerting setup
- [ ] Resource limits configured
- [ ] Horizontal Pod Autoscaling enabled
- [ ] Network policies applied
- [ ] Ingress configured with proper domain
- [ ] Health checks validated
- [ ] Logging aggregation setup

## Support

- **Documentation**: See main README.md
- **Issues**: https://github.com/BoondockSulfur/InventoryApp/issues
- **Kubernetes Docs**: https://kubernetes.io/docs/

---

**Version**: 2.2.0
**Last Updated**: 2025-12-21
