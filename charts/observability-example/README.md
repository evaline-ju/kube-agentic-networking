# Observability Example

**This is an example observability stack for development and demo use only. It is not production-grade.**

Deploys an OTel Collector, Tempo, and Grafana for visualizing distributed traces from the [kube-agentic-networking quickstart](https://github.com/kubernetes-sigs/kube-agentic-networking/tree/main/site-src/guides/quickstart).

## Install

```bash
helm install observability-example charts/observability-example \
  --namespace quickstart-ns --create-namespace
```

## Access

```bash
# Grafana UI (admin/admin)
kubectl port-forward -n quickstart-ns svc/grafana 3000:3000

# Tempo API
kubectl port-forward -n quickstart-ns svc/tempo 3200:3200
```

In Grafana, go to **Explore → Tempo** and search by service name (`adk-agent` or `envoy-gateway-*`) or trace ID.

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `collector.enabled` | Deploy OTel Collector | `true` |
| `collector.tempoEndpoint` | Tempo gRPC endpoint | `tempo.<namespace>.svc.cluster.local:4317` |
| `tempo.enabled` | Deploy Tempo | `true` |
| `tempo.retention` | Trace retention period | `1h` |
| `grafana.enabled` | Deploy Grafana | `true` |
| `telemetryPolicy.enabled` | Create an XTelemetryPolicy enabling tracing on the Gateway | `true` |
| `telemetryPolicy.gatewayName` | Gateway targeted by the XTelemetryPolicy | `agentic-net-gateway` |
| `telemetryPolicy.samplingRate` | Sampling percent numerator | `100` |
| `telemetryPolicy.serviceName` | Optional `service.name` for exported spans | implementation default |
| `telemetryPolicy.attributes` | Optional custom span attributes (Literal / Header source) | `[]` |

The chart's XTelemetryPolicy (experimental `gateway.networking.x-k8s.io` API)
replaces the old flag-only tracing setup: it enables the OTel tracer on the
Gateway and points it at this chart's collector. It requires the Gateway API
experimental channel CRDs:

```bash
kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/experimental-install.yaml
```

When no XTelemetryPolicy targets the Gateway, the controller falls back to its
`--tracing-sampling-rate` flag (implementation default) with the collector at
`otel-collector.<gateway-namespace>.svc.cluster.local:4317`.

## Bring Your Own Backend

To use an external trace backend, disable Tempo and point the collector at your endpoint:

```bash
helm install observability-example charts/observability-example \
  --set tempo.enabled=false \
  --set collector.tempoEndpoint=your-tempo.example.com:4317
```
