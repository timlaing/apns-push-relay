# Status

!!! info "This page"
Component status below reflects the repository as it ships; a generated
uptime snapshot (M8) will replace the manual table once the hosted
instance is live.

## Components

| Component            | State         | Notes                                                            |
| -------------------- | ------------- | ---------------------------------------------------------------- |
| API (`/health`)      | ✅ shipped    | `{"status": "ok"}` — probe it on your instance                   |
| Enrollment (spec)    | ✅ v1.0       | Reviewed spec published; physical-device validation pending (M4) |
| Register / push      | ✅ shipped    | Contract-tested against the notifications spec                   |
| Quotas / denylist    | ✅ shipped    | Per-App, enforced pre-APNs                                       |
| nginx + certbot      | ✅ shipped    | Compose stack, auto-renew                                        |
| `relay` CLI          | ✅ shipped    | doctor/status/logs/tenant/denylist/metrics                       |
| OpenAPI + clients    | ✅ shipped    | Exported schema + reference client                               |
| iOS app integration  | 🚧 other repo | ios-opencode-client (M6)                                         |
| Backend plugin       | 🚧 other repo | OpenCode push plugin (M7)                                        |
| App Attest on device | 🚧 pending    | Requires physical device (M4)                                    |

## Probe it yourself

```sh
curl -sS https://api.push.example.org/health
curl -sS https://api.push.example.org/metrics | head
```

`/metrics` is a Prometheus text snapshot of request counts, APNs result
counts (`accepted/invalidDestination/retryable/rejected`), auth failure
codes and tenant expiry counts — aggregate only, no identifiers.
