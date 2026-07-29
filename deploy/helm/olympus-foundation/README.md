# Olympus Foundation Helm Chart

This chart establishes only the foundational Kubernetes scheduling guardrails:
four namespaces, three priority classes, and the local-worker `ResourceQuota`.
It deliberately creates no workloads and does not contact or mutate a cluster.

## Capacity and override policy

The namespace names and local worker quota are fixed by the approved VPS-4
capacity policy. `values.schema.json` rejects changed, missing, mistyped, or
additional values. The templates repeat the exact-value checks with Helm
`fail`, so `helm template --skip-schema-validation` cannot render a changed
capacity or namespace value either. The quota namespace is sourced solely from
`namespaces.workersLocal`.

Run the reproducible chart verification with portable or installed tools:

```powershell
pwsh deploy/helm/olympus-foundation/tests/verify.ps1 \
  -HelmPath <path-to-helm> \
  -KubeconformPath <path-to-kubeconform>
```

## Singleton lifecycle

Install this as one stable, singleton release per cluster. All `Namespace`,
`PriorityClass`, and `ResourceQuota` objects carry
`helm.sh/resource-policy: keep`; Helm uninstall will retain them. Their
deletion or replacement is therefore a deliberate, manual cluster-lifecycle
operation after dependent workloads have been handled.

## Network-policy boundary

The `olympus.dev/default-deny-network: "required"` label is a compatibility
marker, not network enforcement. This chart installs no `NetworkPolicy`.
Namespaces are annotated as `network-policy-status: not-installed` and
`workload-admission: blocked-until-network-policy-security-slice`; workloads
must not be admitted until that separate security slice is implemented.
