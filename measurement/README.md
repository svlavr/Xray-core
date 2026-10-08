# Raw measurements through native Xray

`github.com/xtls/xray-core/measurement` provides caller-requested Go operations.
It starts no background probe, registers no Xray feature and adds no network API.
Use an existing configured, started `*core.Instance` for exact outbound routes.
`New(nil, limit)` supports independent DIRECT operations without an instance.

Construct an executor with a positive concurrency limit chosen by the caller.
Requests supply their own time and byte budgets; queue waiting uses the request
timeout. Cancel operations and wait for their calls to return before closing
the instance. There is no executor shutdown goroutine or separate core process.

## Routes and results

- `Route{Kind: Direct}` uses native system operations, independently of Xray's
  default outbound. Its Tag must be empty.
- `Route{Kind: ExactOutbound, Tag: "registered-tag"}` uses the handler mapped to
  that exact tag at dispatch. A missing tag fails without default fallback.
  Replacement under the same tag follows normal native handler semantics.
- Routed measurement has the canonical controlled-measurement origin and cannot
  continue a caller's logical USER observation. Native outbound counters still
  mix origins; they must not be interpreted as USER-only totals.
- Receipts retain raw facts and partial progress together with the returned
  error. Always inspect the error; written bytes alone do not prove peer receipt.
  Absent timing fields mean that phase was not independently observed.

## Operations

- `HTTP`: HEAD or GET over HTTP/HTTPS, with bounded response facts.
- `HTTPS`: one HTTPS GET; no redirects, automatic retries, decompression or reuse.
- `Download`, `Upload`: bounded payload transfer; requested integrity or explicit
  upload acknowledgment remains separate from local writer acceptance.
- `UDPEcho`: finite nonce/sequence train with source, duplicate, malformed, late
  and missing-reply facts. Packet/source support depends on native framing.
- `DNSQuery`: one explicit numeric resolver using UDP, TCP, DoT or DoH; no shared
  resolver/cache mutation or automatic fallback. TLS names authenticate the
  endpoint, rather than initiating another resolver lookup.
- `TCPConnect`: a fresh DIRECT numeric TCP connect. Exact proxy routes and
  replacement system dialers without that observable boundary are unsupported.
- `ICMPEcho`: numeric DIRECT endpoint Echo. Native platform/privilege errors are
  returned; arbitrary proxy ICMP is unsupported.
- `EgressIdentity`: bounded reflector JSON with validated IP/family and optional
  country declarations. `IdentityFromHTTPS` reuses an existing exchange after
  its transport error has been handled; declarations are not independent proof.
- `RunSeries`: a caller-selected finite count/worker budget, retaining each
  invoked attempt's typed receipt and error. Failures are not replaced by retries.

Use `errors.Is(err, measurement.ErrUnsupported)` for unsupported execution
shapes. The exported request/receipt comments define each byte and timing
boundary, including header/body budgets and native limits. The package does not
calculate rates, scores, loss percentages, percentiles or node-selection policy.

## Example

The numbers below are example caller budgets, not built-in limits.

```go
func probe(ctx context.Context, instance *core.Instance, url string) (measurement.HTTPReceipt, error) {
    executor, err := measurement.New(instance, 4)
    if err != nil {
        return measurement.HTTPReceipt{}, err
    }
    return executor.HTTP(ctx, http.MethodGet, measurement.HTTPRequest{
        Route: measurement.Route{Kind: measurement.ExactOutbound, Tag: "proxy"},
        URL: url, Timeout: 3 * time.Second,
        MaxBodyBytes: 4096, MaxHeaderBytes: 8192,
    })
}
```

Import `context`, `net/http`, `time`, `github.com/xtls/xray-core/core` and this
package. For DIRECT, pass nil as the instance and use `Route{Kind: Direct}`.
Endpoint TLS uses system roots unless the request provides `RootCAs`.

## Validation boundaries

Package tests cover native protocol profiles, operation errors/cancellation,
packet limits, ordinary-traffic continuity and shared carriers. Run
`go test -mod=readonly ./measurement` in a suitable host environment; native
ICMP and network profiles need their platform capabilities. Optional external
network diagnostics are explicitly enabled and are not normal health probes.
Source/host tests do not by themselves qualify Android bindings, devices,
live networks, product policy or a release.
