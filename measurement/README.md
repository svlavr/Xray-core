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

## Interpreting observations

Read the returned error and receipt together. A completed operation, a received
protocol response and a response satisfying the caller's expected resource are
different observations. A nil error is not an unrestricted-Internet verdict.

- HTTP status 500, a redirect or a captive-portal page can be a complete response
  with no operation error. Redirects are not followed. The caller checks expected
  status, marker, content and endpoint identity. HEAD observes headers without a
  GET body; an advertised Content-Length does not count as received bytes.
- `ContentLength` and `TransferEncoding` retain native HTTP response framing.
  A nil length means no response was observed; -1 means native unknown length.
  `BodyComplete` means native body-reader completion. Go may accept TCP EOF for a
  close-delimited TLS response without an authenticated TLS close notification;
  completion alone does not prove content integrity. Counts exclude transfer
  framing but retain content coding such as gzip; they are not wire byte counts.
- `FirstByteElapsed` starts at admission and may observe an informational HTTP
  response before final headers. `EndpointTLS` records a handshake attempt,
  including a failed attempt, and can include lower proxy setup. Absent fields
  represent unobserved phases. Download read/hash and Upload writer-active times
  do not independently measure network capacity or remote delivered goodput.
- Download retains consumed bytes, the cap fact and any requested prefix digest
  even when that same read returns an error. Integrity requires native completion
  and the caller's expected digest. Upload writer counts and matching endpoint ACK
  declarations remain separate; neither certifies durable server storage.
- A matched DNS REFUSED, SERVFAIL or NOERROR/no-data response is a decoded answer,
  not automatically a transport error or a useful-resolution verdict. TCP, DoT
  and DoH permit omitted Question fields; present questions must match, and UDP
  requires a matching question echo. A complete oversized DNS message retains its
  wire facts but returns `ErrDNSResponse` and `ErrDNSLimit`, with no decoded
  `Message`. The AD flag is observed resolver output, not local DNSSEC validation.
- `UDPSendRecord.WriterBytesObserved` distinguishes a native returned byte count
  from the supplied length of an error-only multibuffer writer. Inspect the write
  error in both cases. A timed-out Echo does not prove packet filtering. Current
  ICMP observes matched Echo replies; ICMP control errors are not retained as
  separate correlated receipts. UDP source rejection precedes payload correlation.
- `OutboundError` is first-observed native feedback at receipt finalization;
  nil does not certify all asynchronous native work finished without error.
  Identity address/family/country fields are endpoint declarations, and finite
  series preserve failed samples without an automatic best-of-two estimate.

Bind observations to the caller's endpoint, route, source version, run and network
context before comparing them. DIRECT uses the current system network path; if
that path traverses a VPN it is not a physical underlay control. A node-port TCP
connect, a resource HTTP exchange through a node, and a second VPN node test have
different endpoints and routes. Attributing a timeout requires suitable matched
controls; an error string alone cannot identify the responsible actor.

Receipt fields added here are typed Go source APIs, not a stable binary layout or
wire schema. External adapters must rebuild and preserve the new fields when
they need these facts; historical receipts do not acquire them retroactively.

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
