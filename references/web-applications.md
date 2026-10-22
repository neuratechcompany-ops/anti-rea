# Web applications

Browser-delivered HTML, CSS, JavaScript, WASM, URLs, and network requests are
observable by the user. Hardening can remove accidental disclosure and raise the
cost of understanding implementation details, but it cannot turn a browser into
a trusted execution environment.

## Architecture before obfuscation

Keep these on the server:

- API provider credentials and private signing keys;
- authorization and tenant-isolation decisions;
- licensing decisions and feature entitlements;
- fraud, pricing, scoring, and other privileged business rules;
- transformations whose confidentiality is commercially important.

The browser receives short-lived, audience-limited credentials and only the
minimum data required for the current user action. Every API operation must
enforce authorization server-side; hiding a route or button is not access
control.

When a third-party API requires a secret, call it through a backend-for-frontend
or controlled server proxy. Do not embed the provider key in a bundle, WASM,
runtime configuration endpoint, HTML attribute, or source map.

## Release artifact

- Build with production settings and disable public source-map publication.
- Store private source maps in a restricted symbol/error-reporting service, not
  in the web root or CDN.
- Do not ship `.env`, TypeScript, framework source, test fixtures, debug routes,
  build logs, repository metadata, or pre-hardening reports.
- Minify and split bundles for performance. Apply stronger obfuscation only to
  measured, non-hot modules; it can increase startup time, bundle size, and
  runtime failures.
- Treat every hostname, route name, GraphQL operation name, and public schema
  used by the browser as discoverable. Protect the operation on the server.
- Use CSP, integrity metadata, secure cookies, CSRF protection, and platform
  headers for exploit resistance. Do not describe them as source-code secrecy.

## Verification

Run `scripts/verify-web-artifact.mjs` on the exact directory uploaded to hosting.
Maintain an explicit `allowedHosts` policy when practical. Archive the report
outside the deployment directory.

For stable production APIs, also set `requiredHosts`. This prevents a hidden or
unexpectedly removed representation of a known endpoint from producing a green
static report merely because the scanner did not reconstruct it. Keep
environment-dependent hosts in a separately reviewed runtime inventory.

The verifier scans raw files, UTF-16 text, common literal encodings, gzip and
Brotli precompressed assets, and simple JavaScript string assembly. It fails
closed on nested archives it cannot inspect and rejects unknown policy fields.
Its `artifactSha256` binds the report to the inspected file inventory; compare
that value in deployment rather than assuming the uploaded directory is the
one that was tested.

A passing static report means that no configured violation was found in the
representations the verifier inspected. It does not prove that arbitrary
program computation, encrypted data, a runtime configuration response, or a
server response cannot produce another value. Static inspection therefore
cannot replace the dynamic steps below.

Then verify dynamically:

1. Load representative authenticated and unauthenticated workflows.
2. Inspect browser requests, storage, workers, and loaded chunks.
3. Confirm that no long-lived secret or privileged decision appears in any
   response, bundle, storage entry, or error payload.
4. Confirm that replaying or modifying a client request does not bypass server
   authorization.
5. Measure startup, interaction latency, error rate, and cache behavior after
   hardening.

## Customer-hosted deployments

If the customer controls the host or has root access, assume they can inspect
containers, binaries, files, process memory, and decrypted runtime state. Ship
signed artifacts without the repository, keep the highest-value logic in a
separate controlled service where the deployment model permits it, and use the
license agreement as an additional control. Do not claim technical
non-recoverability.
