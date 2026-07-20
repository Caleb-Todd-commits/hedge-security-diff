# Hedge live evaluation human adjudication

> Model-generated fields below are untrusted review data. This sheet excludes source snippets, patches, prompts, provider prose, and credentials.

- Corpus SHA-256: 4da85338c82db9e6fdd595831be7b33389625862fbd26e79ddc4ffbb6797edfd
- Models: gpt-5.6-luna / gpt-5.6-sol
- Runs: 30 of 30
- Reviewer: Caleb Todd
- Review completed at: 2026-07-20T13:47:01Z
- [x] Confirm the frozen corpus was not changed or tuned after these results.
- [x] Confirm every run and every accepted model-origin inference below.

## 101-benign-clock-refactor

- [x] Repeat 1: confirmed-no-delta; route no-model; 0 accepted model-origin finding(s).

- [x] Repeat 2: confirmed-no-delta; route no-model; 0 accepted model-origin finding(s).

- [x] Repeat 3: confirmed-no-delta; route no-model; 0 accepted model-origin finding(s).

## 102-feedback-entrypoint

- [x] Repeat 1: completed; route sol-direct; 1 accepted model-origin finding(s).
  - Proposal `0d2d10b223ee7b503b75eb2c3c8962ca`: **medium** New public feedback route parses unbounded request bodies without visible abuse controls
  - Invariant: Unauthenticated feedback requests must consume bounded CPU, memory, and concurrency regardless of body size, nesting depth, malformed input, or request frequency.
  - Missing controls: Explicit request body-size limit enforced before JSON parsing, Rate limiting or request throttling for the public route, Graceful handling of malformed JSON and parsing failures, Payload depth and message-length constraints
  - Evidence: `app/api/feedback/route.ts:1` (nextjs-ast-route, 98a6e88a7194b0ff3afa89d156d3169f)

- [x] Repeat 2: completed; route sol-direct; 1 accepted model-origin finding(s).
  - Proposal `31b3c779e67ae3cb36f0b177f9f38bb5`: **medium** Public feedback endpoint lacks evidenced resource-abuse controls
  - Invariant: Unauthenticated feedback requests must be bounded in body size, parsing cost, and request rate before they can materially consume application resources.
  - Missing controls: Pre-parse request body size limit, Per-client or global rate limiting, Content-Type enforcement and controlled handling of malformed JSON, Documented platform-level quotas or edge protections
  - Evidence: `app/api/feedback/route.ts:1` (nextjs-ast-route, 98a6e88a7194b0ff3afa89d156d3169f)

- [x] Repeat 3: completed; route sol-direct; 1 accepted model-origin finding(s).
  - Proposal `e760ff51245d6d47dba7a5f23f0b0879`: **medium** New public feedback endpoint parses request bodies without an evidenced size or rate limit
  - Invariant: Unauthenticated requests to the feedback endpoint must consume bounded CPU, memory, and concurrency regardless of body size, validity, or request rate.
  - Missing controls: An evidenced maximum request-body size enforced before JSON parsing, An evidenced request-rate or concurrency limit for the public endpoint, Explicit malformed-JSON and oversized-body error handling
  - Evidence: `app/api/feedback/route.ts:1` (nextjs-ast-route, 98a6e88a7194b0ff3afa89d156d3169f)

## 103-rate-limit-addition

- [x] Repeat 1: failed; route sol-direct; 0 accepted model-origin finding(s).

- [x] Repeat 2: failed; route sol-direct; 0 accepted model-origin finding(s).

- [x] Repeat 3: failed; route sol-direct; 0 accepted model-origin finding(s).

## 104-session-control-removal

- [x] Repeat 1: failed; route sol-direct; 0 accepted model-origin finding(s).

- [x] Repeat 2: failed; route sol-direct; 0 accepted model-origin finding(s).

- [x] Repeat 3: failed; route sol-direct; 0 accepted model-origin finding(s).

## 105-customer-data-read

- [x] Repeat 1: completed; route sol-direct; 1 accepted model-origin finding(s).
  - Proposal `30194e99fc4d0c44abe664ec8d0b753b`: **high** New public API path returns customer email and billing address without an observed authorization boundary
  - Invariant: A caller must not receive another customer's email or billing address unless an explicitly authorized role and use case permits it; unauthenticated callers must receive no customer records.
  - Missing controls: Authentication at or before the route, Authorization restricting access to an appropriate role or customer scope, Tenant or ownership filtering derived from an authenticated identity, Data minimization that excludes sensitive fields unless specifically required, Pagination or bounded result size to limit bulk disclosure
  - Evidence: `app/api/customers/route.ts:3` (nextjs-ast-route, dc5a71d4019261564891e5a7fe18858e); `app/api/customers/route.ts:4` (typescript-ast-operation, 5e2d73b8c803bfe8a5f8cd97aec31b83); `prisma/schema.prisma:1` (prisma-extractor, 344da45ff7b019ce97dc59141e63c249); `app/api/customers/route.ts:4` (typescript-ast-operation, 982593af2f07fadc1e2e46092606b434); `app/api/customers/route.ts:4` (typescript-ast-operation, 453151776cee8570b9ace265b7716b9e)

- [x] Repeat 2: completed; route sol-direct; 1 accepted model-origin finding(s).
  - Proposal `2d1a272f155d3414221b8ab1a37850bb`: **high** Public customer-list route crosses into sensitive data without an observed authorization boundary
  - Invariant: A caller must not receive customer email or billing-address data unless authenticated and specifically authorized for every returned customer; collection responses must also be bounded.
  - Missing controls: Authentication at or before the route, Authorization based on role, tenant, ownership, or another business policy, Data minimization that excludes sensitive fields unless required, Pagination or a bounded result limit for the collection read
  - Evidence: `app/api/customers/route.ts:3` (nextjs-ast-route, dc5a71d4019261564891e5a7fe18858e); `app/api/customers/route.ts:4` (typescript-ast-operation, 982593af2f07fadc1e2e46092606b434); `app/api/customers/route.ts:4` (typescript-ast-operation, 453151776cee8570b9ace265b7716b9e); `prisma/schema.prisma:1` (prisma-extractor, 344da45ff7b019ce97dc59141e63c249)

- [x] Repeat 3: completed; route sol-direct; 2 accepted model-origin finding(s).
  - Proposal `7b8b5de334099d15315b63d34d7486c0`: **high** New public route reads and returns sensitive customer records without an observed authorization boundary
  - Invariant: Only authenticated and explicitly authorized principals may retrieve customer data, and each response must be limited to records and fields within that principal's permitted scope.
  - Missing controls: Authentication at or before the route, Authorization for access to customer records, Tenant or ownership scoping where applicable, Response minimization that excludes billing and contact data unless required
  - Evidence: `app/api/customers/route.ts:3` (nextjs-ast-route, dc5a71d4019261564891e5a7fe18858e); `app/api/customers/route.ts:4` (typescript-ast-operation, 982593af2f07fadc1e2e46092606b434); `app/api/customers/route.ts:4` (typescript-ast-operation, 453151776cee8570b9ace265b7716b9e); `prisma/schema.prisma:1` (prisma-extractor, 344da45ff7b019ce97dc59141e63c249)
  - Proposal `da256036ce8d5c5f9d45213554ea9cc9`: **medium** Unbounded customer collection read may enable resource exhaustion and bulk extraction
  - Invariant: A single request and a bounded request rate must consume predictably limited database, serialization, memory, and network resources regardless of total customer-table size.
  - Missing controls: Server-enforced pagination or maximum result count, Rate limiting or equivalent abuse controls, Response-size and execution-time limits, Monitoring for anomalous bulk access
  - Evidence: `app/api/customers/route.ts:3` (nextjs-ast-route, dc5a71d4019261564891e5a7fe18858e); `app/api/customers/route.ts:4` (typescript-ast-operation, 5e2d73b8c803bfe8a5f8cd97aec31b83); `app/api/customers/route.ts:4` (typescript-ast-operation, 982593af2f07fadc1e2e46092606b434)

## 106-avatar-storage-write

- [x] Repeat 1: completed; route sol-direct; 3 accepted model-origin finding(s).
  - Proposal `74e19a5deaabc49262ad70c9fe203b0c`: **high** Publicly inferred avatar endpoint writes to storage without an observed identity or authorization control
  - Invariant: Every profile image storage write must be attributable to an authenticated principal authorized to modify the corresponding profile, and must be subject to an explicit quota.
  - Missing controls: Authentication before accepting the upload, Authorization tying the write to a specific user/profile, Per-user upload quotas or rate limits, Auditable identity-to-object association
  - Evidence: `app/api/profile/avatar/route.ts:5` (nextjs-ast-route, 15dea1da8039b25c40eb065611bdfc07); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, f2decc51c9be67d0daa698a7b27a2d3a); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, 226c410ae6d90001be5d2234ca03e9f1)
  - Proposal `f2f1d3325cd230aa353fd3cfcd52e7c8`: **medium** Arbitrary bytes are persisted as profile images without observed file validation
  - Invariant: Only successfully decoded, policy-compliant images may enter the profile-images bucket; rejected content must cause no storage write.
  - Missing controls: Allowlisted decoded image formats, Magic-byte and successful image-decode validation rather than trusting headers, Safe re-encoding to a canonical image format, Explicit stored Content-Type and download/serving policy, Malware scanning or quarantine where required by the threat model
  - Evidence: `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, f2decc51c9be67d0daa698a7b27a2d3a); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, 226c410ae6d90001be5d2234ca03e9f1)
  - Proposal `fab503b1d395523487422ffe713ebd69`: **high** Request body is fully buffered and stored without an observed size or rate limit
  - Invariant: Requests exceeding the configured avatar size, rate, or account quota must be rejected before the body is fully buffered or any storage write occurs.
  - Missing controls: A strict avatar byte-size limit enforced before full buffering, Request and concurrency rate limiting, Per-principal storage quotas, Handling for missing or misleading Content-Length values, Cleanup or lifecycle controls for abandoned uploads
  - Evidence: `app/api/profile/avatar/route.ts:5` (nextjs-ast-route, 15dea1da8039b25c40eb065611bdfc07); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, f2decc51c9be67d0daa698a7b27a2d3a); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, 226c410ae6d90001be5d2234ca03e9f1)

- [x] Repeat 2: completed; route sol-direct; 3 accepted model-origin finding(s).
  - Proposal `059275a47f254684bcfcef1398e34f04`: **medium** Arbitrary bytes are stored without an observed media validation or serving policy
  - Invariant: Only successfully decoded, policy-compliant image content may enter the published profile-image namespace, and it must be served with non-executable metadata.
  - Missing controls: Allowlisting based on decoded image format rather than caller-provided metadata, Canonical image re-encoding and dimension/pixel-count limits, Explicit safe Content-Type and Content-Disposition metadata, Malware or content scanning where required, A quarantine-to-approved publication workflow and a defined bucket serving policy
  - Evidence: `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, f2decc51c9be67d0daa698a7b27a2d3a); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, 226c410ae6d90001be5d2234ca03e9f1)
  - Proposal `259dc83586e679d39340a427cf18b49f`: **high** Unbounded request buffering can amplify memory and storage consumption
  - Invariant: A single request and aggregate caller activity must be unable to exceed defined memory, request-rate, and persistent-storage budgets.
  - Missing controls: A strict avatar byte-size limit enforced before full buffering, Streaming or otherwise memory-bounded upload handling, Per-principal and global rate limits or quotas, Storage lifecycle and capacity controls, Rejection based on declared and actual body size
  - Evidence: `app/api/profile/avatar/route.ts:5` (nextjs-ast-route, 15dea1da8039b25c40eb065611bdfc07); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, f2decc51c9be67d0daa698a7b27a2d3a); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, 226c410ae6d90001be5d2234ca03e9f1)
  - Proposal `e11974c4cc05e0e480596135adbfa6d6`: **high** Public avatar endpoint introduces a storage write without an observed authorization boundary
  - Invariant: Only an authenticated principal authorized for the target profile may create that profile's avatar object, and the resulting object must be bound to that principal/profile.
  - Missing controls: Authentication before accepting the upload, Authorization tying the write to a specific profile or tenant, An explicit ownership mapping between the generated object key and the authorized principal, Abuse controls such as quotas or rate limits
  - Evidence: `app/api/profile/avatar/route.ts:5` (nextjs-ast-route, 15dea1da8039b25c40eb065611bdfc07); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, f2decc51c9be67d0daa698a7b27a2d3a); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, 226c410ae6d90001be5d2234ca03e9f1)

- [x] Repeat 3: completed; route sol-direct; 2 accepted model-origin finding(s).
  - Proposal `3bc239d5528120d001fa160f0113b48c`: **high** Public avatar endpoint introduces a storage write without an observed identity or authorization boundary
  - Invariant: Every object written through the profile avatar route must be attributable to an authenticated principal who is authorized to modify the corresponding profile, and each principal must be subject to bounded write quotas.
  - Missing controls: Authentication before accepting a write, Authorization binding the write to an eligible user or profile, Abuse controls such as per-principal rate limits, quotas, and lifecycle cleanup, Least-privilege storage permissions and auditable principal attribution
  - Evidence: `app/api/profile/avatar/route.ts:5` (nextjs-ast-route, 15dea1da8039b25c40eb065611bdfc07); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, f2decc51c9be67d0daa698a7b27a2d3a); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, 226c410ae6d90001be5d2234ca03e9f1)
  - Proposal `be14b300fefa0028ff588a26af84d5b6`: **high** Request body is buffered and stored without observed size or media validation
  - Invariant: An upload exceeding the configured avatar byte or dimension limits, or failing verified image-format validation, must be rejected before any storage write and without buffering an unbounded body.
  - Missing controls: A request-size limit enforced before full buffering, Streaming upload with bounded byte counting where appropriate, Allowlisted media types verified from file signatures rather than trusting headers, Image decoding and dimensional limits, Explicit object metadata and safe downstream serving policy, Cleanup when validation or later processing fails
  - Evidence: `app/api/profile/avatar/route.ts:5` (nextjs-ast-route, 15dea1da8039b25c40eb065611bdfc07); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, f2decc51c9be67d0daa698a7b27a2d3a); `app/api/profile/avatar/route.ts:7` (typescript-ast-operation, 226c410ae6d90001be5d2234ca03e9f1)

## 107-link-preview-outbound

- [x] Repeat 1: failed; route sol-direct; 0 accepted model-origin finding(s).

- [x] Repeat 2: failed; route sol-direct; 0 accepted model-origin finding(s).

- [x] Repeat 3: failed; route sol-direct; 0 accepted model-origin finding(s).

## 108-deployment-workflow-authority

- [x] Repeat 1: completed; route sol-direct; 0 accepted model-origin finding(s).

- [x] Repeat 2: completed; route sol-direct; 0 accepted model-origin finding(s).

- [x] Repeat 3: completed; route sol-direct; 0 accepted model-origin finding(s).

## 109-unresolved-billing-control

- [x] Repeat 1: failed; route sol-direct; 0 accepted model-origin finding(s).

- [x] Repeat 2: failed; route sol-direct; 0 accepted model-origin finding(s).

- [x] Repeat 3: failed; route sol-direct; 0 accepted model-origin finding(s).

## 110-integration-boundary-probe

- [x] Repeat 1: completed; route sol-direct; 2 accepted model-origin finding(s).
  - Proposal `1dbc254002007b231437ed2ad2222197`: **high** Public integration receiver has no evidenced sender-authentication or integrity control
  - Invariant: No integration event is acknowledged as accepted or passed to downstream processing unless its sender and message integrity have been verified.
  - Missing controls: Authenticate the integration sender, preferably by verifying a provider signature over the raw request body., Reject stale or replayed signed requests using timestamps and event identifiers., Authorize the expected integration or tenant before accepting an event., Only return an acceptance status after authenticity and schema checks succeed.
  - Evidence: `app/api/integrations/receive/route.ts:1` (nextjs-ast-route, a61d60bc9750b2235d33ed6081b080a8)
  - Proposal `49a580557f24c895e9c6e7ba8c87f031`: **medium** Unbounded and structurally unvalidated JSON is processed at a public entry point
  - Invariant: Only authenticated requests within the configured size limit and matching the integration event schema receive HTTP 202.
  - Missing controls: Enforce a small request-body limit at the edge or before parsing., Require the expected content type., Validate the parsed object against an explicit schema and reject unknown or missing fields., Handle JSON parsing failures with a controlled 4xx response., Apply rate limiting appropriate to the integration sender.
  - Evidence: `app/api/integrations/receive/route.ts:1` (nextjs-ast-route, a61d60bc9750b2235d33ed6081b080a8)

- [x] Repeat 2: completed; route sol-direct; 2 accepted model-origin finding(s).
  - Proposal `a60f82d38fd74194cf5497d30c73a957`: **low** Unbounded JSON parsing exposes the new public route to resource exhaustion
  - Invariant: Integration requests exceeding the documented size and complexity limits must be rejected before full in-memory parsing.
  - Missing controls: Documented request-body size limit at the edge or application boundary, Content-Type and schema validation, Controlled error handling for malformed or oversized bodies, Rate limiting appropriate to the integration sender
  - Evidence: `app/api/integrations/receive/route.ts:1` (nextjs-ast-route, a61d60bc9750b2235d33ed6081b080a8)
  - Proposal `d3cfe9e94ee486453190def7844380be`: **medium** New public integration receiver has no evidenced sender authentication or message-integrity control
  - Invariant: Only events authenticated as originating from an approved integration sender, with valid integrity and freshness evidence, may be accepted for processing.
  - Missing controls: Explicit sender authentication or cryptographic webhook-signature verification, Replay resistance such as a signed timestamp, nonce, or event identifier, A fail-closed authorization decision before parsing or processing the event
  - Evidence: `app/api/integrations/receive/route.ts:1` (nextjs-ast-route, a61d60bc9750b2235d33ed6081b080a8)

- [x] Repeat 3: completed; route sol-direct; 2 accepted model-origin finding(s).
  - Proposal `6eafe09ca51b095152d9cdbce2c4d7e2`: **low** Unbounded JSON parsing is introduced at a public request boundary
  - Invariant: The integration endpoint must reject bodies exceeding the documented maximum size before performing unbounded parsing or downstream processing.
  - Missing controls: Enforce a small request-body size limit before JSON parsing., Apply endpoint-appropriate rate limiting or upstream traffic controls., Handle malformed or oversized payloads with bounded, non-2xx responses., Validate payload depth and schema where relevant.
  - Evidence: `app/api/integrations/receive/route.ts:1` (nextjs-ast-route, a61d60bc9750b2235d33ed6081b080a8)
  - Proposal `926860769b616035c318b9b0279a976b`: **medium** New public integration endpoint accepts events without sender authentication
  - Invariant: Only requests cryptographically authenticated as originating from the configured integration provider are accepted as integration events.
  - Missing controls: Authenticate the integration sender, preferably by verifying a provider signature over the raw request body., Reject missing, invalid, expired, or replayed signatures before accepting an event., Validate event structure and allowlisted event types before dispatch., Document whether the endpoint is intentionally public and which external service is trusted.
  - Evidence: `app/api/integrations/receive/route.ts:1` (nextjs-ast-route, a61d60bc9750b2235d33ed6081b080a8)

> Human confirmation is not implied by generation of this file. Checkboxes, reviewer identity, and completion time must be supplied by the reviewer without changing the frozen corpus.
