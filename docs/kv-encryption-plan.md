# Plan: encrypting Workers KV values at the application layer

Status: proposal · Scope: this repo (Worker + Container backend) and any future KV namespace it binds · Author: Claude (drafted for review)

## TL;DR

Encrypt every value in the Worker before it reaches KV and decrypt it after it comes back, so the plaintext only ever exists inside the Worker isolate. Use one **root key per key version**, held in **Worker Secrets** (or the account-level **Secrets Store** when several Workers share the namespace), and derive a **fresh AES-256-GCM key per write** from the root key with HKDF, bound to the KV key name. Store a small self-describing header in the value and a copy of the key version in KV metadata so rotation can be driven by `list()` without reading every value. Rotation is "add a new root key, flip the primary, sweep, retire the old key", and it never requires downtime.

This is the same shape that Vault Transit, AWS's hierarchical keyring, Google Tink keysets and Rails Active Record Encryption converge on: versioned keys, a key-ID prefix on the ciphertext, associated data that binds the ciphertext to its location, and lazy re-encryption.

---

## 1. Where this fits in the repo

Today the Worker in `src/index.ts` only proxies `/api/*` to the Go container through the `Backend` Durable Object. There is no KV binding yet. The plan assumes a KV namespace is added for data the Worker or the container needs (configuration, cached widget data, per-tenant settings, tokens for third-party APIs, and so on).

Two facts decide *where* encryption runs:

- Containers cannot use Worker bindings. KV is only reachable from the Worker or the Durable Object; the container gets data pushed to it through `envVars` or request bodies.
- Worker secrets are only injected into the Worker isolate and cannot be read back from the dashboard or API.

So the Worker (and the `Backend` Durable Object, which runs in the same script) is the only place that should ever hold the keys. The container stays stateless and receives already-decrypted data when it needs it; it never talks to KV and never sees a key. Encryption is implemented once, as a thin wrapper around the KV binding, and every KV access in the Worker goes through the wrapper.

## 2. Threat model

Cloudflare already encrypts KV at rest with AES-256-GCM using Cloudflare-managed keys, but the docs are explicit that values are decrypted "by the process executing your Worker code **or responding to your API requests**". Anyone who can call the KV REST API, open the dashboard KV viewer, or run `wrangler kv key get` sees plaintext. Application-layer encryption changes that.

What this plan protects against:

| # | Threat | Covered? |
|---|--------|----------|
| T1 | Read access to the namespace outside the Worker: leaked or over-scoped API tokens, dashboard browsing, `wrangler kv` exports, `kv bulk get` dumps in CI logs | Yes. Everything outside the Worker sees opaque tokens. |
| T2 | Backups or copies of the namespace that leak later | Yes, as long as the root keys are not stored with the backup. |
| T3 | Cloudflare-internal or storage-layer access (defense in depth beyond Cloudflare-managed keys) | Yes. |
| T4 | Someone with KV *write* access swapping a value from one key onto another key, or editing a ciphertext | Yes. The ciphertext is bound to its key name and fails authentication anywhere else. |
| T5 | Values that were re-encrypted under a new key after a compromise, read with the old key | Yes, once the old key is retired (crypto-shredding). |

What it does **not** protect against, and what to do about each:

| # | Gap | Mitigation |
|---|-----|------------|
| N1 | Anyone who can deploy the Worker or set its secrets can read the keys, so *Worker deploy permission equals data access*. | Restrict who can deploy. If that is not acceptable, move the root key out of the app Worker (alternatives B, C, D below). |
| N2 | A compromised dependency running inside the Worker sees plaintext. | Out of scope for encryption; standard supply-chain hygiene. |
| N3 | Key names, value sizes, timestamps, expirations and metadata stay visible. | Optional key-name blinding (section 4.8). Never put secrets in key names or metadata. |
| N4 | Rollback: a writer can restore an old, still-valid ciphertext for the same key. | Encryption cannot prevent this. Where freshness matters, keep a version counter in the plaintext and check it in the app. |
| N5 | Losing the root keys loses the data. | Escrow the keyring in a second system (section 4.6). |
| N6 | Rotation does not "un-leak" ciphertext that was already copied together with the old key. | Rotate quickly after an incident and retire the old key; accept that already-exfiltrated copies are gone. 1Password's design document puts it plainly: "once a secret has been shared the recipient cannot be forced to forget that secret". |

## 3. Platform facts that shape the design

| Fact | Consequence |
|------|-------------|
| KV metadata is limited to 1024 bytes of JSON and is returned by `list()` | Put the key version in metadata so a rotation sweep can find stale entries without reading values. |
| KV values may be up to 25 MiB; one write per second per key; 1000 KV operations per invocation | Overhead per value must be small; sweeps must be chunked; per-key nonce reuse is impossible to reach in practice (see 4.3). |
| Multi-key `get(keys[])` does not support `arrayBuffer` | Store ciphertext as a text token, not raw bytes, so bulk reads keep working. |
| Worker secrets are max 5 KB each, 64 or 128 per Worker, and not readable after being set | A JSON keyring with tens of key versions fits in one secret; the same secret is the only copy Cloudflare holds. |
| Secrets Store secrets are shared account-wide, have RBAC (Admin, Deployer, Reporter) and audit logs, and can be updated without redeploying; values are capped at 1024 bytes, 100 secrets per account, one store per account; still open beta | Prefer it when more than one Worker needs the keyring or when auditability of key changes matters. A keyring must stay under 1 KB there, which still holds about fifteen key versions. |
| WebCrypto in Workers supports AES-GCM, AES-KW, HKDF, PBKDF2 (capped at 100,000 iterations), HMAC, RSA-OAEP, ECDH and `timingSafeEqual` | Everything needed is native and fast; no crypto library to bundle. Password-derived keys are out. |
| Durable Object storage is now viewable and editable from the dashboard through Data Studio (Workers Platform Admin role, audit logged) | DO storage is *not* a place to hide keys; it is only a candidate for coordination state such as rotation progress. |
| Containers receive secrets only through `envVars` and cannot reach bindings | Keep crypto in the Worker; the container never handles keys or ciphertext. |
| Cron Triggers (up to 15 minutes of CPU on hourly schedules) and Workflows (durable multi-step execution) exist | Rotation sweeps can run entirely inside the platform, so the keyring never has to leave Cloudflare. |

## 4. Recommended design

### 4.1 Key hierarchy

```
Root key  (32 random bytes, versioned by kid: k1, k2, ...)          lives in Worker Secrets / Secrets Store
   │
   └─ HKDF-SHA256(root[kid], salt = 16 random bytes per write,
                 info = JSON ["cfkv", 1, kid, context, keyName])
        │
        └─ Data key (AES-256-GCM, one per write)                     never stored; recomputed on read
             │
             └─ Ciphertext + 128-bit tag, 96-bit random nonce
```

Two levels are enough. The root key is the only long-lived secret. The per-write data key is derived, not stored, so there is no wrapped key to manage in the value and no keyring document to keep in a database. The random per-write salt means every ciphertext uses a different AES key, so GCM nonce reuse cannot happen even if the same KV key is rewritten forever.

This is not novel. Kubernetes' KMS v2 provider keeps a seed in memory and derives a single-use data key per write with HKDF and 32 random bytes precisely to sidestep the AES-GCM nonce limit that forced its older `aesgcm` provider to be rotated every 200,000 writes, and the AWS Database Encryption SDK's hierarchical keyring derives a per-item key from a cached branch key with a random salt for the same reason.

### 4.2 Where the keys live

**Default: one Worker secret named `KV_KEYRING`** containing a JSON keyring:

```json
{ "primary": "k2",
  "keys": { "k1": "<base64 32 bytes>", "k2": "<base64 32 bytes>" } }
```

Why a single JSON secret instead of one secret per version: the primary pointer and the set of valid keys change together, and one `wrangler secret put` is atomic per Worker version, so the Worker can never observe a primary that points at a missing key. Forty-plus versions fit inside the 5 KB limit of a Worker secret; the 1024-byte limit of a Secrets Store value still holds about fifteen. A live keyring should never carry more than two or three versions anyway: the current primary, the one being retired, and at most one staged ahead of a rotation.

Why an explicit `primary` field instead of list order: Fernet, Kubernetes and the Django field libraries encrypt with the *first* key in their list while Rails encrypts with the *last*. A named primary removes that ambiguity from runbooks.

**When several Workers or environments share a namespace, or when an audit trail for key changes is required:** move the same JSON into the account-level Secrets Store and bind it with `secrets_store_secrets`. Updates apply without redeploying, the Admin/Deployer/Reporter roles separate "can change the key" from "can deploy code that uses it", and every change is in the audit log. Because `env.KV_KEYRING.get()` is asynchronous, the wrapper caches the parsed keyring in module scope and refreshes it on a short TTL (5 minutes is plenty because old keys stay valid until the sweep finishes).

Rules that hold for either location:

- Different keyrings for dev, staging and production. `.dev.vars` (already git-ignored) holds the dev keyring.
- Never derive the root key from a password. Generate 32 bytes from a CSPRNG. Workers caps PBKDF2 at 100,000 iterations, far below the 600,000-plus that password managers use, so a password-derived root would be weak as well as unnecessary.
- Worker code imports each root key once per isolate as a non-extractable HKDF `CryptoKey` and caches it in module scope. Isolates are reused across requests but are not long-lived, so the cache is an optimisation that is rebuilt on a miss, never a source of truth.
- Hardening option: workerd defines a `CryptoKey` binding kind (exposed as `secret_key` in the Cloudflare API and TypeScript SDK) that injects a key as a `CryptoKey` with `extractable = false`. In workerd's own words, that way "you can prevent the Worker code from accessing or leaking the raw key material; it will only be able to use the key to perform WebCrypto operations". It is not yet in the Wrangler configuration docs. If it is available for this account it is the best home for the root keys: one binding per `kid` imported as HKDF with `deriveKey` usage, and the keyring JSON shrinks to `primary` plus the list of `kid`s.
- The `Backend` Durable Object uses the same wrapper and the same secret; it is the same script.

### 4.3 Per-entry encryption

- Cipher: AES-256-GCM via `crypto.subtle`, 96-bit random nonce, 128-bit tag.
- Key derivation: HKDF-SHA256 from the root key with a 16-byte random salt and an `info` value that contains the format version, the `kid`, a **context** string (for example `widgets:prod`) and the KV key name.
- Associated data: the same fields are passed as AAD.
- Canonical encoding: both `info` and the AAD are the UTF-8 bytes of the JSON array `["cfkv", 1, "<kid>", "<context>", "<keyName>"]`, never a separator-joined string. KV key names routinely contain `:`, and a joined string would let `context = "a:b", key = "c"` and `context = "a", key = "b:c"` derive the same key. A JSON array is unambiguous and trivial to produce in a Worker.

Binding the key name into both the derivation and the AAD is deliberate belt-and-braces: a ciphertext copied to another key, another namespace, or another environment derives a different data key and fails the tag check. It also means copying data between namespaces is a decrypt-and-re-encrypt job by design. The precedents are good company: Vault's storage barrier (format v2) uses the storage path as AAD, SOPS feeds in the YAML path of each value, AWS's DynamoDB encryption signs the table name plus the canonical attribute path, and AWS KMS binds Secrets Manager ciphertext to the secret's ARN and version through the encryption context. Kubernetes, Rails and Chef do not bind values to their location, which is why a value can be silently swapped between records in those systems.

Nonce safety: NIST SP 800-38D limits random 96-bit nonces to 2^32 invocations *per key*. Here a key is used exactly once, so the limit is irrelevant. Even without the per-write salt, KV's one-write-per-second-per-key limit would cap one derived key at 2^32 writes only after 136 years. For comparison, Vault's barrier auto-rotates its key after 3,865,470,566 operations, "just under 4 billion encryptions, to satisfy NIST SP 800-38D", and AWS's hierarchical keyring documents 2^96 salted wrapping keys per branch key before wear-out.

Key commitment: AES-GCM is not key-committing, meaning a specially crafted ciphertext can decrypt validly under two different keys. That is exploitable only when an attacker knows or can guess candidate keys (password-derived or user-supplied keys) and can observe which one succeeds. Here every root key is 256 random bits and decryption happens under exactly the key selected by `kid`, never in a loop over candidates, so no commitment tag is needed. If alternative D or any user-supplied key is ever introduced, add the AWS Encryption SDK's approach: a 32-byte HKDF-derived commitment value in the header, compared with `crypto.subtle.timingSafeEqual`.

### 4.4 Stored format

Value (a string, so every KV read type including multi-key `get` works):

```
cfkv:1:<kid>:<base64url( salt(16) ‖ nonce(12) ‖ ciphertext ‖ tag(16) )>
```

Metadata (merged into whatever metadata the caller sets; the `cfkv` field is reserved):

```json
{ "cfkv": { "v": 1, "kid": "k2", "at": 1756800000 } }
```

Properties:

- Self-describing. The `cfkv:` prefix makes plaintext (legacy or accidental) values detectable during migration, exactly like Vault's `vault:v1:` prefix and Kubernetes' `k8s:enc:aesgcm:v1:<keyname>:` prefix.
- Downgrade-safe by configuration. The decoder accepts a configurable minimum format version and only the `kid`s present in the keyring. Chef's encrypted data bags ship with `data_bag_decrypt_minimum_version 0` and document that an attacker can downgrade an item to the weakest format; Vault Transit's `min_decryption_version` is the model to copy instead.
- The version field allows the format (cipher, KDF, encoding) to change later without a flag day.
- The metadata copy of `kid` is advisory only; decryption trusts the in-value header, which is covered by the AAD. If someone edits metadata the worst case is that a sweep re-encrypts an entry it did not need to.
- Overhead is about 60 bytes plus 33 percent base64 expansion. The practical plaintext ceiling therefore drops from 25 MiB to roughly 18 MiB. A binary variant (`arrayBuffer` values, same header) is a small extension if values that large ever appear.

### 4.5 Worker API surface

A ~150-line module, `src/encrypted-kv.ts`, exposing a class with the same shape as `KVNamespace` so call sites do not change:

```ts
const kv = new EncryptedKV(env.APP_KV, { keyring: env.KV_KEYRING, context: "widgets:prod" });
await kv.put("tenant:42:config", JSON.stringify(cfg), { expirationTtl: 3600 });
const cfg = await kv.get("tenant:42:config", "json");
const page = await kv.list({ prefix: "tenant:42:" });        // metadata shows cfkv.kid per entry
```

- `put` derives, encrypts, adds the metadata header, and writes a string.
- `get`/`getWithMetadata` parse the header, pick the root key by `kid`, derive, decrypt, then apply the requested type (`text`, `json`, `arrayBuffer`, `stream` is emulated because GCM cannot stream).
- Unknown `kid` raises a typed error and logs a metric; it is the signal that a key was retired too early.
- `allowPlaintext: true` is an explicit migration switch that returns values without the `cfkv:` prefix unchanged. It defaults to off. This repo has no existing data, so it would only be needed when adopting the wrapper for an existing namespace.
- Everything else (`delete`, `list`, `expiration`, `cacheTtl`) passes straight through.

Integration: add an `APP_KV` binding to `wrangler.jsonc`, the `KV_KEYRING` secret, and route any KV-backed endpoints to the Worker rather than the container (for example keep `/api/widgets` on the container and serve `/api/config/*` from the Worker). If the container needs a decrypted value, the `Backend` Durable Object reads it through the wrapper and passes it in `envVars` or the proxied request, as the Containers docs already show for Secrets Store values.

### 4.6 Key generation, escrow and environments

1. Generate: `node -e 'console.log(crypto.randomBytes(32).toString("base64"))'` on a trusted machine, or a tiny `scripts/keyring.mjs` that prints a whole keyring document.
2. Install: `wrangler secret put KV_KEYRING` (or `wrangler versions secret put` to stage it in a version without deploying). For Secrets Store: create the secret, then add the binding.
3. Escrow: paste the same keyring into the team's password manager or vault entry that is reserved for production keys. Cloudflare cannot show it back, so this copy is the disaster-recovery path. Access to that entry should be at least as restricted as Worker deploy permission.
4. Separate keyrings per environment; never reuse the dev keyring in production. The `context` string differs per environment, so even an accidental reuse would not let staging ciphertext decrypt in production.
5. Record the `kid`, creation date and reason in a short `KEYS.md` runbook table (dates only, never key material).

### 4.7 Rotation

Scheduled rotation (annually, or on the cadence policy requires):

1. Generate `k3`. Update the keyring: keep `k2`, add `k3`, set `primary: "k3"`. Push the secret (or update the Secrets Store secret). New writes now use `k3`; reads of `k2` data keep working.
2. Run the sweep: a Cron Trigger (or a Workflow for large namespaces) calls `list()` page by page, and for every entry whose `metadata.cfkv.kid` is not the primary it does `get → decrypt → encrypt → put`, preserving expiration and user metadata. Each invocation can do about 450 entries within the 1000-operation limit, so the cron loops with the cursor persisted in a small DO or in a reserved KV key.
3. Wait one `cacheTtl` window (60 seconds by default) after the last stale entry is rewritten, confirm with one more `list()` pass that no entry still carries `k2`, then remove `k2` from the keyring. Never remove a key while any deployed Worker version might still use it as primary: with gradual deployments two versions run side by side, so `k2` stays until the version whose primary is `k3` is at 100 percent. Bitwarden documents what happens when a stale-key session keeps writing: data that nothing can decrypt.
4. Monitor the unknown-`kid` metric for a few days. It should stay at zero.

Emergency rotation (suspected root-key exposure): identical steps, run immediately, and additionally revoke the API tokens or accounts involved. Removing `k2` at the end is the crypto-shredding step: any copy of the namespace taken later is unreadable without it.

Why the sweep runs inside the platform: the keyring never has to be exported to a laptop or CI runner. The REST bulk API (10,000 pairs per request) would be faster for huge namespaces, but it requires holding the keyring outside Cloudflare, which widens the trust boundary.

### 4.8 Optional: blinding key names

If key names themselves are sensitive (user email addresses, document titles), the wrapper can store `blind(name) = base64url(HMAC-SHA256(nameKey, name))`, where `nameKey` is derived from the root key with its own HKDF label (`["cfkv-names", 1, kid]`) so the index key and the encryption keys are never the same material. Truncating the HMAC, as CipherSweet does, makes unrelated names collide on purpose, which limits what the index reveals at the cost of occasional double lookups. Keep an optional plaintext prefix (`tenant:42:` + blinded remainder) so `list({ prefix })` still works per tenant. Costs: names become unreadable in the dashboard, arbitrary prefix listing is lost, and blinded names are deterministic by necessity (equal names map to equal tokens), which is the same trade-off MongoDB's deterministic encryption and CipherSweet blind indexes make. Off by default.

### 4.9 Operations

- Metrics and logs: count `decrypt_failed`, `unknown_kid`, and `plaintext_read` (migration mode only). Any non-zero `decrypt_failed` is either tampering or a deployment that lost a key.
- Backups: a `wrangler kv bulk get` export is now ciphertext. A restore needs the keyring version that was current when the export was taken, so keep old keys in escrow even after they are removed from the live keyring, and label exports with the `kid` set they were taken under.
- Testing: unit tests with `@cloudflare/vitest-pool-workers` covering round trip, known-answer vectors for the format, tamper cases (flip a byte, move a value to a different key, change `kid` in the header), rotation (write under k1, rotate to k2, sweep, read, retire k1), and multi-key `get`.
- Performance: WebCrypto is native. For typical values under a few kilobytes the extra work is one HKDF and one AES-GCM call per operation, well under a millisecond; the KV round trip dominates. Encrypted values cache at the edge exactly like plaintext values, and now the edge cache never holds plaintext either.

### 4.10 What this plan deliberately does not do

- It does not store wrapped data keys in the value (classic envelope). For KV that buys nothing, because KV has no metadata-only update, so any root-key rotation rewrites every entry anyway. Section 5, alternative A, covers when to switch.
- It does not put the keyring in Durable Object storage or in KV. Both are readable from the dashboard by sufficiently privileged roles; secrets are the only Cloudflare primitive that cannot be read back.
- It does not encrypt in the container. The container has no bindings, would need the keyring in its environment on every instance, and adds nothing the Worker cannot do.

---

## 5. Alternatives

Each alternative is compared with the recommended design ("Plan"). The comparison table at the end summarises them.

### Alternative A: classic per-value envelope (random data key wrapped by the root key, stored in the value)

Every `put` generates a random 256-bit data key, encrypts the value with it, wraps the data key with the root key (AES-KW or AES-GCM) and stores the wrapped key in the header. This is the AWS Encryption SDK and MongoDB CSFLE shape.

- Pros: the standard textbook pattern; maps one-to-one onto a future external KMS (`GenerateDataKey` / `Decrypt`); root-key rotation only needs to re-wrap 40 bytes per entry instead of re-encrypting the payload; every value has an independent key; AES-KW is native in Workers `wrapKey` and adds only 8 bytes per wrapped key.
- Cons: 40 to 60 extra bytes per value and two key operations per access; in KV the "re-wrap only" advantage is moot because a re-wrap still costs a full `get` and `put` of the value; more code and more format surface than the derived-key design. The plan's HKDF-per-write derivation gives the same one-key-per-value property with nothing extra stored.
- Choose it if: an external KMS is already on the roadmap and you want the on-disk format to match the KMS SDKs from day one.

### Alternative B: external KMS as the root (AWS KMS, Google Cloud KMS, Azure Key Vault, HashiCorp Vault Transit) with a cached branch key

The root key never leaves the HSM. At cold start the Worker calls the KMS to unwrap a "branch key" (or asks Vault Transit for a data key), caches it in module scope for a bounded time, and then derives per-entry keys exactly as in the plan. This is the AWS Database Encryption SDK hierarchical-keyring pattern.

- Pros: the root key is outside Cloudflare, so Worker deploy permission no longer equals data access; independent audit log and instant revocation by disabling the KMS key or its IAM grant; satisfies "customer-managed keys in a FIPS HSM" requirements; KMS handles root rotation transparently.
- Cons: a network call of tens of milliseconds at cold start and whenever the cache expires, across many isolates in hundreds of locations; a hard dependency on a second cloud's availability and IAM; KMS credentials still have to live in Worker Secrets, so the boundary moves to "who can call KMS with these credentials" rather than disappearing; per-call cost; SigV4 or OAuth signing code in the Worker (`aws4fetch` and similar libraries exist); more moving parts for local dev.
- Choose it if: compliance or the threat model requires keys held outside Cloudflare, or a KMS already exists in the organisation.

### Alternative C: a dedicated "crypto service" Worker (Vault Transit on Workers)

A separate Worker holds the keyring in *its* secrets and exposes `encrypt`, `decrypt`, `deriveDataKey` and `rotate` over a Service Binding using `WorkerEntrypoint` RPC. Application Workers never see a root key; they send plaintext or ciphertext across the binding, which stays inside Cloudflare's network.

- Pros: separates "can deploy the app" from "can read the data" without leaving Cloudflare; one place to rotate keys and audit usage for many apps; still fast, because by default both Workers run on the same thread of the same server and Cloudflare documents Service Bindings as adding zero overhead or latency; no external dependency.
- Cons: whoever can deploy the crypto Worker can still exfiltrate the key, so the gain is only as strong as the deploy-permission split; the app Worker still handles plaintext, so runtime compromise is unchanged; one more deployable to own; every KV read becomes a KV call plus an RPC call, or the app caches derived data keys and loses some of the isolation.
- Choose it if: several teams or Workers share the same data and you want a single key owner, but an external KMS is overkill.

### Alternative D: zero-knowledge, user-held keys

For per-user data, derive the key from something only the user has (a passphrase through Argon2 or PBKDF2, a passkey PRF output, or a device-held key) and encrypt in the browser. The server stores ciphertext it cannot read. This is the 1Password and Bitwarden model.

- Pros: strongest possible guarantee; a full compromise of the Worker, its secrets and Cloudflare reveals nothing; no server-side key management at all.
- Cons: only works for data that belongs to one principal who is present when it is read; the Worker and the container cannot process the data (no server-side rendering, search, aggregation or scheduled jobs on it); losing the credential loses the data unless keys are also encrypted to a recovery public key, which is how 1Password and Bitwarden handle it; sharing between users needs public-key wrapping of per-item keys; password stretching must happen in the browser because Workers caps PBKDF2 at 100,000 iterations; a large front-end investment. Infisical launched this way and made it optional in 2023 because customers wanted server-side integrations more than zero knowledge. Not applicable to shared data such as the widget list.
- Choose it if: the product's promise is "we cannot read your data".

### Alternative E: single static key, no versioning, no derivation

One `KV_KEY` secret, AES-256-GCM with a random nonce directly under that key, ciphertext stored as-is. The 30-line version.

- Pros: minimal code; trivially auditable; identical protection against threats T1 to T3 on day one.
- Cons: rotation is a flag day (no `kid` in the header means no mixed-key reads, so every entry must be rewritten between two deployments); the 2^32-writes-per-key GCM bound now applies to the whole namespace, which a busy namespace reaches in weeks (1,000 writes per second reaches it in about 50 days); nothing binds ciphertext to its key name, so value swapping (T4) is not detected; no metadata to drive a sweep. Kubernetes shipped exactly this with its `aesgcm` provider and had to document "rotate the key every 200,000 writes".
- Choose it if: you need something today and will replace it. Even then, adding the `cfkv:1:<kid>:` prefix costs ten lines and removes the flag-day problem, which is why the plan starts there.

### Alternative F: keys in the container, encryption in Go

The `Backend` Durable Object passes the keyring into the container through `envVars`; the Go server encrypts and decrypts, and the Worker stores whatever the container hands it.

- Pros: Go's `crypto/aes` and `golang.org/x/crypto/hkdf` are excellent; keeps the Worker a pure proxy.
- Cons: containers cannot reach KV, so ciphertext must be shuttled through the Worker anyway; every one of the three stateless instances holds the keyring in its process environment; secrets in environment variables are visible to anything that can inspect the process; cold starts are slower than isolates; rotation tooling has to run somewhere that can reach both KV and the container. Net effect is a larger key footprint for no additional protection.
- Not recommended.

### Alternative G: do nothing beyond Cloudflare's encryption at rest

- Pros: zero work; Cloudflare already uses AES-256-GCM at rest with keys in its internal KMS, which covers physical and disk-level threats.
- Cons: every holder of a KV-scoped API token, every dashboard user with KV access, and every export sees plaintext; there is currently no customer-managed-key option for KV; nothing to show an auditor about application-level controls. This is the status quo the plan exists to change.

### Comparison

| | Who can read plaintext | Rotation cost | Extra latency | Complexity | External deps | Handles T4 (value swap) |
|---|---|---|---|---|---|---|
| **Plan** (versioned root in secrets, HKDF per write) | Worker deployers + Cloudflare secret custody | Sweep of entries under old `kid`; no downtime | ~0 (native crypto) | Low–medium | None | Yes |
| A. Per-value envelope | Same as Plan | Same as Plan in KV (full rewrite either way) | ~0 | Medium | None | Yes |
| B. External KMS root | KMS IAM principals; deployers only via KMS credentials | Handled by KMS + sweep for data-key changes | Tens of ms at cold start, then cached | High | KMS, IAM, signing lib | Yes |
| C. Crypto-service Worker | Deployers of the crypto Worker | One place; sweep still needed | ~0 (same-thread RPC) | Medium | None | Yes |
| D. User-held keys | The user only | User-driven | Client-side | High (front end) | None | Yes |
| E. Single static key | Same as Plan | Flag day | ~0 | Lowest | None | No |
| F. Encrypt in container | Deployers + all container instances | Custom tooling | Container hop | Medium | None | Depends |
| G. Status quo | Anyone with KV read access | n/a | 0 | None | None | No |

Sub-choices inside the plan, with the recommended default first:

- Root key location: Worker Secrets (single Worker) or Secrets Store (shared, audited, rotate without redeploy).
- Value encoding: text token (works with multi-key `get`, readable as opaque in the dashboard) or binary (`arrayBuffer`, 25 percent smaller, single-key reads only).
- Key name handling: plaintext names (default) or HMAC-blinded names (section 4.8).
- Sweep runner: Cron Trigger loop (small namespaces) or Workflow (large namespaces, resumable).

---

## 6. What other systems do, and what this plan takes from them

The plan borrows deliberately. Each system below gets the facts that matter for a KV design, with sources, and a note on what was borrowed or avoided.

### 6.1 Secret managers and KMS-backed systems

**HashiCorp Vault.** Everything Vault stores passes through the *barrier*: an unseal key (Shamir-split into shares, or held by a cloud KMS or HSM for auto-unseal) decrypts a root key, the root key decrypts a keyring of AES-256-GCM barrier keys, and each stored value is prefixed with the 4-byte key "term" so the right keyring entry can be found. Barrier format v2 uses the storage path as AEAD associated data. `sys/rotate` adds a new term lazily ("future values are encrypted with the new key, while old values are decrypted with previous encryption keys"), and auto-rotation fires after 3,865,470,566 operations by default to stay under the NIST GCM bound. The Transit engine exposes the same ideas as a service: named keys with numbered versions, ciphertext prefixed `vault:v<version>:`, `min_decryption_version` as a floor, `rewrap` to move ciphertext to the newest version without exposing plaintext, `derived` keys that HKDF-SHA256 a per-context subkey, convergent encryption for equality lookups, and a `datakey` endpoint for envelope encryption. Sources: [architecture](https://developer.hashicorp.com/vault/docs/internals/architecture), [seal](https://developer.hashicorp.com/vault/docs/concepts/seal), [barrier_aes_gcm.go](https://github.com/hashicorp/vault/blob/main/vault/barrier_aes_gcm.go), [sys/rotate](https://developer.hashicorp.com/vault/api-docs/system/rotate), [rotate config](https://developer.hashicorp.com/vault/api-docs/system/rotate-config), [Transit](https://developer.hashicorp.com/vault/docs/secrets/transit), [Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit).
*Borrowed:* the `prefix:version:` ciphertext shape, the minimum-decryptable-version floor, per-context HKDF derivation, lazy rotation. Alternative C is Transit reimplemented as a Worker.

**AWS KMS, Secrets Manager and Parameter Store.** KMS keys never leave HSMs; the service hands out data keys in plaintext and wrapped form and "does not store, manage, or track your data keys". Encryption context is passed as AAD, logged in CloudTrail, and must match exactly on decrypt. Automatic rotation keeps all key material, so old ciphertext decrypts with the material that produced it, and "does not rotate the data keys or re-encrypt any data". Secrets Manager generates a fresh data key per secret value, stores the wrapped key in the secret's metadata, binds the ciphertext to the secret ARN and version, and re-wraps only the current, pending and previous versions when the KMS key changes. Parameter Store `SecureString` uses KMS directly for standard parameters and the Encryption SDK envelope for advanced ones. Sources: [KMS concepts](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html), [data keys](https://docs.aws.amazon.com/kms/latest/developerguide/data-keys.html), [encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html), [rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html), [Secrets Manager encryption](https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html), [Parameter Store](https://docs.aws.amazon.com/kms/latest/developerguide/services-parameter-store.html).
*Borrowed:* encryption context as the model for the plan's AAD; "root rotation does not touch data" as the reason the plan keeps a per-value `kid`. This is the target shape for alternative B.

**AWS Encryption SDK and the Database Encryption SDK for DynamoDB.** The SDK message format carries the algorithm suite, a message ID, the encryption context, and one encrypted data key per keyring, and derives the actual AES key with HKDF from the data key and the message ID; version 2 adds a 32-byte key-commitment string so "each ciphertext can be decrypted only to a single plaintext". The DynamoDB flavour encrypts attribute values but not names, keeps partition and sort keys plaintext, binds every field to the table name plus its canonical path as AAD, and signs the whole item. Its *hierarchical keyring* is the closest published relative of this plan: a KMS key protects a branch key stored in a DynamoDB key store, the branch key is cached in memory for a configurable TTL (one KMS call per branch-key version per TTL instead of one per record), and each record gets a wrapping key derived from the branch key with a 16-byte random salt, giving 2^96 wrapping keys before wear-out. Rotation versions the branch key; old versions keep decrypting. Data-key caching in the SDK is governed by max age, max messages (up to 2^32) and max bytes. Sources: [message format](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html), [algorithms](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html), [encrypted and signed](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/DDB-encrypted-and-signed.html), [hierarchical keyring](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/use-hierarchical-keyring.html), [rotate branch key](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/rotate-branch-key.html), [data key caching](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html).
*Borrowed:* per-record salted derivation from a cached root; key version in the record's metadata; the plan's root key is simply a branch key whose custodian is Worker Secrets instead of KMS, which is why alternative B is a drop-in upgrade.

**Google Cloud KMS, Secret Manager and Tink.** Cloud KMS guidance for envelope encryption is "generate DEKs locally", AES-256-GCM, "generate a new DEK every time you write the data", and "the KEK never leaves Cloud KMS"; ciphertext carries its key version, decrypt picks the version automatically, and rotation neither re-encrypts data nor disables old versions. Secret Manager encrypts each secret version with its own DEK wrapped by a per-replica KEK (or a customer-managed KMS key), and existing versions are not re-encrypted on rotation. Tink formalises the keyset: several keys with IDs and statuses, exactly one primary that encrypts, all keys tried on decrypt, a 5-byte unauthenticated key-ID prefix on ciphertext as a hint, rotation as "add key, roll out, promote", a recommendation of 30- to 90-day keys, deterministic AEAD (AES-SIV) for equality lookups, and a documented malleability issue in its KMS envelope mode because the wrapped-DEK header is not authenticated. Sources: [envelope encryption](https://cloud.google.com/kms/docs/envelope-encryption), [key rotation](https://cloud.google.com/kms/docs/key-rotation), [Secret Manager CMEK](https://cloud.google.com/secret-manager/docs/cmek), [Tink keysets](https://developers.google.com/tink/design/keysets), [Tink wire format](https://developers.google.com/tink/wire-format), [Tink AEAD](https://developers.google.com/tink/aead), [envelope malleability](https://developers.google.com/tink/issues/envelope-aead-malleability).
*Borrowed:* keyset-with-primary; a new key per write. *Improved on:* the plan's header is inside the AAD, so it cannot be tampered with the way Tink's prefix and envelope header can.

**Azure Key Vault and Storage.** Keys are versioned objects protected by FIPS-validated HSMs; storage services wrap a per-account root DEK with the Key Vault key and cache DEKs locally. "Key rotation re-wraps data encryption keys with the new key version, it does not re-encrypt the underlying data. Both old and new key versions must remain enabled until re-wrapping is complete", and Microsoft advises storing the versioned key URI with the data. Sources: [about keys](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys), [key rotation](https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation), [customer-managed keys](https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview).
*Borrowed:* "keep both versions enabled until the sweep completes" is step 3 of section 4.7.

**Data-key caching in practice.** HashiCorp's own guidance is to fetch a data key from Transit and store the wrapped copy with the data rather than send large payloads to Vault, and a 2026 HashiCorp case study caches unwrapped DEKs in memory keyed by key name, context and key version with a one-hour TTL, cutting Vault calls by 96 percent. AWS says to "use data key caching only when it is required" and to bound caches by age, message count and byte count, because plaintext keys sit in process memory. Sources: [Vault envelope encryption](https://developer.hashicorp.com/vault/docs/secrets/transit/envelope-encryption), [HashiCorp case study](https://www.hashicorp.com/en/blog/adopting-hashicorp-vaults-transit-engine-high-performance-envelope-encryption-ariso-ai), [AWS caching](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html), [AWS thresholds](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/thresholds.html).
*Applied in:* section 4.2's module-scope cache with a short TTL, and alternative B's cold-start unwrap.

### 6.2 Key-value stores, config stores and file-based secret tools

**Kubernetes Secrets at rest.** By default the API server writes plaintext to etcd, and etcd itself does not encrypt on disk. The optional `EncryptionConfiguration` offers `aescbc` (documented as weak, padding-oracle prone), `aesgcm` (fastest, but "must be rotated every 200,000 writes" because of random-nonce collision risk), `secretbox`, and `kms` v1/v2 envelope providers. Static keys live base64-encoded in a config file on every control-plane node, which the docs say "only moderately improves your security posture". KMS v2 keeps the KEK in an external KMS behind a gRPC plugin, generates a seed at startup, and derives a single-use DEK per write with HKDF and random bytes; a change in the KMS `key_id` marks old data stale. Stored values carry a `k8s:enc:<provider>:v1:<keyname>:` prefix, and rotation is "add the new key second, restart, move it first, restart, rewrite every secret with `kubectl replace`, drop the old key". No AAD binds a value to its etcd key. Sources: [encrypt-data](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/), [kms-provider](https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/), [KEP-3299](https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/3299-kms-v2-improvements/README.md), [etcd security](https://etcd.io/docs/v3.5/op-guide/security/).
*Borrowed:* per-write HKDF-derived data keys; key-name prefix on ciphertext; the ordered "add, rewrite, remove" rotation dance. *Avoided:* key material in a config file next to the data; no AAD binding.

**HashiCorp Consul KV** does not encrypt KV values at rest. Its encryption features are gossip encryption and mTLS, its security model puts "access to the Consul data directory" outside the threat model, and its snapshots "contain extremely sensitive data, such as credentials in recoverable form". Sources: [encryption](https://developer.hashicorp.com/consul/docs/security/encryption), [security model](https://developer.hashicorp.com/consul/docs/security/security-models/core), [backup](https://developer.hashicorp.com/consul/tutorials/production-deploy/backup-and-restore). *Lesson:* a KV store's own encryption story is usually "the disk", which is exactly the gap this plan closes for Workers KV.

**Redis** (open source) has no at-rest encryption; Redis Software points at file-system encryption and Redis Cloud at encrypted cloud disks. The docs describe client-side encryption as the alternative and list its limits: "operations that must operate on the data, such as increments, comparisons, and searches will not function properly". Sources: [OSS](https://redis.io/docs/latest/operate/oss_and_stack/management/security/encryption/), [Redis Software](https://redis.io/docs/latest/operate/rs/security/encryption/), [Redis Cloud](https://redis.io/docs/latest/operate/rc/security/encryption-at-rest/). *Lesson:* the same trade-off applies here; encrypted KV values cannot be inspected or filtered server-side.

**Mozilla SOPS** generates a random 256-bit data key per file, encrypts every leaf value with AES-256-GCM under it, and wraps the data key to each configured master key (AWS KMS, GCP KMS, Azure Key Vault, Vault, age, PGP) in the file's `sops` metadata block, which also carries a MAC over all values. Keys and structure stay plaintext; only values are encrypted. The YAML path of a value is used as AEAD associated data so values cannot be moved between keys. `sops -r` rotates the data key and re-wraps it. Sources: [README](https://github.com/getsops/sops/blob/v3.8.1/README.rst), [sops.go](https://github.com/getsops/sops/blob/main/sops.go). *Borrowed:* AAD binding to the record path; plaintext keys with encrypted values; multi-recipient wrapping as the model for alternative B.

**Ansible Vault** derives keys from a password with PBKDF2-SHA256 (10,000 iterations), uses AES-256-CTR plus HMAC-SHA256, and prefixes files with `$ANSIBLE_VAULT;1.2;AES256;<vault-id>`. Multiple passwords are labelled with vault IDs; `rekey` re-encrypts whole files, but inline encrypted variables cannot be rekeyed. Sources: [format](https://docs.ansible.com/ansible/latest/vault_guide/vault_using_encrypted_content.html), [passwords](https://docs.ansible.com/ansible/latest/vault_guide/vault_managing_passwords.html). *Lesson:* password-derived keys and un-rekeyable ciphertext are both things to avoid; the plan uses random root keys and a `kid` on every value.

**Chef encrypted data bags and chef-vault.** A shared secret file on every node encrypts values; format v1 was AES-256-CBC, v2 added HMAC, v3 moved to AES-256-GCM with an empty AAD. The item `id` stays plaintext. The `data_bag_decrypt_minimum_version` default of 0 lets a man-in-the-middle downgrade an item to v1. chef-vault fixes key distribution by RSA-wrapping the shared secret to each node's public key, with `refresh` and `rotate keys` commands. Sources: [data bags](https://docs.chef.io/client/latest/policy/data_bags/), [encryptor.rb](https://github.com/chef/chef/blob/main/lib/chef/encrypted_data_bag_item/encryptor.rb), [config](https://github.com/chef/chef/blob/main/chef-config/lib/chef-config/config.rb), [chef-vault theory](https://github.com/chef/chef-vault/blob/main/THEORY.md). *Borrowed:* a minimum accepted version; per-recipient wrapping (alternative B/C). *Avoided:* the same secret on every node.

**Ruby on Rails.** Encrypted credentials are AES-128-GCM under a key from `RAILS_MASTER_KEY` or `config/master.key`, with the ciphertext committed. Active Record Encryption uses AES-256-GCM with keys derived by PBKDF2 from `primary_key` and `key_derivation_salt`, supports a list of primary keys ("the last key is used for encrypting new content and all keys are tried when decrypting"), per-attribute `previous:` schemes, an optional envelope key provider, deterministic mode for lookups (with rotation unsupported), and migration switches `support_unencrypted_data` and `extend_queries`. Payloads are JSON `{"p": ..., "h": {"iv", "at", ...}}` with about 255 bytes of overhead. Sources: [credentials](https://github.com/rails/rails/blob/main/railties/lib/rails/commands/credentials/USAGE), [encrypted_file.rb](https://github.com/rails/rails/blob/main/activesupport/lib/active_support/encrypted_file.rb), [AR Encryption guide](https://guides.rubyonrails.org/active_record_encryption.html). *Borrowed:* "previous keys stay valid until re-encryption", a migration switch for unencrypted data, header fields inside the value. *Avoided:* trying every key on decrypt; the plan reads `kid` instead.

**MongoDB CSFLE and Queryable Encryption.** Data encryption keys live in a key-vault collection wrapped by a customer master key in AWS, Azure, GCP, KMIP, or a local key (not for production). Fields use AEAD AES-256-CBC with HMAC, deterministic or random; deterministic mode is flagged for frequency analysis on low-cardinality data. Rotating the CMK does not re-wrap existing DEKs; `rewrapManyDataKey` does, without touching data. Stored ciphertext is a BSON binary with the key UUID and original type embedded. Sources: [keys and key vaults](https://www.mongodb.com/docs/manual/core/csfle/fundamentals/keys-key-vaults/), [algorithms](https://www.mongodb.com/docs/manual/core/csfle/fundamentals/encryption-algorithms/), [rewrapManyDataKey](https://www.mongodb.com/docs/manual/reference/method/KeyVault.rewrapManyDataKey/), [binary format](https://github.com/mongodb/specifications/blob/master/source/bson-binary-encrypted/binary-encrypted.md). *Borrowed:* key ID embedded in every ciphertext; the explicit "rotation of the wrapping key does not rotate data keys" distinction that section 4.7 spells out.

**CockroachDB and TiKV** (server-side, for contrast). Both take an operator-provided store or master key (file or cloud KMS), generate data keys that rotate automatically every 7 days, keep a registry of which key encrypted which file, and rely on storage churn rather than rewriting old files. Both document that backups and logs fall outside the boundary, and TiKV warns that a key file "leaks the key" unless it lives on tmpfs. Sources: [CockroachDB](https://www.cockroachlabs.com/docs/stable/security-reference/encryption), [TiKV](https://docs.pingcap.com/tidb/stable/encryption-at-rest/). *Lesson:* backups need their own plan (section 4.9).

**Fernet and MultiFernet.** Token = version byte, big-endian timestamp, 16-byte IV, AES-128-CBC ciphertext, HMAC-SHA256; a 32-byte key is split into signing and encryption halves. `MultiFernet` encrypts with the first key, tries every key on decrypt, and `rotate()` re-encrypts under the primary. The timestamp is plaintext. Django's Fernet field libraries add a `FERNET_KEYS` list and, by default, derive keys from Django's `SECRET_KEY`, which has bricked data when that unrelated secret was rotated. Sources: [spec](https://github.com/fernet/spec/blob/master/Spec.md), [cryptography docs](https://cryptography.io/en/latest/fernet/), [django-fernet-fields](https://django-fernet-fields.readthedocs.io/en/latest/), [issue](https://github.com/jazzband/django-fernet-encrypted-fields/issues/13). *Lesson:* never derive the KV root key from a general application secret; give it its own lifecycle.

**Cloudflare's own products.** KV, Durable Objects and Secrets Store are all encrypted at rest with Cloudflare-managed keys, and Secrets Store additionally describes a two-level DEK/KEK hierarchy with frequently refreshed DEKs and a root that "never leaves a secure system", write-only values, RBAC, audit logs, a 1024-byte value limit and 100 secrets per account. Sources: [KV data security](https://developers.cloudflare.com/kv/reference/data-security/), [Secrets Store blog](https://blog.cloudflare.com/secrets-store-beta/), [manage secrets](https://developers.cloudflare.com/secrets-store/manage-secrets/), [access control](https://developers.cloudflare.com/secrets-store/access-control/), [audit logs](https://developers.cloudflare.com/secrets-store/audit-logs/). *Borrowed:* the same DEK/KEK shape, one level down, with the Worker holding the root.

### 6.3 Zero-knowledge stores and recipient-key patterns

**1Password.** Two secrets, the account password and a 128-bit Secret Key that never reaches the server, are combined by "Two-Secret Key Derivation" (PBKDF2-HMAC-SHA256 with 650,000 iterations, HKDF, XOR) into an Account Unlock Key. That key encrypts a per-user keyset (an RSA-OAEP key pair), which decrypts per-vault 256-bit keys, which encrypt items with AES-256-GCM. Sharing a vault means encrypting the vault key to the recipient's public key; recovery works by encrypting every vault key to a recovery group's public key at creation time, because "we at 1Password never have the ability to decrypt your data". Vault keys are deliberately not rotated on revocation: "once a secret has been shared the recipient cannot be forced to forget that secret". Sources: [Secret Key](https://agilebits.github.io/security-design/apsk.html), [key derivation](https://agilebits.github.io/security-design/deepKeys.html), [items](https://agilebits.github.io/security-design/secureItems.html), [shared vaults](https://agilebits.github.io/security-design/sharedVaults.html), [recovery](https://agilebits.github.io/security-design/restore.html), [revocation](https://agilebits.github.io/security-design/revoke-access.html).

**Bitwarden.** Master password → PBKDF2-SHA256 (600,000 iterations) or Argon2id → master key → HKDF-stretched key → a random 512-bit user symmetric key stored encrypted on the server. Each item has its own random cipher key wrapped by the user or organisation key; organisation keys are RSA-OAEP-wrapped to each member's public key when they are confirmed. Rotating the account key re-encrypts every cipher key and requires all other sessions to be logged out first, because "making changes in a session with a stale encryption key will cause data corruption that will make your data unrecoverable". Sources: [security white paper](https://bitwarden.com/help/bitwarden-security-white-paper/), [KDF options](https://bitwarden.com/help/kdf-algorithms/), [key rotation](https://bitwarden.com/help/account-encryption-key/).

**Infisical and Doppler.** Infisical launched end-to-end encrypted (project keys wrapped to user public keys, Argon2id-protected private keys, blind-indexed secret names), then made E2EE optional in 2023 because self-hosting customers "cared little about E2EE, so long as secrets remained encrypted at rest" and integrations need server-side access; today it is server-side AES-256-GCM under a root key from an environment variable or HSM, with per-organisation and per-project data keys. Doppler has always been server-side: AES-GCM under a per-workplace key that is wrapped by an HSM-backed key in Google Cloud KMS, with an optional customer-controlled extra wrapping layer; its only end-to-end feature is one-off secret sharing with the key in the URL fragment. Sources: [Infisical legacy mechanics](https://github.com/Infisical/infisical/blob/8ff33a4/docs/security/mechanics.mdx), [Infisical 2023 update](https://infisical.com/blog/infisical-update-june-2023), [Infisical security](https://infisical.com/docs/internals/security), [Doppler security fact sheet](https://docs.doppler.com/docs/security-fact-sheet), [Doppler EKM](https://docs.doppler.com/docs/enterprise-key-management).

**age and libsodium sealed boxes.** age wraps a per-file key to each recipient (X25519 plus HKDF, or scrypt for passphrases) and encrypts the payload in 64 KiB STREAM chunks under an HKDF-derived key; sealed boxes encrypt to a recipient public key with an ephemeral sender key so the writer "cannot decrypt the message later". Both are write-only-producer patterns. In Workers, RSA-OAEP `wrapKey` is native, while X25519 is derive-only, so an age-style construction has to be assembled by hand from X25519, HKDF and AES-GCM. Sources: [age spec](https://github.com/C2SP/C2SP/blob/main/age.md), [sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes).

*What the plan takes from this group:* the shape of alternative D and its honest costs (no server-side processing, recovery only by pre-encrypting to a recovery key); Bitwarden's rotation hazard as the reason section 4.7 never retires a key while any deployed Worker version might still write with it; Infisical's reversal as evidence that zero-knowledge is a product decision, not a default.

### 6.4 Cryptographic guidance behind the choices

- **AES-GCM limits (NIST SP 800-38D).** 96-bit IVs are recommended; the chance of ever repeating an IV under one key "shall be no greater than 2^-32", and with random IVs "the total number of invocations of the authenticated encryption function shall not exceed 2^32" per key; a single repeated IV "may be vulnerable to the forgery attacks". Plaintext per invocation is capped at 2^39-256 bits, about 64 GiB, far above KV's 25 MiB. Source: [SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf). *Applied:* one derived key per write (4.1, 4.3).
- **HKDF (RFC 5869) and SP 800-108.** The salt is optional but "adds significantly to the strength of HKDF"; `info` exists "to bind the derived key material to application- and context-specific information"; NIST adds that derived keys "should be bound to all relying entities and other information to identify the derived keying material". Naively joining identifiers with a separator is a documented bug class, so inputs must be length-prefixed or otherwise canonical. Sources: [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), [SP 800-108r1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf), [Soatok, Database Cryptography](https://soatok.blog/2023/03/01/database-cryptography-fur-the-rest-of-us/). *Applied:* random 16-byte salt per write and a JSON-array-encoded context (4.3).
- **Associated data as location binding.** Tink: using a user ID as associated data "prevents an attacker from moving medical history from one user to another". AWS KMS: if a file is renamed or moved "the encryption context value changes and the decryption request fails". Soatok: "where your data lives is part of its identity, and MUST be authenticated". Sources: [Tink AEAD](https://developers.google.com/tink/aead), [AWS encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html). *Applied:* AAD carries version, `kid`, context and key name (4.3).
- **Key commitment.** AES-GCM ciphertext can be crafted to decrypt validly under two different keys (Albertini et al.), and "partitioning oracles" turn that into password-guessing attacks when keys are low-entropy and the attacker can trigger decryption under many candidates (Len, Grubbs, Ristenpart). The AWS Encryption SDK added a 32-byte HKDF-derived commitment string in its version 2 format; Tink notes AES-GCM is "not key-committing" while AES-CTR-HMAC is. Sources: [Albertini et al.](https://eprint.iacr.org/2020/1456), [Len et al.](https://eprint.iacr.org/2020/1491), [AWS concepts](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html). *Applied:* not needed while every root key is random and selected by `kid` (4.3); required if alternative D or any password-derived or user-supplied key is ever introduced.
- **Key wrapping.** NIST SP 800-38F approves AES-KW and AES-KWP as deterministic authenticated encryption for keys and states there is "no requirement to protect cryptographic keys with a distinct cryptographic method", so AES-GCM with AAD is equally acceptable; AES-KW adds 8 bytes and needs no IV. WebCrypto in Workers supports `wrapKey` with AES-KW, AES-GCM and RSA-OAEP. Sources: [SP 800-38F](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf), [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394), [MDN wrapKey](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey). *Applied:* alternative A's wrapping choice.
- **Deterministic encryption and blind indexes.** Tink's deterministic AEAD (AES-SIV) and CipherSweet's blind indexes both leak equality by design; CipherSweet derives each index key separately with HKDF and truncates indexes so that several plaintexts collide, which limits what an index reveals. Sources: [Tink DAEAD](https://developers.google.com/tink/deterministic-aead), [RFC 5297](https://www.rfc-editor.org/rfc/rfc5297), [CipherSweet security](https://ciphersweet.paragonie.com/security). *Applied:* section 4.8 derives the name-blinding key with its own HKDF label and keeps it separate from the encryption key.
- **Workers runtime specifics.** Isolates are reused across requests ("a variable set during one request is still present during the next") but "are not necessarily long-lived", so module-scope caches are an optimisation, never a source of truth. PBKDF2 in Workers is capped at 100,000 iterations, which rules out password-derived root keys inside the Worker. workerd also defines a `secret_key` binding kind that hands the Worker a `CryptoKey` with `extractable = false` so "the Worker code cannot access or leak the raw key material"; it appears in workerd's configuration schema and the Cloudflare TypeScript SDK but not yet in the Wrangler configuration docs. Sources: [best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/), [how Workers works](https://developers.cloudflare.com/workers/reference/how-workers-works/), [workerd PBKDF2 issue](https://github.com/cloudflare/workerd/issues/1346), [workerd.capnp](https://github.com/cloudflare/workerd/blob/main/src/workerd/server/workerd.capnp), [cloudflare-typescript](https://github.com/cloudflare/cloudflare-typescript/blob/main/src/resources/workers/scripts/scripts.ts). *Applied:* 4.2's cache caveat, 4.6's "never derive from a password", and the non-extractable-key hardening note in 4.2.

## 7. Implementation phases

1. **Library and tests** (about a day): `src/encrypted-kv.ts`, keyring parsing and caching, format encode/decode, unit tests with `@cloudflare/vitest-pool-workers`, `scripts/keyring.mjs` to generate keyrings. Add `.dev.vars` guidance to the README.
2. **Wire it in** (hours): `APP_KV` binding and `KV_KEYRING` secret in `wrangler.jsonc` and `src/index.ts`; route KV-backed endpoints through the Worker; pass decrypted values to the container via `envVars` only where the container truly needs them.
3. **Rotation tooling and runbook** (about a day): Cron Trigger or Workflow sweep, `unknown_kid` and `decrypt_failed` metrics, `docs/KEYS.md` runbook (rotation steps, escrow location, incident procedure).
4. **Optional hardening**, in order of payoff: move the keyring to Secrets Store; split out a crypto-service Worker (alternative C); adopt an external KMS root (alternative B) if compliance demands it.

## 8. Cloudflare references used for section 3

- KV data security: https://developers.cloudflare.com/kv/reference/data-security/
- KV limits: https://developers.cloudflare.com/kv/platform/limits/
- KV write, read and list APIs: https://developers.cloudflare.com/kv/api/write-key-value-pairs/ , https://developers.cloudflare.com/kv/api/read-key-value-pairs/ , https://developers.cloudflare.com/kv/api/list-keys/
- Worker secrets: https://developers.cloudflare.com/workers/configuration/secrets/
- Worker limits (secrets, CPU, cron): https://developers.cloudflare.com/workers/platform/limits/
- Secrets Store: https://developers.cloudflare.com/secrets-store/ , https://developers.cloudflare.com/secrets-store/integrations/workers/ , https://developers.cloudflare.com/secrets-store/manage-secrets/ , https://blog.cloudflare.com/secrets-store-beta/
- Web Crypto in Workers: https://developers.cloudflare.com/workers/runtime-apis/web-crypto/
- Service bindings: https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/
- Containers environment variables and secrets: https://developers.cloudflare.com/containers/examples/env-vars-and-secrets/
- Durable Objects data security and Data Studio: https://developers.cloudflare.com/durable-objects/reference/data-security/ , https://developers.cloudflare.com/changelog/product/durable-objects/
- Workflows: https://developers.cloudflare.com/workflows/
- workerd CryptoKey binding: https://github.com/cloudflare/workerd/blob/main/src/workerd/server/workerd.capnp
