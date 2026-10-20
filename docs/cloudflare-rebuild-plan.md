# PigeonHole server — build plan

**Status:** Design locked (2026-10-17). Greenfield build. The service is **not live** — no migration, no cutover, no data import. This describes what we build and the order we build it.

PigeonHole is a **zero-knowledge, end-to-end-encrypted** secret/file sharing service. All crypto is client-side; the server only ever stores and streams **opaque ciphertext** and **public** keys. The server is never trusted with plaintext or private keys — and §9 extends that so it can't even be trusted as the key directory.

---

## 1. Decisions (locked)
- **Backend:** TypeScript + **Hono** on **Cloudflare Workers**. No AWS SDKs anywhere.
- **Storage:** **R2** for encrypted payloads (streaming), **D1** (+ Drizzle ORM) for metadata.
- **Contract:** a single **OpenAPI spec is the source of truth** between CLI, web (nestbox) and backend. Types + client + server route validation are generated/validated from it.
- **Observability:** **OpenTelemetry** → `otel.planesailing.io` (OTLP/HTTP, Bearer). No console/ad-hoc logging.
- **Auth:** OIDC (**Authentik**) → PigeonHole **EdDSA JWT** + JWKS endpoint.
- **Crypto:** client-side only (GPG/age); server zero-knowledge. **No KMS/Vault** — pre-join encryption is a client-side key-wrapping concern, fully separate from the API (§6).
- **Email:** Cloudflare **Email Sending** binding (not Resend).
- **Transfer:** two modes — R2 store-and-forward **and** WebRTC direct P2P (NAT-traversing, no self-hosted relay) (§4).
- Exploit Cloudflare platform primitives where they fit (§5); self-host nothing.

---

## 2. The contract (OpenAPI)

The spec (`common/openapi-spec.yaml`, carried forward and refined) defines the full API. We build the server **to** it and generate the CLI/web clients **from** it.

**API surface:**
- **Auth:** `GET /auth/oidc/providers`, `POST /auth/oidc/handler/{provider}`
- **Secret:** `POST /secret` (open an upload envelope), `GET /secret` (list; `?reference`/`?all`), `DELETE /secret` (all), `GET|DELETE /secret/{id}`, `GET /secret/{id}/download` (stream)
- **User/keys/devices:** `GET/POST /user`, `POST /user/invite`, `GET /user/me`, `GET /user/analytics`, `GET/POST /user/me/key`, `GET /user/me/key/validate/{thumbprint}`, `GET /user/{id}`, `GET/POST /user/{id}/key`, `GET/DELETE /user/{id}/key/{key_id}`, `GET /user/{id}/key/validate/{thumbprint}`, `GET /user/{id}/public`, `POST /user/ephemeral-user`
- **Misc:** `GET /ping` (auth check + version)

**Secret semantics:** multi-recipient (`recipient_ids`), `onetime` (burn-after-read), `expiration`, `ephemeralkeys`, `total_payload_size` (quota input).

**🔶 Spec changes to make now (greenfield — do them before clients are generated):**
- Replace the AWS-shaped upload envelope (`s3_info.fields.x-amz-*`) with a **storage-agnostic** one: `upload: { url, method, headers?, fields? }`. Recipient/sender/reference metadata moves into the `POST /secret` DB record, not object metadata.
- Add the **multi-device / master-key** fields to `Key` (§8): `master_key`, `signature`, device `label`.
- Decide `GET /secret/{id}/download` shape: direct stream vs JSON-with-URL (pick one — §4).

**Data model (D1 / Drizzle):** `users`, `keys` (per-device public key + master signature), `devices`/`sessions`, `secrets` (metadata only; payload lives in R2), `tenants`, `oidc_providers`. UUID PKs, `datetime` columns.

---

## 3. Target architecture

```
  CLI  ┐                                          D1   (metadata)
       ├─►  Worker (TypeScript / Hono)  ────────► R2   (ciphertext, streamed)
  web  ┘     • routes validated from OpenAPI      Durable Objects (onetime, quota)
             • EdDSA JWT + JWKS                    Analytics Engine (usage)
             • OIDC exchange (Authentik)           KV (JWKS/key cache)
             • quota + rate limiting               Queues + Cron (expiry GC)
             • Email Sending (invites)             Secrets Store (JWT/OIDC keys)
             • OTEL ──► otel.planesailing.io
                                                 
  CLI ⟷ web   direct real-time (4B):  signaling DO (signed SDP/ICE only)
              + WebRTC DTLS-1.3 data channel ──── P2P ────▶  (Cloudflare Realtime TURN fallback)
```

Store-and-forward payloads flow **directly client↔R2 via presigned URLs** — the Worker is control-plane only and never touches payload bytes (§4A). Real-time payloads flow peer-to-peer and never touch the server at all (§4B).

---

## 4. Encrypted streaming — two modes

Both modes move only **ciphertext** and reuse the same identity/device-key trust (§8, §9). Mode A is the default; Mode B is for when both peers are online and want direct real-time transfer.

### 4A. Store-and-forward (recipient may be offline) — via R2, **presigned direct-to-R2**

**LOCKED model: the Worker is control-plane only and never touches payload bytes.** All data flows **directly client↔R2** via **presigned URLs**, keeping Worker CPU/duration cost flat regardless of payload size (and R2 egress is free). Header and body are **separate objects** (§6.3): `secrets/<id>/hdr/<thumbprint>` + `secrets/<id>/body`.

- **Upload:** Worker authenticates, checks quota, records metadata, then returns a **presigned PUT** URL (R2 multipart for large/resumable). Client uploads the body straight to R2; small PKESK header object(s) PUT likewise (or inline-POSTed to the Worker since tiny).
- **Download (Option 3):** Worker authenticates, returns the **tiny `hdr` inline** + a **presigned GET** for `body`. Client concatenates header → body stream and decrypts. Worker does one small header read + URL signing — no payload streaming.
- **Cost of this choice (accepted):** the Worker needs an **R2 S3 credential** (access key/secret) to sign presigned URLs → stored in **Secrets Store**. This is a deliberate trade away from the binding-only "no static R2 creds" option, in exchange for keeping the Worker out of the data path.
- **Onetime / burn-after-read:** a **Durable Object** gates **issuance** — it hands out a **single-use, short-TTL** presigned URL (≈60s) and marks the secret consumed **on grant**. Semantics are therefore "**one download grant**," not "one confirmed delivery" (a failed fetch still burns). Optional stronger variant: client `POST …/consumed` receipt after successful decrypt → Worker deletes (but a misbehaving client can skip it). R2 event notifications fire on create/delete, **not reads**, so can't observe delivery.
- **🔶 Client-side format:** OpenPGP streams poorly for ranged/resumable decrypt; a chunked AEAD (`age` / Tink-style) client-side makes streaming genuinely usable. Server stays format-agnostic — decide in the client workstream.

### 4B. Real-time direct peer-to-peer (both peers online) — via WebRTC, NAT-traversing
Goal (Rhys): direct device-to-device streaming that traverses NATs, secured by a TLS-1.3-class channel keyed off the users' own public keys, **without orchestrating relay infra**.

- **Transport:** **WebRTC data channels**. ICE does NAT traversal: **STUN** hole-punching handles the common case; the symmetric-NAT fallback uses **Cloudflare Realtime TURN** (managed, anycast 250+ cities, 1000 GB/mo free) — so **no self-hosted coturn/relay**. The data channel's transport security is **DTLS 1.3** (WebRTC's TLS-over-UDP) — this is the "TLS 1.3 based on users' keys" once we bind the handshake to identity, below.
- **Identity-keyed authentication (the clever bit):** the DTLS certificate fingerprint is carried in each peer's SDP. Each peer **signs its SDP+fingerprint with its device key** (which is master-key-signed, §9 Layer 1). The other peer verifies that signature against the pinned identity before accepting the connection. Result: the DTLS channel is authenticated **end-to-end by PigeonHole identity keys**, and the signaling broker — even if malicious — **cannot swap fingerprints to MITM** (it reuses the §9 trust root). No reliance on WebRTC's built-in (unauthenticated) fingerprint exchange.
- **Signaling (the only new infra, and it's tiny):** a **Durable Object** per pairing/session brokers the offer/answer/ICE-candidate exchange over WebSocket. **Media/data never touch it** — it only relays signed signaling blobs; the payload flows peer-to-peer. Kept as a **separate concern** from the REST API (own Worker/binding).
- **Clients:** the CLI is Go → **Pion** (Go WebRTC); web (nestbox) → native browser WebRTC. Fully interoperable (CLI↔CLI, CLI↔web).
- **When to use which:** 4A when the recipient is offline or it's fire-and-forget; 4B when both are online and want a direct, low-latency, relay-free stream. Same send UX, transport chosen at runtime (fall back A↔B).

---

## 5. Cloudflare services

| Service | Role |
|---|---|
| Workers | the API (Hono) |
| R2 | ciphertext payloads — streaming put/get, multipart, Range; encrypted at rest |
| D1 (Drizzle) | metadata: users, keys, devices, secrets, tenants, OIDC providers |
| Durable Objects | atomic onetime/burn-after-read; per-user quota + rate counters; multipart session state |
| Analytics Engine | powers `GET /user/analytics` + ops metrics (write events, query via SQL API) |
| KV | low-latency cache: JWKS, OIDC provider metadata, recipient public keys |
| Secrets Store | account-level write-only secrets: JWT signing key, OIDC client secret(s), **R2 S3 credential** (for signing presigned URLs) |
| Queues | async R2 garbage-collection on expiry, invite emails, analytics fan-out |
| Cron Triggers | scheduled expiry sweep (purge expired/consumed secrets from R2 + D1) |
| Rate Limiting / Turnstile | abuse protection on `/user/ephemeral-user` + `/user/invite` |
| **Email Sending** (`env.EMAIL.send()`) | invites/notifications — native Workers binding (public beta Apr 2026), no API keys/secrets. **Replaces Resend.** Paid plan: 3k/mo incl., then $0.35/1k |
| **Realtime TURN/STUN** | NAT traversal for 4B direct P2P (managed, no self-hosted relay) |
| DO (signaling) | WebRTC offer/answer/ICE broker for 4B — separate from the REST API; relays signed blobs only |

---

## 6. Key management — and why there's no KMS to build

Cloudflare has **no managed KMS/HSM** (confirmed Oct 2026) — only **Secrets Store** (account-level, write-only, 100×1 KB). Good news: a zero-knowledge service needs essentially none.

### 6.1 The pre-join problem (send to someone with no account/key, re-encrypt on arrival)

**The requirement:** Alice sends to `bob@email` who hasn't signed up (no key). The secret waits — possibly a while — and when Bob joins it should become decryptable by him and **re-encrypted to his new device key**. Constraint: **minimise key material held server-side**, and ideally don't make Alice hand Bob a secret out-of-band.

**The fundamental limit (state it honestly).** To decrypt, Bob needs a secret. If Bob contributes none (no prior key) and Alice gives him none (no out-of-band key), then the only secret in play is held by a **third party** — that is escrow, by definition. So **{no out-of-band key} ∧ {no third-party custody} ∧ {claim anytime} is impossible** — information-theoretic, like first-contact MITM (§9). The design is about *where* the capability sits and shrinking it to *nothing useful on its own*. Three points on that spectrum:

**Option A — out-of-band key, zero server custody (plain link-fragment / passphrase).**
Encrypt to a random content key; put the key in the link **fragment** (`…/s/<id>#<key>`, never sent to the server) or derive it from a passphrase (Argon2id). Server stores only ciphertext.
- ✅ zero decrypt capability server-side. ❌ Alice must deliver the key OOB; the link *is* the secret, so a leaked/forwarded link = compromise, and it sits "in the wild" until Bob acts. *(This is what I proposed before — the weaknesses you spotted are real.)*

**Option B — split capability 2-of-2 + identity-gated (recommended default).** Fixes A's weaknesses without becoming escrow:
1. Alice's client generates an **ephemeral recipient keypair E** (HPKE / RFC 9180, or `age`), encrypts the payload to `E_pub`, and wraps `E_priv` under a key `K = K_frag ⊕ K_srv` (XOR 2-of-2; Shamir if you want thresholds later).
2. `K_frag` goes in the **link fragment** (OOB, client-only). `K_srv` is stored by an **isolated claim service** and **released only to a caller who completes OIDC with verified email == `bob@email`**.
3. The blob download is **also identity-gated** on the same OIDC email match.
- **Why it's strictly better than A:** neither half decrypts alone — the server's `K_srv` is **useless without the fragment** (so the server, or anyone who dumps it, *cannot* decrypt → not escrow), and a **leaked link is useless without authenticating as Bob** (so "key in the wild" no longer means compromise). The capability is split across two parties who must *both* act, one of whom must *be Bob*.
4. On first claim, Bob's client reconstructs `K`, unwraps `E_priv`, decrypts, **re-encrypts to his real device key(s)** (§8), re-uploads, and the server **purges `E_priv` + `K_srv`**. Steady state returns to full zero-knowledge; the half-key only ever exists while *unclaimed*.

**Option C — no out-of-band key (bounded escrow via OpenBao), the default.** If the UX goal is "Alice just sends, Bob signs up and it's there — nothing to hand over," the wrapping key is held by an **isolated OpenBao** (LF fork of Vault, MPL, on the homelab k8s/ArgoCD) and released only to a caller who completes OIDC as `bob@email`:
- OpenBao **Transit / unseal** model: the ephemeral private key is **wrapped transiently** by OpenBao's transit KEK and the wrapped blob is stored in R2 — **no per-secret key material is persisted in OpenBao**; only the one transit KEK lives there.
- **Honest trust statement:** because OpenBao holds a KEK that *can* unwrap, OpenBao (and anyone who compromises it) **can decrypt unclaimed secrets** — this **is** escrow. "Unseal / nothing stored" shrinks blast radius (no key pile, auto-unseal protects stolen-disk) but does **not** remove the capability; a live, unsealed instance serving unwraps can serve an attacker too. Escrow is decided by "does a key OpenBao holds suffice to decrypt" — here it does.
- Bound it hard: separate service (not the API), unwrap allowed only for *unclaimed* secrets, **identity-bound policy** keyed to the recipient's verified OIDC email (OpenBao's OIDC/JWT auth backend → same Authentik), **wrapped key deleted on first claim**, short TTL. On claim the recipient re-encrypts to their device key → that secret returns to full zero-knowledge.
- *Identity-Based Encryption (IBE) is the academic version — its PKG master key can derive **any** user's key (total escrow) and a non-escrow threshold PKG is heavy infra, against the "no unnecessary infra" goal. Not used.*

**LOCKED:** ship **both** — **C (OpenBao) is the default** (delivers the "nothing to hand over" UX Rhys wants; bounded, well-managed escrow), and **B (OpenBao half ⊕ fragment half, 2-of-2)** is an explicit **"high-security send" toggle** where no single party — not even OpenBao — can decrypt (at the cost of an OOB fragment). Per-send choice, so the trust assumption is explicit, never implicit. Both live in a **separate claim module**, not the core API. Primitives: **HPKE (RFC 9180)** / `age` for the KEM-wrap, OpenBao **Transit** for the escrowed half, Shamir/XOR for the 2-of-2, **OPAQUE/PAKE** if we later want password-claim without the server seeing the password.

### 6.3 Cheap re-encryption via PKESK header rewrap (O(header), not O(payload))

OpenPGP is `[ PKESK per-recipient (session key wrapped to each pubkey) ] … [ SEIPD: bulk, encrypted once with the session key ]`. To re-encrypt to a new recipient you **only rewrap the session key**: decrypt it from an existing PKESK, re-wrap to the new public key, and swap the PKESK — the SEIPD bulk is untouched and its integrity tag stays valid. **Payload size is irrelevant.** (Generalises to `age` recipient stanzas.)

**R2 fact-check (verified Oct 2026):** ranged **reads** are supported (`get({range})` offset/length/suffix; S3 `Range` → `206`), **but R2 objects are immutable** — `put` overwrites the *whole* object; there is **no partial/byte-range PUT, append, or byte-range copy**. So you **cannot** patch the header at the front of a combined blob. **Therefore store header and body as separate objects:**
```
secrets/<id>/body             ← SEIPD bulk: written once, immutable, never rewritten
secrets/<id>/hdr/<thumbprint> ← PKESK header(s): tiny, one per recipient/device
```
Re-encrypt / add-device = write a new small `hdr/<thumbprint>` object (body never moves; no Range read, no read-modify-write race). Download = Worker returns `hdr` inline + a **presigned GET** for `body` (§4A Option 3); client concatenates and decrypts. This preserves the O(header) property within R2's immutability model and is cheaper than patching.

Used for:
- **Claim-time re-encryption (§6.1):** on claim, rewrap the ephemeral header to the recipient's real device key(s) — trivial regardless of how large the secret is, which removes the "re-encrypting on arrival is expensive / may be deferred" worry.
- **Multi-device add-key (§8):** an existing trusted device rewraps the header to grant a newly-enrolled device access to old secrets — no payload re-upload.

**⚠️ Placement = the zero-knowledge boundary.** Whoever performs the rewrap holds the unwrapping private key and briefly sees the plaintext **session key** → can decrypt the payload.
- **Client-side rewrap (REQUIRED for the E2EE path):** recipient/existing-device does it locally; server never sees the session key. Still fast — only header bytes move.
- **Worker-side rewrap:** fast but the Worker sees the session key ⇒ the server can decrypt ⇒ **breaks zero-knowledge**. Not used for E2EE secrets.
- **Chosen split:** the **Worker is control-plane only** — it returns the tiny `hdr` inline and presigns `body`; it never streams payload (§4A). The **decrypt-and-rewrap stays in the client**. Zero-knowledge holds because the Worker only ever handles ciphertext headers + wrapped keys + signed URLs, never the session key.

### 6.2 Server-held secrets

**The only secrets the server actually holds** (→ **Secrets Store**, not a KMS):
- **JWT signing key:** **EdDSA**, imported via Web Crypto per request; publish a **JWKS** endpoint (verification needs no secret). Versioned keys in KV for rotation.
- **OIDC client secret(s)** for Authentik.

Vault is now **out of scope** unless a future compliance/audit requirement demands HSM-grade custody of the JWT key — not needed for the product itself.

---

## 7. Observability (OTEL → otel.planesailing.io)

Instrument the Worker with `@microlabs/otel-cf-workers` — traces, metrics, logs via **OTLP/HTTP** to `otel.planesailing.io`, **Bearer** auth. Spans at minimum: inbound request, D1 query, R2 presign/put/get, OIDC exchange, JWT verify, DO operations. Tag `tenant`, `device.id`, `user.id` — **never** secret plaintext. No other logging mechanism.

---

## 8. Multi-device

**One identity, one keypair per device** — the model already supports it (`User.keys[]` + key-`validate` endpoints).
- Each device generates its **own** keypair locally and registers only its **public** key (`Key.reference` = device label). Private keys never leave the device; nothing to sync.
- On send, the server returns **all** the recipient's current validated device keys; the client encrypts to all of them. Hybrid crypto wraps only the small symmetric key per device, so N devices add tiny header stanzas — **not** N payload copies.
- **Device/session registry (D1):** `(device_id, user_id, key_thumbprint, label, created_at, last_seen, revoked)`; per-device JWT. Revoke a device = delete its key + session.
- **🔶 Pre-enrolment secrets:** a new device can't read secrets sent before it existed (inherent to forward-secure E2EE). Options: (a) accept it; (b) device-to-device re-wrap from an online trusted device — **cheap via PKESK header rewrap, §6.3** (no payload re-upload); (c) optional passphrase-wrapped recovery key as an extra recipient (weaker).
- **🔶 Onetime + multi-device:** first device to fetch wins (DO-gated). Confirm vs per-recipient onetime.

---

## 9. Defeating server-mediated MITM on key exchange

**Threat model:** TLS stops a network attacker; the hard adversary is the **PigeonHole server itself** (malicious/compromised/subpoenaed). As the key directory it can substitute a key it controls and silently MITM. Goal: make the server's key distribution **unauthoritative and accountable**.

- **Layer 1 — user-rooted device trust (build with the core).** A client-side **master signing key that never touches the server**; every device key is **signed by it**. Senders pin the recipient's master fingerprint once, then auto-trust any device key with a valid master signature. The server **can't inject a device** — it lacks the master key to sign one. (Signal/Matrix cross-signing.) Pure client crypto; server just stores `master_key` + per-key `signature`.
- **Layer 2 — Key Transparency (dedicated phase).** CONIKS/Google-KT verifiable directory: append-only **Merkle log** of `identity → keys`, lookups return **inclusion proofs**, clients **self-audit** their own entry, signed tree-heads **gossiped** to catch split-view. Even a fully compromised server can't substitute a key **without detectable evidence**. CONIKS VRF keeps the directory non-enumerable.
- **Layer 3 — out-of-band anchors (first contact).** Email identities (OIDC) give free independent channels: **WKD / DANE `OPENPGPKEY`** fingerprint publication cross-checked by the client; **SAS/safety-number** human verification; optional **Authentik co-signature** on enrolments so a binding needs both the user's key and the IdP.

**Residual risk (a law of the problem):** zero-prior-knowledge *first contact* is unavoidably TOFU. Layer 2 makes substitution detectable after the fact; Layer 3 removes it wherever users publish an anchor. No design can make first contact with an unknown party fully MITM-proof without some out-of-band anchor.

### 9.1 Key swap at enrolment & rotation — the DH-proof question

**Q: what stops the server swapping a public key during first sign-in or a rotation?** Two distinct sub-problems, two different answers.

**Rotation (device already trusted once) — solvable cryptographically, no OOB needed.** Treat identity keys as a **signed continuity chain**: every new/rotated device key must carry `Sig(master_key ∨ predecessor_key, newKey ‖ ts ‖ reason)`. A verifier who has pinned the master (or the prior key) rejects any key lacking a valid signature → **the server cannot inject or rotate a key it can't sign**, because it never holds the master private key (§6/§8). This is Signal/Matrix **cross-signing** + a git-style signed hash-chain of key history. Combined with the Layer-2 transparency log, a victim also *sees* an unexpected rotation in their own auditable history. So rotation is **self-authenticating** — swaps are cryptographically rejected, not merely detected.

**First enrolment (no prior key) — the DH "proof" works, but only out-of-band.** Rhys's instinct — a value both sender and receiver derive, bound to the transfer — is exactly right and is precisely the **Signal safety-number / X3DH** idea. Construction we adopt:
- Both parties derive a shared secret the **server cannot** (it holds only public keys): `ss = DH(priv_sender, pub_recipient) = DH(priv_recipient, pub_sender)` (X25519; per-recipient for multi-recipient).
- Bind it to the actual transfer: `tag = HMAC(ss, H(ciphertext) ‖ sorted(recipient_pubkeys) ‖ context)`. This is a **channel/transcript-bound authenticator** — it authenticates the sender **and** pins the exact payload (your `sha(file)` idea) and the recipient key set. Reused identically for both file shipping (4A) and the real-time stream (4B), and it doubles as the DTLS-fingerprint signature in §4B.
- **The hard boundary (why this isn't a silver bullet):** a MITM server that *substituted* a key holds the corresponding private key, so it can compute `ss` with **each** side and forge matching tags **if the comparison passes through the server**. The tag therefore only proves "no swap" when the two sides compare it over a channel the attacker **doesn't control** — i.e. the safety-number must be verified **out-of-band** (QR scan, phone, in person), or audited via the transparency log. This is the same residual limit as above: **DH key-confirmation authenticates a session given trusted identity keys; it cannot bootstrap trust in a never-seen identity key against an untrusted directory.** No construction can — it's information-theoretic.

**Net:** rotation → cryptographically self-authenticating (continuity signatures); first contact → DH transcript-tag for authentication/integrity, made swap-proof by OOB safety-number compare (Layer 3) and detectable by Key Transparency (Layer 2). The tag is worth building regardless: it gives strong sender-authentication + payload integrity for every transfer, and is the basis of the "verify this contact" UX.

### 9.2 Bootstrapping master-key trust **without** out-of-band — IdP + OpenBao attestation

The OOB requirement in §9.1 assumes the *only* trust anchor is the PigeonHole server. It isn't — the user already authenticates to **Authentik**, and we run **OpenBao**. The move: **relocate the trust root off the app server onto independent attesters, and split it so no single party can forge a binding.** You can't reach zero-trust (something must anchor identity), but you can make the PigeonHole server **powerless to swap keys on its own**.

**Mechanism A — IdP-attested key binding (Authentik as the binding CA).**
1. On first sign-in the client generates the master key and a **proof-of-possession**: `Sig_master(email ‖ master_pub ‖ ts)`.
2. Client presents that + its **OIDC ID token** to Authentik (custom flow / property-mapper). Authentik verifies the email and PoP, then **signs the binding** — concretely, issues a short attestation JWT (or embeds the master-key fingerprint as a signed claim): `Sig_IdP(email → master_pub, ts)`, verifiable by anyone against Authentik's **published JWKS**.
3. Senders fetching `bob@email`'s master key from the PigeonHole directory **require the Authentik attestation** and verify it against the IdP JWKS. If the PigeonHole server swapped the key, it **cannot produce a valid IdP signature** over the fake binding → swap rejected, **no OOB step**.
- Effect: trust root moves from "the PigeonHole server" (which stores and serves keys) to "**Authentik**" (which the user already trusts for identity and which is a separate compromise surface). Signing is the right primitive here — **attestation/authenticity**, not encryption; the IdP never sees any private key.

**Mechanism B — multi-signer quorum (no single party can forge).**
Require the binding to carry a **quorum of signatures from independent attesters** — e.g. **2-of-3 of { Authentik, OpenBao, the KT log }**:
- **OpenBao** signs via **Transit signing keys** (ed25519), under an **OIDC-gated policy** (only signs a binding for `email` if the caller authenticated as `email`). *This is a **non-escrow** use of OpenBao — it signs public-key bindings, never touches private keys or plaintext — and uses a **different key** from the §6 pre-join escrow KEK. Keep the two roles/keys strictly separate.*
- The **KT log** (§9 Layer 2) counter-signs/includes the binding.
- Result: the PigeonHole API alone can't forge (it holds none of these keys); compromise of **any single** attester can't forge (quorum needed); only simultaneous compromise/collusion of ≥2 independent systems could — and even then the user's **KT self-audit** surfaces the rogue binding in their own history.

**Honest residual (the irreducible floor):** trust is not eliminated, it is **reduced and distributed** — from "trust the app server" to "**trust that ≥1 of {Authentik, OpenBao, KT} is honest, and check your own transparency entry.**" That is the same guarantee class as CT/KT and SSO-verified E2EE, and it is the best achievable — authenticating a key you've never seen always rests on *some* anchor; we've made that anchor (a) not the app server, (b) plural, and (c) auditable.

**CHOSEN PATH:** build **A (IdP-attested binding)** + rely on the **KT log self-audit** (Layer 2) as the backstop against a misbehaving anchor. This makes the PigeonHole server powerless to swap keys (A) *and* makes even an IdP-level forgery detectable (KT), on stock Authentik + the transparency log we're building anyway. **Full B (2-of-3 with OpenBao as a third signer)** stays documented as the hardening upgrade, added only if "withstand an actively malicious Authentik" becomes a hard requirement — it's the marginal case, since Authentik is already the user's identity root.

**Where this plugs in:** once the master key is IdP/quorum-attested, the device-continuity chain (§9.1) and the DH transcript-tag hang off a master key trustable **without** OOB — so the entire send/stream path becomes server-swap-proof end-to-end, modulo the distributed anchor assumption above. OOB safety-numbers (Layer 3) remain available as optional extra assurance, not a requirement.

---

## 10. Open decisions (🔶 — settle as we hit them)
1. ~~Pre-join wrapping~~ **LOCKED (§6.1):** Option C (OpenBao unseal, default) **+** Option B (2-of-2 high-security toggle). OpenBao on homelab; no KMS.
2. **Pre-enrolment-secret policy** for new devices (accept / re-wrap / recovery key). → B3.
3. **Onetime semantics** across multiple devices. → B2.
4. **Client streaming crypto format** (chunked AEAD vs OpenPGP). → client workstream.
5. ~~Download response shape~~ **LOCKED:** inline `hdr` + presigned GET for `body` (§4A Option 3); presigned direct-to-R2 both ways, Worker control-plane only.
6. **OpenAPI tooling:** `@hono/zod-openapi` (spec-as-code) vs consume YAML via codegen. → B0.
7. **Real-time (4B) scope:** ship P2P streaming in v1 or as a fast-follow? → affects B-phase ordering.

---

## 11. Build phases (greenfield — no cutover)

- **B0 — Skeleton & contract.** TS/Hono repo `pigeonhole-server`; `wrangler.toml` with D1 + R2 + DO + Analytics + KV + Secrets Store bindings; OTEL wired to `otel.planesailing.io`; OpenAPI tooling chosen (decision 6); `/ping` live. Lock the refined spec (§2 🔶 edits) and generate types/clients.
- **B1 — Secret flow (presigned direct-to-R2).** `POST /secret` → presigned PUT (+ multipart) for body + header objects; `GET /secret/{id}/download` → inline `hdr` + presigned GET for `body` (§4A Option 3); `GET/DELETE /secret`, `GET /secret/{id}`. Header/body split objects (§6.3). Onetime via DO (single-use short-TTL grant). `expiration` + quota. R2 S3 cred in Secrets Store.
  - *Client (CLI) I/O routing* (deferred, not started — build alongside the CLI regen): retrieve streams to **stdout** when the payload came from piped stdin (archive = single `plain.txt`), else writes the file/folder to the dest path; honour `-`/TTY detection and `--output`. See §12. *(Rhys: hold, folded into plan 2026-10-19.)*
- **B2 — Auth & identity.** OIDC/Authentik exchange, EdDSA JWT + JWKS, `/user*`, `GET /user/{id}/public`, invites via **Email Sending binding**, ephemeral/pre-join flow (link-fragment, §6). Settle decisions 1, 3.
- **B3 — Multi-device + Layer-1 anti-MITM.** Device/session registry, per-device key enrolment w/ master-key signatures, multi-recipient send, device revoke, new-key notifications. Settle decision 2.
- **B4 — Real-time direct P2P (4B).** Signaling Durable Object (WebSocket), device-key-signed SDP/ICE, Cloudflare Realtime TURN wiring, Pion in CLI + browser WebRTC in nestbox. Separate from the REST API. *(Order vs B5 per decision 7.)*
- **B5 — Platform hardening.** `/user/analytics` on Analytics Engine; Queues + Cron expiry GC; rate limiting + Turnstile; quota tuning; OTEL coverage audit.
- **B6 — Launch readiness.** End-to-end CLI + nestbox against prod Worker; `api.pigeonhole.io` DNS; security review; docs.
- **B7 — Key Transparency (Layer 2).** Merkle log, inclusion/consistency proofs, client self-audit, STH gossip/witness. Optional Layer 3 anchors (WKD/DANE, IdP co-sign).

---

## 12. Repos
- **`common`** — OpenAPI spec (source of truth) + shared utils. Spec is the keystone.
- **`pigeonhole-cli`** — Go/Cobra client; regen from spec; new upload path (streaming PUT) + master-key/device logic; **Pion** for 4B P2P.
  - **I/O routing fix (Rhys-started):** on retrieve, if the payload originated from piped **stdin** (archive is a single `plain.txt`) → stream to **stdout**; if a **file/folder** → write to the dest path. Today `secret retrieve` always `MkdirAll`s a dir and untars into it (`secret.go` → `DecompressFile`), and send wraps stdin as `plain.txt` (`compressStdinData`). Fix = detect single-`plain.txt` archive → raw to stdout (unless `--output` given); else extract to dest. Honour `-` / TTY detection.
- **`nestbox`** — React web app (CF Pages); client of the API; same key/device logic; browser WebRTC for 4B.
- **`pigeonhole-server`** — **new**, TS/Hono/Workers. The subject of this plan.
