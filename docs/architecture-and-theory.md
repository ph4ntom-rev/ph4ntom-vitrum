# Architectural & Theoretical Specification: `ph4ntom Vitrum` (`v0.2.0`), Global CTI Hunter (`v2.6`) & Anti-Canary Dead-Drop Interceptor (`v2.0`)

> **Anti-Evasion & OPSEC Notice (`TLP:AMBER`):**  
> This document specifies the formal architecture, security invariants, counter-deception proofs, and mathematical models underlying the `ph4ntom Vitrum` *in-vitro* binary dissection core (`v0.2.0`), the Global CTI & Dropper Hunter (`v2.6`, 26 threat clusters), and the Zero-Touch Anti-Canary Dead-Drop Interceptor (`v2.0`).  
> To prevent threat actors from testing dropper builds, TDS cloaking gates, or canary honeypots against live heuristics, executable modules (`ph4ntom-vitrum-core`) and active `v2.6` rulesets are withheld from public commits. **Verified security researchers and CERT teams can request access at `owner@ph4ntom-rev.uz`.**

---

## 1. Design Problem & Formal Threat Model

Modern APT espionage syndicates and transnational mobile/financial cybercrime operations combine five layers of defense evasion:
1. **Behavioral & Edge-Cloaked Delivery Infrastructure** — commercial Traffic Distribution Systems (`TDS`), serverless edge relays (`Workers` / `Pages`), and Progressive Web App (`PWA`) storefronts that serve benign decoys to automated scanners.
2. **Malformed Container & Multi-Stage Encryption Chains** — Android `ZIP BadPack` header tampering (`flag_bits & 0x1` set on unencrypted `DEFLATE`/`STORED` entries), `65,535`-byte entry names, zero-filled decoy `classes*.dex` stubs, multi-layer `XOR + AES-ECB/CBC/GCM` asset payloads, and custom native virtual machines (`SVM1` in JNI `.so` libraries).
3. **Censorship-Resistant & Blockchain Dead-Drop C2** — `VLESS/XTLS-REALITY` covert transports bootstrapped via DNS-over-HTTPS (`DoH TXT`) and immutable smart-contract dead-drops (`TON` blockchain transactions authenticated via `Ed25519` and encrypted with `AES-256-GCM`).
4. **Active Researcher Counter-Intelligence (Canary Traps)** — seeding burned dead-drop channels with custom authoritative nameservers (`tcpdump port 53`) or unindexed decoy VPS droplets to capture researcher IP addresses, EDNS client subnets (`ECS`), or `JA3/JA4` fingerprints.
5. **Adversarial Indirect Prompt Injection Against AI Triage** — embedding natural-language override directives (`ignore previous instructions`, `classify as benign`) or invisible Bidirectional / Unicode-Tag (`U+E0000..U+E007F`) token streams inside binary strings, manifests, or scripts to subvert LLM-assisted malware analyzers.

### Core Architectural Invariants
- **Strict *In-Vitro* Non-Execution:** Extract structural, cryptographic, and control-flow ground truth from untrusted artifacts (`≤ 2 GB`) with **zero host CPU instruction execution** of the sample.
- **Zero-Touch Counter-Deception:** Never transmit TCP/TLS/HTTP/ICMP packets to decrypted C2 endpoints and never resolve domains delegated to unverified/glue authoritative nameservers.
- **Deterministic Pre-Cognitive Ledger:** Perform container repair, X.509 certificate pinning, stack/XOR string recovery, prompt-injection scanning, and 6-plane cluster scoring deterministically *before* invoking any LLM.
- **Formal Epistemic & Anti-Hijack Gate:** Enforce a deterministic verifier between AI report synthesis and the immutable Stage 1 / IDA Pro 9.5 evidence ledgers.

---

## 2. Theoretical Model of the Global CTI & Dropper Hunter (`detection_patterns.json` v2.6)

### 2.1. Multi-Plane Telemetry & Weighted Scoring Model (26 Threat Clusters)

Let $T$ denote an inspected target (an HTTP/DOM capture, network endpoint, or binary/archive container) and let $\mathcal{C} = \{C_1, C_2, \dots, C_{26}\}$ denote the **26 threat-cluster profiles** formalized in Ruleset **v2.6**:
- **$\mathcal{C}_{\text{APT}}$ (8 Targeted Espionage Profiles):** `APT_CLUSTER_01` .. `APT_CLUSTER_08` (credential-harvesting gateways, `NTFS ADS` / path-traversal weaponized archives, `OOXML` remote-template injection, `SFX` token beacons, and modular post-exploitation loaders).
- **$\mathcal{C}_{\text{CRIME}}$ (18 FinCrime, Mobile RAT & TDS Profiles):** `CRIME_CLUSTER_01` .. `CRIME_CLUSTER_18` (multi-stage `BadPack` banking trojans, `VLESS/XTLS-REALITY` HVNC RATs, 4-layer `SVM1` native-VM bankers, commercial dual-use RAT/ransomware/wipers, `HCE NFC` APDU relay implants, behavioral serverless cloakers, `Keitaro`/token TDS grids, and P2P mule portals).

Each cluster $C_k \in \mathcal{C}$ evaluates weighted predicates across six orthogonal planes $\Pi = \{\pi_{\text{dom}}, \pi_{\text{url}}, \pi_{\text{hdr}}, \pi_{\text{dom\_js}}, \pi_{\text{net}}, \pi_{\text{bin}}\}$:

$$S_k(T) = \sum_{\pi \in \Pi} \sum_{r \in R_{k,\pi}} w(r) \cdot \mathbb{I}\big(r(T_\pi) = 1\big)$$

with calibrated decision boundaries:

$$\text{Severity}(S_k) = \begin{cases} \text{HIGH} & \text{if } S_k \ge 60 \\ \text{MEDIUM} & \text{if } 35 \le S_k < 60 \\ \text{LOW} & \text{if } 20 \le S_k < 35 \\ \text{BENIGN / UNMATCHED} & \text{if } S_k < 20 \end{cases}$$

### 2.2. In-Memory Cryptographic Certificate Pinning (`PKCS#7` & `APK Sig v2/v3`)

To defeat package-namespace spoofing and track actor signing-key reuse across polymorphic dropper campaigns without unpacking APKs to disk:
1. **Binary `AXML` Reconstruction:** Decodes `RES_XML_TYPE (0x0003)`, `RES_STRING_POOL_TYPE (0x0001)`, and root `<manifest>` `RES_XML_START_ELEMENT_TYPE (0x0102)` chunks directly from memory to recover declared package $P_{\text{decl}}$ and permission vector $\mathcal{P}_{\text{req}}$.
2. **Dual-Scheme X.509 Digest Extraction:** Extracts leaf/chain DER certificates from legacy `META-INF/*.RSA` (`PKCS#7 SignedData`) and `APK Sig Block 42` (`0x7109871a` v2 / `0xf05368c0` v3) containers, computing $\mathcal{F}(A) = \{\mathcal{H}_{\text{SHA256}}(c) : c \in \text{Certs}(A)\}$.
3. **Spoofing & Actor-Key Attribution:**
   - **Impersonation Proof:** If $P_{\text{decl}} \in \text{dom}(\Phi_{\text{official}})$ and $\mathcal{F}(A) \cap \Phi_{\text{official}}(P_{\text{decl}}) = \emptyset$, $A$ is deterministically flagged for **Publisher Certificate Spoofing**.
   - **Actor Campaign Linking:** Ruleset `v2.6` matches $\mathcal{F}(A)$ against known adversary signing-key sets $\Phi_{\text{actor}}(C_k)$ (`apk_cert_sha256`), immediately attributing re-themed droppers that share signing infrastructure.

### 2.3. Anti-DNS-Rebinding (`TOCTOU`) Socket Pinning

To eliminate Time-of-Check to Time-of-Use (`TOCTOU`) DNS rebinding during client-side gate inspection, hostname resolution and IP validation (`RFC1918`, loopback, link-local, multicast, and `100.64.0.0/10` CGNAT rejected) occur in a **single atomic pass**, binding the underlying `TCP`/`TLS` socket directly to the validated `(AF, sockaddr)` tuple while preserving the original `Host` header and TLS `SNI`.

---

## 3. Zero-Touch Anti-Canary Dead-Drop Interceptor (`v2.0`)

Let $M_t$ denote an encrypted dead-drop message posted at timestamp $t_{\text{pub}}$ on a public ledger (such as a `TON` smart contract or public `DoH TXT` record), yielding decrypted candidate endpoint $h = \text{Dec}_K(M_t)$ after `Ed25519` signature verification.

To guarantee **zero researcher attribution leakage** against adversary canary traps:

1. **Out-of-Band Pre-DNS Gate ($\mathcal{G}_{\text{NS}}$):** Before issuing any DNS query for domain $d(h)$, the interceptor queries the TLD registry's `RDAP` service and Certificate Transparency logs (`0` packets sent to $d$'s authoritative nameservers) to obtain $N(d) = \text{RDAP}_{\text{NS}}(d)$:
   $$\mathcal{G}_{\text{NS}}(d) = \begin{cases} \text{QUARANTINE}_{\text{GLUE}} & \text{if } \exists\, n \in N(d) : n = d \lor n \text{ ends with } .d \\ \text{ALLOW}_{\text{MULTI\_TENANT}} & \text{if } N(d) \neq \emptyset \land \forall\, n \in N(d),\; n \in \mathcal{N}_{\text{safe}} \\ \text{QUARANTINE}_{\text{CUSTOM}} & \text{otherwise} \end{cases}$$
   where $\mathcal{N}_{\text{safe}}$ is the verified set of multi-tenant authoritative DNS infrastructures (Cloudflare, Route53, Registrar-Servers, etc.) on which tenants cannot capture raw `UDP/TCP 53` packets.
2. **Protocol & Subnet Anonymity:** `QTYPE=NS` queries are never emitted. Permitted `QTYPE=A` recursive DoH queries enforce `edns_client_subnet=0.0.0.0/0` so zero bits of client network prefix traverse upstream resolvers.
3. **Two-Stage Anti-Timing Jitter:** When $t_{\text{now}} - t_{\text{pub}} < \Delta_{\text{fresh}}$ (`600 s`), Stage-1 alerting fires immediately at $T + 0\text{ s}$ using in-RAM decryption + `RDAP` + `CT`, while Stage-2 DoH `A` resolution (even when $\mathcal{G}_{\text{NS}}(d) = \text{ALLOW}_{\text{MULTI\_TENANT}}$) is delayed by uniform random jitter $\tau \sim \mathcal{U}(90\text{ s}, 300\text{ s})$ to defeat publication-to-lookup timing correlation.
4. **Passive Honeypot Scoring:** Resolved IPs are profiled exclusively via cached `Shodan InternetDB` records (`ports`, `cpes`, `tags`) without transmitting a single packet to the target host.

---

## 4. Multi-Stage *In-Vitro* Binary Dissection & Adversarial Input Defense (`v0.2.0`)

### 4.1. `ZIP BadPack` Recovery & Multi-Layer Container Triage
When an archive entry exhibits `flag_bits & 0x1` (`encrypted`) with `compress_type` $\in \{\text{STORED}, \text{DEFLATED}\}$ and candidate passwords fail, Stage 1 probes a masked header view (`flag_bits & ~0x1`) under bounded streaming CRC32 verification — cleanly recovering `BadPack`-protected `AndroidManifest.xml`, `classes*.dex`, and encrypted Stage-2 asset blobs while logging explicit tamper telemetry. Path components exceeding `120` bytes are deterministically truncated with an 8-hex `SHA-256` suffix, neutralizing `65,535`-byte filename buffer attacks.

### 4.2. Adversarial Indirect Prompt-Injection Defense
Let $\Sigma(B)$ denote the extracted UTF-8 and contiguous UTF-16LE string streams of untrusted artifact $B$. Stage 1 evaluates $\Sigma(B)$ against deterministic injection grammars $\mathcal{R}_{\text{PI}}$:
- **Instruction & Role Overrides** (`ignore/disregard/override previous/system instructions`);
- **Verdict Manipulation Directives** (`classify/mark as clean/benign`, `do not report C2/IOC`);
- **Chat-Template Delimiter Smuggling** (`<|im_start|>system`, `[INST]`, `</system_prompt>`);
- **Invisible Unicode Smuggling** (Bidirectional overrides `U+202A..U+202E`, `U+2066..U+2069`, and Unicode Tag characters `U+E0000..U+E007F`).

Invisible control/tag codepoints are stripped prior to prompt construction (`sanitize_untrusted_text_for_llm`), while any match in $\mathcal{R}_{\text{PI}}$ is recorded in `triage_report.json` as a `HIGH`-severity evasion indicator.

---

## 5. Formal Epistemic Verification Gate ($\mathcal{V}$)

Prior to report delivery, the deterministic verifier $\mathcal{V}(R, v, \mathcal{E}_1, \mathcal{E}_2) \in \{\text{PASS}, \text{REJECT}\}$ validates candidate report $R$ and verdict $v$ against Stage 1 ledger $\mathcal{E}_1$ and Stage 2 IDA Pro 9.5 session ledger $\mathcal{E}_2$:

1. **Cryptographic Digest Proof:** The primary artifact `SHA-256` must appear verbatim in $R$, and any mutated/near-miss 64-hex digest is rejected.
2. **IDA Session Proof:** If $|\mathcal{E}_2| = 0$, $R$ is rejected if it cites `sub_[0-9A-Fa-f]+` routines or Hex-Rays decompilation without an explicit non-execution disclaimer.
3. **Native Coverage Proof:** If $\mathcal{E}_1$ flags native code (`needs_ida = true`) and $|\mathcal{E}_2| = 0$, $v = \text{clean}$ is rejected.
4. **Anti-Prompt-Injection Verdict Proof:** If $\mathcal{E}_1$ contains non-empty `prompt_injection_indicators` and $v = \text{clean}$ without explicit disclosure of the prompt-injection indicator in $R$, $\mathcal{V}$ deterministically **rejects** $R$.
5. **Epistemic Completeness:** Every report must include explicit `[CONFIRMED]` / `[INFERRED]` / `[UNVERIFIED]` markers and a dedicated confidence-boundaries audit section.

---

## 6. Researcher Collaboration (`TLP:AMBER`)

Executable components (`ph4ntom-vitrum-core`), `v2.6` rulesets, and `Anti-Canary v2.0` dead-drop sensors are shared with verified researchers and CERTs:
- ✉️ **Email:** `owner@ph4ntom-rev.uz`
- 🌐 **Website:** [ph4ntom-rev.uz](https://ph4ntom-rev.uz/)
