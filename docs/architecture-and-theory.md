# Architectural & Theoretical Specification: `ph4ntom Vitrum` & Global CTI Hunter (`v2.3`)

> **Anti-Evasion & OPSEC Notice (`TLP:AMBER`):**  
> This document details the formal architecture, security invariants, and mathematical models underlying the `ph4ntom Vitrum` *in-vitro* binary dissection core and the `cti_phishing_hunter.py` / `detection_patterns.json` (**v2.3**) global threat-hunting engine.  
> To prevent threat actors from testing dropper builds and TDS cloaking gates against live detection heuristics, executable modules and production `v2.3` signatures are withheld from public commits. **Verified security researchers can request access at `owner@ph4ntom-rev.uz`.**

---

## 1. Design Problem & Formal Objectives

Modern APT espionage and transnational cybercrime operations combine:
1. **Cloaked delivery infrastructure** — commercial Traffic Distribution Systems (`TDS`), token-gated redirects, shared-CDN fronts, and Progressive Web App (`PWA`) dropper storefronts that hide payloads from naive crawlers.
2. **Multi-layer encrypted packaging & publisher spoofing** — nested archives, custom `XOR + AES-ECB/GCM` resource containers, steganographic payload trailers appended after EOF markers, dynamic DEX/PE loaders, and spoofed package namespaces imitating trusted applications.
3. **Control-flow & string obfuscation** — stack-constructed byte arrays, thousands of opaque predicate loops, and encrypted import tables coupled with active anti-sandbox / anti-Frida traps.

### Core Invariants of the Architecture
- **Strict *In-Vitro* Invariant:** Extract maximum structural, cryptographic, and infrastructure truth from untrusted binaries (`≤ 2 GB`) and delivery gateways with **zero instruction execution** of the sample on the host CPU.
- **Deterministic Pre-Cognitive Filtering:** Perform all exhaustive byte-level parsing, container unpacking, certificate pinning, stack/XOR string recovery, and 6-plane cluster scoring deterministically before invoking any AI reasoning model.
- **Isolated Headless Binary Dissection:** Drive headless **IDA Pro 9.5** sessions via [ph4ntom-ida-bridge](https://github.com/ph4ntom-rev/ph4ntom-ida-bridge) under strict `PID` and `IDAUSR` isolation.
- **Formal Anti-Hallucination Guarantee:** Enforce a deterministic verification gate between the AI synthesis layer and the immutable evidence ledger.

---

## 2. Theoretical Model of the Global CTI & Dropper Hunter (`cti_phishing_hunter.py` & `detection_patterns.json` v2.3)

### 2.1. Multi-Plane Telemetry & Weighted Scoring Model (Ruleset v2.3)

Let $T$ denote an inspected target (a network endpoint, HTTP/DOM capture, or downloaded binary/archive artifact) and let $\mathcal{C} = \{C_1, C_2, \dots, C_{20}\}$ denote the 20 generic threat-cluster profiles defined in `detection_patterns.json` (**version 2.3**), partitioned into two abstract classes (specific actor and malware family identifiers are omitted for operational security):
- **$\mathcal{C}_{\text{APT}}$ (8 Targeted Espionage Profiles):** `APT_CLUSTER_01` .. `APT_CLUSTER_08` (covering credential harvesting gateways, OOXML remote-template injection, weaponized archive loaders, and modular post-exploitation C2 profiles).
- **$\mathcal{C}_{\text{CRIME}}$ (12 FinCrime, Mobile Dropper & TDS Profiles):** `CRIME_CLUSTER_01` .. `CRIME_CLUSTER_12` (covering multi-stage mobile banking droppers, token-gated TDS cloaking clusters, cloud-hosted payment phishing funnels, SEO/MFA doorway farms, messenger session-hijack kits, PWA fake-store loaders, steganographic DEX loaders, and HCE NFC APDU relay implants).

Each cluster $C_k \in \mathcal{C}$ defines weighted indicator rules across six orthogonal observation planes $\Pi = \{\pi_{\text{dom}}, \pi_{\text{url}}, \pi_{\text{hdr}}, \pi_{\text{dom\_js}}, \pi_{\text{asn}}, \pi_{\text{bin}}\}$:

$$S_k(T) = \sum_{\pi \in \Pi} \sum_{r \in R_{k,\pi}} w(r) \cdot \mathbb{I}\big(r(T_\pi) = 1\big)$$

where $w(r) \in \mathbb{Z}^+$ is the calibrated evidentiary weight of rule $r$, and severity classification is governed by global thresholds:

$$\text{Severity}(S_k) = \begin{cases} \text{HIGH} & \text{if } S_k \ge 60 \\ \text{MEDIUM} & \text{if } 35 \le S_k < 60 \\ \text{LOW} & \text{if } 20 \le S_k < 35 \\ \text{BENIGN / UNMATCHED} & \text{if } S_k < 20 \end{cases}$$

### 2.2. In-Memory Cryptographic Certificate Pinning & Spoofing Detection

To defeat package-namespace spoofing in mobile droppers and security-classifier bypasses without executing or unpacking APKs to disk, `cti_phishing_hunter.py` implements an in-memory cryptographic verifier:

1. **Binary `AXML` String-Pool & Tree Reconstruction:** Parses little-endian chunk headers (`RES_XML_TYPE = 0x0003`, `RES_STRING_POOL_TYPE = 0x0001`, `RES_XML_START_ELEMENT_TYPE = 0x0102`) directly from the ZIP stream of `AndroidManifest.xml` to extract the declared `package` identifier $P_{\text{decl}}$ and requested permission set $\mathcal{P}_{\text{req}}$.
2. **Dual-Scheme X.509 Certificate Fingerprint Extraction:**
   - **Legacy JAR Signing (`PKCS#7`):** Parses ASN.1/DER `SignedData` structures inside `META-INF/*.RSA` / `*.DSA` / `*.EC` to extract leaf and intermediate X.509 certificates.
   - **Modern `APK Signature Scheme v2 / v3`:** Locates the `APK Sig Block 42` magic footer immediately preceding the ZIP Central Directory, traverses ID-value pairs for block IDs `0x7109871a` (v2) and `0xf05368c0` (v3), and extracts the length-prefixed DER certificate buffers.
3. **Pinning Verification Equation:** Given a map of pinned official publisher certificate digests $\Phi(P) \subset \{0,1\}^{256}$ for protected package namespaces:
   $$\text{Spoofed}(A) \iff P_{\text{decl}} \in \text{dom}(\Phi) \;\land\; \mathcal{H}_{\text{SHA256}}(\text{Cert}(A)) \cap \Phi(P_{\text{decl}}) = \emptyset$$
   Any artifact satisfying $\text{Spoofed}(A)$ is deterministically flagged as a **High-Severity Publisher Impersonation Dropper**, regardless of benign-looking package prefixes.

### 2.3. SSRF-Safe Network Inspection & Shared-CDN Disambiguation

- **Pre-Connection IP Validation:** Every candidate hostname is resolved and validated prior to socket connection, rejecting loopback (`127.0.0.0/8`, `::1`), RFC1918 private ranges, link-local (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), and multicast addresses.
- **CDN Edge Awareness:** Resolved IPs and HTTP response headers are checked against shared cloud/CDN fingerprints (`Cloudflare`, `Vercel`, `Amazon CloudFront/AWS`, `Fastly`, `Akamai`). When a malicious gateway resides on a shared CDN edge, the engine enforces **domain/URL-level filtering recommendations** rather than IP-level blackholing.
- **Weaponized Container Forensics:** Scans ingested archives for NTFS Alternate Data Stream (`:` stream) injection, relative path traversal (`../`), OOXML external relationship hijacking (`TargetMode="External"` in `.rels`), and high-entropy encrypted DEX/native payloads.

---

## 3. Multi-Stage *In-Vitro* Binary Dissection Pipeline (`ph4ntom Vitrum` Core)

### 3.1. Stage 1 — Deterministic Structural & Instruction Pre-Triage

1. **Bounded Recursive Unpacking:**
   - Unpacks nested containers (`ZIP`, WinZip `AES-128/256`, `7z`, `RAR5`, `TAR/GZ/BZ2/XZ`, `CAB`, `ISO`, `APK/JAR`, `OOXML`) under strict recursion depth $D_{\max}$, file count $N_{\max}$, and uncompressed byte quota $B_{\max}$ bounds.
2. **Instruction-Pattern Stack & XOR Recovery:**
   - Scans executable sections (`.text`, `CODE`) for contiguous immediate-to-stack store instructions (`x86/x64` `mov byte ptr [rbp/rsp+disp], imm8`) and rolling/single-byte XOR loops, recovering obfuscated C2 strings and keys before decompilation.
3. **Format-Specific Static Analyzers:**
   - Extracts `PE/PE32+`, `ELF`, `Mach-O`, `DEX`, `Office OLE2/VBA`, `PDF`, `.lnk`, and `PowerShell -EncodedCommand` structural profiles into an immutable JSON evidence ledger $\mathcal{E}_1$.

### 3.2. Stage 2 — Headless IDA Pro 9.5 & Dual-Gated Decoder Sandbox

1. **Ephemeral Headless IDA Pro 9.5 Lease:**
   - Launches `ida.exe -A` with an isolated per-job `IDAUSR` directory and dedicated local `ph4ntom-ida-bridge` port, tracking exact child `PID` ownership so manual IDA sessions on the host are never touched.
2. **2-Hop String-XREF Call-Graph Ranking:**
   - Ranks user functions within 2 call-graph hops of high-signal strings and sensitive API imports to focus Hex-Rays CTree/Microcode decompilation on the core payload logic.
3. **Dual-Gated Static Decoder Sandbox (`AST` + `sys.addaudithook`):**
   - **Layer A (Static AST Gate):** Parses synthesized Python decryption scripts into an Abstract Syntax Tree and rejects unauthorized imports (`subprocess`, `socket`, `ctypes`, `winreg`, `urllib`, `http`) or dynamic evaluation primitives (`eval`, `exec`, `__import__`).
   - **Layer B (Runtime Kernel Audit Hook):** Installs a non-removable `sys.addaudithook` monitor that blocks process creation, network sockets, registry access, and any filesystem write outside the job's isolated `decoded/` directory.

---

## 4. Formal Epistemic Verification Gate

Prior to report emission, the deterministic verifier $\mathcal{V}(R, \mathcal{E}_1, \mathcal{E}_2) \in \{\text{PASS}, \text{REJECT}\}$ checks candidate report $R$ against Stage 1 ledger $\mathcal{E}_1$ and Stage 2 IDA Pro session ledger $\mathcal{E}_2$:

1. **Hash Integrity Proof:** Every 64-character hexadecimal `SHA-256` digest in $R$ must exist verbatim in $\mathcal{E}_1 \cup \mathcal{E}_2$.
2. **Disassembly Session Proof:** If $|\mathcal{E}_2| = 0$, $R$ is rejected if it references `sub_[0-9A-Fa-f]+` routines, virtual tables, or Hex-Rays decompilation claims.
3. **Mandatory Coverage Proof:** If $\mathcal{E}_1$ contains native executables and $|\mathcal{E}_2| = 0$, $R$ cannot issue a `clean` / `benign` verdict.
4. **Epistemic State Completeness:** All claims must carry explicit `[CONFIRMED]`, `[INFERRED]`, or `[UNVERIFIED]` tags.

---

## 5. Anti-Evasion Disclosure & Researcher Access (`TLP:AMBER`)

To prevent adversary counter-adaptation against active `v2.3` detection heuristics and static deobfuscation passes, executable components are shared exclusively with vetted researchers:
- ✉️ **Email:** `owner@ph4ntom-rev.uz`
- 🌐 **Website:** [ph4ntom-rev.uz](https://ph4ntom-rev.uz/)
