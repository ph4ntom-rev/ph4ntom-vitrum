# ph4ntom Vitrum 🧪 — Architectural Specification & Theory

> **Autonomous *In-Vitro* Static Malware Dissection, Threat Infrastructure Hunting & IDA Pro 9.5 Pipeline**  
> Formal architecture for turning opaque binaries, scripts, weaponized documents, multi-layer archives (up to **2 GB**), and live phishing/dropper delivery infrastructure into deterministically verified threat intelligence **behind sealed glass** — zero sample execution (*in vivo* strictly prohibited), isolated headless **IDA Pro 9.5** ([ph4ntom-ida-bridge](https://github.com/ph4ntom-rev/ph4ntom-ida-bridge)), **Global CTI & Dropper Hunter (`cti_phishing_hunter.py` + `detection_patterns.json` v2.3)**, sandboxed static deobfuscation, and two-layer anti-hallucination verification.

[![Architecture](https://img.shields.io/badge/document-Architecture_%26_Theory-blue?style=flat-square)](docs/architecture-and-theory.md)
[![Rule Engine](https://img.shields.io/badge/detection_patterns.json-v2.3_(20_Global_Clusters)-00c853?style=flat-square)](#-module-2-global-cti--dropper-infrastructure-hunter-cti_phishing_hunterpy--detection_patternsjson-v23)
[![IDA Pro 9.x](https://img.shields.io/badge/IDA_Pro-9.0--9.5-blueviolet?style=flat-square)](https://github.com/ph4ntom-rev/ph4ntom-ida-bridge)
[![OPSEC](https://img.shields.io/badge/OPSEC-Anti--Evasion_%7C_TLP%3AAMBER-amber?style=flat-square)](#-anti-evasion--opsec-disclosure-policy)

<p align="left">
  🇬🇧 <strong>English (Primary)</strong> &nbsp;·&nbsp; 🇷🇺 <a href="README.ru.md"><strong>Русская версия (README.ru.md)</strong></a> &nbsp;·&nbsp; 📐 <a href="docs/architecture-and-theory.md"><strong>Deep Technical Specification</strong></a>
</p>

---

> [!IMPORTANT]
> ### 🛡️ Anti-Evasion & OPSEC Disclosure Policy (`TLP:AMBER`)
> Because automated GitHub scrapers and threat actors actively monitor public repositories for detection signatures and deobfuscation heuristics, **operational decoder modules and production `v2.3` hunting rulesets are withheld from public commits to prevent adversary evasion and counter-adaptation** (such as altering TDS cloaking parameters, rotating certificate-spoofing templates, or mutating packer structures against active rules).
>
> This public repository documents the **formal architectural specification and theoretical verification model**.  
> **Verified security researchers and threat-intelligence teams can request access via `owner@ph4ntom-rev.uz`.**

---

## 🏛️ Unified System Topology

```text
   ┌─────────────────────────────────────────┐   ┌─────────────────────────────────────────┐
   │   Encrypted MTProto Ingestion (≤ 2 GB)  │   │  Global CTI & Dropper Hunter (Passive)  │
   │  Binaries, droppers, docs, archives     │   │  cti_phishing_hunter.py + Ruleset v2.3  │
   └────────────────────┬────────────────────┘   └────────────────────┬────────────────────┘
                        │                                             │
                        │    Strict ACL & Quarantine Isolation        │
                        └──────────────────────┬──────────────────────┘
                                               ▼
               ┌──────────────────────────────────────────────────────────┐
               │                Vitrum Orchestration Core                 │
               │     Job Isolation  ·  Policy Engine  ·  State Machine    │
               └──────────────┬─────────────────────────────┬─────────────┘
                              │ Stage 1 (Zero-Token)        │ Stage 2 (AI + IDA 9.5)
                              ▼                             ▼
       ┌────────────────────────────────────┐   ┌────────────────────────────────────┐
       │   Deterministic Static Pre-Triage  │   │   Cognitive Binary Dissection      │
       │ • Recursive container extraction   │   │ • Isolated Headless IDA Pro 9.5    │
       │ • PE/ELF/Mach-O/DEX/OLE/PDF/LNK    │   │ • Hex-Rays CTree & Microcode pass  │
       │ • Stack & XOR byte-array recovery  │   │ • AST + Audit-Hook Decoder Sandbox │
       │ • AXML + APK v2/v3 Cert Pinning    │   │ • 2-Hop String-XREF Function Graph │
       └────────────────────────────────────┘   └─────────────────┬──────────────────┘
                                                                  │
                                                                  ▼
               ┌──────────────────────────────────────────────────────────┐
               │          Two-Layer Epistemic Verification Gate           │
               │  Cryptographic Hash Proof · IDA Session Proof · QA Gate  │
               └──────────────────────────────────────────────────────────┘
```

---

## 🔬 Module 1: The *In-Vitro* Static Binary Dissection Core

Traditional automated malware analysis faces a fundamental dilemma:
1. **Dynamic sandboxes (*in vivo*)** execute untrusted code, exposing the environment to sandbox-evasion triggers, time-bombs, anti-VM/anti-Frida checks, and active C2 callbacks that alert the adversary.
2. **Naive LLM binary analysis** suffers from severe hallucination when confronted with stripped symbols, custom control-flow obfuscation, or multi-stage encrypted payloads (`XOR + AES-ECB/GCM`).

**`ph4ntom Vitrum`** (*in vitro* — *"within the glass"*) resolves this by combining **strictly non-executing static dissection** with a **three-tier deterministic-cognitive pipeline**:

### 1. Stage 1 — Zero-Token Deterministic Pre-Triage
- **Hardened Recursive Container Unpacking:** Traverses nested archives (`ZIP` including WinZip AES-128/256, `7z`, `RAR5`, `TAR/XZ`, `CAB`, `ISO`) and compound formats (`APK/DEX`, `OOXML`, `OLE2`) under strict path-traversal, symlink, recursion-depth, and decompression-bomb quotas. Context-aware password harvesting correlates sibling text notes (`UTF-8` / `CP1251` / `CP866`) prior to inner-archive recursion.
- **Instruction-Level Stack & XOR String Recovery:** Scans raw executable sections for stack-constructed byte sequences (`mov byte ptr [rbp/rsp+disp], imm8`) and adjacent-byte / single-byte XOR loops, deterministically reconstructing obfuscated indicators before decompilation begins.
- **Structural Format Profiling:** Extracts section entropy profiles, RWX anomaly flags, TLS callbacks, overlays, Authenticode certificates, categorized import capability vectors, Office VBA streams, PDF action trees, and LNK/PowerShell payloads into an immutable ground-truth ledger.

### 2. Stage 1.5 — Zero-Leak Passive OSINT Enrichment
- Correlates cryptographic digests (`SHA-256`) and deterministically extracted network indicators passively against external threat-intelligence feeds (**VirusTotal REST v3**, **MalwareBazaar**, **ThreatFox**, **DNS-over-HTTPS**, **RDAP**) with zero sample byte uploads and strict RFC1918/loopback SSRF filtering.

### 3. Stage 2 — Isolated Headless IDA Pro 9.5 & Sandboxed Deobfuscation
- **Process & Workspace Isolation:** Spawns headless **IDA Pro 9.5** workers via [ph4ntom-ida-bridge](https://github.com/ph4ntom-rev/ph4ntom-ida-bridge) with an ephemeral `IDAUSR` environment and isolated `PID`/port lease so concurrent manual IDA Pro researcher sessions on the host are never touched.
- **2-Hop String-XREF Function Ranking:** Computes a proximity graph from high-signal strings and API imports across 2 call-graph hops to prioritize high-value target functions automatically.
- **AST + Runtime Audit-Hook Decoder Sandbox:** Custom static decryption routines execute inside a dual-gated Python sandbox combining static Abstract Syntax Tree (`AST`) whitelisting with runtime `sys.addaudithook` kernel-call interception — mathematically blocking process spawning, network sockets, registry access, and filesystem writes outside the isolated job directory.

---

## 🌐 Module 2: Global CTI & Dropper Infrastructure Hunter (`cti_phishing_hunter.py` & `detection_patterns.json` v2.3)

Operating alongside the binary dissection core is the autonomous **Global Threat Infrastructure & Dropper Hunter** — a zero-dependency passive and client-side telemetry engine paired with a declarative multi-vector cluster ruleset (**Rule Engine v2.3**).

### 1. Theoretical Architecture of `cti_phishing_hunter.py`
- **Multi-Source Passive Telemetry & Cloaking Resilience:** Ingests candidate domains and endpoints from Certificate Transparency (`CT`) streams, passive DNS/RDAP, and telemetry feeds while emulating mobile/desktop client profiles to expose commercial Traffic Distribution Systems (`TDS`), token-gated redirects, and PWA dropper storefronts.
- **Shared-CDN & Sinkhole Disambiguation:** Automatically distinguishes dedicated attacker infrastructure from shared cloud/CDN edges (`Cloudflare`, `Vercel`, `AWS`, `Fastly`, `Bunny CDN`) and parked/sinkholed domains, ensuring remediation recommendations never trigger collateral IP blocking on shared cloud ASNs.
- **In-Memory Binary & Weaponized Container Triage (Zero Execution):**
  - **Raw AXML & Multi-DEX Dissection:** Parses Android binary XML (`AndroidManifest.xml` string pools, package identifiers, service/receiver declarations, and high-risk permission vectors such as `BIND_ACCESSIBILITY_SERVICE`, `BIND_VPN_SERVICE`, `NFC`, `READ_SMS`, `REQUEST_INSTALL_PACKAGES`) and multi-DEX class/string tables purely in memory.
  - **Cryptographic Publisher Certificate Pinning (`PKCS#7` & `APK Signature Scheme v2/v3`):** Extracts raw ASN.1/DER X.509 signing certificates from both legacy `META-INF/*.RSA` blocks and modern APK Signing Block v2/v3 length-prefixed containers, computing `SHA-256` certificate fingerprints to detect **brand/package spoofing** (malicious droppers impersonating trusted financial, tech, or enterprise package namespaces with unverified signing keys).
  - **Weaponized Archive & Document Forensics:** Detects NTFS Alternate Data Stream (`ADS`) / path-traversal exploitation inside archives, remote template injection (`TargetMode="External"`) in OOXML documents, and embedded payload streams inside PDF containers.

### 2. Formal Taxonomy of `detection_patterns.json` (Rule Engine v2.3)
Version **2.3** of the declarative ruleset formalizes **20 global threat clusters** spanning two generic architectural classes:
- **Advanced Persistent Threat (APT) Espionage Clusters** (state-aligned credential harvesting, weaponized document/archive delivery, remote template injection, and custom C2 loaders);
- **Transnational FinCrime, Mobile Malware & TDS Clusters** (two-stage mobile banking trojans, commercial TDS cloaking gateways, fake app-store PWA loaders, HCE NFC relay implants, and session-hijacking phishing kits).

Each cluster $C_k$ is evaluated across **6 orthogonal telemetry planes**:
1. **`domain_regexes`** — Lexical and typosquatting grammars across gTLDs/ccTLDs.
2. **`url_regexes`** — TDS query parameters, signed token patterns, and C2 API routing paths.
3. **`header_cookie_regexes`** — Server fingerprints, TDS session cookies, and custom HTTP response headers.
4. **`dom_js_regexes`** — Client-side JavaScript bundle signatures, WebSocket/API exfiltration endpoints, and tracking pixel IDs.
5. **`asn_and_ip_prefixes`** — Known bulletproof hosting allocations, LIR prefixes, and dedicated C2 subnets.
6. **`binary_and_archive_rules`** — In-memory byte markers, DEX class/string patterns, AXML permission combinations, and archive exploitation indicators.

The engine computes an aggregate weighted risk score $S(T) = \sum_{i} w_i \cdot \mathbb{I}(r_i \text{ matches } T)$ against calibrated decision thresholds (`HIGH ≥ 60`, `MEDIUM ≥ 35`, `LOW ≥ 20`), outputting deterministic cluster attribution and defanged IOC packages ready for automated feed ingestion or Stage 2 IDA Pro 9.5 deep dissection.

---

## 🛡️ Two-Layer Epistemic Anti-Hallucination Gate

Every assertion produced by the cognitive layer is validated against the deterministic Stage 1 and CTI Hunter ledgers:
- **Mandatory Epistemic State Tagging:** `[CONFIRMED]` (proven by cryptographic hash, deterministic decoder, or IDA offset), `[INFERRED]` (structurally derived), or `[UNVERIFIED]`.
- **Cross-Artifact Proof Checking:** Automatically blocks reports with mutated `SHA-256` hashes, fabricated `sub_*` addresses when zero IDA sessions ran, or unverified `clean` verdicts on native binaries.

For the full mathematical and architectural breakdown, see **[docs/architecture-and-theory.md](docs/architecture-and-theory.md)**.

---

## ✉️ Researcher Access & Collaboration (`TLP:AMBER`)

- **Open-Source Companion Project:** [ph4ntom-ida-bridge](https://github.com/ph4ntom-rev/ph4ntom-ida-bridge) — MCP & REST bridge for IDA Pro 9.x.
- **Threat-Intelligence & Engine Access:**  
  Under our **Anti-Evasion Policy**, executable hunting modules and active `v2.3` detection signatures are shared exclusively on a vetted researcher-to-researcher basis (`TLP:AMBER`):
  - ✉️ **Email:** `owner@ph4ntom-rev.uz`
  - 🌐 **Website:** [ph4ntom-rev.uz](https://ph4ntom-rev.uz/)
