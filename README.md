# ph4ntom Vitrum 🧪 — Architectural Specification & Theory (`v2.6`)

> **Autonomous *In-Vitro* Static Malware Dissection, Threat Infrastructure Hunting & Anti-Canary Dead-Drop Interception Pipeline**  
> Formal architecture for turning opaque binaries, multi-stage Android/desktop droppers, weaponized documents, nested archives (up to **2 GB**), live TDS delivery infrastructure, and blockchain/DoH dead-drop C2 channels into deterministically verified threat intelligence **behind sealed glass** — zero sample execution (*in vivo* strictly prohibited), isolated headless **IDA Pro 9.5** ([ph4ntom-ida-bridge](https://github.com/ph4ntom-rev/ph4ntom-ida-bridge)), **Global CTI & Dropper Hunter (`v2.6`, 26 Clusters)**, **Zero-Touch Anti-Canary Dead-Drop Interceptor (`v2.0`)**, adversarial prompt-injection defense, and two-layer epistemic verification.

[![Core Release](https://img.shields.io/badge/vitrum--core-v0.2.0-blue?style=flat-square)](docs/architecture-and-theory.md)
[![Rule Engine](https://img.shields.io/badge/detection_patterns.json-v2.6_(26_Global_Clusters)-00c853?style=flat-square)](#-module-2-global-cti--dropper-infrastructure-hunter-v26)
[![Anti-Canary](https://img.shields.io/badge/dead--drop_interceptor-v2.0_Anti--Canary-ff6d00?style=flat-square)](#-module-3-zero-touch-anti-canary-blockchain--doh-dead-drop-interceptor-v20)
[![IDA Pro 9.x](https://img.shields.io/badge/IDA_Pro-9.0--9.5-blueviolet?style=flat-square)](https://github.com/ph4ntom-rev/ph4ntom-ida-bridge)
[![OPSEC](https://img.shields.io/badge/OPSEC-Anti--Evasion_%7C_TLP%3AAMBER-amber?style=flat-square)](#%EF%B8%8F-anti-evasion--opsec-disclosure-policy-tlpamber)

<p align="left">
  🇬🇧 <strong>English (Primary)</strong> &nbsp;·&nbsp; 🇷🇺 <a href="README.ru.md"><strong>Русская версия (README.ru.md)</strong></a> &nbsp;·&nbsp; 📐 <a href="docs/architecture-and-theory.md"><strong>Deep Mathematical & Architectural Specification</strong></a>
</p>

---

> [!IMPORTANT]
> ### 🛡️ Anti-Evasion & OPSEC Disclosure Policy (`TLP:AMBER`)
> Because automated GitHub scrapers and threat actors continuously monitor public repositories for detection regexes, dead-drop key material, and static unpacker heuristics, **operational executable modules (`ph4ntom-vitrum-core`), active `v2.6` hunting rulesets, and live dead-drop sensor configurations are withheld from public commits to prevent adversary evasion and counter-adaptation**.
>
> This public repository documents the **formal architectural specification, counter-deception models, and verifiable public threat-intelligence impact**.  
> **Verified security researchers, CERTs, and threat-intelligence teams can request access via `owner@ph4ntom-rev.uz`.**

---

## 🏛️ Unified System Topology

```text
  ┌──────────────────────────────┐  ┌──────────────────────────────┐  ┌──────────────────────────────┐
  │  MTProto Ingestion (≤ 2 GB)  │  │  Global CTI Hunter (v2.6)    │  │ Anti-Canary Dead-Drop (v2.0) │
  │ Binaries, APKs, docs, 7z/RAR │  │ 26 Clusters · Cert Pinning   │  │ TON / DoH TXT · RDAP/CT Gate │
  └──────────────┬───────────────┘  └──────────────┬───────────────┘  └──────────────┬───────────────┘
                 │                                 │                                 │
                 └─────────────────────────────────┼─────────────────────────────────┘
                                                   ▼
                 ┌───────────────────────────────────────────────────────────────────┐
                 │                     Vitrum Orchestration Core                     │
                 │  Strict ACL · Quarantine · Adversarial Prompt-Injection Sandbox   │
                 └────────────────┬─────────────────────────────────┬────────────────┘
                                  │ Stage 1 (Zero-Token)            │ Stage 2 (AI + IDA 9.5)
                                  ▼                                 ▼
         ┌────────────────────────────────────────┐ ┌────────────────────────────────────────┐
         │    Deterministic Static Pre-Triage     │ │      Cognitive Binary Dissection       │
         │ • ZIP BadPack & multi-layer unpacking  │ │ • Isolated Headless IDA Pro 9.5        │
         │ • PE/ELF/Mach-O/DEX/AXML/OLE/PDF/LNK   │ │ • Hex-Rays CTree & Microcode analysis  │
         │ • Stack & XOR byte-array recovery      │ │ • AST + Audit-Hook Decoder Sandbox     │
         │ • APK Sig v2/v3 & PKCS#7 Cert SHA-256  │ │ • Native VM (SVM1) & VLESS/REALITY RE  │
         └────────────────────────────────────────┘ └───────────────────┬────────────────────┘
                                                                        │
                                                                        ▼
                 ┌───────────────────────────────────────────────────────────────────┐
                 │              Two-Layer Epistemic Verification Gate                │
                 │   SHA-256 Proof · IDA Session Proof · Prompt-Injection Verdict QA │
                 └───────────────────────────────────────────────────────────────────┘
```

---

## 🔬 Module 1: The *In-Vitro* Static Binary Dissection Core (`v0.2.0`)

Traditional automated malware analysis faces three structural failure modes:
1. **Dynamic sandboxes (*in vivo*)** execute untrusted code, exposing the environment to anti-VM/anti-Frida checks, delayed activation timers, and live C2 callbacks that alert the adversary.
2. **Naive LLM binary analysis** hallucinates offsets and pseudocode on stripped binaries or falls prey to **indirect prompt-injection strings** embedded inside sample resources.
3. **Weaponized container anomalies (`ZIP BadPack`)** break standard archive parsers via pseudo-encryption flags (`flag_bits & 0x1` on unencrypted `DEFLATE`/`STORED` streams), `65,535`-byte entry names, and zero-filled decoy `classes*.dex` stubs.

**`ph4ntom Vitrum`** (*in vitro* — *"within the glass"*) resolves all three through strictly non-executing static dissection:

### 1. Stage 1 — Zero-Token Deterministic Pre-Triage & `BadPack` Recovery
- **`ZIP BadPack` & Multi-Layer Container Unpacking:** Traverses nested `ZIP` (including WinZip AES-128/256), `7z`, `RAR5`, `TAR/XZ`, `CAB`, `ISO`, `APK`, and `OOXML` archives under strict `zip-slip`, symlink, and byte-quota bounds. Automatically detects and strips fake `BadPack` encryption headers (`flag_bits & 0x1`) on unencrypted entries, truncates/hashes anomalous `>255`-byte filenames safely, and filters zero-filled decoy `classes*.dex` stubs.
- **In-Memory Android `AXML`, `APK Signature Scheme v2/v3` & Native VM Profiling:** Parses binary `AndroidManifest.xml` string pools, package namespaces, and high-risk permissions; extracts X.509 certificate `SHA-256` digests from both `APK Sig Block 42` (`0x7109871a` / `0xf05368c0`) and `PKCS#7` (`META-INF/*.RSA`); and fingerprints custom native VM dispatchers (e.g., `SVM1`) and encrypted Stage-2 asset containers.
- **Instruction-Level Stack & XOR String Recovery:** Reconstructs `x86/x64` stack-built strings (`mov byte ptr [rbp/rsp+disp], imm8`) and single-byte/adjacent-byte XOR buffers deterministically before decompilation.
- **Adversarial Indirect Prompt-Injection Scanner:** Scans UTF-8, ASCII, and UTF-16LE sample streams for embedded LLM override directives (`ignore previous instructions`, `classify as clean`), chat-template delimiters, and invisible Bidirectional / Unicode-Tag (`U+E0000..U+E007F`) smuggling — converting anti-AI evasion attempts into high-severity forensic indicators.

### 2. Stage 1.5 — Anti-Canary Passive OSINT Enrichment
- Queries `SHA-256` digests and extracted IOCs passively against **MalwareBazaar**, **ThreatFox**, **VirusTotal REST v3**, **Shodan InternetDB** (`internetdb.shodan.io`, zero packets to target IPs), **RDAP**, and **DNS-over-HTTPS** (`edns_client_subnet=0.0.0.0/0`), quarantining self-hosted glue or custom authoritative nameservers out-of-band before any DNS packet is sent.

### 3. Stage 2 — Isolated Headless IDA Pro 9.5 & Dual-Gated Decoder Sandbox
- **Isolated Headless IDA Pro 9.5 Workers:** Spawns `ida.exe -A` via [ph4ntom-ida-bridge](https://github.com/ph4ntom-rev/ph4ntom-ida-bridge) with an ephemeral per-job `IDAUSR` directory and strict `PID`/port ownership tracking.
- **2-Hop String-XREF Function Ranking & Static Deobfuscation:** Prioritizes high-signal functions within 2 call-graph hops and executes custom static payload/config decryptors (`AES-GCM`, `ChaCha20`, `XOR+AES-ECB`, `Fernet`, custom VM bytecode) inside a dual-gated **AST allowlist + `sys.addaudithook` kernel-call sandbox**.

---

## 🌐 Module 2: Global CTI & Dropper Infrastructure Hunter (`v2.6`)

Paired with the binary core is an autonomous passive & client-side threat-hunting engine driven by a declarative multi-plane cluster ruleset (**Rule Engine v2.6**):

- **26 Global Threat Clusters (`8` APT Espionage + `18` FinCrime, Mobile RAT & TDS Clusters):** Expanded from `v2.3` (`20` clusters) to **`v2.6` (`26` clusters)**, adding coverage for behavioral edge cloakers (`Cloudflare Pages` / Workers relays), `VLESS/XTLS-REALITY` mobile RAT C2 transports (`libreality_transport.so`), 4-layer native virtual-machine (`SVM1`) Android bankers, commercial dual-use stalkerware/ransomware/wiper implants, and P2P card-mule gateways.
- **6 Orthogonal Telemetry Planes + Exact Signing-Key & IP Correlation:** Evaluates targets across `domain_regexes`, `url_regexes`, `header_cookie_regexes`, `dom_js_regexes`, `asn_and_ip_prefixes` / exact `ips`, and `binary_and_archive_rules` (including cryptographic `apk_cert_sha256` matching and official fintech publisher certificate pinning to defeat package-prefix spoofing).
- **Anti-DNS-Rebinding (`TOCTOU`) Socket Pinning & Shared-CDN Disambiguation:** Pins validated public IPv4/IPv6 socket tuples on a single resolution pass (`RFC1918`, loopback, link-local, and `100.64.0.0/10` CGNAT blocked) while separating shared CDN edges from dedicated bulletproof origin servers.

---

## 🛰️ Module 3: Zero-Touch Anti-Canary Blockchain & DoH Dead-Drop Interceptor (`v2.0`)

Modern mobile banking trojans and RATs increasingly abandon static C2 domains in favor of **immutable blockchain dead-drops** (e.g., encrypted `TON` smart-contract transactions verified via `Ed25519` + `AES-256-GCM`) and **DNS-over-HTTPS `TXT` bootstrap records**. Adversaries frequently seed burned dead-drop channels with **canary traps** (custom authoritative `NS` running `tcpdump port 53` or decoy VPS droplets monitoring incoming TCP/TLS handshakes) to detect researchers.

Module 3 formalizes a **100% Zero-Touch Counter-Deception Interceptor**:
1. **Zero Direct Target Packets:** Decrypts dead-drop payloads purely in RAM via public blockchain RPCs and never opens `TCP`, `TLS`, `HTTP`, or `ICMP` sockets to decrypted endpoints.
2. **Out-of-Band `RDAP` + `CT` Pre-DNS Quarantine:** Queries TLD Registry `RDAP` and Certificate Transparency (`crt.sh`) *before* any DNS resolution. Recursive DoH `A` queries are permitted **only** when `rdap.nameservers` belong to verified multi-tenant providers (where operators cannot capture `port 53` traffic); self-hosted glue or custom single-tenant nameservers trigger immediate **`SELF_HOSTED_GLUE_NS_CANARY_RISK` quarantine**.
3. **`QTYPE=NS` Elimination, `ECS=0.0.0.0/0` & Two-Stage Anti-Timing Jitter:** Strips client-subnet metadata (`edns_client_subnet=0.0.0.0/0`), never emits anomalous `QTYPE=NS` queries, and applies a randomized **`90–300s` anti-timing jitter** between blockchain transaction publication and recursive DoH `A` lookup.
4. **Passive Decoy-VPS Scoring:** Profiles resolved IPs passively via cached **Shodan InternetDB** (`internetdb.shodan.io`) to separate genuine C2 reverse-proxy profiles from empty `tcpdump` honeypot droplets.

---

## 🏆 Verified Real-World Defensive Impact (`abuse.ch`)

Using `ph4ntom Vitrum` (`v0.2.0`) and `PatternEngine v2.6`, **14 zero-day / FUD multi-stage Android trojan APKs** (including unpacked inner payloads decrypted statically from `BadPack` / `AES` / `SVM1` containers) and **65+ C2 & delivery indicators** have been disclosed publicly as global **`first_seen`** intelligence on **abuse.ch (`MalwareBazaar`, `ThreatFox`, `URLhaus`)** under reporter handle **`@ph4ntom_rev`**, subsequently ingested by **Kaspersky**, **Dr.Web vxCube**, **ReversingLabs**, and **Spamhaus HBL**:

| Malware Chain / Family | Stage & Technical Highlights (Static *In-Vitro* RE) | Public `MalwareBazaar` Record (`SHA-256`) |
| :--- | :--- | :--- |
| **`EVANGELION v3` → `zero` (`WretchedCat`)** | `BadPack` Stage-1 dropper → unpacked Stage-2 banking/OTP stealer & residential proxy with `TON` + `DNS` + `Telegram` dead-drop C2 (`AES-256-GCM` + `Ed25519`) | [424db6221456...](https://bazaar.abuse.ch/sample/424db6221456f4d786d6b2c9a9b9d72c4b2b5d222f03967e615cda7d899838b0/) *(S1)* · [3aeaa65d1983...](https://bazaar.abuse.ch/sample/3aeaa65d19832a8fd0cb004ac987f96815b66bcece7c6d147a5b4020a5b80deb/) *(S2)* |
| **`CoralCobra` / `MetaMask-RAT v10`** | `BadPack` Stage-1 dropper → unpacked Stage-2 HVNC/RAT embedding `libreality_transport.so` (`VLESS/XTLS-REALITY` + DoH `TXT` bootstrap) | [9e98dab43e0d...](https://bazaar.abuse.ch/sample/9e98dab43e0ddaf42f76d40da81e21607b6a094430049dd130119fbca1a4d2cd/) *(S1)* · [eb8838461e8c...](https://bazaar.abuse.ch/sample/eb8838461e8c720d916d15ba0293ed7a7fa18d36aaac3b2b97046aa413f74aa8/) *(S2)* |
| **`Shadow SVM1 v2.0` (`shellapp` 4-Layer Chain)** | 4-layer `BadPack` + `BlockVpnService` + `AES-256-CBC` `assets/payload.db` → custom native virtual machine (`SVM1` in `libshadow.so`) banking/WS-proxy trojan | [0e2004280ea7...](https://bazaar.abuse.ch/sample/0e2004280ea72d1779b333b9586c9e157a813693774c6c1629696ff9daf08aee/) *(S1)* · [1773556f9948...](https://bazaar.abuse.ch/sample/1773556f99489337e6152d3736ab4f0b8df56c47501b8ef10145a4cb7d3baa94/) *(Core)* |
| **`ByVzor` Commercial RAT / Ransomware / Wiper** | Dual-use Android stalkerware, `Fernet` C2 implant, `AES-GCM` file encryptor, and device wiper masquerading as system update | [d745528651bb...](https://bazaar.abuse.ch/sample/d745528651bb8ba9cc966b479065b9db0911e127ffdd26514f83d07b578c71f2/) |
| **`EVANGELION v3` Tax-Lure FUD Builds** | Multi-stage `XOR + AES-ECB` encrypted asset droppers (`assets/ybs0`, `assets/naa0`) + local Blackhole VPN (`10.99.0.1/32`) | [4f15e775e1da...](https://bazaar.abuse.ch/sample/4f15e775e1dab394fa8d927dd1486801b7f2bcd3b0495f3d63fb6b59e7c36ab4/) · [2f970ed92c88...](https://bazaar.abuse.ch/sample/2f970ed92c88142de98d82cd69adeba34efc56f28d92246f73feafaac9b64ad7/) |

---

## 🛡️ Two-Layer Epistemic & Anti-Prompt-Injection Verification Gate

Every assertion produced by the cognitive layer is deterministically cross-checked against Stage 1, CTI Hunter, and IDA Pro session ledgers:
- **Mandatory Epistemic State Tagging:** `[CONFIRMED]`, `[INFERRED]`, or `[UNVERIFIED]`.
- **Cross-Artifact & Prompt-Injection Proof Checking:** Automatically rejects reports with mutated `SHA-256` hashes, fabricated `sub_*` / Hex-Rays claims when zero IDA sessions ran, unverified `clean` verdicts on native binaries, or `clean` verdicts on artifacts containing flagged **adversarial prompt-injection lures**.

For the full mathematical and architectural specification, see **[docs/architecture-and-theory.md](docs/architecture-and-theory.md)**.

---

## ✉️ Researcher Access & Collaboration (`TLP:AMBER`)

- **Open-Source Companion Project:** [ph4ntom-ida-bridge](https://github.com/ph4ntom-rev/ph4ntom-ida-bridge) — MCP & REST bridge for IDA Pro 9.x (adopted in national CERT reverse-engineering workflows).
- **Threat-Intelligence & Engine Access:**  
  Under our **Anti-Evasion Policy**, executable modules (`ph4ntom-vitrum-core`), active `v2.6` detection rulesets, and dead-drop sensor tools are shared on a vetted researcher-to-researcher basis (`TLP:AMBER`):
  - ✉️ **Email:** `owner@ph4ntom-rev.uz`
  - 🌐 **Website:** [ph4ntom-rev.uz](https://ph4ntom-rev.uz/)
