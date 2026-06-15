# Agentic Integrity Verification Specification (AIVS) v1.0

**Input Draft / Strawman for CG Discussion**  
**Published:** 18 May 2026  
**Latest editor's draft:** https://www.w3.org/community/aivs/  
**Contributed by:** Jinghan Zhang  
**Feedback:** [GitHub w3c-cg/aivs](https://github.com/swarmsync-ai/aivs-spec) ([pull requests](https://github.com/swarmsync-ai/aivs-spec/pulls), [new issue](https://github.com/swarmsync-ai/aivs-spec/issues/new), [open issues](https://github.com/swarmsync-ai/aivs-spec/issues))

---

## Status of This Document

This report was published by the [Agentic Integrity Verification Specification Community Group](https://www.w3.org/community/aivs/). It is not a W3C Standard nor is it on the W3C Standards Track. Please note that under the [W3C Community Contributor License Agreement (CLA)](https://www.w3.org/community/about/process/cla/) there is a limited opt-out and other conditions apply. Learn more about [W3C Community and Business Groups](https://www.w3.org/community/).

Copyright © 2026 the Contributors to the Agentic Integrity Verification Specification v1.0, published by the [Agentic Integrity Verification Specification Community Group](https://www.w3.org/community/aivs/) under the [W3C Community Contributor License Agreement (CLA)](https://www.w3.org/community/about/process/cla/). A human-readable [summary](https://www.w3.org/community/about/process/cla-deed/) is available.

*This document is contributed as an input strawman for the first AIVS CG meeting. Editorship and authorship of the group's official deliverables have not yet been agreed by the Community Group.*

---

## Abstract

This document specifies the Agentic Integrity Verification Specification (AIVS), a portable, self-verifiable archive format for cryptographic proof of AI agent sessions. An AIVS proof bundle is a structured archive containing a SHA-256 hash-chained audit log, an Ed25519 digital signature over the chain, a machine-readable manifest, and an embedded verification script. AIVS enables any party to independently verify that every action in an agent session is accounted for and unmodified, that no actions have been inserted, deleted, or reordered, and that the session was produced by a specific cryptographic identity.

---

## Table of Contents

1. [Introduction](#1-introduction)
   - 1.1 [Problem Statement](#11-problem-statement)
   - 1.2 [Design Goals](#12-design-goals)
   - 1.3 [Relationship to Existing Standards](#13-relationship-to-existing-standards)
   - 1.4 [Conformance](#14-conformance)
   - 1.5 [Terminology](#15-terminology)
   - 1.6 [Document Conventions](#16-document-conventions)
2. [Hash Chain Specification](#2-hash-chain-specification)
   - 2.1 [Row Hash Computation](#21-row-hash-computation)
   - 2.2 [Field Definitions](#22-field-definitions)
   - 2.3 [Chain Integrity Property](#23-chain-integrity-property)
   - 2.4 [Chain Hash Computation](#24-chain-hash-computation)
3. [Audit Row Schema](#3-audit-row-schema)
   - 3.1 [Row Format](#31-row-format)
   - 3.2 [Field Specifications](#32-field-specifications)
   - 3.3 [Sensitive Input Redaction](#33-sensitive-input-redaction)
4. [Cryptographic Identity and Attestation](#4-cryptographic-identity-and-attestation)
   - 4.1 [Ed25519 Signatures](#41-ed25519-signatures)
   - 4.2 [Identity Key Properties](#42-identity-key-properties)
   - 4.3 [Hardware-Backed TEE Attestation (Extension)](#43-hardware-backed-tee-attestation-extension)
5. [Proof Bundle Format](#5-proof-bundle-format)
   - 5.1 [Full Bundle Structure](#51-full-bundle-structure)
   - 5.2 [Manifest Schema](#52-manifest-schema)
   - 5.3 [AIVS-Micro](#53-aivs-micro)
6. [Verification Algorithm](#6-verification-algorithm)
   - 6.1 [Hash Chain Verification](#61-hash-chain-verification)
   - 6.2 [Signature Verification](#62-signature-verification)
7. [Use Cases and Reference Implementations](#7-use-cases-and-reference-implementations)
   - 7.1 [Regulatory Compliance](#71-regulatory-compliance)
   - 7.2 [Agent Accountability and Incident Investigation](#72-agent-accountability-and-incident-investigation)
   - 7.3 [Decentralized Trust Marketplaces](#73-decentralized-trust-marketplaces)
8. [Security Considerations](#8-security-considerations)
   - 8.1 [What AIVS Proves](#81-what-aivs-proves)
   - 8.2 [What AIVS Does Not Prove](#82-what-aivs-does-not-prove)
   - 8.3 [Threat Model](#83-threat-model)
9. [Privacy Considerations](#9-privacy-considerations)
10. [IANA Considerations](#10-iana-considerations)
    - 10.1 [Media Type Registration](#101-media-type-registration)
    - 10.2 [AIVS Action Type Registry](#102-aivs-action-type-registry)
11. [References](#11-references)
    - 11.1 [Normative References](#111-normative-references)
    - 11.2 [Informative References](#112-informative-references)
12. [Acknowledgements](#12-acknowledgements)
13. [Change Log](#13-change-log)

---

## 1. Introduction

### 1.1 Problem Statement

AI agents increasingly perform consequential actions on behalf of humans: navigating websites, filling forms, executing code, extracting data, and making financial decisions. Existing observability platforms log these actions but provide no cryptographic guarantees that the logs are complete, unmodified, or authentic.

Regulatory frameworks mandate audit trails but do not prescribe formats. The EU AI Act Article 19 requires automatically generated logs for high-risk AI systems but specifies no format. ISO/IEC 42001:2023 Annex A.6.2.8 requires event logging but defines no data structure. The NIST AI RMF requires documentation and audit trails but deliberately avoids prescribing formats. This creates a critical gap: organizations that must prove what their AI agents did have no standard way to produce, exchange, or verify that proof.

### 1.2 Design Goals

The AIVS format is designed to address the gap described above. The following table summarizes the core design goals and their rationale:

| Goal | Rationale |
| :--- | :--- |
| **Self-verifiable** | Proof bundles MUST be verifiable offline, without contacting any server, blockchain, or authority. |
| **Portable** | The proof MUST be contained within a single file that can be emailed, stored, or submitted to any system. |
| **Tamper-evident** | Modifying any action in the log MUST be cryptographically detectable. |
| **Zero dependencies** | Verification MUST require only the Python 3 standard library. |
| **Session-level** | The format MUST cover an entire session, defined as a bounded sequence of actions. |
| **Lightweight profile** | AIVS-Micro provides a minimal attestation for high-frequency monitoring contexts. |
| **Domain-agnostic** | The format MUST be applicable to any AI agent performing any action. |

### 1.3 Relationship to Existing Standards

AIVS is designed to complement, rather than replace, existing standards in the cryptographic provenance and identity space. The following table describes how AIVS relates to relevant specifications:

| Standard | Scope | AIVS Relationship |
| :--- | :--- | :--- |
| IETF draft-stone-aivs-00 [[IETF-AIVS-00]](#ref-ietf-aivs-00) | Originating proposal for AIVS | This document builds on the problem framing and format design introduced by Stone (2026) and proposes a concrete v1.0 wire format for CG discussion. |
| W3C Verifiable Credentials 2.0 [[VC-DATA-MODEL-2.0]](#ref-vc-data-model-2.0) | Identity claims | AIVS proof bundles MAY be wrapped as a `credentialSubject` within a Verifiable Credential. |
| IETF SCITT [[SCITT]](#ref-scitt) | Supply chain transparency | AIVS bundles MAY be registered as SCITT signed statements for append-only transparency logs. |
| C2PA v2.2 [[C2PA]](#ref-c2pa) | Media asset provenance | AIVS applies the same manifest-chain concept to agent actions rather than media assets. |
| Certificate Transparency RFC 6962 [[RFC6962]](#ref-rfc6962) | Append-only Merkle logs | The AIVS hash chain is a simplified, linear variant of the Merkle tree structure. |
| EU AI Act Art. 19 | Audit log requirements | AIVS provides a concrete, standardized format satisfying Article 19 obligations. |

### 1.4 Conformance

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [[RFC2119]](#ref-rfc2119).

A **conforming AIVS Producer** is a system that generates AIVS proof bundles. A conforming AIVS Producer MUST:
- Compute row hashes using the exact length-prefixed algorithm specified in [Section 2.1](#21-row-hash-computation).
- Ensure that the `prev_hash` field of the first audit row is set to a string of 64 zero characters (`0000...0000`).
- Include all required fields in each audit row as specified in [Section 3.2](#32-field-specifications).
- Generate a valid `manifest.json` as specified in [Section 5.2](#52-manifest-schema).

A **conforming AIVS Verifier** is a system that validates AIVS proof bundles. A conforming AIVS Verifier MUST:
- Implement the hash chain verification algorithm specified in [Section 6.1](#61-hash-chain-verification).
- Report a verification failure if any row hash does not match its computed value.
- Report a verification failure if the chain is not contiguous.

### 1.5 Terminology

The following terms are used throughout this specification:

**Session**
: A bounded sequence of actions performed by a single AI agent instance, identified by a unique `session_id`.

**Action**
: A single operation performed by the agent, such as navigating to a URL, executing a function call, or processing data.

**Audit Row**
: A JSON object recording one action with its inputs, outputs, timestamp, cost, and hash chain fields.

**Hash Chain**
: A sequence of audit rows where each row's hash depends on the cryptographic hash of the preceding row.

**Chain Hash**
: A single SHA-256 hash computed over all row hashes, serving as a fingerprint of the entire session.

**Proof Bundle**
: A `.tar.gz` archive containing the complete audit log, cryptographic signatures, manifest metadata, and a self-contained verification script.

**AIVS-Micro**
: A minimal JSON attestation format (~200 bytes) for single-action or API-level attestation contexts.

**Identity Key**
: An Ed25519 keypair used to sign the Chain Hash, establishing the cryptographic identity of the agent session's producer.

### 1.6 Document Conventions

Code blocks containing algorithms or data structures are normative unless explicitly marked as informative. Tables defining schema fields are normative. The interpretation of RFC 2119 keywords applies to all normative sections.

---

## 2. Hash Chain Specification

### 2.1 Row Hash Computation

Each audit row is identified by a deterministic SHA-256 hash. To prevent hash collisions and delimiter ambiguity, the hash input MUST be constructed using length-prefixed concatenation of the selected fields.

The hash input is constructed by concatenating the following nine fields in exact order:
1. `row_id` (integer converted to string)
2. `session_id` (string)
3. `action_type` (string)
4. `tool_name` (string)
5. `cost_cents` (integer converted to string)
6. `timestamp` (string)
7. `prev_hash` (string)
8. `input_hash` (string)
9. `output_hash` (string)

For each field, the concatenation format MUST be:
`len(field_bytes_as_4_byte_big_endian) || field_bytes`

Where `field_bytes` is the UTF-8 encoding of the field's string representation.

```
row_hash = SHA-256(
  len(row_id) || row_id ||
  len(session_id) || session_id ||
  len(action_type) || action_type ||
  len(tool_name) || tool_name ||
  len(cost_cents) || cost_cents ||
  len(timestamp) || timestamp ||
  len(prev_hash) || prev_hash ||
  len(input_hash) || input_hash ||
  len(output_hash) || output_hash
)
```

The resulting `row_hash` is represented as a lowercase hexadecimal string of exactly 64 characters.

### 2.2 Field Definitions

The following table defines the fields used in the row hash computation:

| Field | Type | Description |
| :--- | :--- | :--- |
| `row_id` | Integer | A monotonically increasing row identifier, beginning at 1. |
| `session_id` | String | A unique identifier for the session, RECOMMENDED to be a UUID v4. |
| `action_type` | String | A controlled vocabulary term for the category of action (see [Section 10](#10-iana-considerations)). |
| `tool_name` | String | The specific tool, function, or capability invoked. |
| `cost_cents` | Integer | The computational cost of the action in integer cents, or `0` if not applicable. |
| `timestamp` | String | The UTC timestamp of the action in ISO 8601 format. |
| `prev_hash` | String | The `row_hash` of the immediately preceding row. For the first row (`row_id = 1`), this MUST be a string of 64 zero characters. |
| `input_hash` | String | The SHA-256 hash of the JCS-normalized `input` field. |
| `output_hash` | String | The SHA-256 hash of the JCS-normalized `output` field. |

### 2.3 Chain Integrity Property

The hash chain possesses a critical integrity property: because each `row_hash` is computed over the `prev_hash` of the preceding row, any modification to a single audit row will produce a different hash for that row, which will in turn cause all subsequent row hashes to be invalid. This makes any tampering — whether modification, insertion, deletion, or reordering of rows — immediately detectable during verification.

### 2.4 Chain Hash Computation

After all audit rows have been recorded, a single Chain Hash is computed. To prevent cross-session collisions and version downgrade attacks, the Chain Hash MUST bind the `session_id` and the specification version.

```
chain_hash = SHA-256(
  "aivs/1.0" || session_id_bytes || row_count_as_4_byte_big_endian
  || row_hash_1_bytes || row_hash_2_bytes || ... || row_hash_n_bytes
)
```

Where `||` denotes concatenation of raw bytes (not hexadecimal strings). The `row_hash_i_bytes` are the 32-byte raw binary representation of each row hash. The resulting `chain_hash` is represented as a lowercase hexadecimal string of exactly 64 characters.

---

## 3. Audit Row Schema

### 3.1 Row Format

Each audit row MUST be serialized as a single-line JSON object. The audit log file (`audit_log.jsonl`) MUST be a newline-delimited JSON (NDJSON) file, where each line contains exactly one audit row.

To ensure deterministic serialization for storage and third-party diffing, each line MUST be serialized using the JSON Canonicalization Scheme (JCS) as defined in [[RFC8785]](#ref-rfc8785). Note that JCS is used here for the serialization of the entire row object, while the cryptographic `row_hash` is computed using the length-prefixed concatenation defined in [Section 2.1](#21-row-hash-computation).

### 3.2 Field Specifications

An audit row MUST contain the following fields to provide a complete and useful record:

| Field | Required | Description |
| :--- | :--- | :--- |
| `row_id` | REQUIRED | As defined in [Section 2.2](#22-field-definitions). |
| `session_id` | REQUIRED | As defined in [Section 2.2](#22-field-definitions). |
| `action_type` | REQUIRED | As defined in [Section 2.2](#22-field-definitions). |
| `tool_name` | REQUIRED | As defined in [Section 2.2](#22-field-definitions). |
| `cost_cents` | REQUIRED | As defined in [Section 2.2](#22-field-definitions). |
| `timestamp` | REQUIRED | As defined in [Section 2.2](#22-field-definitions). |
| `prev_hash` | REQUIRED | As defined in [Section 2.2](#22-field-definitions). |
| `input_hash` | REQUIRED | The SHA-256 hash of the JCS-normalized `input` field. If the input is empty or omitted, this MUST be the SHA-256 hash of an empty string (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`). |
| `output_hash` | REQUIRED | The SHA-256 hash of the JCS-normalized `output` field. If the output is empty or omitted, this MUST be the SHA-256 hash of an empty string. |
| `row_hash` | REQUIRED | The computed SHA-256 hash of this row, as defined in [Section 2.1](#21-row-hash-computation). |
| `input` | RECOMMENDED | The input provided to the tool or action. MAY be redacted as described in [Section 3.3](#33-sensitive-input-redaction). |
| `output` | RECOMMENDED | The output or result of the action. MAY be truncated for large outputs. |
| `model` | OPTIONAL | The identifier of the AI model used to generate this action, if applicable. |
| `agent_id` | OPTIONAL | A persistent identifier for the agent instance, distinct from the session identifier. |

### 3.3 Sensitive Input Redaction

To protect user privacy and comply with data protection regulations such as the GDPR, AIVS supports the redaction of sensitive inputs within the audit log. When a field is redacted, its value MUST be replaced with a JSON object of the following form:

```json
{
  "redacted": true,
  "hash": "sha256:<lowercase-hex-hash-of-original-value>"
}
```

Because `input_hash` and `output_hash` are REQUIRED fields in the audit row, the verifier can always recompute the `row_hash` even if the `input` or `output` fields are redacted or omitted from the final log. Auditors in possession of the original value can verify the commitment by recomputing the hash.

---

## 4. Cryptographic Identity and Attestation

### 4.1 Ed25519 Signatures

To establish the cryptographic identity of the proof bundle's producer, the Chain Hash SHOULD be signed using an Ed25519 digital signature [[RFC8032]](#ref-rfc8032). The signature payload MUST be a structured byte sequence to prevent cross-session replay attacks.

```
sig_payload = "aivs-sig/1.0" || session_id || chain_hash || created_at
```

The signature file (`session_sig.txt`) MUST contain the following fields, one per line:

```
session_id: <session_id>
chain_hash: <chain_hash>
created_at: <created_at>
signature: <base64url-encoded-ed25519-signature>
public_key: <base64url-encoded-ed25519-public-key>
```

The `created_at` value MUST equal the `created_at` field in `manifest.json`, and MUST be included verbatim in `session_sig.txt` as a signed-payload component, so that the verifier reconstructs the exact bytes that were signed.

### 4.2 Identity Key Properties

An AIVS Identity Key is an Ed25519 keypair. The specification deliberately does not mandate a Public Key Infrastructure (PKI) or certificate chain, as the goal is to enable self-verifiable proofs without external dependencies. The public key is self-asserted; the binding between a public key and a real-world identity is outside the scope of this specification and MAY be established through external mechanisms such as W3C Decentralized Identifiers [[DID-CORE]](#ref-did-core) or W3C Verifiable Credentials.

### 4.3 Hardware-Backed TEE Attestation (Extension)

While Ed25519 signatures establish the cryptographic identity of the bundle's producer, they do not provide guarantees about the execution environment in which the agent operated. As an OPTIONAL extension to the core AIVS specification, implementations MAY incorporate Trusted Execution Environment (TEE) attestations to provide hardware-backed execution guarantees.

When a TEE attestation is present, the AIVS Chain Hash SHOULD be bound to the attestation by embedding it in the TEE's attestation data field. For Intel SGX DCAP v3 quotes, this binding is achieved by computing:

```
report_data[0..31] = SHA-256(session_id || chain_hash || agent_manifest_hash)
```

and embedding this value in the `report_data` field of the SGX quote. This construction provides a cryptographic proof that a specific hardware enclave, identified by its `MRENCLAVE` measurement, produced the specific audit log identified by the Chain Hash.

---

## 5. Proof Bundle Format

### 5.1 Full Bundle Structure

A full AIVS proof bundle is a gzip-compressed tar archive with the following structure:

```
aivs_proof_<session_id>_<timestamp>.tar.gz
└── session_proof/
    ├── audit_log.jsonl      # SHA-256 hash-chained action log (NDJSON)
    ├── manifest.json        # Bundle metadata and chain summary
    ├── session_sig.txt      # Ed25519 signature over the chain hash (OPTIONAL)
    ├── public_key.pem       # Signer's Ed25519 public key (OPTIONAL)
    ├── verify.py            # Self-contained verifier (Python 3 stdlib only)
    └── attestation/         # TEE attestation files (OPTIONAL extension)
        └── <event_key>.json # SGX DCAP attestation record
```

### 5.2 Manifest Schema

The `manifest.json` file provides machine-readable metadata about the proof bundle. It MUST be a valid JSON object containing the following fields:

| Field | Required | Description |
| :--- | :--- | :--- |
| `aivs_version` | REQUIRED | The version of this specification (e.g., `"1.0"`). |
| `session_id` | REQUIRED | The unique identifier for the session. |
| `row_count` | REQUIRED | The total number of audit rows in the log. |
| `chain_hash` | REQUIRED | The final Chain Hash of the session. |
| `created_at` | REQUIRED | The UTC timestamp of bundle creation in ISO 8601 format. |
| `agent_id` | RECOMMENDED | A persistent identifier for the agent instance. |
| `model` | RECOMMENDED | The AI model identifier used during the session. |
| `signed` | RECOMMENDED | A boolean indicating whether a signature file is present. |

### 5.3 AIVS-Micro

For contexts where a full session bundle is impractical — such as continuous monitoring, API responses, or single-action attestations — AIVS defines a lightweight attestation format called AIVS-Micro. An AIVS-Micro proof is a JSON object of approximately 200 bytes containing the following fields:

| Field | Description |
| :--- | :--- |
| `v` | Schema version (e.g., `"micro.1"`). |
| `sid` | Session identifier. |
| `ts` | UTC timestamp in ISO 8601 format. |
| `ch` | The Chain Hash (or row hash for a single-action attestation). |
| `sig` | Base64url-encoded Ed25519 signature over the canonical payload. |
| `pk` | Base64url-encoded Ed25519 public key. |

The canonical payload for signing MUST be constructed using length-prefixed concatenation of the fields `v`, `sid`, `ts`, and `ch`, identical to the mechanism described in [Section 2.1](#21-row-hash-computation).

---

## 6. Verification Algorithm

### 6.1 Hash Chain Verification

Hash chain verification is REQUIRED for all conforming AIVS Verifiers. The algorithm proceeds as follows:

1. Parse the `audit_log.jsonl` file, reading each line as a JSON object.
2. For each row in sequence, recompute the `row_hash` using the length-prefixed algorithm in [Section 2.1](#21-row-hash-computation).
3. Compare the recomputed hash to the `row_hash` field stored in the row. If they differ, report a **TAMPERED** result and halt.
4. Verify that the `prev_hash` of the current row equals the `row_hash` of the preceding row. For the first row, verify that `prev_hash` is a string of 64 zero characters. If the chain is broken, report a **TAMPERED** result and halt.
5. After processing all rows, recompute the Chain Hash as specified in [Section 2.4](#24-chain-hash-computation) and compare it to the `chain_hash` field in `manifest.json`. If they differ, report a **TAMPERED** result and halt.
6. If all checks pass, report a **VERIFIED** result.

### 6.2 Signature Verification

Signature verification is OPTIONAL but RECOMMENDED when a `session_sig.txt` file is present. The algorithm proceeds as follows:

1. Read the `session_id`, `chain_hash`, `created_at`, and `signature` fields from `session_sig.txt`.
2. Read the public key from `public_key.pem`.
3. Reconstruct the `sig_payload` as defined in [Section 4.1](#41-ed25519-signatures).
4. Verify the Ed25519 signature over the `sig_payload` using the public key.
5. If the signature is invalid, report a **SIGNATURE INVALID** result.
6. If the signature is valid, report a **SIGNATURE VERIFIED** result.

---

## 7. Use Cases and Reference Implementations

### 7.1 Regulatory Compliance

A primary use case for AIVS is satisfying the audit trail requirements of emerging AI regulations. The EU AI Act Article 19 mandates that providers of high-risk AI systems ensure that their systems automatically generate logs, but prescribes no specific format. By generating AIVS proof bundles at the conclusion of each agent session, organizations can provide regulators and auditors with a standardized, verifiable, and portable record of agent behavior.

### 7.2 Agent Accountability and Incident Investigation

When an AI agent takes an unintended or harmful action, establishing an accurate and tamper-evident record of the agent's behavior is critical for accountability and remediation. AIVS proof bundles provide an immutable record that can be used to reconstruct the exact sequence of actions taken by an agent during an incident.

### 7.3 Decentralized Trust Marketplaces

AIVS principles are directly applicable to decentralized agent economies, where buyers and sellers of AI agent services must establish trust without relying on a central authority. In such ecosystems, the AIVS hash chain can be combined with hardware-backed TEE attestations and on-chain reputation systems to create a verifiable trust layer.

By anchoring the execution of the audit within a hardware enclave (such as Intel SGX) and binding the AIVS Chain Hash to the TEE attestation (as described in [Section 4.3](#43-hardware-backed-tee-attestation-extension)), marketplaces can provide cryptographic proof that an agent's actions were bounded by hardware isolation. This verifiable audit record can then serve as the foundation for dynamic reputation scoring. AgentLens [[AGENTLENS]](#ref-agentlens) is one such reference implementation.

---

## 8. Security Considerations

### 8.1 What AIVS Proves

When a proof bundle passes verification, the following properties are established:
- **Integrity**: No individual action in the log has been modified since the bundle was created.
- **Completeness**: No actions have been inserted into or deleted from the log.
- **Ordering**: The recorded sequence of actions has not been reordered.
- **Identity** (when a valid signature is present): The bundle was produced by the holder of the specific Ed25519 private key corresponding to the included public key.

### 8.2 What AIVS Does Not Prove

AIVS is a mechanism for tamper-evident logging and MUST NOT be interpreted as providing guarantees beyond those listed above. Specifically:
- **Truthfulness is not guaranteed.** AIVS does not prove that the recorded actions actually occurred as described. A malicious agent could fabricate the contents of audit rows before hashing them. Addressing this limitation requires secure execution environments, such as the TEE extension described in [Section 4.3](#43-hardware-backed-tee-attestation-extension).
- **Timeliness is not guaranteed.** Timestamps within the audit log are self-reported by the agent and are not independently verified. Implementations requiring trusted timestamps SHOULD layer RFC 3161 Trusted Timestamping over AIVS bundles.
- **Key authenticity is not guaranteed.** The binding between an Ed25519 public key and a real-world identity is outside the scope of this specification.

### 8.3 Threat Model

The primary threat addressed by AIVS is **post-hoc log tampering**: the modification of an audit log after the fact to conceal, alter, or fabricate agent actions. The hash chain construction ensures that any such tampering is detectable by any party with access to the proof bundle.

A secondary threat is **bundle forgery**: the creation of a fraudulent proof bundle attributed to a legitimate agent identity. The Ed25519 signature mechanism addresses this threat by binding the bundle to a specific cryptographic key. However, the security of this mechanism depends entirely on the secure management of the private key.

---

## 9. Privacy Considerations

Audit logs by their nature contain potentially sensitive information about user interactions with AI agents. Implementations MUST carefully consider the privacy implications of generating, storing, and sharing AIVS proof bundles.

The redaction mechanism described in [Section 3.3](#33-sensitive-input-redaction) provides a means to protect sensitive inputs while preserving the integrity of the hash chain. However, even redacted logs may contain metadata — such as action types, tool names, and timestamps — that could reveal sensitive information about a user's activities. Implementations SHOULD apply data minimization principles when determining which fields to include in the audit log.

---

## 10. IANA Considerations

### 10.1 Media Type Registration

This document requests the registration of the following media type:
- **Type name:** `application`
- **Subtype name:** `vnd.aivs-bundle`
- **Required parameters:** None
- **Optional parameters:** `version` (e.g., `version=1.0`)
- **Encoding considerations:** Binary (gzip-compressed tar archive)
- **Security considerations:** See [Section 8](#8-security-considerations).

### 10.2 AIVS Action Type Registry

This document establishes the "AIVS Action Type Registry". The initial values for this registry are:
- `tool_call`: Invocation of an external tool or function.
- `browser_navigate`: Navigation to a URL within a browser environment.
- `llm_inference`: Generation of text or data by a Large Language Model.
- `file_read`: Reading data from a file system.
- `file_write`: Writing data to a file system.

New registrations require a specification document and expert review.

---

## 11. References

### 11.1 Normative References

<a id="ref-rfc2119"></a>**[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels," BCP 14, RFC 2119, March 1997. Available: https://www.rfc-editor.org/rfc/rfc2119

<a id="ref-rfc8032"></a>**[RFC8032]** Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)," RFC 8032, January 2017. Available: https://www.rfc-editor.org/rfc/rfc8032

<a id="ref-rfc8785"></a>**[RFC8785]** Rundgren, A., et al., "JSON Canonicalization Scheme (JCS)," RFC 8785, June 2020. Available: https://www.rfc-editor.org/rfc/rfc8785

### 11.2 Informative References

<a id="ref-ietf-aivs-00"></a>**[IETF-AIVS-00]** Stone, B., "AIVS: Agentic Integrity Verification Standard," IETF Internet-Draft draft-stone-aivs-00, March 2026. Available: https://www.ietf.org/archive/id/draft-stone-aivs-00.html

<a id="ref-vc-data-model-2.0"></a>**[VC-DATA-MODEL-2.0]** Sporny, M., et al., "Verifiable Credentials Data Model v2.0," W3C Recommendation, May 2025. Available: https://www.w3.org/TR/vc-data-model-2.0/

<a id="ref-did-core"></a>**[DID-CORE]** Sporny, M., et al., "Decentralized Identifiers (DIDs) v1.0," W3C Recommendation, July 2022. Available: https://www.w3.org/TR/did-core/

<a id="ref-scitt"></a>**[SCITT]** Birkholz, A., et al., "The SCITT Architecture," IETF Internet-Draft, work in progress. Available: https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/

<a id="ref-c2pa"></a>**[C2PA]** Coalition for Content Provenance and Authenticity, "C2PA Technical Specification Version 2.2," 2024. Available: https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html

<a id="ref-rfc6962"></a>**[RFC6962]** Laurie, B., et al., "Certificate Transparency," RFC 6962, June 2013. Available: https://www.rfc-editor.org/rfc/rfc6962

<a id="ref-rfc3161"></a>**[RFC3161]** Adams, C., et al., "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)," RFC 3161, August 2001. Available: https://www.rfc-editor.org/rfc/rfc3161

<a id="ref-gdpr"></a>**[GDPR]** European Parliament, "Regulation (EU) 2016/679 (General Data Protection Regulation)," Official Journal of the European Union, 2016. Available: https://eur-lex.europa.eu/eli/reg/2016/679/oj

<a id="ref-agentlens"></a>**[AGENTLENS]** Zhang, J., "AgentLens: Verify Before You Hire — a decentralized, TEE-attested audit and marketplace protocol for AI agents," GitHub Repository, 2026. Available: https://github.com/ZhangJinHaHaHa/AgentLens

---

## 12. Acknowledgements

The editor would like to thank Ben Stone for his foundational work on the AIVS concept in the IETF draft-stone-aivs-00, which served as the originating proposal for this specification. Thanks also to Erik Newton for his efforts in organizing and driving the AIVS Community Group forward.

---

## 13. Change Log

- **Initial draft, May 2026**: First input strawman for CG discussion.
