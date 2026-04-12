# Canonicalization Specification

Status: Mandatory proof artifact for deterministic validation.

## 1) Scope

This specification defines canonicalization rules used by trust-bearing signing and verification paths.

- `canonical_payload_bytes` for signed messages MUST be deterministic and byte-stable.
- Any deviation from these rules is non-compliant and MUST fail closed.

## 2) Canonical JSON Rules

For JSON payloads, canonicalization is:

1. UTF-8 encoding.
2. Object keys sorted lexicographically at every depth.
3. No insignificant whitespace.
4. No duplicate keys.
5. Integer-only numeric representation in trust-bearing signed configuration.
6. Arrays preserve declared element order.

Result: same semantic object => same canonical byte sequence.

## 3) Canonical Protobuf Rules

For protobuf payloads, canonicalization is:

1. Deterministic protobuf serialization.
2. No unknown fields accepted in trust-bearing verification.
3. No alternate binary forms for the same message class.

Result: same message content => same canonical bytes.

## 4) Signing Input Construction

Signing input is defined exactly as:

`signing_input = signing_context || SHA-256(canonical_payload_bytes)`

No alternate construction is allowed.

## 5) Proof Obligations

The test suite MUST prove all of the following:

1. Different struct or map insertion order yields identical canonical bytes.
2. Signing context registry in implementation equals PRD registry.
3. Cross-language parity: canonicalization and signing-input derivation are byte-exact.
4. Any missing or extra signing context entry is a build failure.

## 6) Fail Conditions

- Missing canonicalization definition: `UNSPECIFIED_BY_PRD`
- Canonicalization/signing mismatch vs PRD: `PROJECTION_DRIFT`
- Missing required proof tests: `BUILD_FAIL`
