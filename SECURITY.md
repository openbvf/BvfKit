# Security

## Reporting vulnerabilities

If you find a security issue, **do not open a public issue.** Instead:

- **GitHub Security Advisories** (preferred): [Submit a private advisory](https://github.com/openbvf/BvfKit/security/advisories/new)
- **Email**: bvf@newvoll.net

## Shared security model

BvfKit and [bvf](https://github.com/openbvf/bvf) (Rust) implement the same file format and cryptographic design. The threat model, cryptographic design, key management, and checks are documented in [bvf's SECURITY.md](https://github.com/openbvf/bvf/blob/main/SECURITY.md) and apply identically here.

## C interop safety

BvfKit calls libsodium C functions directly from Swift. Every source file painstakingly reviewed line-by-line by a human. Some ops abstracted to SafeCryptoHelpers.swift, one-offs in-line.
