---
name: Security review note
about: Report non-sensitive security design concerns for public discussion.
title: "[SECURITY REVIEW]"
labels: Needs Review, Security
assignees: AtharvaMoves
type: Task

---

## Important

Do not disclose exploitable vulnerabilities publicly.

For private vulnerability reports, use the process in `SECURITY.md`.

## Category

Choose one:

- Cryptographic design
- Archive format / parser
- PQC / keyfile handling
- TimeCapsule / drand
- Desktop runtime / IPC
- CLI / packaging
- Documentation claim
- Other

## Concern

Describe the review concern without exploit details.

## Potential Impact

What could this affect if confirmed?

## References

Add standards, papers, documentation, or safe code references if relevant.

## Checklist

- [ ] This report does not include live exploit steps.
- [ ] This report does not include secrets, private keys, private `.avkkey` files, or sensitive user data.
- [ ] I will use `SECURITY.md` for private vulnerability disclosure if this becomes exploitable.
