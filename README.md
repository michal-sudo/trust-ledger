# Dolvero trust ledger

Public mirror of the Dolvero verified-review ledger behind [dolvero.com/trust](https://dolvero.com/trust).

Every review on Dolvero is tied to a paid account, signed by the reviewer's own device (WebAuthn passkey, ECDSA P-256), written into an append-only ledger and anchored on three independent networks:

| Network | What is written | Where to look |
|---|---|---|
| Bitcoin | the daily Merkle root, via OpenTimestamps | `proofs/<day>.root.ots`, verify with `ots verify` |
| Base (Ethereum L2) | an EAS attestation per daily root, review and reply | [base.easscan.org](https://base.easscan.org), schema `0x0f2a83ff4bb975b827339152156d315ee01aa9965a51dcf02bde2823ca5a7f9f`, attester `0x97FAeCe478665b52D56510cD7a0DFD2c1Bb73E33` |
| Arweave | a permanent JSON copy of each root, review and reply | tag `App-Name: Dolvero-Trust`, wallet `vFhb7afURcnMc0FsiNy8PksRnEvd4x2W8562kATZvls` |

This repository is updated by a cron job on dolvero.com. Every change to the ledger is a commit, so the git history is a second, independent timeline.

## Files

- `trust-feed.json`: the full public ledger (reviews, replies, signatures, Merkle paths, daily roots, on-chain references). Same file as https://dolvero.com/trust-feed.json.
- `roots.json`: the daily roots with their Bitcoin block, Base attestation and Arweave id.
- `proofs/`: OpenTimestamps proofs (`.ots`) and the raw 32-byte roots they stamp.
- `verify.mjs`: recomputes one review's leaf and Merkle path and compares it with the sealed root.
- `watchdog.mjs`: checks the whole ledger (every sealed leaf, every root against Base and Arweave) and the chain of previous-review fingerprints. Exits non-zero on any mismatch. Runs daily in GitHub Actions; anyone can run it anywhere.
- `src/`: the hashing scheme (`integrity_ledger.php`), the passkey verification code (`trust_verify.php`) and the on-chain writer (`chain_cli.py`).

## Scheme

```
payload_sha = sha256(canonical_json(payload))         keys sorted recursively, no whitespace, UTF-8 unescaped
leaf        = sha256(0x00 || "dolvero.leaf.v1" || salt || payload_sha)
node        = sha256(0x01 || left || right)
tree        = depth 16, fixed size, padded with keyed dummy leaves; one root per UTC day, also on empty days
```

A review's leaf payload is `{v: 1, kind: "review", review: <signed payload>, signature: <passkey assertion>}`. The passkey challenge is the sha256 of the canonical review payload, so the signature binds the exact text.

Neither the root nor a Merkle path reveals how many records the tree holds.

## Run the checks

```
node verify.mjs                 # one review
node watchdog.mjs               # everything, exit 1 on mismatch
ots verify proofs/2026-10-30.root.ots
```

## What is never published

E-mail addresses, internal ids, IP addresses (country only), totals of a customer's accounts or payouts. Breach evidence is disclosed only next to the review it belongs to, with the signed rules, the forensic MT5 record and its own anchored proof.

MIT licence. Questions: michal@dolvero.com
