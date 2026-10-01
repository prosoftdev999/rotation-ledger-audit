# Rotation Ledger Audit

A cryptographic incident-reconstruction challenge for recovering the trusted history of a release-signing system from merged and out-of-order journal evidence.

The project models a release-signing service restored after an incident where journal records from multiple replicas were merged without preserving causal order.

Individual records may still be correctly encoded or cryptographically signed, but that does not automatically make them part of the final trusted release history.

The objective is to reconstruct the history that the deployed trust policy would actually accept.

## Overview

The incident evidence combines several kinds of records:

- signing-key rotations
- key revocations
- witness receipts
- release records
- manifest components
- channel histories
- cryptographic commitments
- checkpoints

These records must be reconciled using the actual service rules rather than the order in which the recovered JSON records appear.

A simplified reconstruction looks like:

```text
recovered journals
       ↓
canonical record decoding
       ↓
cryptographic verification
       ↓
key rotation / revocation state
       ↓
witness eligibility and quorum
       ↓
manifest validation
       ↓
release authentication
       ↓
release-chain reconstruction
       ↓
checkpoint enforcement
       ↓
trusted channel histories
```

## Repository Structure

```text
rotation-ledger-audit/
├── cheat/
├── environment/
├── solution/
├── tests/
├── instruction.md
└── task.toml
```

### `instruction.md`

Defines the incident-reconstruction task, required result fields, output location, and trust-history requirements.

### `environment/`

Contains the reproducible runtime, recovered incident data, and deployed service logic.

### `solution/`

Contains the reference reconstruction implementation.

### `tests/`

Contains the independent verifier.

### `task.toml`

Defines task metadata, resource limits, and verification configuration.

## Trust Reconstruction

The important distinction in this project is between:

```text
cryptographically valid
```

and:

```text
trusted by the reconstructed system history
```

A release can contain a valid signature and still be rejected because the signing key was not valid at that point in history, a required witness was unavailable, a checkpoint prevents the branch from continuing, or the release does not extend the accepted channel chain.

## Key Rotation

Signing keys change over time.

The audit must reconstruct which keys were trusted during each relevant interval.

Conceptually:

```text
key A active
    ↓
rotation event
    ↓
rotation authentication / witness checks
    ↓
key B becomes active
    ↓
later releases must satisfy key-B policy
```

A rotation record should not be accepted merely because it exists.

Its authentication, timing, witnesses, and surrounding trust state must also satisfy the deployed policy.

## Revocation

Revocation changes whether a key or witness remains eligible.

This is especially important around exact event boundaries.

For example:

```text
before revocation → identity may be eligible
at/after revocation → policy may reject its contribution
```

The deployed service semantics define the exact boundary behavior.

## Witness Quorum

Some security events require witness approval.

Correct processing may involve weighted witness contributions rather than simply counting signatures.

Therefore:

```text
number of witnesses
```

is not necessarily equivalent to:

```text
accepted witness weight
```

Revoked, ineligible, duplicated, or otherwise invalid witnesses must not contribute incorrectly to quorum.

## Manifest Integrity

A release can commit to a structured manifest rather than just a flat list of files.

Manifest validation must preserve the deployed canonicalization and construction rules.

Changing ordering, encoding, or commitment construction can produce a different cryptographic result even when the visible files appear equivalent.

## Release Signatures

Each release must be authenticated against the key state that was valid for that historical point.

The audit should keep two questions separate:

1. Is this release cryptographically authentic?
2. Does it belong to the final trusted channel history?

Passing the first test does not guarantee the second.

## Release Chain

Trusted releases form a history.

A release may contain a reference or cryptographic commitment to its predecessor:

```text
release 1
   ↓
release 2
   ↓
release 3
   ↓
release 4
```

If chain continuity fails, later records cannot simply be accepted because their own signatures are valid.

The historical relationship between releases matters.

## Equivocation

The incident can contain conflicting releases for the same logical channel position.

Conceptually:

```text
channel: alpha
sequence: 42

release-X
release-Y
```

If both claim the same position, the audit must apply the deployed policy rather than arbitrarily choosing whichever record appears first.

Detected conflicts are reported explicitly in the final artifact.

## Checkpoints

Checkpoints constrain which histories can remain trusted.

A checkpoint may authenticate:

- a channel state
- a sequence boundary
- a chain commitment
- witness approval
- other policy-defined state

An otherwise plausible branch can therefore be excluded because it conflicts with an accepted checkpoint.

## Out-of-Order Evidence

Input ordering is not authoritative.

The recovered evidence may combine records from multiple replicas and different stages of the signing process.

A solver must reconstruct causal and trust relationships from the record contents and deployed service contract rather than relying on:

```text
file order
JSON order
journal order
lexicographic identifier order
```

## Output

The final audit is written to:

```text
/app/audit.json
```

The report contains the reconstructed trust result, including:

- trusted release IDs
- rejected release IDs
- equivocations
- trusted channel heads
- rejected key rotations
- rejected revocations
- rejected checkpoints
- aggregate summary counts

See `instruction.md` for the exact schema, ordering, and representation requirements. :chatgpt-content-reference{index="3"}

## Security Properties

The reconstruction exercises several security concepts:

- digital signatures
- key lifecycle management
- rotation and revocation
- weighted trust
- quorum verification
- canonical serialization
- cryptographic commitments
- SHA-256 hashing
- release-chain integrity
- equivocation detection
- checkpoint enforcement
- transparency-style audit history

## Why the Task Is Challenging

Several records can be individually valid while still being mutually incompatible.

For example:

```text
valid release signature
        +
valid manifest
        +
valid witness receipt
```

does not necessarily imply:

```text
trusted release
```

The result depends on the complete historical state surrounding those records.

The reconstruction must therefore combine cryptography with state-machine replay and causal history.

## Design Principle

The task should be approached as a trust-history reconstruction problem rather than as a collection of independent signature checks.

The authoritative result comes from applying the deployed service contract consistently across the entire recovered journal.

## License

No license is currently specified.
