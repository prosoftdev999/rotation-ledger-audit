# Release signing journal audit

A release-signing service was restored after a journal merge, and the incident records are no longer in causal order. The trust anchors survived, but the recovered evidence now mixes key changes, witness receipts, release records, manifest parts, and checkpoints from several replicas. I need one reproducible audit of the history this deployment would actually trust.

The incident inputs are under `/app/data`. The Python modules under `/app/service` are the deployed contract for this system. They define the canonical encoding, signature domains, manifest construction, time handling, quorum values, release-chain hashing, checkpoint behavior, and the policy constants used during replay. Treat those modules as authoritative and do not infer a different wire format or policy from the appearance of the JSON files.

Reconstruct the trusted release history from the recovered evidence. Input order is not meaningful. A record can be individually well-formed or correctly signed and still fail to become part of trusted history, so keep authentication/eligibility decisions separate from the final per-channel replay. The incident also contains conflicting evidence that must be handled according to the deployed policy rather than by picking an arbitrary winner.

Write the final result to `/app/audit.json`. It must be a JSON object with exactly these top-level keys:

- `trusted_release_ids`: release IDs that remain on a trusted channel history, sorted lexicographically.
- `rejected_release_ids`: every other release ID from the incident, sorted lexicographically.
- `equivocations`: objects with `channel`, integer `sequence`, and lexicographically sorted `release_ids`; sort the list by channel and sequence.
- `channel_heads`: one object per channel that has a trusted release, with `channel`, integer `sequence`, `release_id`, and lowercase hexadecimal `chain_hash`; sort by channel.
- `rotation_rejections`: rejected `ROTATE` event IDs, sorted lexicographically.
- `revocation_rejections`: rejected `REVOKE` event IDs, sorted lexicographically.
- `checkpoint_rejections`: checkpoint IDs that fail the checkpoint's own authentication/policy checks, sorted lexicographically.
- `summary`: an object containing integer `trusted_release_count`, `rejected_release_count`, `equivocation_count`, and `channels_with_head`.

Use the exact identifiers from the incident journals and ordinary JSON numbers for counts and sequence values. A release that is not part of the final trusted history belongs in `rejected_release_ids` even when its detached cryptographic checks succeed.

You have 14400 seconds to complete this task. Do not cheat by using online solutions or hints specific to this task.
