from codec import object_digest, sha256_hex

# Release-history contract.  These values are intentionally declarative:
# replay consumers are expected to enforce the cross-row invariant rather
# than call a pre-computed conflict predicate.
MANIFEST_ID_SCOPE = "global"
MANIFEST_POSITION_FIELDS = ("channel", "sequence")
MANIFEST_SINGLE_POSITION = True
DUPLICATE_EVIDENCE_SAME_POSITION_ALLOWED = True


def release_body(row):
    return {
        k: row[k]
        for k in [
            "release_id", "channel", "sequence", "created_at", "key_id",
            "manifest_id", "manifest_root", "prev_chain_hash",
        ]
    }


def release_digest(row):
    return object_digest("release-v2", release_body(row))


def chain_hash(prev_chain_hash, release_digest_hex):
    return sha256_hex(
        b"release-chain-v2\0"
        + bytes.fromhex(prev_chain_hash)
        + bytes.fromhex(release_digest_hex)
    )


def release_position(row):
    return row["channel"], int(row["sequence"])
