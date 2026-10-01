"""Signed record bodies used by the release journal.

The incident files are merged evidence rather than an ordered log.  This
module defines the bytes covered by signatures.  Replay timing rules live in
``policy.py`` and release-history rules live in ``release_chain.py``.
"""

KEY_EVENT_DOMAIN = "key-event-v2"
WITNESS_RECEIPT_DOMAIN = "witness-receipt-v2"
CHECKPOINT_DOMAIN = "checkpoint-v2"
RELEASE_DOMAIN = "release-v2"

MANIFEST_ID_SCOPE = "single-position"
EQUIVOCATION_ACTION = "halt-channel"
CHECKPOINT_MATCH_REQUIRED = True


def key_event_body(row):
    """Return the exact body covered by the root signature."""
    if row["event_type"] == "ROTATE":
        fields = (
            "event_id", "event_type", "channel", "epoch", "key_id",
            "public_key_b64", "not_before", "created_at",
        )
    elif row["event_type"] == "REVOKE":
        fields = (
            "event_id", "event_type", "channel", "key_id",
            "effective_at", "created_at",
        )
    else:
        raise ValueError("unknown key event type")
    return {name: row[name] for name in fields}


def witness_receipt_body(row):
    """Return the exact body covered by a witness receipt signature."""
    fields = ("receipt_id", "kind", "object_digest", "witness_id", "signed_at")
    return {name: row[name] for name in fields}


def checkpoint_body(row):
    """Return the exact body covered by the checkpoint audit signature."""
    fields = ("checkpoint_id", "channel", "sequence", "chain_hash", "created_at")
    return {name: row[name] for name in fields}
