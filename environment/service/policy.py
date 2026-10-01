"""Policy primitives for the recovered signing journal.

The incident files are merged evidence, not an ordered event stream.  This
module supplies the rules that are not encoded directly in a signed record.
The audit still has to combine those rules with the record bodies in
``journal.py`` and the history functions in ``release_chain.py``.
"""

from datetime import datetime, timezone

ROTATION_WITNESS_WEIGHT = 5
CHECKPOINT_WITNESS_WEIGHT = 6
RECEIPT_MAX_SKEW_SECONDS = 900
CHECKPOINT_INTERVAL = 20
ZERO_CHAIN_HASH = "0" * 64

# Event classes use different witness policy.  Root authentication is common
# to both and is defined by the key-event signing body in journal.py.
KEY_EVENT_RECEIPTS = {
    "ROTATE": ("rotation", ROTATION_WITNESS_WEIGHT),
    "REVOKE": None,
}

# A release is bound to the newest rotation that has become effective for its
# channel.  Revocation becomes effective on its timestamp, not after it.
ROTATION_SELECTION = "latest-started"
REVOCATION_BOUNDARY = "inclusive"

# Manifest ids are global.  Seeing the same id at more than one release
# position invalidates every otherwise-eligible use of that id; duplicate
# evidence for one position is harmless.
MANIFEST_BINDING_SCOPE = "global"
MANIFEST_CONFLICT_ACTION = "reject-all-uses"

# Checkpoint rejection is about the checkpoint's own authentication.  A valid
# checkpoint whose commitment does not match the reconstructed chain simply
# cannot satisfy a replay gate.
CHECKPOINT_RECEIPT_KIND = "checkpoint"
CHECKPOINT_REJECTION_SCOPE = ("root-signature", "witness-quorum")
CHECKPOINT_GATE_MATCH = ("channel", "sequence", "chain_hash")

# Channel history is contiguous.  A missing acceptable release, an unsatisfied
# checkpoint gate, or an equivocation ends that channel at the preceding head.
CHANNEL_GAP_ACTION = "halt"
CHECKPOINT_GATE_FAILURE_ACTION = "halt"
EQUIVOCATION_ACTION = "record-and-halt"


def parse_time(value):
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("timezone required")
    return dt.astimezone(timezone.utc)


def witness_active(witness, at_time):
    t = parse_time(at_time)
    if t < parse_time(witness["active_from"]):
        return False
    revoked = witness.get("revoked_at")
    return revoked is None or t < parse_time(revoked)


def receipt_in_window(object_created_at, receipt_signed_at):
    delta = (parse_time(receipt_signed_at) - parse_time(object_created_at)).total_seconds()
    return 0 <= delta <= RECEIPT_MAX_SKEW_SECONDS


def rotation_sort_key(row):
    return parse_time(row["not_before"]), int(row["epoch"]), row["event_id"]


def rotation_has_started(row, at_time):
    return parse_time(row["not_before"]) <= parse_time(at_time)


def revocation_has_started(row, at_time):
    return parse_time(row["effective_at"]) <= parse_time(at_time)


def checkpoint_gate_before(next_sequence):
    seq = int(next_sequence)
    if seq > 1 and (seq - 1) % CHECKPOINT_INTERVAL == 0:
        return seq - 1
    return None


def checkpoint_matches(row, channel, sequence, chain_hash):
    return (
        row["channel"] == channel
        and int(row["sequence"]) == int(sequence)
        and row["chain_hash"] == chain_hash
    )
