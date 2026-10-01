import hashlib

def _leaf(part):
    idx = int(part["part_index"])
    if idx < 0:
        raise ValueError("negative part index")
    name = part["artifact_name"].encode("utf-8")
    digest = bytes.fromhex(part["sha256"])
    return hashlib.sha256(b"manifest-part-v2\0" + idx.to_bytes(4, "big") + name + b"\0" + digest).digest()

def manifest_root(parts):
    ordered = sorted(parts, key=lambda p: int(p["part_index"]))
    if not ordered or [int(p["part_index"]) for p in ordered] != list(range(len(ordered))):
        raise ValueError("manifest part indexes must be contiguous from zero")
    level = [_leaf(p) for p in ordered]
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [hashlib.sha256(b"manifest-node-v2\0" + level[i] + level[i+1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()
