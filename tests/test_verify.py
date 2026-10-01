import json, os, stat
from pathlib import Path

ART=Path('/app/audit.json')
EXPECTED=Path('/tests/expected.json')

def strict_load(path):
    def hook(pairs):
        out={}
        for k,v in pairs:
            if k in out: raise ValueError('duplicate JSON key: '+k)
            out[k]=v
        return out
    return json.loads(path.read_text(),object_pairs_hook=hook)

def test_audit_exact():
    st=ART.lstat()
    assert stat.S_ISREG(st.st_mode), 'audit.json must be a regular file'
    assert not ART.is_symlink(), 'symlink artifact is not accepted'
    assert st.st_size <= 2_000_000, 'audit.json unexpectedly large'
    got=strict_load(ART); exp=strict_load(EXPECTED)
    assert got==exp
