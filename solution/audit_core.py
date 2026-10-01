#!/usr/bin/env python3
import argparse, base64, json, os, sys
from collections import defaultdict
from pathlib import Path

APP=Path(os.environ.get("TASK_APP_ROOT","/app"))
SERVICE=APP/"service"
sys.path.insert(0,str(SERVICE))
from codec import object_digest, verify_ed25519
from merkle import manifest_root
from policy import ROTATION_WITNESS_WEIGHT,CHECKPOINT_WITNESS_WEIGHT,CHECKPOINT_INTERVAL,ZERO_CHAIN_HASH,parse_time,receipt_in_window,witness_active
from release_chain import release_body,release_digest,chain_hash

def load_json(p): return json.loads(Path(p).read_text())
def load_jsonl(p):
    return [json.loads(x) for x in Path(p).read_text().splitlines() if x.strip()]

def key_body(e):
    if e["event_type"]=="ROTATE":
        keys=["event_id","event_type","channel","epoch","key_id","public_key_b64","not_before","created_at"]
    else:
        keys=["event_id","event_type","channel","key_id","effective_at","created_at"]
    return {k:e[k] for k in keys}

def checkpoint_body(c):
    return {k:c[k] for k in ["checkpoint_id","channel","sequence","chain_hash","created_at"]}

def valid_receipt_weight(kind,digest,created_at,receipts,witnesses,mode):
    seen=set(); weight=0; count=0
    for r in receipts.get((kind,digest),[]):
        wid=r.get("witness_id")
        if wid in seen or wid not in witnesses: continue
        rb={k:r[k] for k in ["receipt_id","kind","object_digest","witness_id","signed_at"]}
        w=witnesses[wid]
        if not verify_ed25519(w["public_key_b64"],r.get("signature_b64",""),"witness-receipt-v2",rb): continue
        if not receipt_in_window(created_at,r["signed_at"]): continue
        if mode!="ignore_witness_revocation" and not witness_active(w,r["signed_at"]): continue
        seen.add(wid); weight += int(w["weight"]); count += 1
    return count if mode=="rotation_by_count" and kind=="rotation" else weight

def solve(mode="reference"):
    data=APP/"data"
    trust=load_json(data/"trust_anchors.json")
    witnesses={w["witness_id"]:w for w in load_json(data/"witness_registry.json")["witnesses"]}
    recs=defaultdict(list)
    for r in load_jsonl(data/"witness_receipts.jsonl"): recs[(r["kind"],r["object_digest"])].append(r)
    valid_rot=defaultdict(list); invalid_rot=[]; valid_rev=[]; invalid_rev=[]
    for e in load_jsonl(data/"key_events.jsonl"):
        body=key_body(e)
        if not verify_ed25519(trust["root_ed25519_public_key_b64"],e.get("root_signature_b64",""),"key-event-v2",body):
            (invalid_rot if e["event_type"]=="ROTATE" else invalid_rev).append(e["event_id"]); continue
        if e["event_type"]=="ROTATE":
            dg=object_digest("key-event-v2",body)
            score=valid_receipt_weight("rotation",dg,e["created_at"],recs,witnesses,mode)
            needed = 3 if mode=="rotation_by_count" else ROTATION_WITNESS_WEIGHT
            if score < needed: invalid_rot.append(e["event_id"]); continue
            valid_rot[e["channel"]].append(e)
        else:
            valid_rev.append(e)
    for ch in valid_rot: valid_rot[ch].sort(key=lambda e:(parse_time(e["not_before"]),int(e["epoch"]),e["event_id"]))
    rev_by_key=defaultdict(list)
    for e in valid_rev: rev_by_key[e["key_id"]].append(parse_time(e["effective_at"]))

    parts=defaultdict(list)
    for p in load_jsonl(data/"manifest_parts.jsonl"): parts[p["manifest_id"]].append(p)
    computed_roots={}
    for mid,ps in parts.items():
        try:
            if mode=="sort_manifest_names":
                # Deliberately plausible but wrong interpretation of leaf order.
                ordered=sorted(ps,key=lambda p:p["artifact_name"])
                # Reuse public leaf function behavior by rewriting indexes in name order would be even worse;
                # instead call the normative root on a name-ordered list with original indexes via local implementation.
                import hashlib
                def leaf(part):
                    return hashlib.sha256(b"manifest-part-v2\0"+int(part["part_index"]).to_bytes(4,"big")+part["artifact_name"].encode()+b"\0"+bytes.fromhex(part["sha256"])).digest()
                level=[leaf(p) for p in ordered]
                while len(level)>1:
                    if len(level)&1: level.append(level[-1])
                    level=[hashlib.sha256(b"manifest-node-v2\0"+level[i]+level[i+1]).digest() for i in range(0,len(level),2)]
                computed_roots[mid]=level[0].hex()
            else: computed_roots[mid]=manifest_root(ps)
        except Exception: computed_roots[mid]=None

    def active_key(channel,at):
        t=parse_time(at); eligible=[e for e in valid_rot.get(channel,[]) if parse_time(e["not_before"])<=t]
        if not eligible: return None
        e=eligible[-1]
        rv=rev_by_key.get(e["key_id"],[])
        if rv:
            earliest=min(rv)
            if mode=="revocation_strict_gt":
                if t>earliest: return None
            elif t>=earliest: return None
        return e

    rows=load_jsonl(data/"releases.jsonl")
    prevalid=[]
    for r in rows:
        k=active_key(r["channel"],r["created_at"])
        if not k or k["key_id"]!=r["key_id"]: continue
        if computed_roots.get(r["manifest_id"])!=r["manifest_root"]: continue
        if mode!="skip_signature" and not verify_ed25519(k["public_key_b64"],r.get("signature_b64",""),"release-v2",release_body(r)): continue
        prevalid.append(r)
    if mode!="ignore_manifest_reuse":
        bindings=defaultdict(set)
        for r in prevalid: bindings[r["manifest_id"]].add((r["channel"],int(r["sequence"])))
        bad={m for m,s in bindings.items() if len(s)>1}
        prevalid=[r for r in prevalid if r["manifest_id"] not in bad]

    # Pre-validate checkpoints cryptographically; chain commitment is checked at each gate.
    cps_by=(defaultdict(list)); invalid_cp=[]
    for c in load_jsonl(data/"checkpoints.jsonl"):
        body=checkpoint_body(c)
        ok=verify_ed25519(trust["checkpoint_ed25519_public_key_b64"],c.get("audit_signature_b64",""),"checkpoint-v2",body)
        dg=object_digest("checkpoint-v2",body)
        score=valid_receipt_weight("checkpoint",dg,c["created_at"],recs,witnesses,mode)
        need=5 if mode=="checkpoint_threshold_5" else CHECKPOINT_WITNESS_WEIGHT
        if not ok or score<need: invalid_cp.append(c["checkpoint_id"]); continue
        cps_by[(c["channel"],int(c["sequence"]))].append(c)

    by_ch_seq=defaultdict(lambda:defaultdict(list))
    for r in prevalid: by_ch_seq[r["channel"]][int(r["sequence"])].append(r)
    all_release_ids={r["release_id"] for r in rows}
    trusted=[]; equiv=[]; heads=[]
    for ch in sorted(load_json(data/"incident.json")["channels"]):
        prev=ZERO_CHAIN_HASH; last=None
        for seq in range(1,121):
            if seq>1 and (seq-1)%CHECKPOINT_INTERVAL==0:
                cps=cps_by.get((ch,seq-1),[])
                matches=[c for c in cps if mode=="ignore_checkpoint_hash" or c["chain_hash"]==prev]
                if len(matches)!=1: break
            candidates=[]
            for r in by_ch_seq[ch].get(seq,[]):
                if mode=="ignore_chain_hash" or r["prev_chain_hash"]==prev: candidates.append(r)
            if len(candidates)==0: break
            if len(candidates)>1:
                ids=sorted(r["release_id"] for r in candidates)
                equiv.append({"channel":ch,"sequence":seq,"release_ids":ids})
                if mode=="ignore_equivocation":
                    chosen=sorted(candidates,key=lambda r:(not r["release_id"].endswith("-main"),r["release_id"]))[0]
                else: break
            else: chosen=candidates[0]
            dg=release_digest(chosen); prev=chain_hash(prev,dg); trusted.append(chosen["release_id"]); last=(seq,chosen["release_id"],prev)
        if last: heads.append({"channel":ch,"sequence":last[0],"release_id":last[1],"chain_hash":last[2]})
    trusted=sorted(trusted); rejected=sorted(all_release_ids-set(trusted))
    out={
      "trusted_release_ids":trusted,
      "rejected_release_ids":rejected,
      "equivocations":sorted(equiv,key=lambda x:(x["channel"],x["sequence"])),
      "channel_heads":heads,
      "rotation_rejections":sorted(invalid_rot),
      "revocation_rejections":sorted(invalid_rev),
      "checkpoint_rejections":sorted(invalid_cp),
      "summary":{"trusted_release_count":len(trusted),"rejected_release_count":len(rejected),"equivocation_count":len(equiv),"channels_with_head":len(heads)}
    }
    return out

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--mode",default="reference"); ap.add_argument("--output",default=str(APP/"audit.json")); a=ap.parse_args()
    out=solve(a.mode); Path(a.output).write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
if __name__=="__main__": main()
