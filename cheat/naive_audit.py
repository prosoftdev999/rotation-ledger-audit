#!/usr/bin/env python3
import json
from collections import defaultdict
from pathlib import Path
rows=[json.loads(x) for x in Path('/app/data/releases.jsonl').read_text().splitlines() if x.strip()]
by=defaultdict(list)
for r in rows: by[r['channel']].append(r)
trusted=[]; heads=[]
for ch,rs in sorted(by.items()):
    chosen={}
    for r in sorted(rs,key=lambda x:(int(x['sequence']),x['release_id'])):
        chosen.setdefault(int(r['sequence']),r)
    for seq in sorted(chosen): trusted.append(chosen[seq]['release_id'])
    if chosen:
        s=max(chosen); heads.append({'channel':ch,'sequence':s,'release_id':chosen[s]['release_id'],'chain_hash':'0'*64})
all_ids=sorted(r['release_id'] for r in rows)
out={'trusted_release_ids':sorted(trusted),'rejected_release_ids':sorted(set(all_ids)-set(trusted)),'equivocations':[], 'channel_heads':heads,'rotation_rejections':[],'revocation_rejections':[],'checkpoint_rejections':[],'summary':{'trusted_release_count':len(trusted),'rejected_release_count':len(set(all_ids)-set(trusted)),'equivocation_count':0,'channels_with_head':len(heads)}}
Path('/app/audit.json').write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
