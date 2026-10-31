
import sys,os,json,pathlib,tempfile,secrets,subprocess,hashlib
W=pathlib.Path(sys.argv[1]);P=pathlib.Path(sys.argv[2]);EV=pathlib.Path(sys.argv[3]);sys.path.insert(0,str(W))
from proof.proofkit import inspect_pin_inputs,base_env,DRIVERS_29
from proof.artifact_legs import run_row
pin=inspect_pin_inputs(str(P),str(W),str(P/'.build/iyi'),DRIVERS_29)
D=pathlib.Path(tempfile.mkdtemp(prefix='iyi-canary-6bbe1bf2e-',dir='/private/tmp'));t=D/'t';work=t/'w0';work.mkdir(parents=True)
for n in ('c','s'): (D/n).mkdir()
nonce=secrets.token_hex(16);ledger=D/'ledger.jsonl';ledger.write_text(json.dumps({'v':1,'kind':'header','nonce':nonce,'driver':'cookie','attempt':1,'chain_id':secrets.token_hex(16)})+'\n')
# write a real JSONL newline, not a quoted backslash-n
ledger.write_text(ledger.read_text().replace('\\n','\n'))
config={'real':str(P/'.build/iyi'),'census':str(W/'proof/census/cookie.json'),'ledger':str(ledger),'nonce':nonce,'driver':'cookie','work_tmp':str(t),'scratch':str(D/'s'),'repo':str(W),'canonical_roots':pin['canonical_roots'],'platform_tmp':pin['platform_tmp']}
(D/'shim.json').write_text(json.dumps(config));out=work/'cookie-plain';env=base_env(pin,{'IYI_CACHE_DIR':str(D/'c'),'TMPDIR':str(t),'IYI_PATH':str(W/'src')+os.pathsep+str(W/'samples/iyi')})
a=[sys.executable,'-B',str(W/'proof/roundtrip_shim.py'),'--config',str(D/'shim.json'),'--','build','-o',str(out),str(W/'bench/std_cookie_exercise.iyi')]
r=subprocess.run(a,cwd=W,env=env,capture_output=True,timeout=300);(D/'shim.stdout').write_bytes(r.stdout);(D/'shim.stderr').write_bytes(r.stderr)
assert r.returncode==0,(r.returncode,r.stderr[-4000:])
end=[json.loads(l) for l in ledger.read_text().splitlines() if json.loads(l).get('phase')=='end'][-1]
assert end['own'] and end['producer']['rc']==0 and end['producer']['mods_count']>0 and end['consumer']['rc']==0,end
ref=pathlib.Path(end['out_ref']);before=ref.stat();out_before=out.stat();assert before.st_ino==out_before.st_ino==end['out_ino'] and before.st_atime_ns==end['atime_set_ns'] and before.st_atime_ns<before.st_mtime_ns,(before,out_before,end)
rr=subprocess.run([str(out)],cwd=W,env=env,capture_output=True,timeout=60);after=ref.stat();(D/'out.stdout').write_bytes(rr.stdout);(D/'out.stderr').write_bytes(rr.stderr)
assert rr.returncode==0 and b'ALL CHECKS PASSED' in rr.stdout,(rr.returncode,rr.stdout,rr.stderr)
assert after.st_atime_ns>after.st_mtime_ns,(after.st_atime_ns,after.st_mtime_ns)
# Hash only after the post-execution stat: this read must not manufacture the atime witness.
assert hashlib.sha256(out.read_bytes()).hexdigest()==end['consumer']['out_sha256']
result={'canary_root':str(D),'shim_rc':r.returncode,'execution_rc':rr.returncode,'end':end,'before_atime_ns':before.st_atime_ns,'after_atime_ns':after.st_atime_ns}
(EV/'canary-shim.json').write_text(json.dumps(result,indent=2)+'\n');print('C1 PASS',D)
row=run_row('samples/iyi/calc.iyi',repo=str(W),compiler=str(P/'.build/iyi'),work_root=str(D/'legs'),nm_bin=pin['nm_path'])
(EV/'canary-legs.json').write_text(json.dumps(row,indent=2)+'\n');print('C2',json.dumps(row));assert row['status']=='PASS',row
