#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Accept URL streaming over TCP and verified TLS with caller-owned DNS and original controls."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from accept import digest, sources
from accept_clients import url_control_consumer
from accept_tcp_upload import Peer as TcpPeer, CASES as TCP_CASES
from accept_https_upload import Peer as HttpsPeer, CASES as HTTPS_CASES

from sdk_layout import sdk_package
from baseline_receipt import require_baseline
PACKAGE = Path(__file__).resolve().parents[1]

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('sdk','openssl-root','out-dir'): parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--baseline',type=Path,help='matching complete connected HTTPS upload receipt directory')
    args=parser.parse_args();sdk=args.sdk.resolve();out=args.out_dir.resolve()
    if out==PACKAGE or PACKAGE in out.parents or (out.exists() and any(out.iterdir()) and not args.baseline): parser.error('new/empty external output required')
    out.mkdir(parents=True,exist_ok=True)
    meta=json.loads((sdk/'manifest.json').read_text());compiler=sdk/meta['tools']['nyrac']['path']
    assert digest(compiler)==meta['tools']['nyrac']['sha256'],'SDK compiler identity mismatch'
    host={'Darwin':'darwin','Linux':'linux','Windows':'windows'}[platform.system()]+'-'+('arm64' if platform.machine().lower() in ('arm64','aarch64') else 'x86_64')
    kit=sdk/'hosts'/host/'llvm/bin';suffix='.exe' if platform.system()=='Windows' else ''
    env={k:v for k,v in os.environ.items() if not k.startswith(('NYRA','DYLD_','LD_')) and k!='LLVM_PREFIX'}
    env.update(PATH=str(kit)+os.pathsep+env.get('PATH',''),NYRA_SDK_ROOT=str(sdk),NYRA_KERNEL_ROOT=str(out/'source-fallback-disabled'))
    if platform.system()=='Darwin':
        target=next(line.split(':',1)[1].strip().strip('"') for line in (sdk_package(sdk, host, 'stdlib') / 'manifest.yaml').read_text().splitlines() if line.startswith('target:'))
        env.update(SDKROOT=subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip(),MACOSX_DEPLOYMENT_TARGET=target.split('-apple-macosx',1)[1])
    packages={name:PACKAGE.parent/name for name in ('http','http_tls','tls','net_core')}
    report={'format':'nyra-http-url-upload-v1','status':'running','host':host,'sdk_version':meta['version'],
            'sdk_manifest_sha256':digest(sdk/'manifest.json'),'compiler_sha256':digest(compiler),'compiler_origin':'public-sdk',
            'source_fallback_disabled':True,'scope':'Streamed HTTP/HTTPS URL entry points; no producer replay or automatic redirects.',
            'source_sha256':{name:sources(path) for name,path in packages.items()},'commands':[],'cases':[]}
    def save(): (out/'acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(name,cmd):
        command=list(map(str,cmd));report['commands'].append({'name':name,'command':command});save();print('BEGIN '+name,flush=True)
        with (out/(name+'.log')).open('w') as log: subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=4200,check=True)
        print('END '+name,flush=True)
    try:
        base=args.baseline.resolve() if args.baseline else out/'base'
        if not args.baseline: run('prior',[sys.executable,PACKAGE/'scripts/accept_https_upload.py','--sdk',sdk,'--openssl-root',args.openssl_root.resolve(),'--out-dir',base])
        prior=json.loads((base/'acceptance.json').read_text());require_baseline(prior,sdk,compiler,report['source_sha256']);assert prior['status']=='passed' and prior['source_sha256']==report['source_sha256'],'prior sources differ'
        assert prior['compiler_sha256']==report['compiler_sha256'] and prior['sdk_manifest_sha256']==report['sdk_manifest_sha256'],'prior SDK differs'
        report['base']=prior
        client_base=prior['base']['base']['base']['base'];client_dir=base/'base/base/base/base'
        for transport,cases,peer in [('tcp',TCP_CASES,TcpPeer),('https',HTTPS_CASES,HttpsPeer)]:
            links=[v for row in client_base['commands'] if row['name']==transport+'-build' for v in row['command'] if v.startswith(('--link-arg=','--platform-archive='))]
            assert links,'missing imported consumer link recipe'
            project=out/(transport+'-consumer');project.mkdir()
            names=('http','net_core') if transport=='tcp' else ('http','http_tls','tls','net_core')
            deps=''.join('  '+name+':\n    path: '+json.dumps(str(client_dir/'project'/name))+'\n' for name in names)
            (project/'package.yaml').write_text('name: url_'+transport+'_upload_consumer\ndependencies:\n'+deps)
            shutil.copyfile(PACKAGE/('tests/data/url_'+transport+'_upload_consumer.ny.in'),project/'main.ny')
            binary=out/('url-'+transport+'-upload'+suffix)
            run(transport+'-consumer',[compiler,'build',project/'main.ny','--link','-O2','-j','4','--out-dir',out/(transport+'-objects'),'-o',binary,*links])
            for case in cases:
                print('BEGIN '+transport+'-'+str(case),flush=True)
                server=peer(case,client_dir/'fixtures',url=True) if transport=='https' else peer(case,url=True)
                record=server.run(binary,env,out/(transport+'-case-'+str(case)+'.log'))
                report['cases'].append({'transport':transport,**record});save()
            # Reuse the gated native resolver to prove return-before-worker-retirement and recovery.
            text=url_control_consumer(transport=='https').replace('.Open(','.OpenStreaming(').replace('NetBuffer{}','HttpBodyPlan{}').replace(',dial,options)',',dial,options,80)')
            (project/'main.ny').write_text(text)
            controls=[v for row in client_base['commands'] if row['name']==transport+'-url-control-build' for v in row['command'] if v.startswith(('--link-arg=','--platform-archive='))]
            control_binary=out/('url-'+transport+'-controls'+suffix)
            run(transport+'-controls',[compiler,'build',project/'main.ny','--link','-O2','-j','4','--out-dir',out/(transport+'-control-objects'),'-o',control_binary,*controls])
            for case,name in {1:'dns-name-not-found',2:'blocked-dns-deadline',3:'blocked-dns-cancel',4:'expired-before-dns',5:'closed-resolver',6:'reserved-host-before-dns',7:'address-cap-before-dns',8:'scheme-before-dns',11:'request-cap-before-dns',**({9:'peer-before-dns',10:'alpn-before-dns'} if transport=='https' else {})}.items():
                identity=transport+'-control-'+str(case)
                print('BEGIN '+identity,flush=True)
                with (out/(identity+'.log')).open('w') as log: subprocess.run([str(control_binary)],env=env|{'HTTP_TEST_CASE':str(case)},stdout=log,stderr=subprocess.STDOUT,timeout=12,check=True)
                report['cases'].append({'transport':transport,'case':case,'name':name,'profile':'controlled-dns','status':'passed'});save()
        assert report['source_sha256']=={name:sources(path) for name,path in packages.items()},'sources changed during acceptance'
        report['status']='passed'
    except (OSError,ValueError,AssertionError,RuntimeError,subprocess.SubprocessError) as error:
        report['status']='failed';report['error']=str(error);print(str(error),file=sys.stderr)
    save();print(out/'acceptance.json');return 0 if report['status']=='passed' else 1

if __name__=='__main__': raise SystemExit(main())
