#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Accept explicit streamed producer replay and automatic TCP/HTTPS redirects without hidden retries."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from accept import digest, sources

from sdk_layout import sdk_package
from baseline_receipt import require_baseline
PACKAGE=Path(__file__).resolve().parents[1]
CASES={1:'302-post-get-rewrite',2:'307-two-explicit-fixed-replays',3:'308-chunked-trailer-replay',
       4:'never-replay-rejected',5:'unsafe-replay-opt-in-required',6:'early-307-before-100',
       7:'early-303-drops-gated-producer',8:'cross-origin-permanent-filter',9:'origin-or-downgrade-rejected',
       10:'duplicate-location-rejected',11:'exact-hop-limit',12:'original-deadline-during-rewind',
       13:'cancel-during-rewind',14:'replay-gate-no-dns-or-dial',15:'missing-location-terminal',
       16:'transport-failure-never-retried',17:'producer-shortage-sticks',18:'empty-get-needs-no-replay',
       19:'head-preserved-without-body',20:'cross-origin-trailer-promise-rejected',21:'partial-prefix-replay-starts-at-zero',22:'unsent-gated-body-still-needs-replay-permission'}

class Peer:
    def __init__(self,case:int,transport:str,fixtures:Path):
        self.case=case;self.transport=transport;self.fixtures=fixtures;self.error=None;self.record={'hops':[]}
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.port=self.listener.getsockname()[1]
        self.listener.listen(4);self.listener.settimeout(10);self.thread=threading.Thread(target=self.serve,daemon=True)
    def secure(self,hop:int)->bool:return self.transport=='https' or (self.transport=='tcp-to-tls' and hop>0)
    def serve(self):
        connection=None;n=self.case
        try:
            total=3 if n in (2,8) else 1 if n in (4,5,9,10,12,13,15,16,17,20,22) else 2
            for hop in range(total):
                connection,_=self.listener.accept();connection.settimeout(8)
                if self.secure(hop):
                    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.set_alpn_protocols(['http/1.1']);context.load_cert_chain(self.fixtures/'peer.pem',self.fixtures/'peer.key');connection=context.wrap_socket(connection,server_side=True)
                head=b''
                while not head.endswith(b'\r\n\r\n'):
                    part=connection.recv(1)
                    assert part,'missing request head';head+=part;assert len(head)<=4096
                fields=[('Content-Type','text/plain'),('Authorization','secret'),('X-Secret','secret'),('Accept','text/plain')]
                if n in (3,20):fields=[('Trailer','X-End')]
                if n in (6,7,22):fields=[('Expect','100-continue'),('Content-Type','text/plain')]
                rewritten=hop>0 and n in (1,7)
                if rewritten:fields=[f for f in fields if f[0] not in ('Content-Type','Expect','Trailer')]
                if hop>0 and (n in (8,14) or self.transport=='tcp-to-tls'):fields=[f for f in fields if f[0] in ('Content-Type','Accept')]
                method='PUT' if n in (3,20) else 'GET' if n==18 or rewritten else 'HEAD' if n==19 else 'POST'
                length=0 if rewritten or n in (18,19) else 6
                authority=('127.0.0.1' if (n==8 and hop==1) or (n==14 and hop>0) else 'localhost')+':'+str(self.port)
                target='/start' if hop==0 else '/next' if hop==1 else '/last'
                framing='Transfer-Encoding: chunked\r\n' if n in (3,20) else 'Content-Length: '+str(length)+'\r\n'
                expected=(method+' '+target+' HTTP/1.1\r\nHost: '+authority+'\r\n'+framing+''.join(k+': '+v+'\r\n' for k,v in fields)+'\r\n').encode()
                assert head==expected,('head',hop,head,expected)
                early=n in (6,7,22) and hop==0
                if n==6 and hop>0:connection.sendall(b'HTTP/1.1 100 Continue\r\n\r\n')
                payload=b'' if early else b'3\r\nabc\r\n3\r\ndef\r\n0\r\nX-End: yes\r\n\r\n' if n in (3,20) else b'abcdef' if length else b''
                if n==17 or (n==21 and hop==0):payload=b'abc'
                body=b''
                while len(body)<len(payload):
                    part=connection.recv(len(payload)-len(body));assert part,'truncated upload';body+=part
                assert body==payload,('body',hop,body,payload)
                self.record['hops'].append({'hop':hop,'secure':self.secure(hop),'head_exact':True,'body_wire_bytes':len(body),'authority':authority,'method':method})
                if n==21 and hop==0:connection.sendall(b'HTTP/1.1 103 Hints\r\n\r\n')
                if n==17:connection.sendall(b'HTTP/1.1 103 Hints\r\n\r\n')
                elif n==16:
                    # Raw EOF is a transport/protocol failure, never permission to replay.
                    raw=socket.socket(fileno=connection.detach());raw.shutdown(socket.SHUT_RDWR);raw.close();connection=None
                elif hop<total-1 or n in (4,5,9,10,11,12,13,20,22):
                    status=302 if n==1 else 303 if n in (7,19) else 308 if n in (3,8,18) else 307
                    scheme='https' if self.secure(hop) else 'http';target='/next' if hop==0 else '/last'
                    location=target
                    if n in (8,14,20):location=scheme+'://'+('127.0.0.1' if hop==0 else 'localhost')+':'+str(self.port)+target
                    if self.transport=='tcp-to-tls' and hop==0:location='https://localhost:'+str(self.port)+target
                    if n==9:location='http://other.invalid/blocked'
                    extra='Location: /ambiguous\r\n' if n==10 else ''
                    connection.sendall(('HTTP/1.1 '+str(status)+' Redirect\r\nLocation: '+location+'\r\n'+extra+'Content-Length: 999999\r\n\r\nignored').encode())
                else:
                    status=307 if n==15 else 200
                    connection.sendall(('HTTP/1.1 '+str(status)+' End\r\nContent-Length: 2\r\n\r\n').encode()+(b'' if n==19 else b'ok'))
                if connection is not None:
                    try:extra=connection.recv(1)
                    except (ConnectionError,ssl.SSLError):extra=b''
                    assert not extra,('unexpected upload/retry after response',extra)
                    connection.close();connection=None
                if n==14 and hop==0:
                    self.listener.settimeout(.08)
                    try:unexpected,_=self.listener.accept()
                    except socket.timeout:self.record['no_connection_before_replay_ack']=True
                    else:unexpected.close();raise AssertionError('next hop opened before replay acknowledgement')
                    self.listener.settimeout(10)
            self.listener.settimeout(.1)
            try:unexpected,_=self.listener.accept()
            except socket.timeout:self.record['no_extra_connection']=True
            else:unexpected.close();raise AssertionError('unexpected retry/redirect connection')
        except BaseException as error:self.error=repr(error)
        finally:
            if connection is not None:connection.close()
            self.listener.close()
    def run(self,binary:Path,env:dict,log:Path):
        self.thread.start();started=time.monotonic()
        with log.open('w') as output:result=subprocess.run([str(binary)],env=env|{'HTTP_TEST_CASE':str(self.case),'HTTP_TEST_PORT':str(self.port),'HTTP_TEST_CA':str(self.fixtures/'ca.pem')},stdout=output,stderr=subprocess.STDOUT,timeout=20)
        self.thread.join(11)
        if result.returncode or self.error or self.thread.is_alive():raise RuntimeError(f'{self.transport} streamed follow case {self.case}: exit={result.returncode}, peer={self.error}; see {log}')
        return {'transport':self.transport,'case':self.case,'name':CASES[self.case],'status':'passed','elapsed_seconds':time.monotonic()-started,**self.record}

def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('sdk','openssl-root','out-dir'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--baseline',type=Path,help='matching complete URL upload receipt directory')
    args=parser.parse_args();sdk=args.sdk.resolve();out=args.out_dir.resolve()
    if out==PACKAGE or PACKAGE in out.parents or (out.exists() and any(out.iterdir()) and not args.baseline):parser.error('new/empty external output required')
    out.mkdir(parents=True,exist_ok=True)
    meta=json.loads((sdk/'manifest.json').read_text());compiler=sdk/meta['tools']['nyrac']['path'];assert digest(compiler)==meta['tools']['nyrac']['sha256']
    host={'Darwin':'darwin','Linux':'linux','Windows':'windows'}[platform.system()]+'-'+('arm64' if platform.machine().lower() in ('arm64','aarch64') else 'x86_64')
    kit=sdk/'hosts'/host/'llvm/bin';suffix='.exe' if platform.system()=='Windows' else ''
    env={k:v for k,v in os.environ.items() if not k.startswith(('NYRA','DYLD_','LD_')) and k!='LLVM_PREFIX'}
    env.update(PATH=str(kit)+os.pathsep+env.get('PATH',''),NYRA_SDK_ROOT=str(sdk),NYRA_KERNEL_ROOT=str(out/'source-fallback-disabled'))
    if platform.system()=='Darwin':
        target=next(line.split(':',1)[1].strip().strip('"') for line in (sdk_package(sdk, host, 'stdlib') / 'manifest.yaml').read_text().splitlines() if line.startswith('target:'))
        env.update(SDKROOT=subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip(),MACOSX_DEPLOYMENT_TARGET=target.split('-apple-macosx',1)[1])
    packages={name:PACKAGE.parent/name for name in ('http','http_tls','tls','net_core')}
    report={'format':'nyra-http-stream-follow-v1','status':'running','host':host,'sdk_version':meta['version'],'sdk_manifest_sha256':digest(sdk/'manifest.json'),'compiler_sha256':digest(compiler),'compiler_origin':'public-sdk','source_fallback_disabled':True,'source_sha256':{name:sources(path) for name,path in packages.items()},'commands':[],'cases':[],'scope':'Explicit streamed replay and automatic redirects; no transport retry, payload buffering, connection reuse or downgrade.'}
    def save():(out/'acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(name,cmd):
        command=list(map(str,cmd));report['commands'].append({'name':name,'command':command});save();print('BEGIN '+name,flush=True)
        with (out/(name+'.log')).open('w') as log:subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=4800,check=True)
        print('END '+name,flush=True)
    try:
        base=args.baseline.resolve() if args.baseline else out/'base'
        if not args.baseline:run('prior',[sys.executable,PACKAGE/'scripts/accept_url_upload.py','--sdk',sdk,'--openssl-root',args.openssl_root.resolve(),'--out-dir',base])
        prior=json.loads((base/'acceptance.json').read_text());require_baseline(prior,sdk,compiler,report['source_sha256']);assert prior['status']=='passed' and prior['source_sha256']==report['source_sha256'] and prior['compiler_sha256']==report['compiler_sha256'] and prior['sdk_manifest_sha256']==report['sdk_manifest_sha256']
        report['base']=prior
        client_base=prior['base']['base']['base']['base']['base'];client_dir=base/'base/base/base/base/base'
        links=[v for row in client_base['commands'] if row['name']=='https-build' for v in row['command'] if v.startswith(('--link-arg=','--platform-archive='))]
        assert links
        for transport in ('tcp','https','tcp-to-tls'):
            project=out/(transport+'-consumer');project.mkdir()
            (project/'package.yaml').write_text('name: streamed_follow_consumer\ndependencies:\n'+''.join('  '+name+':\n    path: '+json.dumps(str(client_dir/'project'/name))+'\n' for name in ('http','http_tls','tls','net_core')))
            text=(PACKAGE/'tests/data/stream_follow_consumer.ny.in').read_text().replace('@@SCHEME@@','https' if transport=='https' else 'http').replace('@@MIXED@@','true' if transport=='tcp-to-tls' else 'false').replace('@@SCHEME_ERROR@@','HttpErrorKind.InsecureRedirect' if transport=='https' else 'HttpErrorKind.CrossOriginRedirect')
            (project/'main.ny').write_text(text);binary=out/(transport+'-stream-follow'+suffix)
            run(transport+'-consumer',[compiler,'build',project/'main.ny','--link','-O2','-j','4','--out-dir',out/(transport+'-objects'),'-o',binary,*links])
            for case in ([2] if transport=='tcp-to-tls' else CASES):
                print('BEGIN '+transport+'-'+str(case),flush=True);report['cases'].append(Peer(case,transport,client_dir/'fixtures').run(binary,env,out/(transport+'-case-'+str(case)+'.log')));save()
        assert report['source_sha256']=={name:sources(path) for name,path in packages.items()},'sources changed during acceptance'
        report['status']='passed'
    except (OSError,ValueError,AssertionError,RuntimeError,subprocess.SubprocessError) as error:
        report['status']='failed';report['error']=str(error);print(str(error),file=sys.stderr)
    save();print(out/'acceptance.json');return 0 if report['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
