#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Accept streamed verified HTTPS, independent response probes and constrained-window early rejection."""
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
PACKAGE = Path(__file__).resolve().parents[1]
CASES = {1:'fixed-producer-adoption-move-admission', 2:'chunked-producer-trailers',
         3:'103-does-not-release-100-gate', 4:'417-without-producer',
         5:'early-final-after-prefix', 6:'finite-continue-fallback',
         7:'coalesced-100-final-no-producer', 8:'cancel-after-observed-head',
         9:'shortage-after-observed-prefix', 10:'constrained-window-early-final',
         11:'partial-final-pauses-past-continue-fallback', 12:'original-deadline-during-continue',
         13:'original-deadline-during-producer', 14:'early-final-authenticated-truncated-response',15:'raw-tls-truncation',16:'untrusted-ca-before-http'}

class Peer:
    def __init__(self, case: int, fixtures: Path, url: bool = False):
        self.url=url; self.fixtures=fixtures; self.case=case; self.error=None; self.record={}
        self.listener=socket.socket()
        if case==10: self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
        self.listener.bind(('127.0.0.1',0)); self.port=self.listener.getsockname()[1]
        self.listener.listen(1); self.listener.settimeout(10)
        self.thread=threading.Thread(target=self.serve,daemon=True)

    def serve(self):
        connection=None
        try:
            connection,_=self.listener.accept(); connection.settimeout(10)
            if self.case==11:
                # TLS tickets can leave unacknowledged data ahead of the partial response.
                # Isolate the 40 ms continue timer from the peer's Nagle buffering.
                connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
                self.record['peer_tcp_nodelay']=True
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.set_alpn_protocols(['http/1.1'])
            context.load_cert_chain(self.fixtures/'peer.pem',self.fixtures/'peer.key')
            try: connection=context.wrap_socket(connection,server_side=True)
            except ssl.SSLError:
                if self.case==16: self.record['untrusted_client_rejected_before_http']=True; return
                raise
            assert self.case!=16,'untrusted peer accepted' 
            framing='Transfer-Encoding: chunked\r\nTrailer: X-End\r\n' if self.case==2 else 'Content-Length: 67108864\r\n' if self.case==10 else 'Content-Length: 6\r\n'
            if self.case in (3,4,6,7,11,12,14,15): framing+='Expect: 100-continue\r\n'
            target='/upload%2f?q=' if self.url else '/upload'
            authority=('127.0.0.1' if self.case==1 else 'localhost')+':'+str(self.port) if self.url else 'localhost'
            expected=('POST '+target+' HTTP/1.1\r\nHost: '+authority+'\r\n'+framing+'\r\n').encode()
            actual=b''
            while not actual.endswith(b'\r\n\r\n'):
                part=connection.recv(1)
                if not part: break
                actual+=part
                assert len(actual)<=4096
            assert actual==expected,('head',actual,expected)
            self.record['head_exact']=True
            if self.case in (8,13): connection.sendall(b'HTTP/1.1 103 Hints\r\n\r\n')
            if self.case==3:
                connection.sendall(b'HTTP/1.1 103 Hints\r\n\r\n'); connection.settimeout(.04)
                try: extra=connection.recv(1)
                except socket.timeout: extra=b''
                assert not extra,'103 released body'
                self.record['body_withheld_across_103']=True; connection.settimeout(10)
                connection.sendall(b'HTTP/1.1 100 Continue\r\n\r\n')
            body=b''
            payload=b'3\r\nabc\r\n3\r\ndef\r\n0\r\nX-End: yes\r\n\r\n' if self.case==2 else b'abcdef'
            if self.case in (4,7,8,10,11,12,13,14,15): payload=b''
            if self.case in (5,9): payload=b'abc'
            started=time.monotonic()
            while len(body)<len(payload):
                part=connection.recv(len(payload)-len(body))
                if not part: break
                body+=part
            assert body==payload,('body',body,payload)
            self.record['body_exact']=True; self.record['body_wire_bytes']=len(body)
            if self.case==6:
                elapsed=time.monotonic()-started
                assert .04<=elapsed<4,('fallback wait',elapsed)
                self.record['continue_wait_seconds']=elapsed
            if self.case==9: connection.sendall(b'HTTP/1.1 103 Hints\r\n\r\n')
            if self.case==10:
                self.record['peer_receive_buffer_bytes']=connection.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
                # Do not drain a 64 MiB upload: a bounded sender eventually waits for
                # writability. The final response must wake its read registration.
                time.sleep(.3)
            if self.case==12: time.sleep(1.0)
            if self.case not in (8,9,12,13):
                status={4:417,5:409,7:413,10:413,11:413,14:417,15:417}.get(self.case,200)
                prefix=b'HTTP/1.1 100 Continue\r\n\r\n' if self.case==7 else b'HTTP/1.1 103 Hints\r\n\r\n' if self.case==5 else b''
                wire=prefix+f'HTTP/1.1 {status} Result\r\nContent-Length: 2\r\n\r\n'.encode()+(b'no' if status!=200 else b'ok')
                if self.case==11:
                    connection.sendall(wire[:12]); time.sleep(.16); connection.sendall(wire[12:])
                    self.record['partial_head_pause_seconds']=.16
                elif self.case in (14,15):
                    connection.sendall(wire[:-1])
                    if self.case==15: connection.shutdown(socket.SHUT_WR)
                    else:
                        try: connection=connection.unwrap()
                        except (ssl.SSLError,ConnectionError): pass
                else: connection.sendall(wire)
            suffix=b''
            while True:
                try: part=connection.recv(65536)
                except (ConnectionError,ssl.SSLError): break
                if not part: break
                suffix+=part
                assert len(suffix)<67108864,'whole upload sent before early response'
            if self.case==10:
                assert suffix and set(suffix)=={97},'invalid bulk payload'
                self.record['accepted_suffix_observed_bytes']=len(suffix)
            else: assert not suffix,('unexpected upload or retry',suffix)
            if self.case==2:
                connection=connection.unwrap();self.record['closure']='close-notify'
            self.record['connection_retired']=True
        except BaseException as error: self.error=repr(error)
        finally:
            if connection is not None: connection.close()
            self.listener.close()

    def run(self, binary: Path, env: dict, log: Path):
        self.thread.start(); started=time.monotonic()
        with log.open('w') as output:
            result=subprocess.run([str(binary)],env=env|{'HTTP_TEST_PORT':str(self.port),'HTTP_TEST_CASE':str(self.case),'HTTP_TEST_CA':str(self.fixtures/('wrong-ca.pem' if self.case==16 else 'ca.pem'))},stdout=output,stderr=subprocess.STDOUT,timeout=20)
        self.thread.join(11)
        if result.returncode or self.thread.is_alive() or self.error:
            raise RuntimeError(f'HTTPS upload case {self.case}: exit={result.returncode}, peer={self.error}; see {log}')
        return {'case':self.case,'name':CASES[self.case],'status':'passed','elapsed_seconds':time.monotonic()-started,**self.record}

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('sdk','openssl-root','out-dir'): parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--compiler',type=Path)
    parser.add_argument('--baseline-upload',type=Path)
    parser.add_argument('--baseline-tcp',type=Path)
    args=parser.parse_args(); sdk=args.sdk.resolve(); out=args.out_dir.resolve()
    if out==PACKAGE or PACKAGE in out.parents or (out.exists() and any(out.iterdir()) and not args.baseline_upload): parser.error('new/empty external output required')
    out.mkdir(parents=True,exist_ok=True)
    meta=json.loads((sdk/'manifest.json').read_text()); compiler=args.compiler.resolve() if args.compiler else sdk/meta['tools']['nyrac']['path']
    host={'Darwin':'darwin','Linux':'linux','Windows':'windows'}[platform.system()]+'-'+('arm64' if platform.machine().lower() in ('arm64','aarch64') else 'x86_64')
    kit=sdk/'hosts'/host/'llvm/bin'; suffix='.exe' if platform.system()=='Windows' else ''
    env={k:v for k,v in os.environ.items() if not k.startswith(('NYRA','DYLD_','LD_')) and k!='LLVM_PREFIX'}
    env.update(PATH=str(kit)+os.pathsep+env.get('PATH',''),NYRA_SDK_ROOT=str(sdk),NYRA_KERNEL_ROOT=str(out/'source-fallback-disabled'))
    if platform.system()=='Darwin':
        target=next(line.split(':',1)[1].strip().strip('"') for line in (sdk_package(sdk, host, 'stdlib') / 'manifest.yaml').read_text().splitlines() if line.startswith('target:'))
        env.update(SDKROOT=subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip(),MACOSX_DEPLOYMENT_TARGET=target.split('-apple-macosx',1)[1])
    packages={name:PACKAGE.parent/name for name in ('http','http_tls','tls','net_core')}
    report={'format':'nyra-http-https-upload-v1','status':'running','host':host,'sdk_version':meta['version'],
            'sdk_manifest_sha256':digest(sdk/'manifest.json'),'compiler_sha256':digest(compiler),
            'compiler_origin':'public-sdk' if digest(compiler)==meta['tools']['nyrac']['sha256'] else 'source-candidate',
            'source_fallback_disabled':True,'scope':'Connected streamed HTTPS client over the optional TLS channel; URL/redirect clients retain immutable uploads.',
            'source_sha256':{name:sources(path) for name,path in packages.items()},'commands':[],'cases':[]}
    def save(): (out/'acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(name,cmd):
        command=list(map(str,cmd));report['commands'].append({'name':name,'command':command});save();print('BEGIN '+name,flush=True)
        with (out/(name+'.log')).open('w') as log: subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=3600,check=True)
        print('END '+name,flush=True)
    try:
        base=args.baseline_upload.resolve() if args.baseline_upload else out/'base'
        if not args.baseline_upload: run('prior',[sys.executable,PACKAGE/'scripts/accept_upload.py','--sdk',sdk,'--compiler',compiler,'--openssl-root',args.openssl_root.resolve(),'--out-dir',base])
        prior=json.loads((base/'acceptance.json').read_text());require_baseline(prior,sdk,compiler,report['source_sha256']);assert prior['status']=='passed' and prior['source_sha256']==report['source_sha256'],'prior sources differ'
        report['base']=prior
        tcp=args.baseline_tcp.resolve() if args.baseline_tcp else out/'tcp-base'
        if not args.baseline_tcp: run('tcp-facade',[sys.executable,PACKAGE/'scripts/accept_tcp_upload.py','--sdk',sdk,'--compiler',compiler,'--baseline',base/'base/base/base/core','--out-dir',tcp])
        tcp_report=json.loads((tcp/'acceptance.json').read_text());assert tcp_report['status']=='passed' and tcp_report['source_sha256']==report['source_sha256']['http'],'TCP sources differ'
        assert tcp_report['compiler_sha256']==prior['compiler_sha256']==report['compiler_sha256'] and tcp_report['sdk_manifest_sha256']==prior['sdk_manifest_sha256']==report['sdk_manifest_sha256']
        report['tcp_base']=tcp_report
        client_base=prior['base']['base']['base']
        links=[v for row in client_base['commands'] if row['name']=='https-build' for v in row['command'] if v.startswith(('--link-arg=','--platform-archive='))]
        project=out/'consumer';project.mkdir()
        deps=''.join('  '+name+':\n    path: '+json.dumps(str(base/'base/base/base/project'/name))+'\n' for name in ('http','http_tls','tls','net_core'))
        (project/'package.yaml').write_text('name: https_upload_consumer\ndependencies:\n'+deps)
        shutil.copyfile(PACKAGE/'tests/data/https_upload_consumer.ny.in',project/'main.ny')
        binary=out/('https-upload'+suffix)
        run('consumer',[compiler,'build',project/'main.ny','--link','-O2','-j','4','--out-dir',out/'objects','-o',binary,*links])
        for case in CASES:
            print('BEGIN '+CASES[case],flush=True);report['cases'].append(Peer(case,base/'base/base/base/fixtures').run(binary,env,out/('case-'+str(case)+'.log')));save()
        assert report['source_sha256']=={name:sources(path) for name,path in packages.items()},'sources changed during acceptance'
        report['status']='passed'
    except (OSError,ValueError,AssertionError,RuntimeError,subprocess.SubprocessError) as error:
        report['status']='failed';report['error']=str(error);print(str(error),file=sys.stderr)
    save();print(out/'acceptance.json');return 0 if report['status']=='passed' else 1

if __name__=='__main__': raise SystemExit(main())
