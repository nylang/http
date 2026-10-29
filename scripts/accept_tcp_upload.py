#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Accept the producer-driven TCP facade, including constrained receive-window early rejection."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
from accept import digest, sources

PACKAGE = Path(__file__).resolve().parents[1]
CASES = {1:'fixed-producer-adoption-move-admission', 2:'chunked-producer-trailers',
         3:'103-does-not-release-100-gate', 4:'417-without-producer',
         5:'early-final-after-prefix', 6:'finite-continue-fallback',
         7:'coalesced-100-final-no-producer', 8:'cancel-after-observed-head',
         9:'shortage-after-observed-prefix', 10:'constrained-window-early-final',
         11:'partial-final-pauses-past-continue-fallback', 12:'original-deadline-during-continue',
         13:'original-deadline-during-producer', 14:'early-final-truncated-response'}

class Peer:
    def __init__(self, case: int, url: bool = False):
        self.url=url; self.case=case; self.error=None; self.record={}
        self.listener=socket.socket()
        if case==10: self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
        self.listener.bind(('127.0.0.1',0)); self.port=self.listener.getsockname()[1]
        self.listener.listen(1); self.listener.settimeout(10)
        self.thread=threading.Thread(target=self.serve,daemon=True)

    def serve(self):
        connection=None
        try:
            connection,_=self.listener.accept(); connection.settimeout(10)
            framing='Transfer-Encoding: chunked\r\nTrailer: X-End\r\n' if self.case==2 else 'Content-Length: 67108864\r\n' if self.case==10 else 'Content-Length: 6\r\n'
            if self.case in (3,4,6,7,11,12,14): framing+='Expect: 100-continue\r\n'
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
            if self.case in (4,7,8,10,11,12,13,14): payload=b''
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
            if self.case==12: time.sleep(.25)
            if self.case not in (8,9,12,13):
                status={4:417,5:409,7:413,10:413,11:413,14:417}.get(self.case,200)
                prefix=b'HTTP/1.1 100 Continue\r\n\r\n' if self.case==7 else b'HTTP/1.1 103 Hints\r\n\r\n' if self.case==5 else b''
                wire=prefix+f'HTTP/1.1 {status} Result\r\nContent-Length: 2\r\n\r\n'.encode()+(b'no' if status!=200 else b'ok')
                if self.case==11:
                    connection.sendall(wire[:12]); time.sleep(.16); connection.sendall(wire[12:])
                    self.record['partial_head_pause_seconds']=.16
                elif self.case==14:
                    connection.sendall(wire[:-1]); connection.shutdown(socket.SHUT_WR)
                else: connection.sendall(wire)
            suffix=b''
            while True:
                try: part=connection.recv(65536)
                except ConnectionError: break
                if not part: break
                suffix+=part
                assert len(suffix)<67108864,'whole upload sent before early response'
            if self.case==10:
                assert suffix and set(suffix)=={97},'invalid bulk payload'
                self.record['accepted_suffix_observed_bytes']=len(suffix)
            else: assert not suffix,('unexpected upload or retry',suffix)
            self.record['connection_retired']=True
        except BaseException as error: self.error=repr(error)
        finally:
            if connection is not None: connection.close()
            self.listener.close()

    def run(self, binary: Path, env: dict, log: Path):
        self.thread.start(); started=time.monotonic()
        with log.open('w') as output:
            result=subprocess.run([str(binary)],env=env|{'HTTP_TEST_PORT':str(self.port),'HTTP_TEST_CASE':str(self.case)},stdout=output,stderr=subprocess.STDOUT,timeout=20)
        self.thread.join(11)
        if result.returncode or self.thread.is_alive() or self.error:
            raise RuntimeError(f'TCP upload case {self.case}: exit={result.returncode}, peer={self.error}; see {log}')
        return {'case':self.case,'name':CASES[self.case],'status':'passed','elapsed_seconds':time.monotonic()-started,**self.record}

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('sdk','out-dir'): parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--compiler',type=Path)
    parser.add_argument('--baseline',type=Path,help='optional completed core acceptance directory for development; source inventories must match')
    args=parser.parse_args(); sdk=args.sdk.resolve(); out=args.out_dir.resolve()
    if out==PACKAGE or PACKAGE in out.parents or (out.exists() and any(out.iterdir())): parser.error('new/empty external output required')
    out.mkdir(parents=True,exist_ok=True)
    meta=json.loads((sdk/'manifest.json').read_text()); compiler=args.compiler.resolve() if args.compiler else sdk/meta['tools']['nyrac']['path']
    host={'Darwin':'darwin','Linux':'linux','Windows':'windows'}[platform.system()]+'-'+('arm64' if platform.machine().lower() in ('arm64','aarch64') else 'x86_64')
    kit=sdk/'hosts'/host/'llvm/bin'; suffix='.exe' if platform.system()=='Windows' else ''
    env={k:v for k,v in os.environ.items() if not k.startswith(('NYRA','DYLD_','LD_')) and k!='LLVM_PREFIX'}
    env.update(PATH=str(kit)+os.pathsep+env.get('PATH',''),NYRA_SDK_ROOT=str(sdk),NYRA_KERNEL_ROOT=str(out/'source-fallback-disabled'))
    if platform.system()=='Darwin':
        target=next(line.split(':',1)[1].strip().strip('"') for line in (sdk/'targets'/host/'stdlib/manifest.yaml').read_text().splitlines() if line.startswith('target:'))
        env.update(SDKROOT=subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip(),MACOSX_DEPLOYMENT_TARGET=target.split('-apple-macosx',1)[1])
    report={'format':'nyra-http-tcp-upload-v1','status':'running','host':host,'sdk_version':meta['version'],
            'sdk_manifest_sha256':digest(sdk/'manifest.json'),'compiler_sha256':digest(compiler),
            'compiler_origin':'public-sdk' if digest(compiler)==meta['tools']['nyrac']['sha256'] else 'source-candidate',
            'source_fallback_disabled':True,'scope':'Connected streaming TCP convenience client only; TLS and redirect clients retain immutable uploads.',
            'source_sha256':sources(PACKAGE),'net_core_source_sha256':sources(PACKAGE.parent/'net_core'),'commands':[],'cases':[]}
    def save(): (out/'acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(name,cmd):
        command=list(map(str,cmd)); report['commands'].append({'name':name,'command':command}); save(); print('BEGIN '+name,flush=True)
        with (out/(name+'.log')).open('w') as log: subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=1200,check=True)
        print('END '+name,flush=True)
    try:
        base=args.baseline.resolve() if args.baseline else out/'core'
        if not args.baseline: run('core',[sys.executable,PACKAGE/'scripts/accept.py','--sdk',sdk,'--compiler',compiler,'--out-dir',base])
        prior=json.loads((base/'acceptance.json').read_text()); assert prior['status']=='passed'
        assert prior['source_sha256']==sources(PACKAGE) and prior['net_core_source_sha256']==report['net_core_source_sha256'],'baseline sources differ'
        assert prior['compiler_sha256']==report['compiler_sha256'] and prior['sdk_manifest_sha256']==report['sdk_manifest_sha256'],'baseline SDK differs'
        report['base']=prior
        project=out/'consumer';project.mkdir()
        (project/'package.yaml').write_text('name: tcp_upload_consumer\ndependencies:\n  http:\n    path: '+json.dumps(str(base/'project/http'))+'\n  net_core:\n    path: '+json.dumps(str(base/'project/net_core'))+'\n')
        shutil.copyfile(PACKAGE/'tests/data/tcp_upload_consumer.ny.in',project/'main.ny')
        fixture=out/'fixture.o'
        run('fixture',[kit/('clang'+suffix),'-std=c11','-O2','-Wall','-Wextra','-Werror','-D_CRT_SECURE_NO_WARNINGS','-c',PACKAGE/'tests/data/client_fixture.c','-o',fixture])
        links=['--platform-archive='+str(sdk/'targets'/host/'stdlib/lib/libnyra_platform.a'),'--link-arg='+str(base/'net-native/libnet_core_native.a'),'--link-arg='+str(fixture)]
        links+=['--link-arg=-l'+name for name in (('ws2_32','iphlpapi') if suffix else ('pthread',))]
        binary=out/('tcp-upload'+suffix)
        run('consumer',[compiler,'build',project/'main.ny','--link','-O2','-j','4','--out-dir',out/'objects','-o',binary,*links])
        run('plain-imports',[kit/('llvm-nm'+suffix),'-u',binary]); assert not any(s in (out/'plain-imports.log').read_text() for s in ('SSL_','OPENSSL_','nyra_tls_'))
        for case in CASES:
            print('BEGIN '+CASES[case],flush=True);report['cases'].append(Peer(case).run(binary,env,out/('case-'+str(case)+'.log')));save()
        assert report['source_sha256']==sources(PACKAGE) and report['net_core_source_sha256']==sources(PACKAGE.parent/'net_core'),'sources changed during acceptance'
        report['status']='passed'
    except (OSError,ValueError,AssertionError,RuntimeError,subprocess.SubprocessError) as error:
        report['status']='failed';report['error']=str(error);print(str(error),file=sys.stderr)
    save();print(out/'acceptance.json');return 0 if report['status']=='passed' else 1

if __name__=='__main__': raise SystemExit(main())
