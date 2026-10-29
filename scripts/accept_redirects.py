#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Accept explicit redirect decisions with ordinary TCP/optional verified HTTPS multi-hop peers."""
from __future__ import annotations
import argparse, json, os, platform, socket, ssl, subprocess, sys, threading, time
from pathlib import Path
from accept import digest, sources
PACKAGE=Path(__file__).resolve().parents[1]
CASES={1:'post-302-get',2:'post-307-replay-opt-in',3:'post-307-rejected',4:'cross-origin-filter',5:'cross-origin-rejected',6:'cycle-hop-limit',7:'duplicate-location',8:'cancel-before-follow',9:'relative-303-no-body-drain',10:'malformed-location',11:'original-deadline',12:'missing-location-terminal'}

def consumer(secure: bool) -> str:
    text=(PACKAGE/'tests/data/redirect_consumer.ny.in').read_text()
    mapping={'TLS_IMPORTS':'import "tls:tls.ny";\nimport "http_tls:http_tls.ny";' if secure else '', 'SCHEME':'https' if secure else 'http','CLIENT':'HttpsClient' if secure else 'HttpTcpClient','ERROR':'HttpsClientError' if secure else 'HttpClientError','CONFIG':'let settings: TlsClientConfig = TlsClientConfig{ca_file:string.ViewFrom(HttpFixtureCa(),HttpFixtureCaLength())};' if secure else '', 'OPEN':'HttpsClient.OpenRequest(request,settings,resolver,HttpDialOptions{family:IpFamily.V4})' if secure else 'request.OpenTcp(resolver,HttpDialOptions{family:IpFamily.V4})','SHUTDOWN':'if client.Shutdown().IsErr() { return 15; }' if secure else ''}
    for key,value in mapping.items():text=text.replace('@@'+key+'@@',value)
    assert '@@' not in text
    return text

class RedirectPeer:
    def __init__(self,case:int,secure:bool,fixtures:Path,*,automatic:bool=False,mixed:bool=False):
        self.case=case;self.secure=secure;self.fixtures=fixtures;self.automatic=automatic;self.mixed=mixed;self.error=None;self.records=[]
        self.listeners=[]
        for _ in range(2):
            listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(4);listener.settimeout(5);self.listeners.append(listener)
        self.ports=[listener.getsockname()[1] for listener in self.listeners]
        self.thread=threading.Thread(target=self.serve,daemon=True)
    def serve(self):
        connection=None
        try:
            count=3 if self.case==6 else (2 if self.case in (1,2,4,9) else 1)
            for hop in range(count):
                index=1 if self.case==4 and hop==1 else 0
                connection,_=self.listeners[index].accept();connection.settimeout(5)
                secure=self.secure or (self.mixed and hop>0)
                if secure:
                    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.set_alpn_protocols(['http/1.1']);context.load_cert_chain(self.fixtures/'peer.pem',self.fixtures/'peer.key');connection=context.wrap_socket(connection,server_side=True)
                    assert connection.selected_alpn_protocol()=='http/1.1'
                verb='GET' if self.case in (4,5,6,13) or (hop>0 and self.case in (1,9)) else 'POST'
                body=b'' if verb=='GET' else b'abc'
                target='/dir/start' if hop==0 else (f'/hop{hop}' if self.case==6 else ('/next/leaf?x=%2f' if self.case==9 else '/next'))
                fields=[('Authorization','Bearer secret'),('Cookie','sid=secret'),('X-Secret','secret'),('Accept','text/plain'),('Content-Type','text/plain'),('Connection','X-Hop'),('X-Hop','remove')]
                if hop>0:
                    fields=[v for v in fields if v[0] not in ('Connection','X-Hop')]
                    if self.case in (1,9):fields=[v for v in fields if v[0]!='Content-Type']
                    if self.case==4:fields=[v for v in fields if v[0] in ('Accept','Content-Type')]
                head=f'{verb} {target} HTTP/1.1\r\nHost: localhost:{self.ports[index]}\r\nContent-Length: {len(body)}\r\n'+''.join(f'{k}: {v}\r\n' for k,v in fields)+'\r\n'
                expected=head.encode()+body;actual=b''
                while len(actual)<len(expected):
                    part=connection.recv(min(73,len(expected)-len(actual)))
                    if not part:break
                    actual+=part
                assert actual==expected,('request mismatch',hop,actual,expected)
                record={'hop':hop,'request_exact':True,'method':verb,'target':target,'body_bytes':len(body),'host_port':self.ports[index]};self.records.append(record)
                terminal=(hop==count-1 and self.case in (1,2,4,9)) or self.case==12
                if terminal:
                    status=302 if self.case==12 else 200
                    connection.sendall(f'HTTP/1.1 {status} Done\r\nContent-Length: 5\r\n\r\nhello'.encode())
                    if secure:connection=connection.unwrap();record['closure']='close-notify'
                else:
                    location='../next';status=302
                    if self.case in (2,3):status=307
                    if self.case in (4,5):location=f'{"https" if self.secure or self.mixed else "http"}://localhost:{self.ports[1]}/next'
                    if self.case==6:location=f'/hop{hop+1}'
                    if self.case==9:status=303;location='../next/./leaf?x=%2f#ignored'
                    if self.case==10:location='bad%/../next'
                    if self.case==13:location=f'http://localhost:{self.ports[1]}/next'
                    header=f'HTTP/1.1 {status} Redirect\r\nLocation: {location}\r\n'
                    if self.case==7:header+='Location: /other\r\n'
                    # A large advertised body is intentionally never sent/drained before following.
                    if self.automatic and self.case in (8,11):
                        connection.sendall(b'HTTP/1.1 103 Hints\r\n\r\n')
                    connection.sendall((header+'Content-Length: 1000000\r\n\r\n').encode())
                    try:extra=connection.recv(1)
                    except (ssl.SSLError,ConnectionError):extra=b''
                    assert not extra,'old connection reused or duplicate request bytes';record['old_connection_closed']=True
                connection.close();connection=None
            # A rejected or completed chain must not open an unrequested connection.
            for listener in self.listeners:
                listener.settimeout(.05)
                try:unexpected,_=listener.accept()
                except socket.timeout:continue
                unexpected.close();raise AssertionError('unexpected extra redirect connection')
        except BaseException as error:self.error=repr(error)
        finally:
            if connection is not None:connection.close()
            for listener in self.listeners:listener.close()
    def run(self,binary:Path,env:dict,out:Path):
        self.thread.start();start=time.monotonic()
        with out.open('w') as log:done=subprocess.run([str(binary)],env=env|{'HTTP_TEST_PORT':str(self.ports[0]),'HTTP_TEST_CASE':str(self.case),'HTTP_TEST_CA':str(self.fixtures/'ca.pem')},stdout=log,stderr=subprocess.STDOUT,timeout=15)
        self.thread.join(6)
        if self.thread.is_alive() or done.returncode or self.error:raise RuntimeError(f'case {self.case}: exit={done.returncode}, peer={self.error}; see {out}')
        return {'case':self.case,'name':(CASES|{13:'https-downgrade-rejected'})[self.case],'status':'passed','duration_seconds':round(time.monotonic()-start,3),'requests':self.records}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--sdk',type=Path,required=True);p.add_argument('--compiler',type=Path,required=True);p.add_argument('--http-tls',type=Path);p.add_argument('--tls',type=Path,default=PACKAGE.parent/'tls');p.add_argument('--openssl-root',type=Path);p.add_argument('--openssl-cli');p.add_argument('--out-dir',type=Path,required=True);a=p.parse_args()
    out=a.out_dir.resolve();secure=a.http_tls is not None;sdk=a.sdk.resolve();compiler=a.compiler.resolve()
    if out.exists() and any(out.iterdir()):p.error('new/empty external output required')
    if out==PACKAGE or PACKAGE in out.parents:p.error('outputs must be outside package')
    if secure and a.openssl_root is None:p.error('--openssl-root required for HTTPS')
    out.mkdir(parents=True,exist_ok=True)
    suffix='.exe' if platform.system()=='Windows' else '';host={'Darwin':'darwin','Linux':'linux','Windows':'windows'}[platform.system()]+'-'+('arm64' if platform.machine().lower() in ('arm64','aarch64') else 'x86_64');kit=sdk/'hosts'/host/'llvm/bin'
    env={k:v for k,v in os.environ.items() if not k.startswith(('NYRA','DYLD_','LD_')) and k!='LLVM_PREFIX'};env.update(PATH=str(kit)+os.pathsep+env.get('PATH',''),NYRA_SDK_ROOT=str(sdk),NYRA_KERNEL_ROOT=str(out/'source-fallback-disabled'))
    if platform.system()=='Darwin':
        target=next(line.split(':',1)[1].strip().strip('\"') for line in (sdk/'targets'/host/'stdlib/manifest.yaml').read_text().splitlines() if line.startswith('target:'))
        env.update(SDKROOT=subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip(),MACOSX_DEPLOYMENT_TARGET=target.split('-apple-macosx',1)[1])
    packages={'http':PACKAGE,'net_core':PACKAGE.parent/'net_core'}
    if secure:packages|={'http_tls':a.http_tls.resolve(),'tls':a.tls.resolve()}
    report={'format':'nyra-http-redirect-acceptance-v1','status':'running','host':host,'source_sha256':{name:sources(path) for name,path in packages.items()},'cases':[],'commands':[]}
    def save():(out/'acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(name,cmd):
        report['commands'].append({'name':name,'command':list(map(str,cmd))});save();print('BEGIN '+name,flush=True)
        with (out/(name+'.log')).open('w') as log:subprocess.run(list(map(str,cmd)),env=env,stdout=log,stderr=subprocess.STDOUT,timeout=600,check=True)
        print('END '+name,flush=True)
    try:
        cmd=[sys.executable,PACKAGE/'scripts/accept_clients.py','--sdk',sdk,'--compiler',compiler,'--out-dir',out/'base']
        if secure:cmd+=['--http-tls',a.http_tls.resolve(),'--tls',a.tls.resolve(),'--openssl-root',a.openssl_root.resolve()]
        if a.openssl_cli:cmd+=['--openssl-cli',a.openssl_cli]
        run('base',cmd);base=json.loads((out/'base/acceptance.json').read_text());assert base['status']=='passed';report['base']=base
        for mode in (['tcp','https'] if secure else ['tcp']):
            directory=out/'base'/('redirect-'+mode);directory.mkdir();deps='  http:\n    path: ../project/http\n  net_core:\n    path: ../project/net_core\n'
            if mode=='https':deps+='  tls:\n    path: ../project/tls\n  http_tls:\n    path: ../project/http_tls\n'
            (directory/'package.yaml').write_text('name: redirect_'+mode+'\ndependencies:\n'+deps);(directory/'main.ny').write_text(consumer(mode=='https'))
            original=next(row['command'] for row in base['commands'] if row['name']==mode+'-build');links=[v for v in original if v.startswith(('--platform-archive=','--link-arg='))]
            binary=out/('redirect-'+mode+suffix)
            run(mode+'-build',[compiler,'build',directory/'main.ny','--link','-O2','-j','4','--out-dir',out/(mode+'-objects'),'-o',binary,*links])
            if mode=='tcp':
                run('plain-imports',[kit/('llvm-nm'+suffix),'-u',binary]);assert not any(v in (out/'plain-imports.log').read_text() for v in ('SSL_','OPENSSL_','nyra_tls_'))
            for case,name in (CASES|({13:'https-downgrade-rejected'} if mode=='https' else {})).items():
                print('BEGIN '+mode+'-'+name,flush=True);record=RedirectPeer(case,mode=='https',out/'base/fixtures').run(binary,env,out/(mode+'-'+str(case)+'.log'));report['cases'].append({'transport':mode,**record});save();print('END '+mode+'-'+name,flush=True)
        for name,path in packages.items():assert report['source_sha256'][name]==sources(path),'sources changed: '+name
        report['status']='passed'
    except (OSError,ValueError,AssertionError,RuntimeError,subprocess.SubprocessError) as error:report['status']='failed';report['error']=str(error);print(str(error),file=sys.stderr)
    save();print(out/'acceptance.json');return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
