#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Exercise connected TCP/optional verified HTTPS clients with controlled loopback peers."""
from __future__ import annotations
import argparse, ast, hashlib, json, os
from pathlib import Path
import platform, shutil, socket, ssl, subprocess, sys, threading, time
from accept import digest, sources
from sdk_layout import sdk_package, sdk_entry
PACKAGE=Path(__file__).resolve().parents[1]
COMMON={1:'fixed-informational',2:'chunked-upload-trailers',3:'eof-body',4:'truncated-fixed',5:'framing-conflict',6:'upgrade-rejected',8:'cancelled-constructor',9:'expired-constructor',10:'cancel-buffered-body',11:'expire-buffered-body',12:'retained-options',17:'durable-completion',18:'response-body-cap',19:'informational-cap',20:'missing-final',22:'ipv4-identity',23:'dns-case',25:'deadline-native-wait',27:'invalid-request-adoption',28:'expect-rejected',29:'streaming-large-response',40:'url-dns-open',41:'url-numeric-bypass',42:'url-unspecified-family',43:'url-escaped-query',44:'url-native-deadline',45:'url-retained-options'}
SECURE={7:'unauthenticated-eof',13:'host-peer-mismatch',14:'certificate-name-mismatch',15:'trust-unavailable',16:'alpn-offer-rejected',24:'ipv6-identity',31:'alpn-absent',32:'certificate-untrusted'}
REJECT={8,9,13,15,16,27,28}
FAIL={4,5,6,7,8,9,10,11,13,14,15,16,17,18,19,20,25,27,28,32,44}

def consumer(secure: bool) -> str:
    text=(PACKAGE/'tests/data/client_consumer.ny.in').read_text()
    if secure:
        error='HttpsClientError';client='HttpsClient'
        provider='''  if error.tls_error != nil {
    let stream: TlsStreamError = error.tls_error as TlsStreamError;
    if stream.transport_error != nil {
      let kind: NetErrorKind = (stream.transport_error as NetError).kind;
      if n == 8 || n == 10 { return kind == NetErrorKind.Cancelled; }
      if n == 9 || n == 11 || n == 25 || n == 44 { return kind == NetErrorKind.TimedOut; }
    }
    if stream.tls_error != nil {
      let kind: TlsErrorKind = (stream.tls_error as TlsError).kind;
      if n == 8 || n == 10 { return kind == TlsErrorKind.Cancelled; }
      if n == 9 || n == 11 || n == 25 || n == 44 { return kind == TlsErrorKind.TimedOut; }
      if n == 7 { return kind == TlsErrorKind.UnexpectedEof; }
      if n == 14 { return kind == TlsErrorKind.PeerNameMismatch; }
      if n == 15 { return kind == TlsErrorKind.TrustUnavailable; }
      if n == 32 { return kind == TlsErrorKind.CertificateRejected; }
    }
  }'''
        config='''  var peer: string = "localhost";
  if n >= 40 { peer = ""; }
  if n == 13 || n == 14 { peer = "wrong.test"; }
  if n == 22 { peer = "127.0.0.1"; }
  if n == 24 { peer = "::1"; }
  var ca: string = string.ViewFrom(HttpFixtureCa(),HttpFixtureCaLength());
  if n == 15 { ca = ca.Concat(".missing"); }
  var settings: TlsClientConfig = TlsClientConfig{peer_name: peer,ca_file: ca};
  if n == 16 { settings.alpn = "h2"; }'''
        constructor='HttpsClient.New(connection,settings,buffer(request),buffer(payload),limits,options)'
        imports='import "tls:tls.ny";\nimport "http_tls:http_tls.ny";'
        shutdown='  if client.Shutdown().IsErr() { Console.Eprintln("graceful TLS shutdown failed"); return 19; }'
    else:
        error='HttpClientError';client='HttpTcpClient';config='';imports='';shutdown=''
        constructor='HttpTcpClient.New(connection,buffer(request),buffer(payload),limits,options)'
        provider='''  if error.transport_error != nil {
    let kind: NetErrorKind = (error.transport_error as NetError).kind;
    if n == 8 || n == 10 { return kind == NetErrorKind.Cancelled; }
    if n == 9 || n == 11 || n == 25 || n == 44 { return kind == NetErrorKind.TimedOut; }
  }'''
    for key,value in {'TLS_IMPORTS':imports,'CLIENT':client,'ERROR':error,'EXPECT_PROVIDER':provider,'CONFIG':config,'CONSTRUCTOR':constructor,'SHUTDOWN':shutdown,'SCHEME':'https' if secure else 'http','OPEN':('HttpsClient.Open(url,settings,\"POST\",new <HttpField>[0],buffer(payload),limits,resolver,dial_options,options)' if secure else 'HttpTcpClient.Open(url,\"POST\",new <HttpField>[0],buffer(payload),limits,resolver,dial_options,options)')}.items():text=text.replace('@@'+key+'@@',value)
    assert '@@' not in text
    return text

def url_control_consumer(secure: bool) -> str:
    text=(PACKAGE/'tests/data/url_control_consumer.ny.in').read_text()
    replacements={
        'TLS_IMPORTS':'import "tls:tls.ny";\nimport "http_tls:http_tls.ny";' if secure else '',
        'SCHEME':'https' if secure else 'http',
        'OTHER_SCHEME':'http' if secure else 'https',
        'SCHEME_ERROR':'HttpErrorKind.InvalidArgument' if secure else 'HttpErrorKind.Unsupported',
        'CONFIG':('var settings: TlsClientConfig = TlsClientConfig{ca_file: \"unused-explicit-ca\"}; if n == 9 { settings.peer_name = \"wrong.test\"; } if n == 10 { settings.alpn = \"h2\"; }' if secure else ''),
        'CLIENT':'HttpsClient' if secure else 'HttpTcpClient',
        'ERROR':'HttpsClientError' if secure else 'HttpClientError',
        'OPEN':'HttpsClient.Open(url,settings,"GET",fields,NetBuffer{},limits,resolver,dial,options)' if secure else 'HttpTcpClient.Open(url,"GET",fields,NetBuffer{},limits,resolver,dial,options)',
        'NETWORK_ERROR':('if error.tls_error == nil || (error.tls_error as TlsStreamError).transport_error == nil { return 18; } let network: NetError = ((error.tls_error as TlsStreamError).transport_error as NetError);' if secure else 'if error.transport_error == nil { return 18; } let network: NetError = error.transport_error as NetError;'),
    }
    for key,value in replacements.items():text=text.replace('@@'+key+'@@',value)
    assert '@@' not in text
    return text

class Peer:
    def __init__(self,case:int,secure:bool,fixtures:Path):
        self.case=case;self.secure=secure;self.fixtures=fixtures
        self.socket=socket.socket();self.socket.bind(('127.0.0.1',0));self.socket.listen(1);self.socket.settimeout(10)
        self.port=self.socket.getsockname()[1];self.error=None;self.record={};self.thread=threading.Thread(target=self.serve,daemon=True)
    def serve(self):
        connection=None;phase='accept';request_ok=False
        try:
            connection,_=self.socket.accept();connection.settimeout(8);self.record['accepted']=True
            if self.secure:
                phase='handshake';context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(str(self.fixtures/'peer.pem'),str(self.fixtures/'peer.key'))
                if self.case!=31:context.set_alpn_protocols(['http/1.1'])
                connection=context.wrap_socket(connection,server_side=True);self.record['alpn']=connection.selected_alpn_protocol();self.record['tls_version']=connection.version()
                assert self.record['alpn']==(None if self.case==31 else 'http/1.1'),self.record
            phase='request'
            host='localhost'
            if self.case in (22,41):host='127.0.0.1'
            if self.case==23:host='LOCALHOST'
            if self.case==24:host='[0:0:0:0:0:0:0:1]'
            target='/resource?x=%2f' if self.case==43 else '/resource'
            head=f'POST {target} HTTP/1.1\r\nHost: {host}:{self.port}\r\n'
            if self.case==2:
                head+='Transfer-Encoding: chunked\r\n\r\n';body=b'4000\r\n'+b'q'*16384+b'\r\ne20\r\n'+b'q'*3616+b'\r\n0\r\n\r\n'
            else:head+='Content-Length: 3\r\n\r\n';body=b'abc'
            expected=head.encode()+body;actual=b''
            while len(actual)<len(expected):
                part=connection.recv(min(97,len(expected)-len(actual)))
                if not part:break
                actual+=part
            if self.case in REJECT:
                assert not actual,'rejected constructor sent application bytes';self.record['request_bytes']=0;return
            assert actual==expected,('request mismatch',len(actual),len(expected),actual[:100])
            # Look for duplicate trailing upload bytes before replying; protocol control records are not payload.
            connection.settimeout(.025)
            try:extra=connection.recv(1)
            except (socket.timeout,TimeoutError):extra=b''
            assert not extra,'duplicate trailing request bytes'
            connection.settimeout(8);request_ok=True
            self.record.update(request_bytes=len(actual),request_sha256=hashlib.sha256(actual).hexdigest(),request_exact=True)
            phase='reply'
            if self.case in (25,44):time.sleep(1.0)
            else:
                if self.case==2:response=b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;x=y\r\nhe\r\n3\r\nllo\r\n0\r\nX-End: kept\r\n\r\n'
                elif self.case in (3,7):response=b'HTTP/1.1 200 OK\r\n\r\nhello'
                elif self.case==4:response=b'HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort'
                elif self.case==5:response=b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n'
                elif self.case==6:response=b'HTTP/1.1 101 Switching\r\n\r\nOPAQUE'
                elif self.case==19:response=b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Hints\r\n\r\n'
                elif self.case==20:response=b'HTTP/1.1 103 Hints\r\n\r\n'
                elif self.case==29:response=b'HTTP/1.1 200 OK\r\nContent-Length: 40000\r\n\r\n'+b'r'*40000
                else:response=b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello'
                if self.case==1:response=b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Hints\r\n\r\n'+response
                if self.case in (1,2):
                    for start in range(0,len(response),7):connection.sendall(response[start:start+7])
                else:connection.sendall(response)
                self.record['response_bytes']=len(response)
            phase='shutdown'
            if self.secure:
                if self.case==7:
                    raw=connection.detach();socket.socket(fileno=raw).close();connection=None;self.record['closure']='raw-eof'
                else:connection=connection.unwrap();self.record['closure']='close-notify'
        except BaseException as error:
            allowed=False
            if not isinstance(error,(socket.timeout,TimeoutError)):
                if self.secure and phase=='handshake' and self.case in REJECT|{14,32} and isinstance(error,(ssl.SSLError,ConnectionError)):allowed=True
                if request_ok and phase in ('reply','shutdown') and self.case in FAIL and isinstance(error,(ssl.SSLError,ConnectionError,OSError)):allowed=True
            if allowed:self.record['expected_peer_error']=str(error)
            else:self.error=repr(error)
        finally:
            if connection is not None:connection.close()
            self.socket.close()
    def run(self,binary:Path,environment:dict,log:Path):
        self.thread.start();env=environment|{'HTTP_TEST_PORT':str(self.port),'HTTP_TEST_CASE':str(self.case),'HTTP_TEST_CA':str(self.fixtures/('wrong-ca.pem' if self.case==32 else 'ca.pem'))}
        started=time.monotonic()
        with log.open('w') as output:done=subprocess.run([str(binary)],env=env,stdout=output,stderr=subprocess.STDOUT,timeout=12)
        self.thread.join(10)
        if self.thread.is_alive():raise RuntimeError('peer did not terminate')
        if done.returncode or self.error:raise RuntimeError(f'case {self.case}: exit={done.returncode}, peer={self.error}; see {log}')
        if not self.record.get('accepted'):raise RuntimeError('peer never accepted')
        if self.case not in REJECT|{14,32} and not self.record.get('request_exact'):raise RuntimeError('request was not checked')
        return {'case':self.case,'name':(COMMON|SECURE)[self.case],'status':'passed','duration_seconds':round(time.monotonic()-started,3),**self.record}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--resume',action='store_true');p.add_argument('--resume-source-commit');p.add_argument('--sdk',type=Path,required=True);p.add_argument('--compiler',type=Path,required=True)
    p.add_argument('--http-tls',type=Path);p.add_argument('--tls',type=Path,default=PACKAGE.parent/'tls');p.add_argument('--openssl-root',type=Path);p.add_argument('--openssl-cli');p.add_argument('--out-dir',type=Path,required=True)
    a=p.parse_args();sdk=a.sdk.resolve();compiler=a.compiler.resolve();out=a.out_dir.resolve();secure=a.http_tls is not None
    if out.exists() and any(out.iterdir()) and not a.resume:p.error('new/empty external output required')
    if secure and a.openssl_root is None:p.error('--openssl-root is required for HTTPS')
    if PACKAGE==out or PACKAGE in out.parents:p.error('outputs must be outside package')
    out.mkdir(parents=True,exist_ok=True);win=platform.system()=='Windows';suffix='.exe' if win else '';os_name={'Darwin':'darwin','Linux':'linux','Windows':'windows'}[platform.system()];arch='arm64' if platform.machine().lower() in ('arm64','aarch64') else 'x86_64';host=os_name+'-'+arch
    kit=sdk/'hosts'/host/'llvm/bin';runtime=sdk_package(sdk, host, 'stdlib');net=PACKAGE.parent/'net_core'
    env={k:v for k,v in os.environ.items() if not k.startswith(('NYRA','DYLD_','LD_')) and k!='LLVM_PREFIX'};env.update(CC=str(kit/('clang'+suffix)),AR=str(kit/('llvm-ar'+suffix)),PATH=str(kit)+os.pathsep+env.get('PATH',''),NYRA_SDK_ROOT=str(sdk),NYRA_KERNEL_ROOT=str(out/'source-fallback-disabled'))
    if os_name=='darwin':
        target=next(line.split(':',1)[1].strip().strip('\"') for line in (runtime/'manifest.yaml').read_text().splitlines() if line.startswith('target:'))
        env.update(SDKROOT=subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip(),MACOSX_DEPLOYMENT_TARGET=target.split('-apple-macosx',1)[1])
    packages={'http':PACKAGE,'net_core':net}
    if secure:packages|={'http_tls':a.http_tls.resolve(),'tls':a.tls.resolve()}
    report={'format':'nyra-http-connected-clients-v1','status':'running','host':host,'compiler_origin':'public-sdk' if digest(compiler)==json.loads((sdk/'manifest.json').read_text())['tools']['nyrac']['sha256'] else 'source-candidate','compiler_sha256':digest(compiler),'sdk_version':json.loads((sdk/'manifest.json').read_text())['version'],'sdk_manifest_sha256':digest(sdk/'manifest.json'),'source_fallback_disabled':True,'source_sha256':{name:sources(path) for name,path in packages.items()},'commands':[],'cases':[],'url_control_cases':[],'plain_tls_link_inputs':[]}
    completed=set()
    if a.resume:
        prior=json.loads((out/'acceptance.json').read_text())
        if prior['sdk_manifest_sha256']!=report['sdk_manifest_sha256'] or prior['compiler_sha256']!=report['compiler_sha256'] or prior['host']!=host:raise ValueError('resume SDK/compiler/host changed')
        if not a.resume_source_commit or len(a.resume_source_commit)!=40:raise ValueError('original tooling commit is required for interrupted-gate continuation')
        for package, files in prior['source_sha256'].items():
            for relative, checksum in files.items():
                current=packages[package]/relative
                if digest(current)==checksum:continue
                if package!='http' or Path(relative).suffix!='.py':raise ValueError('resume package/fixture input changed')
                old=subprocess.check_output(['git','show',a.resume_source_commit+':'+relative],cwd=PACKAGE)
                if hashlib.sha256(old).hexdigest()!=checksum:raise ValueError('original tooling snapshot differs from receipt')
                def semantic_helpers(text):
                    return [ast.dump(node,include_attributes=False) for node in ast.parse(text).body if not isinstance(node,(ast.Import,ast.ImportFrom)) and not (isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name=='main') and not isinstance(node,ast.If)]
                if semantic_helpers(old)!=semantic_helpers(current.read_bytes()):raise ValueError('test generator/peer inputs changed; cannot reuse cases')
        report['resume_original_tooling_commit']=a.resume_source_commit
        completed={row['name'] for row in prior['commands'][:-1]}
        report['commands']=list(prior['commands'][:-1])
        report['previous_attempt']=prior
        report['resume_scope']='Reuse complete core/build prerequisites; retry interrupted compilation and run connected behavior cases.'
    def save():(out/'acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(name,cmd):
        if name in completed:
            if not (out/(name+'.log')).is_file():raise ValueError('missing completed step log')
            return
        report['commands'].append({'name':name,'command':list(map(str,cmd))});save();print('BEGIN '+name,flush=True)
        with (out/(name+'.log')).open('w') as log:subprocess.run(list(map(str,cmd)),env=env,stdout=log,stderr=subprocess.STDOUT,timeout=300,check=True)
        print('END '+name,flush=True)
    try:
        run('core',[sys.executable,PACKAGE/'scripts/accept.py','--sdk',sdk,'--compiler',compiler,'--net-core',net,'--out-dir',out/'core'])
        report['core']=json.loads((out/'core/acceptance.json').read_text())
        stage=out/'project'
        for name,path in packages.items():
            shutil.copytree(path,stage/name,dirs_exist_ok=a.resume,ignore=shutil.ignore_patterns('.git','docs','__pycache__'))
            deps='  stdlib:\n    precompiled: '+json.dumps(str(sdk_entry(sdk, host, 'stdlib')))+'\n'
            for dep in {'http':['net_core'],'http_tls':['http','tls','net_core'],'tls':['net_core'],'net_core':[]}[name]:deps+='  '+dep+':\n    path: ../'+dep+'\n'
            (stage/name/'package.yaml').write_text('name: '+name+'\nversion: 0.1.0\nlicense: MIT\ndependencies:\n'+deps+'directories:\n  interface:\n    - interface\n  private:\n    - private\n    - tests\n')
        report['staged_manifest_sha256']={name:digest(stage/name/'package.yaml') for name in packages}
        fixture=out/'fixture.o';run('fixture',[env['CC'],'-std=c11','-O2','-Wall','-Wextra','-Werror','-D_CRT_SECURE_NO_WARNINGS','-c',PACKAGE/'tests/data/client_fixture.c','-o',fixture])
        fixtures=out/'fixtures';fixtures.mkdir(exist_ok=a.resume)
        base_links=['--platform-archive='+str(runtime/'lib/libnyra_platform.a'),'--link-arg='+str(out/'core/net-native/libnet_core_native.a'),'--link-arg='+str(fixture)]
        base_links+=['--link-arg=-l'+name for name in (('ws2_32','iphlpapi') if win else ('pthread',))]
        dns_flags=['--cflag=-DNET_CORE_TEST_DNS']
        if win:dns_flags.append('--cflag=-Dnet_core_os_wake_open=net_core_test_real_wake_open')
        run('dns-test-native',[sys.executable,net/'scripts/build_native.py','--out-dir',out/'dns-test-native','--cc',env['CC'],'--ar',env['AR'],*dns_flags])
        dns_fixture=out/'dns-fixture.o'
        run('dns-fixture',[env['CC'],'-std=c11','-O2','-Wall','-Wextra','-Werror','-c',net/'tests/native/n3_fixture.c','-o',dns_fixture])
        for mode in (['tcp','https'] if secure else ['tcp']):
            directory=out/(mode+'-consumer');directory.mkdir(exist_ok=a.resume);deps='  http:\n    path: ../project/http\n  net_core:\n    path: ../project/net_core\n'
            links=base_links.copy()
            if mode=='https':
                deps+='  http_tls:\n    path: ../project/http_tls\n  tls:\n    path: ../project/tls\n'
                ssl_root=a.openssl_root.resolve();bundled_cli=ssl_root/'apps'/('openssl'+suffix)
                openssl=a.openssl_cli or (str(bundled_cli) if bundled_cli.exists() else 'openssl')
                pin=json.loads((a.tls.resolve()/'openssl.lock.json').read_text())
                assert pin['version']=='3.5.9' and 'OPENSSL_FULL_VERSION_STR \"3.5.9\"' in (ssl_root/'include/openssl/opensslv.h').read_text(),'pinned client OpenSSL headers required'
                fixture_config=fixtures/'openssl.cnf';fixture_config.write_text('[req]\ndistinguished_name=dn\n[dn]\n');env['OPENSSL_CONF']=str(fixture_config)
                run('openssl-version',[openssl,'version'])
                run('tls-native',[sys.executable,a.tls.resolve()/'scripts/build_native.py','--openssl-root',ssl_root,'--out-dir',out/'tls-native','--cc',env['CC'],'--ar',env['AR']])
                libs=[ssl_root/('libssl.lib' if win else 'libssl.a'),ssl_root/('libcrypto.lib' if win else 'libcrypto.a')]
                links+=['--link-arg='+str(out/'tls-native/libtls_native.a'),*['--link-arg='+str(v) for v in libs]]
                links+=['--link-arg=-l'+v for v in (('gdi32','advapi32','crypt32','user32') if win else (('dl',) if os_name=='linux' else ()))]
                report['openssl']={'version':'3.5.9','pin_sha256':digest(a.tls.resolve()/'openssl.lock.json'),'libraries_sha256':{v.name:digest(v) for v in libs},'server':ssl.OPENSSL_VERSION,'fixture_cli':(out/'openssl-version.log').read_text().strip()}
                for prefix in ['ca','wrong-ca']:
                    run(prefix,[openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','2','-sha256','-subj','/CN=HTTP loopback '+prefix,'-keyout',fixtures/(prefix+'.key'),'-out',fixtures/(prefix+'.pem'),'-addext','basicConstraints=critical,CA:TRUE'])
                run('peer-key',[openssl,'req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',fixtures/'peer.key','-out',fixtures/'peer.csr'])
                (fixtures/'peer.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n')
                run('peer-cert',[openssl,'x509','-req','-in',fixtures/'peer.csr','-CA',fixtures/'ca.pem','-CAkey',fixtures/'ca.key','-CAcreateserial','-days','2','-sha256','-extfile',fixtures/'peer.ext','-out',fixtures/'peer.pem'])
                run('https-production',[compiler,'precompile',stage/'http_tls/http_tls.ny','-O2','-j','4','--out-dir',out/'https-production-objects','-o',out/'https-production'])
                run('https-production-imports',[kit/('llvm-nm'+suffix),'-u',out/'https-production/lib/libpackage.a'])
                forbidden=('AddFail','HttpFixture','nyra_tls_test_','client_assert','http_test_')
                assert not any(v in (out/'https-production-imports.log').read_text() for v in forbidden),'test symbols leaked into HTTPS archive'
                report['https_production_fixture_imports']=[]
            (directory/'package.yaml').write_text('name: '+mode+'_consumer\ndependencies:\n'+deps);(directory/'main.ny').write_text(consumer(mode=='https'))
            binary=out/(mode+'-consumer-test'+suffix)
            run(mode+'-build',[compiler,'build',directory/'main.ny','--link','-O2','-j','4','--out-dir',out/(mode+'-objects'),'-o',binary,*links])
            if mode=='tcp':
                run('plain-imports',[kit/('llvm-nm'+suffix),'-u',binary]);assert not any(v in (out/'plain-imports.log').read_text() for v in ('SSL_','OPENSSL_','nyra_tls_')),'plain consumer imported TLS'
            for case,name in sorted((COMMON|SECURE if mode=='https' else COMMON).items()):
                print('BEGIN '+mode+'-'+name,flush=True);peer=Peer(case,mode=='https',fixtures);record=peer.run(binary,env,out/(mode+'-'+str(case)+'.log'));report['cases'].append({'transport':mode,**record});save();print('END '+mode+'-'+name,flush=True)
            (directory/'main.ny').write_text(url_control_consumer(mode=='https'))
            control_links=[v.replace(str(out/'core/net-native/libnet_core_native.a'),str(out/'dns-test-native/libnet_core_native.a')) for v in links]+['--link-arg='+str(dns_fixture)]
            control_binary=out/(mode+'-url-control'+suffix)
            run(mode+'-url-control-build',[compiler,'build',directory/'main.ny','--link','-O2','-j','4','--out-dir',out/(mode+'-url-control-objects'),'-o',control_binary,*control_links])
            for case,name in {1:'dns-name-not-found',2:'blocked-dns-deadline',3:'blocked-dns-cancel',4:'expired-before-dns',5:'closed-resolver',6:'reserved-host-before-dns',7:'address-cap-before-dns',8:'scheme-before-dns',11:'request-cap-before-dns',**({9:'peer-before-dns',10:'alpn-before-dns'} if mode=='https' else {})}.items():
                identity=mode+'-url-control-'+name;print('BEGIN '+identity,flush=True)
                with (out/(identity+'.log')).open('w') as log:subprocess.run([str(control_binary)],env=env|{'HTTP_TEST_CASE':str(case)},stdout=log,stderr=subprocess.STDOUT,timeout=12,check=True)
                report['url_control_cases'].append({'transport':mode,'case':case,'name':name,'status':'passed'});save();print('END '+identity,flush=True)
        for name,path in packages.items():assert sources(path)==report['source_sha256'][name],'source changed during acceptance: '+name
        report['status']='passed'
    except (OSError,ValueError,AssertionError,RuntimeError,subprocess.SubprocessError) as error:
        report['status']='failed';report['error']=str(error);print(str(error),file=sys.stderr)
    save();print(out/'acceptance.json');return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
