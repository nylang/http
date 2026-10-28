#!/usr/bin/env python3
"""Accept the streamed exchange with explicit TCP/TLS drivers; convenience clients remain immutable."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import subprocess
import sys
import threading
from accept import digest, sources

PACKAGE = Path(__file__).resolve().parents[1]
CASES = {1: 'fixed-producer', 2: 'chunked-producer-trailers', 3: '103-before-100',
         4: '417-before-body', 5: 'early-final-revokes-queued-suffix',
         6: 'caller-bounded-continue-release', 7: '100-and-early-final',
         8: 'cancel-before-producer', 9: 'fixed-producer-shortage'}


def consumer(secure: bool) -> str:
    text = (PACKAGE/'tests/data/upload_consumer.ny.in').read_text()
    helpers = '''func wait_tls(io: ref mut TlsStream, queued: Result<AsyncFuture<TlsTransfer>,TlsStreamError>) -> Result<TlsTransfer,TlsStreamError> {
  if queued.IsErr() { return (queued.get_if<TlsStreamError>()) as TlsStreamError; }
  let future: AsyncFuture<TlsTransfer> = (queued.get_if<AsyncFuture<TlsTransfer>>()) as AsyncFuture<TlsTransfer>;
  while !future.is_completed { let polled: Result<int32,TlsStreamError> = io.Poll(-1); if polled.IsErr() { return (polled.get_if<TlsStreamError>()) as TlsStreamError; } }
  let result: Result<TlsTransfer,AsyncError> = future.GetResult(); if result.IsErr() { return TlsStreamError{tls_error:TlsError{kind:TlsErrorKind.InvalidState}}; }
  return (result.get_if<TlsTransfer>()) as TlsTransfer;
}''' if secure else ''
    write = '''let sent: Result<TlsTransfer,TlsStreamError> = wait_tls(io,io.WriteAllAsync(block,options));
    if sent.IsErr() { return false; } let transfer: TlsTransfer = (sent.get_if<TlsTransfer>()) as TlsTransfer;
    if transfer.error!=nil { if transfer.bytes_transferred>(0 as intptr) { exchange.AcknowledgeOutput(transfer.bytes_transferred); } return false; }
    let count: intptr = transfer.bytes_transferred;''' if secure else '''let sent: Result<intptr,NetError> = io.Write(block.Bytes(),options); if sent.IsErr() { return false; }
    let count: intptr = (sent.get_if<intptr>()) as intptr;'''
    read = '''let result: Result<TlsTransfer,TlsStreamError> = wait_tls(io,io.ReadAsync(16384,options)); if result.IsErr() { return false; }
  let transfer: TlsTransfer = (result.get_if<TlsTransfer>()) as TlsTransfer; if transfer.error!=nil { return false; }
  return exchange.Receive(transfer.buffer,transfer.eof).IsOk();''' if secure else '''var storage: <uint8>[16384] = <uint8>[16384]{};
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0],16384 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  let result: Result<intptr,NetError> = io.Read(output,options); if result.IsErr() { return false; }
  let count: intptr = (result.get_if<intptr>()) as intptr;
  let bytes: NetBytes = (output.AsReadOnly().Slice(0 as intptr,count).get_if<NetBytes>()) as NetBytes;
  let copied: Result<NetBuffer,NetError> = NetBuffer.CopyFrom(bytes); if copied.IsErr() { return false; }
  return exchange.Receive((copied.get_if<NetBuffer>()) as NetBuffer,count==(0 as intptr)).IsOk();'''
    opened = '''let config: TlsClientConfig = TlsClientConfig{peer_name:"localhost",ca_file:string.ViewFrom(HttpFixtureCa(),HttpFixtureCaLength()),alpn:"http/1.1"};
  var ready: Result<TlsStream,TlsStreamError> = TlsStream.NewClient(connection,config); if ready.IsErr() { return 20; }
  var io: TlsStream = move((ready.get_if<TlsStream>()) as TlsStream);
  let handshake: Result<TlsTransfer,TlsStreamError> = wait_tls(io,io.HandshakeAsync(options));
  if handshake.IsErr() || ((handshake.get_if<TlsTransfer>()) as TlsTransfer).error!=nil { return 21; }
  let alpn: Result<string,TlsStreamError> = io.SelectedAlpn(); if alpn.IsErr() || !((alpn.get_if<string>()) as string).Equal("http/1.1") { return 22; }''' if secure else 'var io: TcpConnection = move(connection);'
    shutdown = '''let closed: Result<TlsTransfer,TlsStreamError> = wait_tls(io,io.ShutdownAsync(options));
  if closed.IsErr() || ((closed.get_if<TlsTransfer>()) as TlsTransfer).error!=nil { return 23; } io.Close();''' if secure else 'io.Close();'
    for key, value in {'TLS_IMPORT':'import "tls:tls.ny";' if secure else '', 'IO':'TlsStream' if secure else 'TcpConnection',
                       'HELPERS':helpers, 'WRITE':write, 'READ':read, 'OPEN':opened,
                       'ABORT':'io.Close();', 'SHUTDOWN':shutdown}.items():
        text = text.replace('@@'+key+'@@', value)
    assert '@@' not in text
    return text


class UploadPeer:
    def __init__(self, case: int, secure: bool, fixtures: Path):
        self.case, self.secure, self.fixtures = case, secure, fixtures
        self.listener = socket.socket(); self.listener.bind(('127.0.0.1', 0)); self.listener.listen(1); self.listener.settimeout(8)
        self.port = self.listener.getsockname()[1]; self.error = None; self.record = {}
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        connection = None
        try:
            connection, _ = self.listener.accept(); connection.settimeout(8)
            if self.secure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.set_alpn_protocols(['http/1.1'])
                context.load_cert_chain(self.fixtures/'peer.pem', self.fixtures/'peer.key')
                connection = context.wrap_socket(connection, server_side=True)
                assert connection.selected_alpn_protocol() == 'http/1.1'
            framing = 'Transfer-Encoding: chunked\r\nTrailer: X-End\r\n' if self.case == 2 else 'Content-Length: 6\r\n'
            if self.case in (3, 4, 6, 7):
                framing += 'Expect: 100-continue\r\n'
            expected = f'POST /upload HTTP/1.1\r\nHost: localhost:{self.port}\r\n{framing}\r\n'.encode()
            actual = b''
            while not actual.endswith(b'\r\n\r\n'):
                part = connection.recv(1)
                if not part: break
                actual += part
                assert len(actual) <= 4096
            assert actual == expected, ('request head', actual, expected)
            self.record['head_exact'] = True; self.record['head_bytes'] = len(actual)
            if self.case == 8:
                connection.sendall(b'HTTP/1.1 103 Hints\r\n\r\n')
                self.record['abort_checkpoint'] = 'head-observed'
            if self.case == 3:
                connection.sendall(b'HTTP/1.1 103 Hints\r\n\r\n')
                connection.settimeout(.04)
                try: extra = connection.recv(1)
                except socket.timeout: extra = b''
                assert not extra, 'body preceded 100 Continue'
                self.record['body_withheld_before_100'] = True; connection.settimeout(8)
                connection.sendall(b'HTTP/1.1 100 Continue\r\n\r\n')
            payload = b'3\r\nabc\r\n3\r\ndef\r\n0\r\nX-End: yes\r\n\r\n' if self.case == 2 else b'abcdef'
            if self.case in (4, 7, 8): payload = b''
            if self.case in (5, 9): payload = b'abc'
            body = b''
            while len(body) < len(payload):
                part = connection.recv(len(payload)-len(body))
                if not part: break
                body += part
            assert body == payload, ('request body', body, payload)
            self.record['body_exact'] = True; self.record['body_wire_bytes'] = len(body)
            if self.case == 9:
                connection.sendall(b'HTTP/1.1 103 Hints\r\n\r\n')
                self.record['abort_checkpoint'] = 'prefix-observed'
            if self.case not in (8, 9):
                status = {4:417, 5:409, 7:413}.get(self.case, 200)
                prefix = b'HTTP/1.1 100 Continue\r\n\r\n' if self.case == 7 else b''
                content = b'no' if self.case in (4, 5, 7) else b'ok'
                connection.sendall(prefix+f'HTTP/1.1 {status} Result\r\nContent-Length: 2\r\n\r\n'.encode()+content)
            try: extra = connection.recv(1)
            except (ssl.SSLError, ConnectionError): extra = b''
            assert not extra, 'unexpected body suffix or request retry'
            self.record['no_extra_upload_or_retry'] = True
            if self.secure and self.case not in (8, 9):
                connection = connection.unwrap(); self.record['closure'] = 'close-notify'
        except BaseException as error:
            self.error = repr(error)
        finally:
            if connection is not None: connection.close()
            self.listener.close()

    def run(self, binary: Path, env: dict, log: Path):
        self.thread.start()
        with log.open('w') as output:
            result = subprocess.run([str(binary)], env=env|{'HTTP_TEST_PORT':str(self.port), 'HTTP_TEST_CASE':str(self.case), 'HTTP_TEST_CA':str(self.fixtures/'ca.pem')}, stdout=output, stderr=subprocess.STDOUT, timeout=20)
        self.thread.join(9)
        if result.returncode or self.thread.is_alive() or self.error:
            raise RuntimeError(f'upload case {self.case}: exit={result.returncode}, peer={self.error}; see {log}')
        return {'case':self.case, 'name':CASES[self.case], 'status':'passed', **self.record}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('sdk', 'compiler', 'openssl-root', 'out-dir'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--openssl-cli'); args = parser.parse_args()
    sdk, compiler, out = (p.resolve() for p in (args.sdk, args.compiler, args.out_dir))
    if out == PACKAGE or PACKAGE in out.parents or (out.exists() and any(out.iterdir())): parser.error('new/empty external output required')
    out.mkdir(parents=True, exist_ok=True)
    host = {'Darwin':'darwin', 'Linux':'linux', 'Windows':'windows'}[platform.system()]+'-'+('arm64' if platform.machine().lower() in ('arm64', 'aarch64') else 'x86_64')
    suffix = '.exe' if platform.system() == 'Windows' else ''; kit = sdk/'hosts'/host/'llvm/bin'
    env = {k:v for k,v in os.environ.items() if not k.startswith(('NYRA','DYLD_','LD_')) and k!='LLVM_PREFIX'}
    env.update(PATH=str(kit)+os.pathsep+env.get('PATH',''), NYRA_SDK_ROOT=str(sdk), NYRA_KERNEL_ROOT=str(out/'source-fallback-disabled'))
    if platform.system() == 'Darwin':
        target = next(line.split(':',1)[1].strip().strip('"') for line in (sdk/'targets'/host/'stdlib/manifest.yaml').read_text().splitlines() if line.startswith('target:'))
        env.update(SDKROOT=subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip(), MACOSX_DEPLOYMENT_TARGET=target.split('-apple-macosx',1)[1])
    packages = {name:PACKAGE.parent/name for name in ('http','http_tls','tls','net_core')}
    meta = json.loads((sdk/'manifest.json').read_text()); assert digest(sdk/meta['tools']['nyrac']['path'])==meta['tools']['nyrac']['sha256']
    report = {'format':'nyra-http-streamed-exchange-v1','status':'running','host':host,'scope':'Transport-independent streamed exchange with explicit test TCP/TLS drivers; existing convenience and automatic-follow clients remain immutable.',
              'sdk_version':meta['version'],'sdk_manifest_sha256':digest(sdk/'manifest.json'),'compiler_sha256':digest(compiler),'compiler_origin':'public-sdk' if digest(compiler)==meta['tools']['nyrac']['sha256'] else 'source-candidate',
              'source_fallback_disabled':True,'source_sha256':{name:sources(path) for name,path in packages.items()},'commands':[],'cases':[]}
    def save(): (out/'acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(name, cmd):
        command = list(map(str, cmd)); report['commands'].append({'name':name,'command':command}); save(); print('BEGIN '+name,flush=True)
        with (out/(name+'.log')).open('w') as log: subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=1200,check=True)
        print('END '+name,flush=True)
    try:
        cmd = [sys.executable,PACKAGE/'scripts/accept_follow.py','--sdk',sdk,'--compiler',compiler,'--openssl-root',args.openssl_root.resolve(),'--out-dir',out/'base']
        if args.openssl_cli: cmd += ['--openssl-cli',args.openssl_cli]
        run('base',cmd); base=json.loads((out/'base/acceptance.json').read_text()); assert base['status']=='passed'; report['base']=base
        links = [v for row in base['base']['commands'] if row['name']=='https-build' for v in row['command'] if v.startswith(('--link-arg=','--platform-archive='))]
        for secure in (False,True):
            mode='https' if secure else 'tcp'; directory=out/('upload-'+mode); directory.mkdir()
            deps=''.join('  '+name+':\n    path: ../base/base/base/project/'+name+'\n' for name in (('http','net_core','tls') if secure else ('http','net_core')))
            (directory/'package.yaml').write_text('name: upload_'+mode+'\ndependencies:\n'+deps); (directory/'main.ny').write_text(consumer(secure))
            selected=links if secure else [v for v in links if not any(s in v for s in ('libtls_native','libssl','libcrypto','-lgdi32','-ladvapi32','-lcrypt32','-luser32','-ldl'))]
            binary=out/('upload-'+mode+'-test'+suffix)
            run(mode+'-build',[compiler,'build',directory/'main.ny','--link','-O2','-j','4','--out-dir',out/(mode+'-objects'),'-o',binary,*selected])
            if not secure:
                run('plain-imports',[kit/('llvm-nm'+suffix),'-u',binary]); assert not any(v in (out/'plain-imports.log').read_text() for v in ('SSL_','OPENSSL_','nyra_tls_'))
            for case,name in CASES.items():
                print('BEGIN '+mode+'-'+name,flush=True); record=UploadPeer(case,secure,out/'base/base/base/fixtures').run(binary,env,out/(mode+'-'+str(case)+'.log')); report['cases'].append({'transport':mode,**record}); save()
        for name,path in packages.items(): assert report['source_sha256'][name]==sources(path),'sources changed: '+name
        report['status']='passed'
    except (OSError,ValueError,AssertionError,RuntimeError,subprocess.SubprocessError) as error:
        report['status']='failed';report['error']=str(error);print(str(error),file=sys.stderr)
    save();print(out/'acceptance.json');return 0 if report['status']=='passed' else 1


if __name__=='__main__': raise SystemExit(main())
