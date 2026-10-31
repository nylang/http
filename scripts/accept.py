#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Validate HTTP heads and streaming bodies using a public SDK runtime, without linking TLS."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from sdk_layout import sdk_package, sdk_entry
PACKAGE = Path(__file__).resolve().parents[1]

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def sources(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): digest(p) for p in sorted(root.rglob('*'))
            if p.is_file() and '.git' not in p.parts and p.suffix in ('.ny', '.ni', '.c', '.h', '.py', '.yaml', '.in')}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, help='optional explicit native source candidate')
    parser.add_argument('--net-core', type=Path, default=PACKAGE.parent / 'net_core')
    parser.add_argument('--out-dir', type=Path, required=True)
    args = parser.parse_args()
    sdk, net, output = [p.expanduser().resolve() for p in (args.sdk, args.net_core, args.out_dir)]
    if output == PACKAGE or PACKAGE in output.parents or output == net or net in output.parents:
        parser.error('use an external output directory')
    if output.exists() and any(output.iterdir()):
        parser.error('--out-dir must be new or empty')
    os_name = {'Darwin': 'darwin', 'Linux': 'linux', 'Windows': 'windows'}.get(platform.system())
    if not os_name:
        parser.error('desktop hosts only')
    arch = 'arm64' if platform.machine().lower() in ('arm64', 'aarch64') else 'x86_64'
    host = os_name + '-' + arch
    windows = os_name == 'windows'; suffix = '.exe' if windows else ''
    metadata = json.loads((sdk / 'manifest.json').read_text())
    sdk_compiler = (sdk / metadata['tools']['nyrac']['path']).resolve()
    if sdk not in sdk_compiler.parents or digest(sdk_compiler) != metadata['tools']['nyrac']['sha256']:
        parser.error('SDK compiler path/hash mismatch')
    compiler = args.compiler.expanduser().resolve() if args.compiler else sdk_compiler
    if not compiler.is_file():
        parser.error('compiler is missing')
    toolkit = sdk / 'hosts' / host / 'llvm/bin'; stdlib = sdk_package(sdk, host, 'stdlib')
    output.mkdir(parents=True, exist_ok=True)
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('NYRA', 'DYLD_', 'LD_')) and k != 'LLVM_PREFIX'}
    environment.update(CC=str(toolkit / ('clang' + suffix)), AR=str(toolkit / ('llvm-ar' + suffix)),
        PATH=str(toolkit) + os.pathsep + environment.get('PATH', ''), NYRA_SDK_ROOT=str(sdk),
        NYRA_KERNEL_ROOT=str(output / 'source-fallback-disabled'))
    if os_name == 'darwin':
        environment['SDKROOT'] = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
        target = next(line.split(':', 1)[1].strip().strip('"') for line in (stdlib / 'manifest.yaml').read_text().splitlines() if line.startswith('target:'))
        environment['MACOSX_DEPLOYMENT_TARGET'] = target.split('-apple-macosx', 1)[1]
    report = {'format': 'nyra-http-framing-acceptance-v1', 'status': 'running', 'host': host,
              'sdk_version': metadata['version'], 'sdk_manifest_sha256': digest(sdk / 'manifest.json'),
              'compiler_origin': 'public-sdk' if digest(compiler) == metadata['tools']['nyrac']['sha256'] else 'source-candidate',
              'compiler_sha256': digest(compiler), 'source_fallback_disabled': True,
              'source_sha256': sources(PACKAGE), 'net_core_source_sha256': sources(net),
              'commands': [], 'scope': 'Strict HTTP/1.x heads, streaming body decoding/writing and informational/final response sequencing; no network client'}
    def save():
        (output / 'acceptance.json').write_text(json.dumps(report, indent=2) + '\n')
    def run(name, command):
        report['commands'].append({'name': name, 'command': command}); save()
        print('BEGIN ' + name, flush=True)
        with (output / (name + '.log')).open('w') as log:
            done = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        done.check_returncode(); print('END ' + name, flush=True)
        return (output / (name + '.log')).read_text()
    try:
        stage = output / 'project'
        for name, source in [('http', PACKAGE), ('net_core', net)]:
            shutil.copytree(source, stage / name, ignore=shutil.ignore_patterns('.git', '__pycache__', 'docs'))
            dependencies = '  stdlib:\n    precompiled: ' + json.dumps(str(sdk_entry(sdk, host, 'stdlib'))) + '\n'
            if name == 'http': dependencies += '  net_core:\n    path: ../net_core\n'
            (stage / name / 'package.yaml').write_text('name: ' + name + '\nversion: 0.1.0\nlicense: MIT\ndependencies:\n' + dependencies + 'directories:\n  interface:\n    - interface\n  private:\n    - private\n    - tests\n')
        report['staged_manifest_sha256'] = {name: digest(stage / name / 'package.yaml') for name in ('http', 'net_core')}
        run('net-native', [sys.executable, str(net / 'scripts/build_native.py'), '--out-dir', str(output / 'net-native')])
        listing = run('list', [str(compiler), 'test', str(stage / 'http'), '--tag', 'http_core', '--list'])
        names = [line.strip() for line in listing.splitlines() if line.startswith('test_http_')]
        if not names or len(names) != len(set(names)): raise ValueError('missing/duplicate case discovery')
        report['case_names'] = names
        binary = output / ('http-tests' + suffix)
        links = ['--platform-archive=' + str(stdlib / 'lib/libnyra_platform.a'),
                 '--link-arg=' + str(output / 'net-native/libnet_core_native.a')]
        links += ['--link-arg=-l' + name for name in (('ws2_32', 'iphlpapi') if windows else ('pthread',))]
        run('tests', [str(compiler), 'test', str(stage / 'http'), '--tag', 'http_core', '-O2', '-j', '4',
            '--out-dir', str(output / 'objects'), '-o', str(binary), *links, '--report', str(output / 'tests.json')])
        tests = json.loads((output / 'tests.json').read_text())
        if tests['passed'] != len(names) or tests['failed'] or tests['ignored'] or tests['skipped']: raise ValueError('not all cases passed')
        report['tests'] = tests
        for index in range(len(names)): run('case-' + str(index), [str(binary), str(index)])
        report['isolated_replays'] = len(names)
        run('production', [str(compiler), 'precompile', str(stage / 'http/http.ny'), '-O2', '-j', '4',
            '--out-dir', str(output / 'production-objects'), '-o', str(output / 'production')])
        imports = run('production-imports', [str(toolkit / ('llvm-nm' + suffix)), '-u', str(output / 'production/lib/libpackage.a')])
        if any(name in imports for name in ('AddFail', 'http_test_', 'nyra_tls_', 'SSL_', 'OPENSSL_')):
            raise ValueError('test or TLS dependency leaked into protocol production archive')
        report['production_fixture_imports'] = []; report['tls_link_inputs'] = []
        consumer = output / 'consumer'; consumer.mkdir()
        (consumer / 'package.yaml').write_text('name: http_consumer\ndependencies:\n  http:\n    path: ../project/http\n')
        (consumer / 'main.ny').write_text(r'''/** @brief Imported response sequencing and streaming body consumer. */
import "stdlib:stdlib.ny";
import "http:http.ny";
import "net_core:net_core.ny";
func chunk_trailers() -> int32 {
  var made: Result<HttpResponseParser, HttpError> = HttpResponseParser.New("GET", HttpResponseLimits{});
  if made.IsErr() { return 10; }
  var parser: HttpResponseParser = move((made.get_if<HttpResponseParser>()) as HttpResponseParser);
  let wire: string = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n";
  if parser.Push(NetBytes.FromString(wire)).IsErr() || !parser.IsComplete() { return 11; }
  let head: HttpHead = (parser.Head().get_if<HttpHead>()) as HttpHead;
  var result: Result<HttpBodyWriter, HttpError> = HttpBodyWriter.New(head, HttpBodyLimits{});
  if result.IsErr() { return 12; }
  var writer: HttpBodyWriter = move((result.get_if<HttpBodyWriter>()) as HttpBodyWriter);
  var fields: <HttpField>[1] = <HttpField>[1]{}; fields[0] = HttpField{name: "X-End", value: "ok"};
  if writer.Finish(fields).IsErr() { return 13; }
  fields[0].value = "changed";
  var storage: <uint8>[2] = <uint8>[2]{};
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0], 2 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  var generated: StringBuffer = StringBuffer.New(); var calls: int32 = 0;
  while !writer.IsComplete() && calls < 32 {
    let fed: Result<HttpBodyProgress, HttpError> = writer.Push(NetBytes{}, output);
    if fed.IsErr() { return 14; }
    let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
    if step.consumed != (0 as intptr) || step.produced == (0 as intptr) { return 15; }
    generated.Append(string.ViewFrom(&storage[0] as *const int8, step.produced as int32)); calls = calls+1;
  }
  let body: string = generated.Take();
  if !writer.IsComplete() || !body.Equal("0\r\nX-End: ok\r\n\r\n") { return 16; }
  var decoder_result: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(head, HttpBodyLimits{});
  if decoder_result.IsErr() { return 17; }
  var decoder: HttpBodyDecoder = move((decoder_result.get_if<HttpBodyDecoder>()) as HttpBodyDecoder);
  let fed: Result<HttpBodyProgress, HttpError> = decoder.Push(NetBytes.FromString(body.Concat("NEXT")), output);
  if fed.IsErr() || !decoder.IsComplete() { return 18; }
  let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
  let field: Result<HttpField, HttpError> = decoder.TrailerAt(0);
  if step.consumed != body.length as intptr || step.produced != (0 as intptr) || field.IsErr() || !((field.get_if<HttpField>()) as HttpField).value.Equal("ok") { return 19; }
  return 0;
}
func main() -> int32 {
  var made: Result<HttpResponseParser, HttpError> = HttpResponseParser.New("GET", HttpResponseLimits{});
  if made.IsErr() { return 1; }
  var parser: HttpResponseParser = move((made.get_if<HttpResponseParser>()) as HttpResponseParser);
  let wire: string = "HTTP/1.1 103 Hints\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
  var used: intptr = 0 as intptr;
  while !parser.IsComplete() && used < wire.length as intptr {
    let input: NetBytes = (NetBytes.FromString(wire).Slice(used, (wire.length as intptr)-used).get_if<NetBytes>()) as NetBytes;
    let fed: Result<HttpResponseProgress, HttpError> = parser.Push(input);
    if fed.IsErr() { return 2; }
    let progress: HttpResponseProgress = (fed.get_if<HttpResponseProgress>()) as HttpResponseProgress;
    if progress.consumed == (0 as intptr) { return 3; }
    used = used+progress.consumed;
  }
  if !parser.IsComplete() || parser.InformationalCount() != 2 || used != (wire.length-3) as intptr { return 4; }
  let head: HttpHead = (parser.Head().get_if<HttpHead>()) as HttpHead;
  var decoded: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(head, HttpBodyLimits{});
  var encoded: Result<HttpBodyWriter, HttpError> = HttpBodyWriter.New(head, HttpBodyLimits{});
  if decoded.IsErr() || encoded.IsErr() { return 5; }
  var decoder: HttpBodyDecoder = move((decoded.get_if<HttpBodyDecoder>()) as HttpBodyDecoder);
  var writer: HttpBodyWriter = move((encoded.get_if<HttpBodyWriter>()) as HttpBodyWriter);
  var storage: <uint8>[2] = <uint8>[2]{};
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0], 2 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  let first: Result<HttpBodyProgress, HttpError> = writer.Push(NetBytes.FromString("abc"), output);
  if first.IsErr() { return 6; }
  let encoded_first: HttpBodyProgress = (first.get_if<HttpBodyProgress>()) as HttpBodyProgress;
  if encoded_first.consumed != (2 as intptr) || encoded_first.produced != (2 as intptr) || encoded_first.state != HttpBodyState.NeedOutput || storage[0] != 97u8 || storage[1] != 98u8 { return 7; }
  let last: Result<HttpBodyProgress, HttpError> = writer.Push(NetBytes.FromString("c"), output);
  if last.IsErr() || !writer.IsComplete() || writer.Finish(new <HttpField>[0]).IsErr() || storage[0] != 99u8 { return 8; }
  let fed: Result<HttpBodyProgress, HttpError> = decoder.Push(NetBytes.FromString("abcNEXT"), output);
  if fed.IsErr() { return 9; }
  let progress: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
  if progress.consumed != (2 as intptr) || progress.produced != (2 as intptr) || storage[0] != 97u8 || storage[1] != 98u8 { return 20; }
  let end: Result<HttpBodyProgress, HttpError> = decoder.Push(NetBytes.FromString("cNEXT"), output);
  if end.IsErr() || !decoder.IsComplete() || decoder.EndInput().IsErr() || ((end.get_if<HttpBodyProgress>()) as HttpBodyProgress).consumed != (1 as intptr) { return 21; }
  return chunk_trailers();
}
''')
        # Declare the byte-range dependency explicitly: imports never rely on transitive visibility.
        (consumer / 'package.yaml').write_text((consumer / 'package.yaml').read_text() + '  net_core:\n    path: ../project/net_core\n')
        application = output / ('consumer-test' + suffix)
        run('consumer-build', [str(compiler), 'build', str(consumer / 'main.ny'), '--link', '-O2',
            '--out-dir', str(output / 'consumer-objects'), '-o', str(application), *links])
        run('consumer', [str(application)])
        if sources(PACKAGE) != report['source_sha256'] or sources(net) != report['net_core_source_sha256']:
            raise ValueError('sources changed during acceptance')
        report['status'] = 'passed'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report['status'] = 'failed'; report['error'] = str(error); print(str(error), file=sys.stderr)
    save(); print(output / 'acceptance.json')
    return 0 if report['status'] == 'passed' else 1

if __name__ == '__main__':
    raise SystemExit(main())
