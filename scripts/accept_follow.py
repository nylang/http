#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Accept automatic redirect following, including a plain TCP to verified TLS transition."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from accept import digest, sources
from accept_redirects import RedirectPeer, CASES

from sdk_layout import sdk_package
PACKAGE = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--openssl-root', type=Path, required=True)
    parser.add_argument('--openssl-cli')
    parser.add_argument('--out-dir', type=Path, required=True)
    args = parser.parse_args()
    out, sdk, compiler = (p.resolve() for p in (args.out_dir, args.sdk, args.compiler))
    if out == PACKAGE or PACKAGE in out.parents or (out.exists() and any(out.iterdir())):
        parser.error('use a new/empty output directory outside the package')
    out.mkdir(parents=True, exist_ok=True)
    host = {'Darwin': 'darwin', 'Linux': 'linux', 'Windows': 'windows'}[platform.system()]
    host += '-' + ('arm64' if platform.machine().lower() in ('arm64', 'aarch64') else 'x86_64')
    suffix = '.exe' if platform.system() == 'Windows' else ''
    kit = sdk / 'hosts' / host / 'llvm/bin'
    env = {k: v for k, v in os.environ.items() if not k.startswith(('NYRA', 'DYLD_', 'LD_')) and k != 'LLVM_PREFIX'}
    env.update(PATH=str(kit)+os.pathsep+env.get('PATH', ''), NYRA_SDK_ROOT=str(sdk), NYRA_KERNEL_ROOT=str(out/'source-fallback-disabled'))
    if platform.system() == 'Darwin':
        env.update(SDKROOT=subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip(), MACOSX_DEPLOYMENT_TARGET=next(line.split(':',1)[1].strip().strip('\"') for line in (sdk_package(sdk, host, 'stdlib') / 'manifest.yaml').read_text().splitlines() if line.startswith('target:')).split('-apple-macosx',1)[1])
    packages = {name: PACKAGE.parent/name for name in ('http', 'http_tls', 'tls', 'net_core')}
    manifest = json.loads((sdk/'manifest.json').read_text())
    official = sdk/manifest['tools']['nyrac']['path']
    assert digest(official) == manifest['tools']['nyrac']['sha256'], 'SDK compiler mismatch'
    report = {'format': 'nyra-http-automatic-follow-v1', 'status': 'running', 'host': host,
              'sdk_version': manifest['version'], 'sdk_manifest_sha256': digest(sdk/'manifest.json'),
              'compiler_sha256': digest(compiler), 'compiler_origin': 'public-sdk' if digest(compiler)==digest(official) else 'source-candidate',
              'source_fallback_disabled': True, 'source_sha256': {name: sources(path) for name, path in packages.items()},
              'commands': [], 'cases': []}
    def save():
        (out/'acceptance.json').write_text(json.dumps(report, indent=2)+'\n')
    def run(name, cmd):
        command = list(map(str, cmd)); report['commands'].append({'name': name, 'command': command}); save()
        print('BEGIN '+name, flush=True)
        with (out/(name+'.log')).open('w') as log:
            subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=900, check=True)
        print('END '+name, flush=True)
    try:
        cmd = [sys.executable, PACKAGE/'scripts/accept_redirects.py', '--sdk', sdk, '--compiler', compiler,
               '--http-tls', packages['http_tls'], '--tls', packages['tls'], '--openssl-root', args.openssl_root.resolve(), '--out-dir', out/'base']
        if args.openssl_cli:
            cmd += ['--openssl-cli', args.openssl_cli]
        run('base', cmd)
        base = json.loads((out/'base/acceptance.json').read_text()); assert base['status']=='passed'; report['base']=base
        links = [arg for row in base['commands'] if row['name']=='https-build' for arg in row['command'] if arg.startswith(('--link-arg=', '--platform-archive='))]
        for secure in (False, True):
            mode = 'https' if secure else 'tcp'
            directory = out/'base'/('follow-'+mode); directory.mkdir()
            deps = ''.join('  '+name+':\n    path: ../base/project/'+name+'\n' for name in packages)
            (directory/'package.yaml').write_text('name: follow_'+mode+'\ndependencies:\n'+deps)
            text = (PACKAGE/'tests/data/follow_consumer.ny.in').read_text().replace('@@SCHEME@@', 'https' if secure else 'http')
            (directory/'main.ny').write_text(text)
            binary = out/('follow-'+mode+suffix)
            run(mode+'-build', [compiler, 'build', directory/'main.ny', '--link', '-O2', '-j', '4', '--out-dir', out/(mode+'-objects'), '-o', binary, *links])
            cases = CASES | ({13: 'https-downgrade-rejected'} if secure else {})
            for case, name in cases.items():
                print('BEGIN '+mode+'-'+name, flush=True)
                record = RedirectPeer(case, secure, out/'base/base/fixtures', automatic=True).run(binary, env, out/(mode+'-'+str(case)+'.log'))
                report['cases'].append({'transport': mode, **record}); save()
            if not secure:
                record = RedirectPeer(4, False, out/'base/base/fixtures', automatic=True, mixed=True).run(binary, env, out/'tcp-to-tls.log')
                report['cases'].append({'transport': 'tcp-to-tls', **record}); save()
        for name, path in packages.items():
            assert report['source_sha256'][name]==sources(path), 'sources changed: '+name
        report['status']='passed'
    except (OSError, ValueError, AssertionError, RuntimeError, subprocess.SubprocessError) as error:
        report['status']='failed'; report['error']=str(error); print(str(error), file=sys.stderr)
    save(); print(out/'acceptance.json')
    return 0 if report['status']=='passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
