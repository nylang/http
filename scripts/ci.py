#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Qualify exact Git sources with checksum-pinned public SDK runtimes before source release."""
from __future__ import annotations
import argparse,json,os,platform,re,shutil,subprocess,sys,tarfile,urllib.request,zipfile
from pathlib import Path,PurePosixPath
from accept import digest,sources
from native_provider import source_layout
PACKAGE=Path(__file__).resolve().parents[1]
def revision(path):return subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip()
def manifest_dependency(path,name):
    text=(path/'package.yaml').read_text();match=re.search(r'^  '+re.escape(name)+r':\n    git: (\S+)\n    rev: ([0-9a-f]{40})\s*$',text,re.M)
    if not match:raise ValueError('missing immutable Git dependency: '+name)
    return match.groups()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out-dir',type=Path,required=True);p.add_argument('--sdk',type=Path,help='Reuse a local SDK, still checked against release.lock hashes');p.add_argument('--openssl-root',type=Path,help='Reuse the matching managed static OpenSSL provider');p.add_argument('--adapter-root',type=Path);a=p.parse_args();out=a.out_dir.resolve()
    if out.exists():p.error('new external output required')
    out.mkdir(parents=True);owner=a.adapter_root.resolve() if a.adapter_root else PACKAGE;kind='http_tls' if a.adapter_root else 'http'
    win=os.name=='nt';suffix='.exe' if win else '';host={'Darwin':'darwin','Linux':'linux','Windows':'windows'}[platform.system()]+'-'+('arm64' if platform.machine().lower() in ('arm64','aarch64') else 'x86_64')
    lock=json.loads((owner/'release.lock.json').read_text());sdk_lock=lock['sdk'];pin=sdk_lock['hosts'].get(host);name='nyra-sdk-'+sdk_lock['version']+'-'+host
    if pin is None:raise ValueError('qualified SDK '+sdk_lock['version']+' pins are pending for '+host)
    report={'format':'nyra-http-release-ci-v1','status':'running','package':kind,'host':host,'source_commit':revision(owner),'commands':[],'sdk_version':sdk_lock['version'],'sdk_archive_sha256':pin['archive_sha256'],'sdk_manifest_sha256':pin['manifest_sha256']}
    def save():(out/'ci-report.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(name,cmd,env=None):
        command=list(map(str,cmd));report['commands'].append({'name':name,'command':command});save();print('BEGIN '+name,flush=True)
        with (out/(name+'.log')).open('w') as log:subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=6000,check=True)
        print('END '+name,flush=True)
    def clone(name,url,ref):
        dest=out/'packages'/name;run(name+'-init',['git','init',dest]);run(name+'-eol',['git','-C',dest,'config','core.autocrlf','false']);run(name+'-remote',['git','-C',dest,'remote','add','origin',url]);run(name+'-fetch',['git','-C',dest,'fetch','--depth','1','origin',ref]);run(name+'-checkout',['git','-C',dest,'checkout','--detach','FETCH_HEAD']);assert revision(dest)==ref;return dest
    try:
        run('provider-layout-unit',[sys.executable,PACKAGE/'tests/tools/test_native_provider.py'])
        run('sdk-layout-unit',[sys.executable,PACKAGE/'tests/tools/test_sdk_layout.py'])
        if a.sdk:
            sdk=a.sdk.expanduser().resolve()
        else:
            archive=out/(name+('.zip' if win else '.tar.gz'))
            with urllib.request.urlopen('https://github.com/nylang/sdk/releases/download/v'+sdk_lock['version']+'/'+archive.name,timeout=180) as source,archive.open('wb') as target:shutil.copyfileobj(source,target,1024*1024)
            if digest(archive)!=pin['archive_sha256']:raise ValueError('SDK archive mismatch')
            extracted=out/'sdk';extracted.mkdir()
            if win:
                with zipfile.ZipFile(archive) as bundle:
                    for member in bundle.infolist():
                        parts=PurePosixPath(member.filename).parts
                        if not parts or parts[0]!=name or '..' in parts or '\\' in member.filename or ':' in member.filename or (member.external_attr>>16)&0o170000==0o120000:raise ValueError('unsafe SDK archive')
                    bundle.extractall(extracted)
            else:
                with tarfile.open(archive) as bundle:
                    for member in bundle.getmembers():
                        parts=PurePosixPath(member.name).parts
                        if not parts or parts[0]!=name or '..' in parts or '\\' in member.name:raise ValueError('unsafe SDK archive')
                    bundle.extractall(extracted,filter='data')
            sdk=extracted/name
        meta=json.loads((sdk/'manifest.json').read_text());compiler=(sdk/meta['tools']['nyrac']['path']).resolve()
        if sdk.resolve() not in compiler.parents or digest(sdk/'manifest.json')!=pin['manifest_sha256'] or meta['version']!=sdk_lock['version'] or meta['host']!=host or digest(compiler)!=meta['tools']['nyrac']['sha256']:raise ValueError('SDK identity mismatch')
        report['compiler_sha256']=digest(compiler)
        report['sdk_archive_verified']=not bool(a.sdk)
        package_root=out/'packages';package_root.mkdir()
        if kind=='http_tls':
            http_origin,http_api=manifest_dependency(owner,'http')
            tooling=lock.get('ci_tooling',{'url':http_origin,'commit':http_api})
            if tooling['url']!=http_origin or not re.fullmatch('[0-9a-f]{40}',tooling['commit']):raise ValueError('invalid HTTP CI tooling pin')
            http=clone('http',tooling['url'],tooling['commit'])
            if tooling['commit']!=http_api:
                run('http-api-fetch',['git','-C',http,'fetch','--depth','1','origin',http_api])
                run('http-api-equivalence',['git','-C',http,'diff','--exit-code',http_api,tooling['commit'],'--','package.yaml','*.ny','*.ni','*.nk','*.c','*.h'])
                report['http_api_commit']=http_api;report['http_ci_tooling_commit']=tooling['commit']
            adapter=clone('http_tls',str(owner),revision(owner));tls=clone('tls',*manifest_dependency(owner,'tls'))
            if manifest_dependency(http,'net_core')!=manifest_dependency(owner,'net_core') or manifest_dependency(tls,'net_core')!=manifest_dependency(owner,'net_core'):raise ValueError('incoherent shared dependency pin')
        else:http=clone('http',str(PACKAGE),revision(PACKAGE))
        net=clone('net_core',*manifest_dependency(owner,'net_core'))
        report['source_commits']={path.name:revision(path) for path in package_root.iterdir()};report['source_sha256']={path.name:sources(path) for path in package_root.iterdir()};save()
        if kind=='http_tls':
            provider_env=os.environ.copy()
            if sys.platform=='darwin':provider_env['MACOSX_DEPLOYMENT_TARGET']='14.0'
            if a.openssl_root:
                provider=source_layout(a.openssl_root.expanduser(),out/'openssl-provider',win)
            else:
                run('openssl',[sys.executable,tls/'scripts/build_openssl.py','--out-dir',out/'openssl','--perl','C:/Strawberry/perl/bin/perl.exe' if win else 'perl','--build-cli','--jobs','4'],provider_env)
                provider=out/'openssl'/('openssl-'+json.loads((tls/'openssl.lock.json').read_text())['version'])
            run('accept',[sys.executable,http/'scripts/accept_stream_follow.py','--sdk',sdk,'--openssl-root',provider,'--out-dir',out/'acceptance'])
            accepted=json.loads((out/'acceptance/acceptance.json').read_text());client=accepted['base']['base']['base']['base']['base']['base'];core=client['core']
            assert len(accepted['cases'])==45 and len(accepted['base']['cases'])==50
            report['profile']='96 core/replays and complete 276 TCP/HTTPS/DNS/upload/redirect scenarios'
        else:
            run('clients',[sys.executable,http/'scripts/accept_clients.py','--sdk',sdk,'--compiler',compiler,'--out-dir',out/'acceptance'])
            client=json.loads((out/'acceptance/acceptance.json').read_text());core=client['core']
            run('tcp-upload',[sys.executable,http/'scripts/accept_tcp_upload.py','--sdk',sdk,'--baseline',out/'acceptance/core','--out-dir',out/'tcp-upload'])
            accepted=client;report['tcp_upload']=json.loads((out/'tcp-upload/acceptance.json').read_text());assert report['tcp_upload']['status']=='passed' and len(report['tcp_upload']['cases'])==14
            report['profile']='96 core/replays, 27 TCP clients, 9 DNS control cases and 14 connected TCP upload cases; complete optional adapter matrix is separate'
        assert accepted['status']=='passed' and core['tests']['passed']==96 and core['isolated_replays']==96 and core['tests']['failed']==0 and not core['production_fixture_imports'] and not client['plain_tls_link_inputs']
        report['acceptance']=accepted;report['status']='passed'
    except (OSError,ValueError,AssertionError,subprocess.SubprocessError) as error:report['status']='failed';report['error']=str(error);print(str(error),file=sys.stderr)
    save();return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
