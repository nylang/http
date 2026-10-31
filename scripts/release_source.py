#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Package exact tested source manifests without replacing Git edges with local paths."""
from __future__ import annotations
import argparse,io,json,re,subprocess,tarfile
from pathlib import Path
from accept import digest,sources

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package-root',type=Path,required=True);p.add_argument('--receipts',type=Path,required=True);p.add_argument('--out-dir',type=Path,required=True);a=p.parse_args();root=a.package_root.resolve();out=a.out_dir.resolve()
    if out.exists() or root in out.parents:p.error('new external output required')
    manifest=(root/'package.yaml').read_text();name=re.search(r'^name: (\S+)',manifest,re.M)[1];version=re.search(r'^version: (\S+)',manifest,re.M)[1]
    if '\n    path:' in manifest:raise ValueError('public manifest contains local dependencies')
    commit=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip();lock=json.loads((root/'release.lock.json').read_text());receipts={}
    if set(lock['sdk']['hosts'])!={'darwin-arm64','darwin-x86_64','linux-x86_64','windows-x86_64'}:raise ValueError('four qualified SDK host pins are required before source packaging')
    for path in a.receipts.rglob('ci-report.json'):
        r=json.loads(path.read_text());host=r['host']
        if host in receipts or host not in lock['sdk']['hosts'] or r['status']!='passed' or r['package']!=name or r['source_commit']!=commit or r['sdk_manifest_sha256']!=lock['sdk']['hosts'][host]['manifest_sha256'] or r['sdk_archive_sha256']!=lock['sdk']['hosts'][host]['archive_sha256'] or r['source_sha256'][name]!=sources(root):raise ValueError('source qualification mismatch')
        receipts[host]=r
    if set(receipts)!=set(lock['sdk']['hosts']):raise ValueError('four-host acceptance incomplete')
    out.mkdir(parents=True);record={'format':'nyra-http-source-release-v1','package':name,'version':version,'source_commit':commit,'sdk_protocol_acceptance':lock['sdk'],'git_consumer_requirement':'The exact SDK version and manifest/archives pinned in release.lock.json.','manifest_rewrite':'None: original immutable Git dependency declarations are preserved.','hosts':{h:{'profile':r['profile'],'source_commits':r['source_commits'],'compiler_sha256':r['compiler_sha256']} for h,r in receipts.items()}}
    (out/'release.json').write_text(json.dumps(record,indent=2)+'\n');archive=out/(name+'-'+version+'-source.tar.gz');prefix=name+'-'+version
    names=filter(None,subprocess.check_output(['git','-C',str(root),'ls-files','-z']).decode().split('\0'))
    with tarfile.open(archive,'w:gz',format=tarfile.PAX_FORMAT) as bundle:
        def add(name,data):
            info=tarfile.TarInfo(prefix+'/'+name);info.size=len(data);info.mode=0o644;info.mtime=0;bundle.addfile(info,io.BytesIO(data))
        for path in names:
            relative=Path(path);source=root/path
            if relative.is_absolute() or '..' in relative.parts or source.is_symlink() or not source.is_file():raise ValueError('unsafe tracked source')
            add(path,source.read_bytes())
        add('release.json',(out/'release.json').read_bytes())
        for host,row in receipts.items():add('evidence/'+host+'.json',(json.dumps(row,indent=2)+'\n').encode())
    (out/'SHA256SUMS').write_text(''.join(digest(path)+'  '+path.name+'\n' for path in [archive,out/'release.json']));print(archive)
if __name__=='__main__':main()
