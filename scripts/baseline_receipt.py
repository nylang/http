"""Admit an explicitly selected complete composition baseline against exact inputs."""
import hashlib,json

def require_baseline(value, sdk, compiler, sources):
    if value.get('status')!='passed' or value.get('source_sha256')!=sources:
        raise ValueError('baseline is incomplete or source inputs differ')
    cursor=value
    while 'sdk_manifest_sha256' not in cursor:
        cursor=cursor['base']
    digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    if cursor['sdk_manifest_sha256']!=digest(sdk/'manifest.json') or cursor['compiler_sha256']!=digest(compiler):
        raise ValueError('baseline SDK/compiler identity differs')
