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


def require_equivalent_sources(prior, root, commit):
    """Admit orchestration-main edits while preserving generators, peers and fixtures."""
    import ast,subprocess
    from pathlib import Path
    if len(commit)!=40 or any(c not in '0123456789abcdef' for c in commit):
        raise ValueError('original immutable tooling commit required')
    changed=[]
    def semantic_helpers(text):
        return [ast.dump(n,include_attributes=False) for n in ast.parse(text).body
                if not isinstance(n,(ast.Import,ast.ImportFrom,ast.If))
                and not (isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=='main')]
    for relative,checksum in prior.items():
        file=root/relative
        current=file.read_bytes()
        if hashlib.sha256(current).hexdigest()==checksum:continue
        if file.suffix!='.py':raise ValueError('baseline language/native/fixture input changed')
        old=subprocess.check_output(['git','show',commit+':'+relative],cwd=root)
        if hashlib.sha256(old).hexdigest()!=checksum or semantic_helpers(old)!=semantic_helpers(current):
            raise ValueError('baseline test generator or peer changed')
        changed.append(relative)
    for file in root.rglob('*'):
        if file.is_file() and '.git' not in file.parts and file.suffix in ('.ny','.ni','.nk','.c','.h','.yaml','.in') and file.relative_to(root).as_posix() not in prior:
            raise ValueError('baseline omits a current language/native/fixture input')
    return dict(original_tooling_commit=commit,changed_orchestration_files=changed,
                generated_language_native_fixture_inputs_equal=True,protocol_generators_peers_equal=True)
