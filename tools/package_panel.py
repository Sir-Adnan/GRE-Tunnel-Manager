#!/usr/bin/env python3
"""Cross-build prebuilt, self-contained Linux panel packages (development only)."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def package():
    version = re.search(r'^GTM_VERSION=(\d+\.\d+\.\d+)$', (ROOT/'src/core.sh').read_text(encoding='utf-8'), re.M)[1]
    target = ROOT/'panel/bin'
    target.mkdir(parents=True, exist_ok=True)
    sums = []
    for arch in ['amd64', 'arm64']:
        binary = target/f'gtm-panel-linux-{arch}'
        environment = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=arch)
        subprocess.run(['go', 'build', '-trimpath', '-ldflags=-s -w', '-o', str(binary), './cmd/gtm-panel'], cwd=ROOT/'panel', env=environment, check=True)
        archive = target/f'gtm-panel-v{version}-linux-{arch}.tar.gz'
        with tarfile.open(archive, 'w:gz') as output:
            members=[(binary,'gtm-panel'), (ROOT/'gre.sh','gre.sh'),(ROOT/'LICENSE','LICENSE'),(ROOT/'panel/NOTICE.md','NOTICE.md')]
            members.extend((path,'LICENSES/'+path.name) for path in sorted((ROOT/'panel/LICENSES').glob('*')) if path.is_file())
            for source, name in members:
                info = output.gettarinfo(str(source), arcname=name)
                info.uid = info.gid = 0
                info.uname = info.gname = 'root'
                info.mode = 0o755
                with source.open('rb') as stream:
                    output.addfile(info, stream)
        sums.append(f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}')
        print(f'Built {archive.name} ({archive.stat().st_size:,} bytes)')
    (target/'SHA256SUMS').write_text('\n'.join(sums)+'\n', encoding='ascii', newline='\n')


if __name__ == '__main__':
    package()
