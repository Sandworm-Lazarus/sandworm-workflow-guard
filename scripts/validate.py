"""Run standard-library tests and record exact code/fixture fingerprints."""
import contextlib
import hashlib
import io
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    suite=unittest.TestLoader().discover(str(ROOT/'tests'),pattern='test_*.py')
    output=io.StringIO()
    with contextlib.redirect_stdout(output):
        result=unittest.TextTestRunner(stream=output,verbosity=1).run(suite)
    paths=set(ROOT.glob('*.py')) | set((ROOT/'tests').glob('*.py')) | set((ROOT/'scripts').glob('*.py'))
    paths |= {p for p in (ROOT/'examples').rglob('*') if p.is_file()}
    paths |= {ROOT/'upstream.lock.json'} | set(ROOT.glob('*.toml')) | set(ROOT.glob('requirements*.txt'))
    files=[{'path':p.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(paths)]
    payload=json.dumps(files,sort_keys=True,separators=(',',':')).encode()
    skipped=len(result.skipped)
    report={'schema_version':1,'project':ROOT.name,'checked_at':datetime.now(timezone.utc).isoformat(),
            'tests':{'total':result.testsRun,'passed':result.testsRun-len(result.failures)-len(result.errors)-skipped,
                     'failed':len(result.failures)+len(result.errors),'skipped':skipped},
            'live_engine':{'tested':skipped==0,'versions':json.loads((ROOT/'upstream.lock.json').read_text())},
            'manifest_sha256':hashlib.sha256(payload).hexdigest(),'files':files,
            'scope':'Python unit/regression tests including local live-engine test when installed; web tests run separately'}
    (ROOT/'reports').mkdir(exist_ok=True)
    (ROOT/'reports/validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report['tests']))
    if not result.wasSuccessful():
        print(output.getvalue(),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
