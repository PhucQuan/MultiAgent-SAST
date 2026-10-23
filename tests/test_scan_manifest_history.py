"""Regression checks for real manifests and persisted scan isolation."""
from pathlib import Path
import pytest
from aegis_sast.api.routes import ScanJobStore, ScanPipelineRequestModel

@pytest.mark.parametrize('directory', [False, True])
def test_manifest_history_zero_findings(tmp_path, directory):
    root = tmp_path / 'nested'
    root.mkdir()
    target = root / 'clean.py'
    target.write_text('answer = 42\n', encoding='utf-8')
    nested = root / 'child'
    nested.mkdir()
    second = nested / 'also_clean.py'
    second.write_text('message = "hello"\n', encoding='utf-8')
    store = ScanJobStore(tmp_path / 'history')
    payload = ScanPipelineRequestModel(path=str(root if directory else target), config={'scan_engine':'deterministic'})
    first = store.create(payload)
    second_job = store.create(payload)
    store.executor.shutdown(wait=True)
    assert first.scan_id != second_job.scan_id
    for job in store.list_all():
        assert job.status == 'completed', job.error
        assert job.result['summary']['total_vulnerabilities'] == 0
        expected = {str(target.resolve()), str(second.resolve())} if directory else {str(target.resolve())}
        assert set(job.result['scanned_files']) == expected
        assert job.result['summary']['files_scanned'] == len(expected)
        assert job.target_type == ('folder' if directory else 'file')
        assert job.result['scan_id'] == job.scan_id
    restored = ScanJobStore(tmp_path / 'history')
    assert {j.scan_id for j in restored.list_all()} == {first.scan_id, second_job.scan_id}
    restored.executor.shutdown()

def test_semgrep_manifest_includes_zero_finding_files(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace
    from aegis_sast.integrations.semgrep_runner import SemgrepRunner
    target = tmp_path / 'clean.py'
    target.write_text('answer = 42\n')
    runner = SemgrepRunner()
    monkeypatch.setattr(runner, '_resolve_config_args', lambda: ['--config', 'test.yaml'])
    monkeypatch.setattr('aegis_sast.integrations.semgrep_runner.subprocess.run', lambda *a, **kw: SimpleNamespace(returncode=0, stdout=json.dumps({'results':[], 'paths':{'scanned':[str(target)]}}), stderr=''))
    assert runner.run(str(tmp_path)) == []
    assert runner.scanned_files == [str(target)]


def test_interrupted_job_is_not_reported_as_running(tmp_path):
    import json
    from aegis_sast.api.routes import ScanJob
    job = ScanJob(scan_id='interrupted', status='running', started_at='2026-10-23T00:00:00Z')
    (tmp_path / 'interrupted.json').write_text(json.dumps(job.model_dump()))
    restored = ScanJobStore(tmp_path)
    assert restored.get('interrupted').status == 'failed'
    assert 'restart' in restored.get('interrupted').error
    restored.executor.shutdown()
