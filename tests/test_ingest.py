"""Unit test for the pull channel (no Elasticsearch, no Logstash). Run: .venv\\Scripts\\python -m pytest -q"""
import os

from hunt import config, ingest


def test_pull_counts_records_even_if_logstash_already_deleted_the_file(tmp_path, monkeypatch):
    # Logstash reads every dropzone file and then deletes it (file_completed_action log_and_delete), possibly
    # before pull() counts it. Simulate the fastest case: the file is gone right after the rename.
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.log").write_text("1\n2\n\n", encoding="utf-8")
    (src / "b.log").write_text("3\r\n", encoding="utf-8")
    monkeypatch.setattr(config, "DROPZONE", tmp_path / "dropzone")
    real_replace = os.replace

    def replace_then_delete(a, b):
        real_replace(a, b)
        os.remove(b)

    monkeypatch.setattr(ingest.os, "replace", replace_then_delete)
    assert ingest.pull(str(src), "t") == {"channel": "pull", "source_id": "t", "files": 2, "records": 3}
    assert not any((tmp_path / "dropzone" / "t").iterdir())
