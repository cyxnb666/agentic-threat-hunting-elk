"""Unit test for clearing the project's state on the host (no Elasticsearch, no Docker). Run: .venv\\Scripts\\python -m pytest -q"""
from hunt import admin, config, registry


def test_reset_files_clears_host_state_without_elasticsearch(tmp_path, monkeypatch):
    # scripts/rebuild_all.py calls this after docker compose down -v, when no Elasticsearch is running
    # (2026-10-22: the old reset needed Elasticsearch, failed with the stack stopped, and the rebuild kept old state).
    generated, builtin, drop = tmp_path / "generated", tmp_path / "builtin", tmp_path / "dropzone"
    for d in (generated, builtin, drop / "apt29-sysmon"):
        d.mkdir(parents=True)
    (generated / "zeek.json").write_text("{}", encoding="utf-8")
    (builtin / "windows-sysmon.json").write_text("{}", encoding="utf-8")
    (drop / ".gitkeep").write_text("", encoding="utf-8")
    monkeypatch.setattr(config, "TEMPLATES_DIR", tmp_path)
    monkeypatch.setattr(config, "DROPZONE", drop)
    monkeypatch.setattr(registry, "ROUTES", tmp_path / "sources.json")
    monkeypatch.setattr(registry, "META", tmp_path / "sources_meta.json")
    registry._write(registry.ROUTES, {"zeek-nashua": {"pipeline": "hunt-tpl-zeek", "dataset": "zeek"}})
    registry._write(registry.META, {"zeek-nashua": {"template": "zeek"}})

    def no_elasticsearch(*a, **k):
        raise AssertionError("reset_files must not need Elasticsearch")

    monkeypatch.setattr(config, "es", no_elasticsearch)
    admin.reset_files(log=lambda m: None)
    assert not any(generated.iterdir())
    assert (builtin / "windows-sysmon.json").exists()
    assert registry.routes() == {} and registry.meta() == {}
    assert sorted(p.name for p in drop.iterdir()) == [".gitkeep", ".staging"]
