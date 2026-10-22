"""Reset helpers for reproducible re-runs (uses the elastic superuser; touches only this project's data)."""
import shutil
import subprocess

from . import config, registry, templates


def reset_files(keep_generated: bool = False, log=print) -> None:
    """The project's state on the host: generated template files, registry, dropzone. Needs no running stack, so
    scripts/rebuild_all.py can clear it after docker compose down -v (which removes everything inside the stack)."""
    if not keep_generated:
        for p in (config.TEMPLATES_DIR / "generated").glob("*.json"):
            p.unlink()
    registry.reset()
    log("registry cleared")
    for child in config.DROPZONE.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
    (config.DROPZONE / ".staging").mkdir(exist_ok=True)
    log("dropzone cleared")


def reset_all(keep_generated: bool = False, log=print) -> None:
    es = config.es("admin")
    for ds in es.indices.get_data_stream(name="logs-*")["data_streams"]:
        es.indices.delete_data_stream(name=ds["name"])
        log(f"deleted data stream {ds['name']}")
    if not keep_generated:
        for name, spec in templates.installed("admin").items():
            if spec.get("origin") == "generated":
                es.ingest.delete_pipeline(id=templates.pipeline_id(name))
                log(f"deleted generated template {name}")
    reset_files(keep_generated, log)
    # Logstash remembers files it has read (sincedb); forget them so the same paths can be re-ingested.
    subprocess.run(["docker", "compose", "exec", "-T", "logstash", "rm", "-f",
                    "/usr/share/logstash/data/sincedb_dropzone", "/usr/share/logstash/data/dropzone_completed.log"],
                   cwd=config.ROOT, capture_output=True)
    subprocess.run(["docker", "compose", "restart", "logstash"], cwd=config.ROOT, capture_output=True)
    log("logstash sincedb cleared and logstash restarted")
