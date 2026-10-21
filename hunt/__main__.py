"""Command line: python -m hunt <command> ...   (run from the project root with the .venv interpreter)

  templates install            install builtin templates (+ previously generated ones) into Elasticsearch
  templates list               show installed templates
  ingest pull|push|stream PATH --source-id ID [--eps N] [--no-watch]
                               point the system at a log source: deliver it through the channel, then let the
                               watcher/onboarding agent parse it; ends when every record is in its parsed data stream
  watch [--once] [--idle-exit S]   run the watcher (discover unknown sources, onboard, backfill)
  onboard SOURCE_ID [--sample-file PATH]   run the onboarding agent for one source
  status                       data streams, registry and backlog
  reset --yes [--keep-generated]   delete all ingested data, registry, dropzone (and generated templates)
  mcp                          run the MCP server on stdio
  hunt "HYPOTHESIS" [--profile converged|baseline] [--run-name NAME] [--plan-from RUN_DIR]
  evaluate RUN_DIR             score a hunt report against the APT29 Day 1 step 6 ground truth
  render RUN_DIR               re-create report.md from report.json
  compare RUN_DIR_A RUN_DIR_B  compare two hunt reports
"""
import argparse
import json
import sys
import threading
import time


def cmd_templates(a):
    from . import templates
    if a.action == "install":
        for folder in ("builtin", "generated"):
            for spec in templates.load_specs(folder):
                templates.install(spec)
                print(f"installed {templates.pipeline_id(spec['name'])} ({spec['origin']}, dataset {spec['dataset']})")
    for name, spec in sorted(templates.installed().items()):
        print(f"  {name:28s} {spec['origin']:9s} dataset={spec['dataset']:22s} match={json.dumps(spec['match'])}")


def cmd_ingest(a):
    from . import ingest
    sender = {"pull": ingest.pull, "push": ingest.push, "stream": ingest.stream}[a.channel]
    kwargs = {"eps": a.eps} if a.channel == "stream" else {}
    result = {}
    t0 = time.time()
    th = threading.Thread(target=lambda: result.update(sender(a.path, a.source_id, **kwargs)), daemon=True)
    th.start()
    print(f"[ingest] delivering {a.path} via {a.channel} as source '{a.source_id}' ...")
    if a.no_watch:
        th.join()
        print(json.dumps(result))
        return
    while True:
        time.sleep(5)
        ingest.watch(once=False, interval=0, idle_exit=0)
        done = not th.is_alive()
        waiting = ingest.unparsed_counts().get(a.source_id, {}).get("count", 0)
        parsed = ingest.parsed_count(a.source_id)
        print(f"[ingest] sent={'%s (done)' % result.get('records') if done else 'in progress'} parsed={parsed} waiting={waiting}")
        if done and waiting == 0 and parsed >= result.get("records", 0):
            break
        if done and time.time() - t0 > 3600:
            print("[ingest] giving up after 1 h"); break
    print(json.dumps({**result, **ingest.quality(a.source_id), "seconds": round(time.time() - t0, 1)}))


def cmd_watch(a):
    from . import ingest
    ingest.watch(once=a.once, idle_exit=a.idle_exit)


def cmd_onboard(a):
    from . import sampling
    from .onboarding import OnboardingAgent
    lines = sampling.sample_file(a.sample_file) if a.sample_file else sampling.sample_unparsed(a.source_id)
    print(json.dumps(OnboardingAgent(a.source_id, lines, "cli").run()["outcome"], indent=2))


def cmd_status(a):
    from . import config, ingest, registry
    es = config.es("agent")
    print("Data streams:")
    for ds in sorted(es.indices.get_data_stream(name="logs-*")["data_streams"], key=lambda d: d["name"]):
        es.indices.refresh(index=ds["name"])
        print(f"  {ds['name']:40s} {es.count(index=ds['name'])['count']:>8d} docs")
    print("Registered sources:")
    for sid, m in sorted(registry.meta().items()):
        print(f"  {sid:24s} -> {m['template']:24s} ({m['decision']}, channel {m.get('channel')}, parsed {ingest.parsed_count(sid)})")
    print("Unparsed backlog:", ingest.unparsed_counts() or "none")


def cmd_reset(a):
    from . import admin
    if not a.yes:
        print("This deletes every logs-* data stream, the registry and the dropzone. Re-run with --yes."); return
    admin.reset_all(keep_generated=a.keep_generated)


def cmd_mcp(a):
    from .mcp_server import main
    main()


def cmd_hunt(a):
    from .hunting import run_hunt
    print(run_hunt(a.hypothesis, profile=a.profile, run_name=a.run_name, plan_from=a.plan_from))


def cmd_evaluate(a):
    from .evaluate import evaluate
    print(json.dumps(evaluate(a.run_dir), indent=2, default=str))


def cmd_render(a):
    from .report import render_markdown
    render_markdown(a.run_dir)
    print(f"rendered {a.run_dir}/report.md")


def cmd_compare(a):
    from .compare import compare_runs
    print(compare_runs(a.run_a, a.run_b))


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m hunt", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("templates"); t.add_argument("action", choices=["install", "list"]); t.set_defaults(f=cmd_templates)
    i = sub.add_parser("ingest"); i.add_argument("channel", choices=["pull", "push", "stream"]); i.add_argument("path")
    i.add_argument("--source-id", required=True); i.add_argument("--eps", type=int, default=500)
    i.add_argument("--no-watch", action="store_true"); i.set_defaults(f=cmd_ingest)
    w = sub.add_parser("watch"); w.add_argument("--once", action="store_true"); w.add_argument("--idle-exit", type=int); w.set_defaults(f=cmd_watch)
    o = sub.add_parser("onboard"); o.add_argument("source_id"); o.add_argument("--sample-file"); o.set_defaults(f=cmd_onboard)
    sub.add_parser("status").set_defaults(f=cmd_status)
    r = sub.add_parser("reset"); r.add_argument("--yes", action="store_true"); r.add_argument("--keep-generated", action="store_true")
    r.set_defaults(f=cmd_reset)
    sub.add_parser("mcp").set_defaults(f=cmd_mcp)
    h = sub.add_parser("hunt"); h.add_argument("hypothesis"); h.add_argument("--profile", default="converged", choices=["converged", "baseline"])
    h.add_argument("--run-name"); h.add_argument("--plan-from", help="re-use the plan of an earlier run (frozen playbook)")
    h.set_defaults(f=cmd_hunt)
    e = sub.add_parser("evaluate"); e.add_argument("run_dir"); e.set_defaults(f=cmd_evaluate)
    rr = sub.add_parser("render"); rr.add_argument("run_dir"); rr.set_defaults(f=cmd_render)
    c = sub.add_parser("compare"); c.add_argument("run_a"); c.add_argument("run_b"); c.set_defaults(f=cmd_compare)
    a = p.parse_args(argv)
    a.f(a)


if __name__ == "__main__":
    sys.exit(main())
