"""CLI:  python -m netinv serve | collect <ad|snmp|pcs|pcs_updates|dc_logons|all> | demo | views"""
import argparse
import sys

from .config import settings
from .correlate import create_views
from .db import SessionLocal, init_db


def main() -> None:
    ap = argparse.ArgumentParser(prog="netinv")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8080)
    c = sub.add_parser("collect")
    c.add_argument("job", choices=["ad", "snmp", "pcs", "pcs_updates", "dc_logons", "all"])
    sub.add_parser("demo", help="load sample data so you can try the dashboard")
    sub.add_parser("views", help="(re)create the reporting views")
    args = ap.parse_args()

    if args.cmd == "serve":
        import uvicorn
        uvicorn.run("netinv.main:app", host=args.host, port=args.port)
        return

    init_db(settings.database_url)
    with SessionLocal() as db:
        create_views(db)
    if args.cmd == "collect":
        from . import jobs
        names = jobs.ALL_ORDER if args.job == "all" else [args.job]
        failed = False
        for n in names:
            run = jobs.run_job(n)
            print(f"[{'ok' if run.ok else 'FAIL'}] {n}: {run.message}")
            failed |= not run.ok
        sys.exit(1 if failed else 0)
    elif args.cmd == "demo":
        from .demo import seed
        with SessionLocal() as db:
            print(seed(db))


if __name__ == "__main__":
    main()
