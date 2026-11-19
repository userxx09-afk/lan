"""CLI:  python -m netinv serve | collect <ad|snmp|pcs|pcs_updates|dc_logons|all> | demo | views | cert | hashpw"""
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
    ce = sub.add_parser("cert", help="make a self-signed HTTPS certificate (tls.crt / tls.key)")
    ce.add_argument("--out", required=True, help="folder to write tls.crt and tls.key to")
    ce.add_argument("--force", action="store_true", help="replace existing files")
    sub.add_parser("hashpw", help="hash the password in NETINV_HASHPW (or on stdin) for config.toml")
    args = ap.parse_args()

    if args.cmd == "serve":
        import logging

        import uvicorn

        class _QuietResets(logging.Filter):
            """On Windows, asyncio logs a full traceback whenever a browser or probe drops a connection
            ([WinError 10054] in _ProactorBasePipeTransport._call_connection_lost). It's harmless noise."""
            def filter(self, record: logging.LogRecord) -> bool:
                exc = record.exc_info[1] if record.exc_info else None
                return not isinstance(exc, (ConnectionResetError, ConnectionAbortedError))

        logging.getLogger("asyncio").addFilter(_QuietResets())
        tls = {}
        if settings.tls_cert and settings.tls_key:
            tls = {"ssl_certfile": settings.tls_cert, "ssl_keyfile": settings.tls_key}
        uvicorn.run("netinv.main:app", host=args.host, port=args.port, proxy_headers=False, **tls)
        return
    if args.cmd == "cert":
        from .tlscert import make_self_signed
        print(make_self_signed(args.out, force=args.force))
        return
    if args.cmd == "hashpw":
        from .auth import hash_password
        import os
        pw = os.environ.pop("NETINV_HASHPW", None)   # Unicode-safe on Windows, unlike a PowerShell pipe
        if pw is None:
            pw = sys.stdin.readline().rstrip("\r\n")
        if len(pw) < 8:
            sys.exit("password too short")
        print(hash_password(pw))
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
        from . import portmap
        with SessionLocal() as db:      # the server refreshes its copy within 15 minutes; do it now
            portmap.refresh(db)
        sys.exit(1 if failed else 0)
    elif args.cmd == "demo":
        from .demo import seed
        with SessionLocal() as db:
            print(seed(db))


if __name__ == "__main__":
    main()
