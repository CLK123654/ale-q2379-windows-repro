from __future__ import annotations

import argparse
import atexit
import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path


ACTORS = (
    "north_reader",
    "north_editor",
    "south_editor",
    "east_reader",
    "portfolio_auditor",
)
SQL_FILES = (
    "01_roles.sql",
    "02_schema.sql",
    "03_rls.sql",
    "04_reporting.sql",
    "05_load.sql",
)


def run(command: list[str], *, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
        timeout=300,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed with return code {completed.returncode}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def psql_base(psql: str, url: str) -> list[str]:
    return [psql, "--dbname", url, "-X", "--set", "ON_ERROR_STOP=1"]


def sql_path(path: Path) -> str:
    return path.resolve().as_posix().replace("'", "''")


def export_csv(psql: str, admin_url: str, sql: str, target: Path) -> None:
    completed = run(
        psql_base(psql, admin_url)
        + ["--quiet", "--command", f"COPY ({sql}) TO STDOUT WITH (FORMAT CSV, HEADER TRUE)"]
    )
    target.write_text(completed.stdout, encoding="utf-8", newline="")


def scalar(psql: str, admin_url: str, sql: str) -> str:
    return run(
        psql_base(psql, admin_url) + ["--tuples-only", "--no-align", "--command", sql]
    ).stdout.strip()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def copy_delivery_material(output: Path) -> None:
    script = Path(__file__).resolve()
    authoring_source = script.parent / "template_output"
    sql_source = authoring_source / "sql" if authoring_source.is_dir() else script.parent.parent / "sql"
    scenario_source = script.parent / "run_access_scenarios.py"
    if not scenario_source.is_file():
        scenario_source = script.parent.parent / "tools" / "run_access_scenarios.py"
    shutil.copytree(sql_source, output / "sql")
    (output / "tools").mkdir()
    shutil.copy2(script, output / "tools" / "build_delivery.py")
    shutil.copy2(scenario_source, output / "tools" / "run_access_scenarios.py")


def deploy(psql: str, admin_url: str, input_root: Path, output: Path, actor_password: str) -> None:
    sql_root = output / "sql"
    statements = ["BEGIN;"]
    for name in SQL_FILES:
        text = (sql_root / name).read_text(encoding="utf-8")
        text = text.replace("__ACTOR_PASSWORD__", actor_password)
        text = text.replace("__TENANT_CSV__", sql_path(input_root / "data" / "tenant.csv"))
        text = text.replace(
            "__ACTOR_GRANT_CSV__", sql_path(input_root / "data" / "actor_tenant_grant.csv")
        )
        text = text.replace(
            "__METER_INTERVAL_CSV__", sql_path(input_root / "data" / "meter_interval.csv")
        )
        statements.append(text)
    statements.append("COMMIT;")
    run(psql_base(psql, admin_url), stdin="\n".join(statements))


def actor_urls(host: str, port: int, database: str, password: str) -> dict[str, str]:
    return {
        actor: f"postgresql://{actor}:{password}@{host}:{port}/{database}"
        for actor in ACTORS
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--psql", default="psql")
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--database", required=True)
    parser.add_argument("--actor-password", required=True)
    parser.add_argument("--deploy-only", action="store_true")
    args = parser.parse_args()

    input_root = Path(args.input).resolve()
    output = Path(args.output).resolve()
    required = [
        input_root / "contracts" / "access_contract.json",
        input_root / "contracts" / "access_scenarios.csv",
        input_root / "data" / "tenant.csv",
        input_root / "data" / "actor_tenant_grant.csv",
        input_root / "data" / "meter_interval.csv",
        input_root / "starter" / "20_rls_broken.sql",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise SystemExit("missing input files: " + ", ".join(missing))

    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    completed = {"value": False}

    def clean_failure() -> None:
        if not completed["value"] and output.exists():
            shutil.rmtree(output)

    atexit.register(clean_failure)
    copy_delivery_material(output)
    deploy(args.psql, args.admin_url, input_root, output, args.actor_password)
    if args.deploy_only:
        completed["value"] = True
        return

    results = output / "results"
    results.mkdir()
    export_csv(
        args.psql,
        args.admin_url,
        """SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
             FROM pg_policies
             WHERE schemaname='core' AND tablename='meter_interval'
             ORDER BY policyname""",
        results / "policy_catalog.csv",
    )
    export_csv(
        args.psql,
        args.admin_url,
        """SELECT n.nspname AS schema_name, c.relname AS table_name,
                    c.relrowsecurity::text AS rls_enabled,
                    c.relforcerowsecurity::text AS rls_forced,
                    pg_get_userbyid(c.relowner) AS owner_name
             FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='core' AND c.relname='meter_interval'""",
        results / "relation_security.csv",
    )
    export_csv(
        args.psql,
        args.admin_url,
        """SELECT role_name, object_name, privilege_name, granted::text AS granted
             FROM (VALUES
               ('north_editor','core.meter_interval','DELETE',has_table_privilege('north_editor','core.meter_interval','DELETE')),
               ('north_reader','core.meter_interval','SELECT',has_table_privilege('north_reader','core.meter_interval','SELECT')),
               ('portfolio_auditor','core.meter_interval','SELECT',has_table_privilege('portfolio_auditor','core.meter_interval','SELECT')),
               ('portfolio_auditor','reporting.tenant_daily_summary(text)','EXECUTE',has_function_privilege('portfolio_auditor','reporting.tenant_daily_summary(text)','EXECUTE')),
               ('public','auth.actor_allowed(text,text)','EXECUTE',has_function_privilege('public','auth.actor_allowed(text,text)','EXECUTE')),
               ('public','reporting.tenant_daily_summary(text)','EXECUTE',has_function_privilege('public','reporting.tenant_daily_summary(text)','EXECUTE')),
               ('report_owner','auth.actor_tenant_grant','SELECT',has_table_privilege('report_owner','auth.actor_tenant_grant','SELECT')),
               ('report_owner','core.meter_interval','SELECT',has_table_privilege('report_owner','core.meter_interval','SELECT'))
             ) AS v(role_name, object_name, privilege_name, granted)""",
        results / "privilege_surface.csv",
    )
    export_csv(
        args.psql,
        args.admin_url,
        """SELECT tenant_id, (observed_at AT TIME ZONE 'UTC')::date AS usage_date,
                    count(*)::bigint AS interval_count, sum(kwh)::numeric AS total_kwh,
                    count(*) FILTER (WHERE quality_flag='ESTIMATED')::bigint AS estimated_count
             FROM core.meter_interval
             GROUP BY tenant_id, (observed_at AT TIME ZONE 'UTC')::date
             ORDER BY tenant_id, usage_date""",
        results / "daily_summary.csv",
    )

    urls = actor_urls(args.host, args.port, args.database, args.actor_password)
    scenario_command = [
        sys.executable,
        str(output / "tools" / "run_access_scenarios.py"),
        "--input-root",
        str(input_root),
        "--output",
        str(results / "access_matrix.csv"),
        "--psql",
        args.psql,
    ]
    for actor in ACTORS:
        scenario_command.extend(["--actor-url", f"{actor}={urls[actor]}"])
    run(scenario_command)

    tenants = read_csv(input_root / "data" / "tenant.csv")
    grants = read_csv(input_root / "data" / "actor_tenant_grant.csv")
    intervals = read_csv(input_root / "data" / "meter_interval.csv")
    scenarios = read_csv(input_root / "contracts" / "access_scenarios.csv")
    policies = read_csv(results / "policy_catalog.csv")
    access_rows = read_csv(results / "access_matrix.csv")
    summaries = read_csv(results / "daily_summary.csv")
    relation = read_csv(results / "relation_security.csv")
    privilege = read_csv(results / "privilege_surface.csv")
    expected_daily = len({(row["tenant_id"], row["observed_at"][:10]) for row in intervals})
    checks = {
        "relation_rls_enabled": relation == [{
            "schema_name": "core", "table_name": "meter_interval", "rls_enabled": "true",
            "rls_forced": "true", "owner_name": "rls_owner",
        }],
        "all_access_scenarios_match": len(access_rows) == len(scenarios)
        and all(row["result"] == "PASS" for row in access_rows),
        "daily_summary_key_set_matches_input": len(summaries) == expected_daily,
        "authorization_rows_loaded": int(scalar(args.psql, args.admin_url, "SELECT count(*) FROM auth.actor_tenant_grant")) == len(grants),
        "tenant_rows_loaded": int(scalar(args.psql, args.admin_url, "SELECT count(*) FROM auth.tenant")) == len(tenants),
        "interval_rows_loaded": int(scalar(args.psql, args.admin_url, "SELECT count(*) FROM core.meter_interval")) == len(intervals),
        "no_delete_policy": all(row["cmd"] != "DELETE" for row in policies),
        "public_function_execute_revoked": all(
            row["granted"] == "false" for row in privilege if row["role_name"] == "public"
        ),
    }
    if not all(checks.values()):
        raise RuntimeError("security review contains failed controls")
    review = {
        "status": "READY",
        "source_counts": {
            "tenants": len(tenants),
            "actor_grants": len(grants),
            "meter_intervals": len(intervals),
            "access_scenarios": len(scenarios),
        },
        "observed_counts": {
            "policies": len(policies),
            "access_results": len(access_rows),
            "daily_summary_rows": len(summaries),
        },
        "checks": checks,
    }
    (results / "security_review.json").write_text(
        json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output / "HANDOVER.md").write_text(
        "# 共享计量库安全交接\n\n"
        "sql目录保存角色、表结构、RLS策略、受控日报和数据装载脚本。\n\n"
        "results目录保存数据库目录快照、访问场景结果、日报结果和安全复核结论。"
        "security_review.json状态为READY时，可以进入发布评审。\n",
        encoding="utf-8",
    )
    completed["value"] = True


if __name__ == "__main__":
    main()
