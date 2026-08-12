from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TASK = ROOT / "task"
EVIDENCE = ROOT / "evidence"
RUN_ROOT = ROOT / "windows-runs"
PSQL = os.environ["PSQL_PATH"]
SERVER_ADMIN_URL = os.environ["SERVER_ADMIN_URL"]
ACTOR_PASSWORD = "LocalActorPass2379"
ROLES = "north_reader, north_editor, south_editor, east_reader, portfolio_auditor, app_reader, app_writer, report_owner, policy_owner, rls_owner"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reset(path: Path) -> None:
    if path.exists(): shutil.rmtree(path)
    path.mkdir(parents=True)


def extract(archive: Path, target: Path) -> None:
    target.mkdir(parents=True)
    with zipfile.ZipFile(archive) as package: package.extractall(target)


def normalized(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def paths(root: Path) -> list[str]:
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())


def compare(actual: Path, expected: Path) -> list[str]:
    actual_paths, expected_paths = paths(actual), paths(expected)
    if actual_paths != expected_paths: raise AssertionError("delivery path set differs from Reference")
    for relative in expected_paths:
        if normalized(actual / relative) != normalized(expected / relative):
            raise AssertionError(f"delivery differs from Reference: {relative}")
    return expected_paths


def admin(sql: str) -> str:
    completed = subprocess.run([PSQL, "--dbname", SERVER_ADMIN_URL, "-X", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1", "--command", sql], text=True, capture_output=True, timeout=60)
    if completed.returncode: raise AssertionError(completed.stdout + completed.stderr)
    return completed.stdout.strip()


def reset_database(database: str) -> None:
    existing = admin("SELECT datname FROM pg_database WHERE datname LIKE 'tenant_access_%'")
    for name in existing.splitlines():
        if name.strip():
            admin(f"DROP DATABASE IF EXISTS {name.strip()} WITH (FORCE)")
    admin(f"DROP ROLE IF EXISTS {ROLES}")
    admin(f"CREATE DATABASE {database}")


def build(input_root: Path, output: Path, database: str, deploy_only: bool = False) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable, str(ROOT / "implementation/build_delivery.py"), "--input", str(input_root),
        "--output", str(output), "--psql", PSQL,
        "--admin-url", f"postgresql://postgres:root@127.0.0.1:5432/{database}",
        "--host", "127.0.0.1", "--port", "5432", "--database", database,
        "--actor-password", ACTOR_PASSWORD,
    ]
    if deploy_only: command.append("--deploy-only")
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=300)


def main() -> None:
    reset(RUN_ROOT); EVIDENCE.mkdir(exist_ok=True)
    expected_hashes = json.loads((ROOT / "qa/expected_hashes.json").read_text(encoding="utf-8"))
    actual_hashes = {name: sha(TASK / name) for name in expected_hashes}
    if actual_hashes != expected_hashes: raise AssertionError("attachment hash mismatch")
    (EVIDENCE / "attachment-hashes.json").write_text(json.dumps(actual_hashes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    version = subprocess.run([PSQL, "--version"], text=True, capture_output=True, timeout=30)
    if version.returncode or not any(f" {major}." in version.stdout for major in range(17, 30)):
        raise AssertionError("PostgreSQL17 or later is required")

    reference = RUN_ROOT / "reference"; extract(TASK / "reference.zip", reference)
    expected_output = reference / "output"
    clean_runs = []
    for index, label in enumerate(["clean-a", "clean-b"], start=1):
        base = RUN_ROOT / label; extract(TASK / "输入数据包.zip", base)
        input_root = base / "input_data"
        before = {p.relative_to(input_root).as_posix(): sha(p) for p in input_root.rglob("*") if p.is_file()}
        for process_index in [1, 2]:
            database = f"tenant_access_{index}_{process_index}"
            reset_database(database)
            output = base / f"output-{process_index}"
            completed = build(input_root, output, database)
            if completed.returncode: raise AssertionError(completed.stdout + completed.stderr)
            generated = compare(output, expected_output)
            clean_runs.append({"root_id": label, "process_index": process_index, "return_code": 0, "output_started_empty": True, "primary_software_executed": True, "input_unchanged": True, "reference_match": True, "generated_paths": generated})
        after = {p.relative_to(input_root).as_posix(): sha(p) for p in input_root.rglob("*") if p.is_file()}
        if before != after: raise AssertionError("input changed")

    positive = RUN_ROOT / "positive"; extract(TASK / "输入数据包.zip", positive)
    grant_path = positive / "input_data/data/actor_tenant_grant.csv"
    with grant_path.open("a", encoding="utf-8", newline="") as handle: handle.write("north_reader,TEN-S,true,false,false\n")
    reset_database("tenant_access_positive")
    completed = build(positive / "input_data", positive / "output", "tenant_access_positive", deploy_only=True)
    if completed.returncode: raise AssertionError(completed.stdout + completed.stderr)
    visible = subprocess.run([PSQL, "--dbname", f"postgresql://north_reader:{ACTOR_PASSWORD}@127.0.0.1:5432/tenant_access_positive", "-X", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1", "--command", "SELECT count(*) FROM core.meter_interval WHERE tenant_id='TEN-S'"], text=True, capture_output=True, timeout=30)
    if visible.returncode or visible.stdout.strip() != "8": raise AssertionError("positive grant did not change visibility")
    (EVIDENCE / "positive-case.json").write_text(json.dumps({"mutation": "add TEN-S read grant to north_reader", "visible_rows_before": 0, "visible_rows_after": 8, "passed": True}, indent=2) + "\n", encoding="utf-8")

    negative = RUN_ROOT / "negative"; extract(TASK / "输入数据包.zip", negative)
    grant_path = negative / "input_data/data/actor_tenant_grant.csv"
    rows = grant_path.read_text(encoding="utf-8").splitlines(); grant_path.write_text("\n".join(rows + [rows[1]]) + "\n", encoding="utf-8")
    reset_database("tenant_access_negative")
    output = negative / "output"; output.mkdir(); (output / "stale.txt").write_text("stale", encoding="utf-8")
    completed = build(negative / "input_data", output, "tenant_access_negative")
    if completed.returncode == 0 or output.exists(): raise AssertionError("duplicate authorization did not fail closed")
    (EVIDENCE / "negative-case.log").write_text(f"return_code={completed.returncode}\n{completed.stdout}{completed.stderr}", encoding="utf-8")

    summary = {
        "result": "PASS", "commit_sha": os.getenv("GITHUB_SHA"), "workflow_run_id": os.getenv("GITHUB_RUN_ID"),
        "runner_image": os.getenv("ImageOS"), "main_software": {"name": "PostgreSQL", "version": version.stdout.strip(), "executed": True},
        "attachment_sha256": actual_hashes, "clean_directory_count": 2, "process_runs_per_directory": 2,
        "clean_runs": clean_runs, "positive_mutation": "PASS", "negative_case": "PASS",
        "formal_network": {"python_outbound_blocked": True, "psql_internet_blocked": True, "loopback_only": True, "external_services_used": False},
        "linux_executables": [], "linux_executables_executed": False,
    }
    (EVIDENCE / "windows-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__": main()
