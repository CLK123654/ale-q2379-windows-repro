import argparse
import csv
import json
import os
import re
import subprocess
from pathlib import Path

ACTOR_URL_ENV = {
    "north_reader": "PGURL_NORTH_READER",
    "north_editor": "PGURL_NORTH_EDITOR",
    "south_editor": "PGURL_SOUTH_EDITOR",
    "east_reader": "PGURL_EAST_READER",
    "portfolio_auditor": "PGURL_PORTFOLIO_AUDITOR",
}
COMMAND_TAG = re.compile(r"^(BEGIN|ROLLBACK|INSERT [0-9]+ [0-9]+|UPDATE [0-9]+|DELETE [0-9]+)$")
SQLSTATE = re.compile(r"(?:ERROR|FATAL):\s+([0-9A-Z]{5}):")


def run_probe(psql, url, statement):
    script = "BEGIN;\n" + statement.rstrip(";") + ";\nROLLBACK;\n"
    completed = subprocess.run(
        [
            psql,
            "--dbname",
            url,
            "-X",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
            "--set",
            "VERBOSITY=verbose",
        ],
        input=script,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        match = SQLSTATE.search(completed.stderr)
        error_lines = [line for line in completed.stderr.splitlines() if "ERROR:" in line]
        evidence = error_lines[0] if error_lines else completed.stderr.splitlines()[-1]
        return "DENY", 0, match.group(1) if match else "", evidence
    rows = [
        line
        for line in completed.stdout.splitlines()
        if line.strip() and not COMMAND_TAG.match(line.strip())
    ]
    return "ALLOW", len(rows), "", rows[:3]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--psql", default="psql")
    parser.add_argument(
        "--actor-url",
        action="append",
        default=[],
        metavar="ACTOR=URL",
        help="LOGIN-role connection URL; repeat once for each actor",
    )
    args = parser.parse_args()
    input_root = Path(args.input_root).resolve()
    contract = input_root / "contracts" / "access_scenarios.csv"
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    actor_urls = {}
    for item in args.actor_url:
        actor, separator, url = item.partition("=")
        if not separator or actor not in ACTOR_URL_ENV or not url:
            raise SystemExit(f"invalid --actor-url value: {item}")
        actor_urls[actor] = url
    result_rows = []
    with contract.open(newline="", encoding="utf-8") as handle:
        for probe in csv.DictReader(handle):
            env_name = ACTOR_URL_ENV[probe["actor"]]
            url = actor_urls.get(probe["actor"]) or os.environ.get(env_name)
            if not url:
                raise SystemExit(
                    f"missing connection for {probe['actor']}; pass --actor-url "
                    f"{probe['actor']}=URL or set {env_name}"
                )
            outcome, row_count, sqlstate, evidence = run_probe(args.psql, url, probe["sql"])
            passed = (
                outcome == probe["expected_outcome"]
                and row_count == int(probe["expected_row_count"])
                and sqlstate == probe["expected_sqlstate"]
            )
            result_rows.append({
                "scenario_id": probe["scenario_id"],
                "actor": probe["actor"],
                "objective": probe["objective"],
                "expected_outcome": probe["expected_outcome"],
                "actual_outcome": outcome,
                "expected_row_count": probe["expected_row_count"],
                "actual_row_count": row_count,
                "expected_sqlstate": probe["expected_sqlstate"],
                "actual_sqlstate": sqlstate,
                "result": "PASS" if passed else "FAIL",
                "evidence": json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))
                if isinstance(evidence, list)
                else evidence,
            })
    headers = list(result_rows[0])
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(result_rows)
    if any(row["result"] != "PASS" for row in result_rows):
        raise SystemExit("probe matrix failed")
    print(f"PASS: {len(result_rows)} access scenarios")


if __name__ == "__main__":
    main()
