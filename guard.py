"""Offline, read-only zizmor 1.32.0 adapter. Original Sandworm code, MIT."""
import argparse
import hashlib
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from guard_safeio import InputError, read_bytes, parse_json, bounded_run, write_json

PROJECT = "sandworm-workflow-guard"
ENGINE_VERSION = "1.32.0"
HINTS = {
    "template-injection": "ย้ายค่าจาก event ไป env แล้วอ้างผ่านตัวแปร shell แทนการแทรก expression ลง run",
    "excessive-permissions": "กำหนด permissions เท่าที่ job ต้องใช้ โดยเริ่มจาก contents: read",
    "artipacked": "ปิด persist-credentials ของ checkout หากขั้นตอนถัดไปไม่ต้อง push",
    "unpinned-uses": "ตรึง action ด้วย commit SHA ที่ตรวจสอบแล้ว และใช้ระบบอัปเดต dependency",
    "unpinned-images": "ตรึง image ด้วย digest ที่ตรวจสอบแล้ว",
    "dangerous-triggers": "ตรวจ trust boundary ของ pull_request_target/workflow_run ก่อนใช้ข้อมูล PR",
    "cache-poisoning": "แยก cache ของงานที่รับข้อมูลไม่เชื่อถือออกจากงานที่มีสิทธิ์สูง",
    "use-trusted-publishing": "พิจารณา trusted publishing แทน token ที่อายุยาว",
    "secrets-outside-env": "ทบทวนการส่ง secret และขอบเขตสิทธิ์ของขั้นตอนนั้น",
    "unredacted-secrets": "ตรวจการ mask secret และหยุดเผยแพร่ค่าลง log",
    "unsound-contains": "ตรวจเงื่อนไขการอนุญาตด้วยการเทียบที่ชัดเจน",
    "stale-action-refs": "ตรวจรุ่น action และข้อกำหนดการอัปเดต",
    "unspanned": "เปิด finding ต้นทางในเครื่องแล้วตรวจบริบทของ workflow",
}
LEVELS = {"Informational", "Low", "Medium", "High", "Unknown"}

def normalize(rows, mode="import"):
    if mode not in {"live", "import", "fixture"}:
        raise InputError("INVALID_MODE")
    if not isinstance(rows, list) or len(rows) > 5000:
        raise InputError("ZIZMOR_JSON_V1_ARRAY_REQUIRED")
    findings = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("ident"), str) or not 1 <= len(row["ident"]) <= 160:
            raise InputError("INVALID_FINDING")
        ident = row["ident"]
        determinations = row.get("determinations")
        locations = row.get("locations")
        if not isinstance(determinations, dict) or not isinstance(locations, list) or not locations or len(locations) > 100:
            raise InputError("INVALID_FINDING")
        severity = determinations.get("severity", "Unknown")
        confidence = determinations.get("confidence", "Unknown")
        if not isinstance(severity, str) or not isinstance(confidence, str) or severity not in LEVELS or confidence not in LEVELS:
            raise InputError("INVALID_LEVEL")
        if any(not isinstance(x, dict) or not isinstance(x.get("symbolic"), dict) for x in locations):
            raise InputError("INVALID_FINDING")
        primary = next((x for x in locations if x["symbolic"].get("kind") == "Primary"), locations[0])
        try:
            path = primary["symbolic"]["key"]["Local"]["verbatim_path"]
            start = primary["concrete"]["location"]["start_point"]
            line, column = start["row"], start["column"]
        except (KeyError, TypeError):
            raise InputError("LOCAL_LOCATION_REQUIRED") from None
        if not isinstance(path, str) or not 1 <= len(path) <= 1024 or any(c in path for c in "\x00\r\n"):
            raise InputError("INVALID_PATH")
        if type(line) is not int or not 0 <= line <= 10000000 or type(column) is not int or not 0 <= column <= 1000000:
            raise InputError("INVALID_LOCATION")
        # Do not copy snippets, annotations, free-text descriptions, URLs or paths.
        rule = ident if ident in HINTS else "unclassified-rule"
        fingerprint = hashlib.sha256(json.dumps([ident, path, line, column], separators=(",", ":")).encode()).hexdigest()
        findings[fingerprint] = {"id": fingerprint, "rule": rule,
                                 "file_id": hashlib.sha256(path.encode()).hexdigest(),
                                 "line": line + 1, "column": column + 1,
                                 "severity": severity.lower(), "confidence": confidence.lower(),
                                 "guidance_th": HINTS.get(ident, "อ่าน finding ต้นทางในเครื่อง แล้วตรวจสิทธิ์และบริบทก่อนแก้ไข")}
    ordered = sorted(findings.values(), key=lambda x: x["id"])
    return {"schema_version": 1, "project": PROJECT, "mode": mode,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "engine": {"name": "zizmor", "version": None, "supported_version": ENGINE_VERSION,
                       "version_verified": False, "network": None, "format": "json-v1"},
            "summary": {"findings": len(ordered), "high": sum(x["severity"] == "high" for x in ordered),
                        "duplicates_removed": len(rows)-len(ordered)},
            "findings": ordered,
            "privacy": {"paths": "SHA-256 aliases", "workflow_snippets": "omitted", "raw_metadata": "omitted"}}

def compare(current, baseline):
    if not isinstance(baseline, dict) or baseline.get("project") != PROJECT or baseline.get("schema_version") != 1:
        raise InputError("INVALID_BASELINE")
    rows = baseline.get("findings")
    if not isinstance(rows, list) or len(rows) > 5000:
        raise InputError("INVALID_BASELINE")
    old = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not re.fullmatch("[0-9a-f]{64}", row["id"]):
            raise InputError("INVALID_BASELINE")
        old.add(row["id"])
    now = {row["id"] for row in current["findings"]}
    return {"new_ids": sorted(now-old), "resolved_ids": sorted(old-now), "unchanged": len(now & old)}

def collect_files(root, selected):
    root_path = Path(root)
    if root_path.is_symlink() or not root_path.is_dir():
        raise InputError("LOCAL_DIRECTORY_REQUIRED")
    root_path = root_path.resolve()
    if not selected or len(selected) > 64 or any(not isinstance(x, str) for x in selected) or len(set(selected)) != len(selected):
        raise InputError("SELECT_1_TO_64_UNIQUE_FILES")
    files, total = [], 0
    for value in selected:
        path = Path(value)
        if value.startswith("-") or path.is_absolute() or any(part in {"", ".", ".."} for part in value.replace("\\", "/").split("/")) or "\\" in value:
            raise InputError("RELATIVE_PATH_REQUIRED")
        if path.suffix not in {".yml", ".yaml"}:
            raise InputError("YAML_FILE_REQUIRED")
        source = root_path/path
        if any((root_path/Path(*path.parts[:i])).is_symlink() for i in range(1, len(path.parts)+1)):
            raise InputError("SYMLINK_NOT_ALLOWED")
        if not source.resolve().is_relative_to(root_path):
            raise InputError("PATH_OUTSIDE_ROOT")
        data = read_bytes(source, 256*1024)
        total += len(data)
        if total > 2*1024*1024:
            raise InputError("INPUT_TOO_LARGE")
        files.append((path, data))
    return files

def scan(root, selected, binary):
    files = collect_files(root, selected)
    executable = str(Path(binary).resolve())
    with tempfile.TemporaryDirectory(prefix="sandworm-workflow-") as temp:
        cwd = Path(temp)
        version = bounded_run([executable, "--version"], cwd, timeout=10, limit=1024).decode("utf-8", errors="replace")
        if not re.search(r"\b1\.32\.0\b", version):
            raise InputError("ENGINE_VERSION_MISMATCH")
        for path, data in files:
            target = cwd/path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        argv = [executable, "--offline", "--no-config", "--strict-collection", "--no-exit-codes", "--format=json-v1", "--", *[p.as_posix() for p, _ in files]]
        rows = parse_json(bounded_run(argv, cwd, timeout=60))
        report = normalize(rows, "live")
        report["engine"].update({"version": ENGINE_VERSION, "version_verified": True, "network": "offline"})
        report["inputs"] = [{"file_id": hashlib.sha256(path.as_posix().encode()).hexdigest(),
                             "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for path, data in files]
        return report

def main(argv=None):
    parser = argparse.ArgumentParser(description="Sandworm Workflow Guard — read-only offline workflow audits")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import")
    imp.add_argument("input")
    sc = sub.add_parser("scan")
    sc.add_argument("root")
    sc.add_argument("files", nargs="+")
    sc.add_argument("--binary", default=".venv/bin/zizmor")
    for cmd in (imp, sc):
        cmd.add_argument("--output", required=True)
        cmd.add_argument("--baseline")
    args = parser.parse_args(argv)
    try:
        report = scan(args.root, args.files, args.binary) if args.command == "scan" else normalize(parse_json(read_bytes(args.input)))
        if args.baseline:
            report["comparison"] = compare(report, parse_json(read_bytes(args.baseline)))
        write_json(args.output, report)
        print("REPORT_WRITTEN")
        return 0
    except InputError as exc:
        print(str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
