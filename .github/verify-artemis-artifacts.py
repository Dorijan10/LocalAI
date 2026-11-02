"""Verify every TurinTech Hugging Face file referenced by the model library."""
import argparse
import hashlib
import os
import subprocess
import sys
from urllib.parse import urlparse

import requests
import yaml

ORG_PREFIX = "https://huggingface.co/turintech/"


def repo_and_file(uri):
    parts = urlparse(uri).path.strip("/").split("/")
    return f"{parts[0]}/{parts[1]}", parts[-1]


def checker_sha(uri):
    """LFS sha256 as reported by LocalAI's nightly checker, .github/check_and_update.py."""
    p = subprocess.run([sys.executable, ".github/check_and_update.py", uri],
                       capture_output=True, text=True)
    lines = p.stdout.strip().splitlines()
    return p.returncode, (lines[-1].strip() if lines else ""), p.stderr.strip()[-300:]


def scan_clean(repo):
    r = requests.get(f"https://huggingface.co/api/models/{repo}/scan", timeout=60)
    r.raise_for_status()
    scan = r.json()
    return not scan.get("hasUnsafeFile", False) and not scan.get("filesWithIssues")


def bytes_sha(uri):
    h = hashlib.sha256()
    size = 0
    with requests.get(uri, stream=True, timeout=120) as r:
        r.raise_for_status()
        for chunk in r.iter_content(chunk_size=8 << 20):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def collect(library):
    with open(library) as fh:
        entries = yaml.safe_load(fh)
    files = {}
    for e in entries:
        for f in (e.get("model") or {}).get("files") or []:
            uri = f.get("uri", "")
            if not uri.startswith(ORG_PREFIX):
                continue
            rec = files.setdefault(uri, {"sha": f.get("sha256", ""), "entries": [], "conflict": False})
            rec["conflict"] |= rec["sha"] != f.get("sha256", "")
            rec["entries"].append(e.get("name"))
    return files


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("library")
    ap.add_argument("--skip-bytes", action="store_true", help="skip the full download (local dry run)")
    args = ap.parse_args()

    files = collect(args.library)
    if not files:
        sys.exit("no TurinTech files found in the library")

    scans, rows = {}, []
    for uri, rec in files.items():
        repo, name = repo_and_file(uri)
        if repo not in scans:
            scans[repo] = scan_clean(repo)
        rc, lfs, err = checker_sha(uri)
        lfs_ok = rc == 0 and lfs == rec["sha"]
        if args.skip_bytes:
            got, size, bytes_ok = "", 0, None
        else:
            got, size = bytes_sha(uri)
            bytes_ok = got == rec["sha"]
        ok = scans[repo] and lfs_ok and bytes_ok is not False and not rec["conflict"]
        rows.append((repo, name, size, rec, lfs_ok, bytes_ok, scans[repo], ok))
        print(f"{'OK  ' if ok else 'FAIL'} {repo}/{name} entry={rec['sha'][:12]} "
              f"checker={lfs[:12] or 'exit %d' % rc} bytes={got[:12] or '-'} size={size} "
              f"scan_clean={scans[repo]}" + (f" stderr={err}" if rc else ""), flush=True)

    passed = sum(r[-1] for r in rows)
    n_entries = len({n for _, _, _, rec, *_ in rows for n in rec["entries"]})
    word = {True: "match", False: "MISMATCH", None: "skipped"}
    out = [
        "## TurinTech files in the model library",
        "",
        f"{passed} of {len(rows)} files passed, across {n_entries} entries.",
        "",
        "Per file, the sha256 in the entry must equal the LFS sha256 that LocalAI's "
        "`.github/check_and_update.py` reports and the sha256 of the bytes downloaded from the "
        "entry's uri, and the repo's Hugging Face security scan must list no issues.",
        "",
        "| Repo | File | GiB | Entry sha256 | check_and_update.py | Downloaded bytes | Scan | Entries |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for repo, name, size, rec, lfs_ok, bytes_ok, clean, ok in rows:
        out.append(f"| {repo} | `{name}` | {size / 2**30:.2f} | `{rec['sha'][:16]}` | "
                   f"{word[lfs_ok]} | {word[bytes_ok]} | {'clean' if clean else 'FLAGGED'} | "
                   f"{', '.join(rec['entries'])} |")
    text = "\n".join(out) + "\n"
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(text)
    else:
        print(text)
    sys.exit(0 if passed == len(rows) else 1)


if __name__ == "__main__":
    main()
