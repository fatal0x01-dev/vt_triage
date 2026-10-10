#!/usr/bin/env python3
"""Scoped Arch/UEFI rootkit triage: inventory first, then optional VirusTotal lookup/upload.

Uses only the Python standard library. Never executes files from the evidence disk and
never follows symlinks while inventorying. The default inventory is deliberately limited
to system binary/library trees, kernel/boot files, the ESP, and selected persistence paths.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

VT_API = "https://www.virustotal.com/api/v3"
MAX_VT_SIZE = 650 * 1024 * 1024
MODULE_SUFFIXES = (".ko", ".ko.xz", ".ko.zst", ".ko.gz", ".ko.bz2")
KERNEL_RE = re.compile(r"^(vmlinuz(?:[-_.].*)?|bzimage|vmlinux|image|zimage)$", re.I)
BOOT_SUPPORT_RE = re.compile(r"^(initramfs|initrd|intel-ucode|amd-ucode)([-_.].*)?\.img$", re.I)
PE_SUFFIXES = (".efi",)
SCHEMA_VERSION = 3

# Paths are supplied explicitly on the command line. These exclusions remain enforced
# even if a user accidentally chooses a broad parent directory as a scan path.
EXCLUDED_ARCH_PATHS = (
    ("home",), ("root",), ("tmp",), ("run",), ("proc",), ("sys",),
    ("dev",), ("mnt",), ("media",), ("lost+found",),
    ("var", "cache"), ("var", "tmp"), ("var", "log"),
    ("usr", "share"),
)


class VTError(RuntimeError):
    pass


class RateLimiter:
    def __init__(self, delay: float, max_requests: int):
        if delay < 15:
            raise ValueError("--delay must be at least 15 seconds for the VirusTotal Public API (4 requests/minute).")
        self.delay, self.max_requests = delay, max_requests
        self.requests, self.last_call = 0, 0.0

    def wait(self) -> None:
        if self.requests >= self.max_requests:
            raise VTError(f"request cap reached ({self.max_requests}); stop before exceeding the configured cap")
        remaining = self.delay - (time.monotonic() - self.last_call)
        if self.last_call and remaining > 0:
            print(f"    rate limit: waiting {remaining:.1f}s", flush=True)
            time.sleep(remaining)
        self.last_call = time.monotonic()
        self.requests += 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pe_signature(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            head = f.read(4096)
        if not head.startswith(b"MZ") or len(head) < 0x40:
            return False
        offset = int.from_bytes(head[0x3C:0x40], "little")
        return 0 <= offset <= len(head) - 4 and head[offset:offset + 4] == b"PE\0\0"
    except OSError:
        return False


def classify_binary(path: Path, scope: str) -> tuple[str, bool] | None:
    """Return (type, upload-eligible) for a target binary/artifact, else None."""
    name = path.name.lower()
    if name.endswith(MODULE_SUFFIXES):
        return ("kernel-module", True)
    if name.endswith(".efi"):
        return ("efi-binary", True)
    if scope in ("boot", "efi"):
        if KERNEL_RE.match(name):
            return ("kernel-image", True)
        if BOOT_SUPPORT_RE.match(name):
            # Initramfs may include configuration/secrets; inventory it, don't upload by default.
            return ("boot-support (inventory only)", False)
    try:
        with path.open("rb") as f:
            if f.read(4) == b"\x7fELF":
                return ("ELF binary/library", True)
    except OSError:
        return None
    if pe_signature(path):
        return ("PE binary", True)
    return None


def within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def safe_scoped_path(root: Path, relative: str, allow_final_symlink: bool = False) -> Path | None:
    """Walk components with lstat, rejecting symlinks before accessing their children.

    This matters for forensic mounts: an absolute symlink inside the suspect filesystem
    would otherwise be interpreted relative to the live CAINE environment.
    """
    try:
        root_mode = root.lstat().st_mode
        import stat
        if not stat.S_ISDIR(root_mode) or stat.S_ISLNK(root_mode):
            return None
        current = root
        parts = Path(relative).parts
        for index, part in enumerate(parts):
            if part in ("", ".", "..", "/"):
                return None
            current = current / part
            mode = current.lstat().st_mode
            final = index == len(parts) - 1
            if stat.S_ISLNK(mode) and not (final and allow_final_symlink):
                return None
            if not final and not stat.S_ISDIR(mode):
                return None
        return current
    except (OSError, ValueError):
        return None


def excluded_arch_relative(relative: Path) -> bool:
    """Return True for general user/runtime/data trees intentionally excluded from triage."""
    parts = tuple(part.lower() for part in relative.parts if part not in ("", "."))
    return any(parts[:len(excluded)] == excluded for excluded in EXCLUDED_ARCH_PATHS)


def identify_root(path: Path, arch_root: Path, esp_root: Path) -> tuple[Path, str] | None:
    """Return (mounted root, label) for an explicitly requested path without resolving links."""
    path = Path(os.path.abspath(path))
    for mounted_root, label in ((arch_root, "arch"), (esp_root, "efi")):
        try:
            relative = path.relative_to(mounted_root)
        except ValueError:
            continue
        if not relative.parts and label != "efi":
            return None  # never allow the entire Arch filesystem as a scan target
        if label == "arch" and excluded_arch_relative(relative):
            return None
        try:
            import stat
            mode = mounted_root.lstat().st_mode
            if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
                return None
        except OSError:
            return None
        return mounted_root, label
    return None


def safe_requested_path(path: Path, arch_root: Path, esp_root: Path) -> tuple[Path, Path, str] | None:
    """Validate that a requested file/directory is below a mount root with no symlink ancestor."""
    path = Path(os.path.abspath(path))
    identified = identify_root(path, arch_root, esp_root)
    if identified is None:
        return None
    mounted_root, label = identified
    try:
        relative = path.relative_to(mounted_root)
        checked = mounted_root if not relative.parts else safe_scoped_path(mounted_root, str(relative))
        if checked is None or checked != path:
            return None
        import stat
        mode = checked.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            return None
        if label == "arch" and excluded_arch_relative(relative):
            return None
        return path, mounted_root, label
    except (OSError, ValueError):
        return None


def path_is_excluded(path: Path, arch_root: Path, esp_root: Path) -> bool:
    try:
        rel = path.relative_to(arch_root)
    except ValueError:
        return False
    return excluded_arch_relative(rel)


def iter_custom_path(base: Path, scope: str, scan_root: Path, include_all_files: bool,
                     arch_root: Path, esp_root: Path) -> Iterable[dict[str, Any]]:
    """Walk only one explicitly requested path. Never follow symlinks or enter excluded trees."""
    try:
        import stat
        base_mode = base.lstat().st_mode
    except OSError:
        return

    def record_file(path: Path) -> dict[str, Any] | None:
        classified = classify_binary(path, scope)
        if classified:
            kind, eligible = classified
        elif include_all_files:
            kind, eligible = "scoped artifact (inventory only)", False
        else:
            return None
        record = make_record(path, kind, scope, eligible, scan_root=scan_root)
        return record

    if stat.S_ISREG(base_mode):
        record = record_file(base)
        if record:
            yield record
        return
    if not stat.S_ISDIR(base_mode):
        return

    for dirpath, dirnames, filenames in os.walk(base, topdown=True, followlinks=False):
        current = Path(dirpath)
        safe_dirs: list[str] = []
        for dirname in dirnames:
            child = current / dirname
            if path_is_excluded(child, arch_root, esp_root):
                continue
            if child.is_symlink():
                if include_all_files:
                    try:
                        yield {
                            "path": str(child), "scan_root": str(scan_root), "size": 0,
                            "sha256": "", "mtime_utc": "", "kind": "symlink (inventory only)",
                            "scope": scope, "upload_eligible": False,
                            "link_target": os.readlink(child), "vt_status": "inventory-only",
                        }
                    except OSError:
                        pass
                continue
            safe_dirs.append(dirname)
        dirnames[:] = safe_dirs
        for filename in filenames:
            path = current / filename
            try:
                if path.is_symlink():
                    if include_all_files:
                        yield {
                            "path": str(path), "scan_root": str(scan_root), "size": 0,
                            "sha256": "", "mtime_utc": "", "kind": "symlink (inventory only)",
                            "scope": scope, "upload_eligible": False,
                            "link_target": os.readlink(path), "vt_status": "inventory-only",
                        }
                    continue
                if not path.is_file() or path_is_excluded(path, arch_root, esp_root):
                    continue
                record = record_file(path)
                if record:
                    yield record
            except OSError:
                continue


def add_persistence_record(path: Path, arch_root: Path, records: list[dict[str, Any]]) -> None:
    """Record selected persistence files/links as evidence only, never upload candidates."""
    try:
        mode = path.lstat().st_mode
        if path.is_symlink():
            records.append({
                "path": str(path), "size": 0, "sha256": "", "mtime_utc": "",
                "kind": "persistence symlink", "scope": "persistence", "upload_eligible": False,
                "link_target": os.readlink(path), "vt_status": "inventory-only",
            })
            return
        if not path.is_file():
            return
        st = path.stat()
        records.append({
            "path": str(path), "size": st.st_size,
            "sha256": sha256_file(path),
            "mtime_utc": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            "kind": "persistence configuration/script", "scope": "persistence", "upload_eligible": False,
            "vt_status": "inventory-only",
        })
    except OSError as exc:
        records.append({
            "path": str(path), "size": 0, "sha256": "", "kind": "persistence item",
            "scope": "persistence", "upload_eligible": False, "vt_status": "error", "error": str(exc),
        })


def build_inventory(arch_root: Path, esp_root: Path, scan_paths: list[str],
                   inventory_paths: list[str]) -> list[dict[str, Any]]:
    """Inventory only the exact paths selected by the operator on the command line.

    --scan-path inventories recognized binaries/artifacts only.
    --inventory-path inventories every file under the selected path, while marking
    only recognized executable samples upload-eligible.
    """
    records: list[dict[str, Any]] = []
    selections: list[tuple[str, bool]] = [(raw, False) for raw in scan_paths]
    selections.extend((raw, True) for raw in inventory_paths)
    if not selections:
        raise VTError("specify at least one --scan-path or --inventory-path")

    for raw_path, include_all in selections:
        checked = safe_requested_path(Path(raw_path), arch_root, esp_root)
        if checked is None:
            raise VTError(
                f"refusing scan path {raw_path!r}: it must be an existing file/directory below "
                f"--arch-root or --esp-root, with no symlink ancestors, and must not be an excluded data path"
            )
        selected_path, mounted_root, root_label = checked
        relative = selected_path.relative_to(mounted_root)
        if root_label == "efi":
            classification_scope = "efi"
            display_scope = "efi:" + str(relative)
        elif relative.parts[:1] == ("boot",):
            classification_scope = "boot"
            display_scope = "arch:" + str(relative)
        else:
            classification_scope = str(relative)
            display_scope = "arch:" + str(relative)
        print(f"[*] {'inventory all files' if include_all else 'binary/artifact candidates'}: {selected_path}")
        records.extend(iter_custom_path(selected_path, classification_scope if classification_scope in ("boot", "efi") else "custom",
                                        selected_path, include_all, arch_root, esp_root))
        # Preserve the operator-visible scope label on every record (classification used above
        # is separate, so arbitrary paths still get kernel/EFI recognition where relevant).
        for record in records:
            if record.get("scan_root") == str(selected_path):
                record["scope"] = display_scope

    # Deduplicate overlapping selections, preferring a record that is upload-eligible or has a hash.
    dedup: dict[str, dict[str, Any]] = {}
    for record in records:
        key = record["path"]
        previous = dedup.get(key)
        if previous is None or (record.get("upload_eligible") and not previous.get("upload_eligible")):
            dedup[key] = record
    return sorted(dedup.values(), key=lambda r: str(r.get("path", "")).lower())


def make_record(path: Path, kind: str, scope: str, eligible: bool,
                scan_root: Path | None = None) -> dict[str, Any]:
    try:
        st = path.stat()
        return {
            "path": str(path), "scan_root": str(scan_root) if scan_root else "",
            "size": st.st_size,
            "mtime_utc": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            "sha256": sha256_file(path), "kind": kind, "scope": scope,
            "upload_eligible": bool(eligible), "vt_status": "inventory" if eligible else "inventory-only",
        }
    except OSError as exc:
        return {
            "path": str(path), "scan_root": str(scan_root) if scan_root else "", "size": 0,
            "sha256": "", "kind": kind, "scope": scope, "upload_eligible": bool(eligible),
            "vt_status": "error", "error": str(exc),
        }


def api_request(method: str, endpoint: str, key: str, limiter: RateLimiter,
                data: bytes | None = None, content_type: str | None = None) -> dict[str, Any]:
    limiter.wait()
    headers = {"x-apikey": key, "accept": "application/json", "user-agent": "vt-arch-triage/2.0"}
    if content_type:
        headers["content-type"] = content_type
    req = urllib.request.Request(VT_API + endpoint, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        message = exc.read(1500).decode("utf-8", errors="replace")
        if exc.code == 404:
            raise VTError("NOT_FOUND") from exc
        if exc.code == 429:
            raise VTError("VirusTotal returned HTTP 429 (rate/quota limit). stop and try later.") from exc
        raise VTError(f"VirusTotal HTTP {exc.code}: {message[:500]}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise VTError(f"network error: {exc}") from exc
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VTError("VirusTotal returned a non-JSON response") from exc


def post_file(path: Path, key: str, limiter: RateLimiter) -> dict[str, Any]:
    size = path.stat().st_size
    if size > MAX_VT_SIZE:
        raise VTError(f"file exceeds VirusTotal's 650 MiB upload limit ({size} bytes)")
    if size > 32 * 1024 * 1024:
        endpoint_url = api_request("GET", "/files/upload_url", key, limiter).get("data")
        if not isinstance(endpoint_url, str):
            raise VTError("large-file upload URL missing from API response")
    else:
        endpoint_url = VT_API + "/files"
    boundary = "----vt-arch-triage-" + uuid.uuid4().hex
    safe_name = path.name.replace('"', "_").replace("\r", "_").replace("\n", "_")
    prefix = (f"--{boundary}\r\n"
              f'Content-Disposition: form-data; name="file"; filename="{safe_name}"\r\n'
              "Content-Type: application/octet-stream\r\n\r\n").encode("utf-8", errors="replace")
    suffix = f"\r\n--{boundary}--\r\n".encode()
    parsed = urllib.parse.urlsplit(endpoint_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise VTError("VirusTotal returned an unexpected upload URL")
    request_path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    limiter.wait()
    conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=180)
    content_length = len(prefix) + size + len(suffix)
    try:
        conn.putrequest("POST", request_path)
        conn.putheader("Host", parsed.hostname)
        conn.putheader("x-apikey", key)
        conn.putheader("Accept", "application/json")
        conn.putheader("User-Agent", "vt-arch-triage/2.0")
        conn.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
        conn.putheader("Content-Length", str(content_length))
        conn.endheaders()
        conn.send(prefix)
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                conn.send(chunk)
        conn.send(suffix)
        response, body = conn.getresponse(), None
        body = response.read()
        if response.status < 200 or response.status >= 300:
            message = body[:1500].decode("utf-8", errors="replace")
            if response.status == 429:
                raise VTError("VirusTotal returned HTTP 429 (rate/quota limit). stop and try later.")
            raise VTError(f"VirusTotal upload HTTP {response.status}: {message[:500]}")
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VTError("VirusTotal returned a non-JSON upload response") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise VTError(f"upload/network error: {exc}") from exc
    finally:
        conn.close()


def api_file_report(sha256: str, key: str, limiter: RateLimiter) -> dict[str, Any]:
    return api_request("GET", "/files/" + urllib.parse.quote(sha256), key, limiter)


def summarise_vt(data: dict[str, Any]) -> dict[str, Any]:
    item = data.get("data", {})
    attributes = item.get("attributes", {})
    stats = attributes.get("last_analysis_stats") or {}
    results = attributes.get("last_analysis_results") or {}
    flagged = []
    for engine, details in results.items():
        if details.get("category") in ("malicious", "suspicious"):
            flagged.append({"engine": engine, "category": details.get("category", ""), "result": details.get("result") or ""})
    flagged.sort(key=lambda x: (x["category"] != "malicious", x["engine"].lower()))
    return {
        "vt_status": "analysed", "vt_permalink": "https://www.virustotal.com/gui/file/" + item.get("id", ""),
        "vt_stats": stats, "vt_total_engines": sum(v for v in stats.values() if isinstance(v, int)),
        "vt_flagged": flagged, "vt_meaningful_name": attributes.get("meaningful_name") or "",
        "vt_type_description": attributes.get("type_description") or "", "vt_last_analysis_date": attributes.get("last_analysis_date"),
    }


def save_manifest(records: list[dict[str, Any]], json_path: Path) -> None:
    payload = {"schema_version": SCHEMA_VERSION, "generated_utc": datetime.now(timezone.utc).isoformat(),
               "scope_description": "operator-specified scan paths only; excluded user/runtime/data trees are not traversed",
               "records": records}
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_manifest(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise VTError(f"manifest not found: {path}. run inventory first.")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VTError(f"cannot read manifest {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION or not isinstance(data.get("records"), list):
        raise VTError("manifest is not a parameterized v3 inventory. rerun inventory with this script before uploading.")
    return data["records"]


def upload_path_is_safe(record: dict[str, Any], arch_root: Path, esp_root: Path) -> tuple[Path | None, str | None]:
    """Revalidate a sample against the scan root explicitly recorded in the inventory."""
    try:
        path = Path(str(record.get("path", "")))
        base = Path(str(record.get("scan_root", "")))
        if not path.is_absolute() or not base.is_absolute():
            return None, "record has no absolute path/scan root"
        identified = identify_root(base, arch_root, esp_root)
        if identified is None:
            return None, "recorded scan root is outside the configured mount roots or excluded"
        mounted_root, _label = identified
        try:
            if not (path == base or within(path, base)):
                return None, "path is outside its recorded scan root"
        except (ValueError, TypeError):
            return None, "path is outside its recorded scan root"
        import stat
        root_mode = mounted_root.lstat().st_mode
        if not stat.S_ISDIR(root_mode) or stat.S_ISLNK(root_mode):
            return None, "mounted root is missing or a symlink"
        base_rel = base.relative_to(mounted_root)
        safe_base = mounted_root if not base_rel.parts else safe_scoped_path(mounted_root, str(base_rel))
        if safe_base is None or safe_base != base:
            return None, "recorded scan root is missing or has a symlink ancestor"
        relative = path.relative_to(mounted_root)
        safe_path = safe_scoped_path(mounted_root, str(relative))
        if safe_path is None or safe_path != path:
            return None, "file path is missing or has a symlink ancestor"
        if path_is_excluded(path, arch_root, esp_root) or path_is_excluded(base, arch_root, esp_root):
            return None, "path is in an excluded data/runtime tree"
        if not stat.S_ISREG(path.lstat().st_mode):
            return None, "file no longer exists or is not a regular file"
        return path, None
    except (OSError, ValueError) as exc:
        return None, f"cannot validate path: {exc}"


def generate_dashboard(records: list[dict[str, Any]], html_path: Path, json_path: Path) -> None:
    eligible = sum(1 for r in records if r.get("upload_eligible"))
    analysed = sum(1 for r in records if r.get("vt_status") == "analysed")
    submitted = sum(1 for r in records if r.get("vt_status") == "submitted")
    errors = sum(1 for r in records if r.get("vt_status") == "error")
    detections = sum(1 for r in records if int((r.get("vt_stats") or {}).get("malicious", 0)) > 0 or int((r.get("vt_stats") or {}).get("suspicious", 0)) > 0)
    rows: list[str] = []
    for r in records:
        stats = r.get("vt_stats") or {}
        bad, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total, status = int(r.get("vt_total_engines", 0)), str(r.get("vt_status", "inventory-only"))
        if status == "analysed": verdict = f"{bad} malicious / {sus} suspicious"
        elif status == "submitted": verdict = "submitted; report pending"
        elif status == "error": verdict = "error: " + str(r.get("error", "unknown"))
        elif status == "not_found": verdict = "not found on VirusTotal"
        elif status == "skipped_size": verdict = "skipped: file too large"
        elif status == "inventory-only": verdict = "evidence only; not uploaded"
        else: verdict = "not queried"
        flagged_html = ""
        if r.get("vt_flagged"):
            details = "".join(f"<tr><td>{html.escape(str(x.get('engine','')))}</td><td>{html.escape(str(x.get('category','')))}</td><td>{html.escape(str(x.get('result','')))}</td></tr>" for x in r["vt_flagged"])
            flagged_html = f"<details><summary>flagged engines ({len(r['vt_flagged'])})</summary><table><thead><tr><th>engine</th><th>category</th><th>result</th></tr></thead><tbody>{details}</tbody></table></details>"
        link = r.get("vt_permalink") or ("https://www.virustotal.com/gui/file/" + str(r.get("sha256", "")))
        path_text = str(r.get("path", ""))
        searchable = html.escape(" ".join((path_text, str(r.get("sha256", "")), verdict, str(r.get("kind", "")), str(r.get("scope", "")), str(r.get("link_target", "")))).lower(), quote=True)
        status_class = status if status in {"analysed", "submitted", "error", "not_found", "skipped_size", "inventory"} else "inventory-only"
        eligible_label = "yes" if r.get("upload_eligible") else "no"
        path_cell = html.escape(path_text) + (f"<br><small>link target: {html.escape(str(r.get('link_target')))}</small>" if r.get("link_target") else "")
        rows.append(
            f'<tr data-search="{searchable}" data-status="{html.escape(status)}" data-bad="{bad}" data-sus="{sus}">'
            f'<td><span class="status {html.escape(status_class)}">{html.escape(status)}</span></td>'
            f'<td>{html.escape(str(r.get("kind", "unknown")))}</td><td>{html.escape(str(r.get("scope", "")))}</td>'
            f'<td class="filepath">{path_cell}</td><td>{int(r.get("size", 0)):,}</td>'
            f'<td><code>{html.escape(str(r.get("sha256", "")))}</code></td><td>{eligible_label}</td>'
            f'<td>{bad} / {sus} / {total}<br>{html.escape(verdict)}{flagged_html}</td>'
            f'<td><a href="{html.escape(str(link), quote=True)}" target="_blank" rel="noopener">open VT</a></td></tr>'
        )
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    document = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arch rootkit triage — VirusTotal</title><style>
:root{{--bg:#101318;--panel:#191e26;--line:#303846;--text:#e6e9ef;--muted:#9ba5b5;--accent:#91b8ff;--red:#ff7777;--amber:#f2ca75;--green:#8fd6ad}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}}main{{max-width:1800px;margin:0 auto;padding:26px}}h1{{font-size:24px;margin:0 0 4px}}.sub,small{{color:var(--muted)}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px;margin:22px 0}}.card{{background:var(--panel);border:1px solid var(--line);padding:16px;border-radius:8px}}.value{{font-size:26px;font-weight:700}}.label{{color:var(--muted)}}.controls{{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}}input,select{{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:10px}}input{{min-width:250px;flex:1}}.tablewrap{{overflow:auto;border:1px solid var(--line);border-radius:8px}}table{{width:100%;border-collapse:collapse;min-width:1300px}}th,td{{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid var(--line)}}th{{background:#202631;position:sticky;top:0}}tr:hover{{background:#1b222c}}code{{font-size:12px;overflow-wrap:anywhere}}.filepath{{max-width:400px;overflow-wrap:anywhere}}.status{{font-weight:700;text-transform:uppercase;font-size:11px}}.analysed{{color:var(--green)}}.submitted{{color:var(--amber)}}.error,.not_found{{color:var(--red)}}a{{color:var(--accent)}}details{{margin-top:7px}}details table{{min-width:0;margin-top:8px}}details td,details th{{padding:5px}}.warning{{border-left:3px solid var(--amber);padding:10px 14px;background:var(--panel);color:var(--muted);margin:18px 0}}
</style></head><body><main><h1>arch rootkit triage</h1><div class="sub">generated {generated} · manifest: {html.escape(json_path.name)}</div>
<div class="warning">Only operator-specified paths are inventoried. Common user/runtime/data trees (including /home, caches, logs, temporary paths, and /usr/share) are excluded. Upload-eligible files are submitted only during the explicit upload phase. VirusTotal detections are a signal, not proof.</div>
<section class="cards"><div class="card"><div class="value">{len(records)}</div><div class="label">inventory records</div></div><div class="card"><div class="value">{eligible}</div><div class="label">upload-eligible samples</div></div><div class="card"><div class="value">{analysed}</div><div class="label">reports retrieved</div></div><div class="card"><div class="value">{submitted}</div><div class="label">submitted, pending report</div></div><div class="card"><div class="value">{detections}</div><div class="label">files with detections</div></div><div class="card"><div class="value">{errors}</div><div class="label">errors</div></div></section>
<div class="controls"><input id="search" type="search" placeholder="filter by path, hash, type, scope…"><select id="status"><option value="">all statuses</option><option>analysed</option><option>submitted</option><option>inventory</option><option>inventory-only</option><option>error</option><option>not_found</option><option>skipped_size</option></select><select id="eligible"><option value="">upload eligibility: all</option><option value="yes">eligible</option><option value="no">not eligible</option></select><select id="verdict"><option value="">all verdicts</option><option value="flagged">detections present</option><option value="clean">no current detections</option></select></div>
<div class="tablewrap"><table><thead><tr><th>status</th><th>type</th><th>scope</th><th>path</th><th>bytes</th><th>sha256</th><th>upload?</th><th>VirusTotal result</th><th>link</th></tr></thead><tbody id="rows">{''.join(rows)}</tbody></table></div>
<p class="sub">Keep this HTML and the JSON manifest together. Paths are stored locally. VirusTotal may receive sample contents and upload filenames only for records marked upload-eligible when you run --upload.</p></main>
<script>const search=document.querySelector('#search'),status=document.querySelector('#status'),eligible=document.querySelector('#eligible'),verdict=document.querySelector('#verdict');function filterRows(){{const q=search.value.toLowerCase();for(const r of document.querySelectorAll('#rows tr')){{const text=r.dataset.search.includes(q);const st=!status.value||r.dataset.status===status.value;const isEligible=r.children[6].textContent.trim()==='yes';const el=!eligible.value||(eligible.value==='yes'?isEligible:!isEligible);const flagged=Number(r.dataset.bad)>0||Number(r.dataset.sus)>0;const vd=!verdict.value||(verdict.value==='flagged'?flagged:!flagged&&r.dataset.status==='analysed');r.hidden=!(text&&st&&el&&vd)}}}}[search,status,eligible,verdict].forEach(x=>x.addEventListener('input',filterRows));</script></body></html>'''
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(document, encoding="utf-8")


def run_upload(records: list[dict[str, Any]], key: str, limiter: RateLimiter, arch_root: Path, esp_root: Path,
               max_file_mb: float, limit: int) -> list[dict[str, Any]]:
    candidates = [r for r in records if r.get("upload_eligible") and r.get("sha256") and r.get("vt_status") not in ("analysed", "submitted")]
    candidates.sort(key=lambda r: str(r.get("path", "")).lower())
    if limit > 0:
        candidates = candidates[:limit]
    print(f"[*] upload phase: {len(candidates)} eligible record(s) queued; no other paths will be scanned")
    for idx, record in enumerate(candidates, 1):
        path, problem = upload_path_is_safe(record, arch_root, esp_root)
        if problem or path is None:
            record["vt_status"], record["error"] = "error", "refusing upload: " + str(problem)
            print(f"[{idx}/{len(candidates)}] [!] {record['error']}", file=sys.stderr)
            continue
        size = path.stat().st_size
        if size > max_file_mb * 1024 * 1024 or size > MAX_VT_SIZE:
            record["vt_status"] = "skipped_size"
            record["error"] = f"file exceeds upload size limit ({max_file_mb} MiB configured; 650 MiB API maximum)"
            print(f"[{idx}/{len(candidates)}] skip (too large): {path}")
            continue
        # Re-hash immediately before upload to avoid submitting a changed file under a stale hash.
        try:
            current_hash = sha256_file(path)
            if current_hash != record["sha256"]:
                record["vt_status"], record["error"] = "error", "file changed since inventory; re-inventory before upload"
                print(f"[{idx}/{len(candidates)}] [!] changed since inventory: {path}", file=sys.stderr)
                continue
            print(f"[{idx}/{len(candidates)}] {record['kind']}: {path} [{current_hash[:12]}]")
            try:
                report = api_file_report(current_hash, key, limiter)
                record.update(summarise_vt(report))
                record.pop("error", None)
                stats = record.get("vt_stats") or {}
                print(f"    known: malicious={stats.get('malicious', 0)}, suspicious={stats.get('suspicious', 0)}")
            except VTError as exc:
                if str(exc) != "NOT_FOUND":
                    raise
                uploaded = post_file(path, key, limiter)
                analysis_id = uploaded.get("data", {}).get("id", "")
                record.update({"vt_status": "submitted", "vt_analysis_id": analysis_id,
                               "vt_permalink": "https://www.virustotal.com/gui/file/" + current_hash})
                print("    uploaded; report may take time to appear")
        except VTError as exc:
            record["vt_status"], record["error"] = "error", str(exc)
            print(f"    [!] {exc}", file=sys.stderr)
            if "429" in str(exc) or "request cap reached" in str(exc):
                break
        except OSError as exc:
            record["vt_status"], record["error"] = "error", str(exc)
            print(f"    [!] read error: {exc}", file=sys.stderr)
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description="Scoped Arch/UEFI rootkit inventory, followed by optional VirusTotal upload/reporting.")
    phase = parser.add_mutually_exclusive_group()
    phase.add_argument("--inventory", action="store_true", help="inventory only (default; no network/API calls)")
    phase.add_argument("--upload", action="store_true", help="upload/query only files marked eligible in an existing inventory manifest")
    phase.add_argument("--refresh", action="store_true", help="refresh reports for samples previously submitted to VirusTotal")
    parser.add_argument("--arch-root", default="/mnt/arch", help="mounted Arch root used to validate selected paths (default /mnt/arch)")
    parser.add_argument("--esp-root", default="/mnt/arch_esp", help="mounted EFI System Partition used to validate selected paths (default /mnt/arch_esp)")
    parser.add_argument("--scan-path", action="append", default=[], metavar="PATH",
                        help="scan this path recursively for recognized binaries/artifacts only; repeat for multiple paths")
    parser.add_argument("--inventory-path", action="append", default=[], metavar="PATH",
                        help="inventory every regular file under this path; recognized binaries remain upload-eligible; repeat as needed")
    parser.add_argument("--api-key", help="VirusTotal API key; prefer VT_API_KEY environment variable")
    parser.add_argument("--html", default="vt-dashboard.html", help="dashboard path (default vt-dashboard.html)")
    parser.add_argument("--json", dest="json_path", default="vt-results.json", help="manifest path (default vt-results.json)")
    parser.add_argument("--delay", type=float, default=16.0, help="seconds between API calls; minimum 15 for Public API")
    parser.add_argument("--max-requests", type=int, default=450, help="maximum API calls in this run (default 450)")
    parser.add_argument("--max-file-mb", type=float, default=650.0, help="maximum upload file size in MiB (default 650)")
    parser.add_argument("--limit", type=int, default=0, help="maximum files processed during upload/refresh; 0 means all")
    args = parser.parse_args()
    arch_root, esp_root = Path(args.arch_root).absolute(), Path(args.esp_root).absolute()
    html_path, json_path = Path(args.html), Path(args.json_path)
    key = args.api_key or os.environ.get("VT_API_KEY")

    if args.inventory or not (args.upload or args.refresh):
        print("[*] inventory phase: scanning only paths supplied on the command line")
        print("[*] excluded: /home, /root, caches, temporary/runtime trees, logs, /usr/share, and general data paths")
        try:
            records = build_inventory(arch_root, esp_root, args.scan_path, args.inventory_path)
        except VTError as exc:
            parser.error(str(exc))
        save_manifest(records, json_path)
        generate_dashboard(records, html_path, json_path)
        eligible = sum(1 for r in records if r.get("upload_eligible"))
        print(f"[*] recorded {len(records)} items; {eligible} marked upload-eligible")
        print(f"[*] dashboard: {html_path.resolve()}\n[*] manifest:  {json_path.resolve()}")
        print("[*] review the inventory/dashboard before running --upload")
        return 0

    if not key:
        parser.error("--upload/--refresh requires --api-key or the VT_API_KEY environment variable")
    if args.delay < 15:
        parser.error("--delay must be at least 15 seconds for VirusTotal's Public API")
    try:
        records = load_manifest(json_path)
    except VTError as exc:
        parser.error(str(exc))
    limiter = RateLimiter(args.delay, args.max_requests)

    if args.upload:
        records = run_upload(records, key, limiter, arch_root, esp_root, args.max_file_mb, args.limit)
    elif args.refresh:
        pending = [r for r in records if r.get("sha256") and r.get("vt_status") in ("submitted", "not_found") and r.get("upload_eligible")]
        if args.limit > 0:
            pending = pending[:args.limit]
        print(f"[*] refreshing {len(pending)} previously submitted/not-found samples")
        for idx, record in enumerate(pending, 1):
            try:
                print(f"[{idx}/{len(pending)}] {record.get('path')}")
                data = api_file_report(str(record["sha256"]), key, limiter)
                record.update(summarise_vt(data))
                record.pop("error", None)
            except VTError as exc:
                if str(exc) == "NOT_FOUND":
                    record["vt_status"] = "not_found"
                else:
                    record["vt_status"], record["error"] = "error", str(exc)
                    print(f"    [!] {exc}", file=sys.stderr)
                    if "429" in str(exc) or "request cap reached" in str(exc):
                        break
    save_manifest(records, json_path)
    generate_dashboard(records, html_path, json_path)
    print(f"[*] dashboard: {html_path.resolve()}\n[*] manifest:  {json_path.resolve()}")
    if args.upload:
        print("[*] after uploads finish processing, run --refresh to retrieve reports")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted; completed results remain in the manifest", file=sys.stderr)
        raise SystemExit(130)
