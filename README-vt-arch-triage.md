# Parameterized Arch / EFI rootkit triage

`vt_arch_triage.py` inventories only the paths you specify on the command line. It has no internal list of scan directories. Use `--scan-path` for binary/artifact discovery and `--inventory-path` when you want every file in a selected location recorded, such as EFI boot configuration or persistence directories.

The workflow is deliberately split into three phases: inventory, explicit VirusTotal lookup/upload, then report refresh. The script uses the Python standard library, never executes evidence files, and never follows symlinks.

## Path arguments

- `--scan-path PATH`: repeatable; recursively records recognised ELF/PE binaries, `.efi` files, kernel modules, and recognised kernel images. Other files are ignored.
- `--inventory-path PATH`: repeatable; records all regular files under the selected path. Recognised binary/artifact files remain eligible for VirusTotal; other files are inventory-only. Symlinks are recorded as evidence when encountered but never followed.
- `--arch-root PATH`: mounted Arch root used to validate the selected paths; default `/mnt/arch`.
- `--esp-root PATH`: mounted EFI System Partition; default `/mnt/arch_esp`. The ESP root itself may be passed as `--inventory-path`.

Every selected path must exist under `--arch-root` or `--esp-root`. The Arch filesystem root itself is not allowed as a scan path; select particular directories instead. The script also refuses scan paths in common user/runtime/data locations, including `/home`, `/root`, `/tmp`, `/run`, `/proc`, `/sys`, `/dev`, `/mnt`, `/media`, `/var/cache`, `/var/tmp`, `/var/log`, and `/usr/share`, and prunes those exclusions when scanning a broader selected directory. On usr-merged Arch systems, `/bin` and `/sbin` may be symlinks; use `/usr/bin` and `/usr/sbin` instead because symlinks are not followed.

## 1. Inventory only — no API calls

Keep the script and output on the CAINE live environment, not the suspect disk. Example for your current mount points:

```bash
mkdir -p ~/vt-triage
cd ~/vt-triage

python3 /path/to/vt_arch_triage.py --inventory \
  --scan-path /mnt/arch/usr/bin \
  --scan-path /mnt/arch/usr/sbin \
  --scan-path /mnt/arch/usr/lib \
  --scan-path /mnt/arch/boot \
  --inventory-path /mnt/arch/etc/modprobe.d \
  --inventory-path /mnt/arch/etc/modules-load.d \
  --inventory-path /mnt/arch/etc/systemd/system \
  --inventory-path /mnt/arch/etc/ld.so.conf.d \
  --inventory-path /mnt/arch_esp
```

Those are example paths, not enforced defaults. Each selected path must exist; omit optional locations that are absent (for example, `/etc/ld.so.preload` if the file is not present). Add or remove `--scan-path` and `--inventory-path` arguments to define your own scope. For paths outside the default mount locations, pass matching `--arch-root` and/or `--esp-root` values in every phase that needs to access those files.

The command creates `vt-results.json` and `vt-dashboard.html`. Inventory computes SHA-256 hashes locally but performs no API requests. Review the scope, path, classification, hash and upload eligibility before continuing.

## 2. Explicit VirusTotal upload phase

Set your key in the environment, rather than putting it in shell history:

```bash
export VT_API_KEY='YOUR_VIRUSTOTAL_API_KEY'
python3 /path/to/vt_arch_triage.py --upload --limit 5
```

The upload phase uses the saved manifest; it does not rescan the disk. It validates each sample against its recorded scan path and re-hashes it before sending. Only records marked upload-eligible are considered. After reviewing a small initial batch, process the remaining eligible samples with:

```bash
python3 /path/to/vt_arch_triage.py --upload
```

## 3. Refresh reports and dashboard

After submitted samples have been analysed:

```bash
python3 /path/to/vt_arch_triage.py --refresh
```

Run `--refresh` again later if reports are not ready. Both the JSON manifest and static HTML dashboard are updated in place.

## Safety notes

Prefer mounting the evidence filesystem read-only; reads on read-write mounts can update access-time metadata. Check with:

```bash
findmnt /mnt/arch
findmnt /mnt/arch_esp
```

VirusTotal is a third-party disclosure. Hash lookups disclose hashes, and sample uploads disclose file contents and upload filenames. Do not upload proprietary or sensitive samples unless that is acceptable. VirusTotal detections are leads, not proof of compromise; zero detections do not prove a file is safe.

## Other options

- `--json PATH`: manifest path, default `vt-results.json`.
- `--html PATH`: dashboard path, default `vt-dashboard.html`.
- `--api-key KEY`: API key; environment variable `VT_API_KEY` is preferred.
- `--limit N`: cap files processed during upload/refresh; `0` means all.
- `--delay SECONDS`: delay between API requests, minimum 15 seconds for the public API.
- `--max-requests N`: API request cap per run, default 450.
- `--max-file-mb N`: maximum sample size to upload, default 650 MiB.
