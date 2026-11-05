# Versioned cloud backup & lab distribution

Status: **prepared, not provisioned** (2026-11-05). No backup has been uploaded or restored as part of this work.

## Architecture: GitHub is the entry point, not the VM disk store

| Layer | Purpose | Data classification |
| --- | --- | --- |
| GitHub `detection-engineering-blue-team` | Versioned detection code, rules, tests, manifests, instructions, CI | Public |
| Backblaze B2 + Restic | Encrypted, deduplicated, incremental snapshots of the entire VirtualBox VM folders and optional private evidence | **Private, never published** |
| Cloudflare R2 (future) | Downloadable sanitized, redistributable lab images/packages by release | Public, after review |
| Optional local/offsite second copy | Separate disaster-recovery failure domain | Private |

**Why:** Regular GitHub Git repositories are unsuitable for multi-GB VDI/OVA images. The repository remains the installation, documentation, testing, contribution, and release control plane. A public release can reference signed/checksummed cloud-hosted artifacts and track their versions in Git.

### Local discovery on 2026-11-05 (informational, not secrets)

- VirtualBox VMs: Kali Linux 2025.3, WindowsServer, WIN10-CLIENT.
- Two running (Kali, Windows Server); Windows 10 was powered off during discovery.
- Raw VDI disk-file sizes observed: Kali ~78.78 GiB, Server ~25.27 GiB, Win10 ~11.45 GiB (**~115.50 GiB total**, excluding other files and historical versions).
- Available space on D: ~93.9 GiB. **Do not stage a full copy on D.** Restic reads sources and streams encrypted chunks directly to remote object storage.
- Docker Desktop on Windows was not running; the Wazuh Docker stack is described as running inside Kali. Backing up Windows Docker Desktop is not part of this procedure.
- Backups should include the full VM folders, including `.vbox`, disks, and related files; do not rely on Git for raw `.lab/` evidence.
- No VirtualBox snapshots were registered. This is not a consistency guarantee.

## What needs to be created by the owner (in the provider dashboard)

1. A **private** Backblaze B2 bucket dedicated to the laboratory. Set the region, record its S3-compatible endpoint, and enable any required billing.
2. A **bucket-scoped application key** with only the required capabilities. Never paste it in GitHub issues, PRs, chat, or screenshots.
3. A unique Restic repository password stored outside the source repository and preserved securely. **Without this password, Restic backups cannot be recovered.**
4. [Restic](https://restic.net/) on the Windows host (and optionally on an offline recovery host). Keep the Restic binary under a trusted installation path.

Backblaze's current documentation recommends Restic over its S3-compatible API. Use the actual endpoint from **your** B2 bucket, not a copied region guess.

## Prepare a private local configuration

From the repository root, on the VirtualBox host:

```powershell
Copy-Item .\scripts\cloud-backup\lab.local.example.json .\scripts\cloud-backup\lab.local.json
notepad .\scripts\cloud-backup\lab.local.json
```

Configure `vmFolders` with the **actual parent folder of each VM's .vbox and disk files**. You can find them in VirtualBox's machine settings or via:

```powershell
& 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe' list vms
& 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe' showvminfo 'WindowsServer'
```

All paths and any `additionalFolders` must exist. Private Wazuh evidence can be included in `additionalFolders` if it is on the host, but avoid duplicating secrets in publicly available directories. `lab.local.json` is gitignored.

### Configure Restic privately in the local terminal

Use private local environment variables, a dedicated secrets manager, or an appropriately access-controlled file. Never commit credentials. Example variable **names**:

```powershell
$env:RESTIC_REPOSITORY = 's3:s3.<YOUR_B2_REGION_ENDPOINT>/<PRIVATE_BUCKET>/soc-lab'
$env:RESTIC_PASSWORD_FILE = 'C:\private\soc-backup\restic-password.txt'
$env:AWS_ACCESS_KEY_ID = '<B2_KEY_ID>'
$env:AWS_SECRET_ACCESS_KEY = '<B2_APPLICATION_KEY>'
```

Replace placeholders **only on the private computer**; do not send the values into the conversation. Restrict read access to the password file, preserve a secure offsite recovery copy of the password, and do not put credentials into script files or repository history.

Create the encrypted repository **once**:

```powershell
restic init
```

### First read-only preflight

```powershell
.\scripts\cloud-backup\Backup-Lab.ps1 -Action Plan
```

The plan only checks folder availability and reports how many VMs are currently running. It does not use cloud credentials and performs no backup.

### Make a recoverable, consistent backup

1. Record a change window. Capture Wazuh configuration and Indexer snapshots where applicable. Avoid changing index or agent state during the backup.
2. Gracefully stop Wazuh services as appropriate, and shut down the Kali Linux, Windows Server and Windows 10 guests from their operating systems. Confirm they are powered off in VirtualBox.
3. Run `Backup-Lab.ps1 -Action Plan` again. It must indicate no running VMs.
4. Run:

```powershell
.\scripts\cloud-backup\Backup-Lab.ps1 -Action Backup
.\scripts\cloud-backup\Backup-Lab.ps1 -Action Snapshots
.\scripts\cloud-backup\Backup-Lab.ps1 -Action Check
```

`Backup` **fails closed** if *any* VirtualBox VM remains running; it does **not** shut down guests or start an export. Backups are Restic snapshots of entire VM folders, not OVA exports. Backup completion is not proven until you also validate a restore.

### Verify recovery into an isolated location

```powershell
.\scripts\cloud-backup\Restore-Lab.ps1 -Action List
.\scripts\cloud-backup\Restore-Lab.ps1 -Action Restore -SnapshotId '<SNAPSHOT_ID>' -Target 'E:\SOC-RESTORE-TEST'
```

The script refuses an existing non-empty destination and does not overwrite live VMs. Review restored `.vbox`/`.vdi` paths and source/destination folder structure, adapt paths/UUIDs as needed, then test **only in a disconnected recovery environment**, never alongside the originals. Restore the Wazuh services and check Manager → Indexer → Dashboard correlation (six events across five custom rule IDs in the previous evidence baseline).

Only after a real restore and verification may you claim **RECOVERY_TESTED**.

## Versioning and retention

Restic snapshots are timestamped and deduplicated. Suggested *initial* policy: take a snapshot after each approved milestone or controlled change, retain daily snapshots for 7 days, weekly snapshots for 4 weeks, and monthly snapshots for 3 months. This is a target policy, **not an enabled schedule**. Actual storage grows with changed blocks and retention.

**Do not enable automatic pruning yet.** Configure and test separate recovery credentials and restoration first; then define retention, deletion protections, and a periodic integrity check. If B2 bucket versioning/Object Lock or lifecycle rules are enabled, reconcile them with Restic's prune behavior; otherwise duplicate hidden object versions can keep accumulating storage charges.

## Public lab releases (separate pipeline; not implemented yet)

1. Build a **clean** demo lab from official Linux images, authorized Windows media, version-pinned Compose files, and scripted bootstrap.
2. Replace private Wazuh agent identities, tokens, certificates, passwords, hostnames, network details and raw logs with fresh generated values or synthetic sanitized fixtures.
3. Verify licensing and distribution rights before packaging VM images. Do **not** publish the private VM backup or preinstalled Windows Server disk image.
4. Upload reviewed public build artifacts to Cloudflare R2. Publish release tag, asset URL, checksums, minimum hardware requirements, and reproduction steps in GitHub Releases.
5. Download and bootstrap from an isolated clean machine, validate detection tests, and verify hashes. Only then call the release publicly reproducible.

## Immediate next gates

- [x] Create project-specific cloud-backup scripts on a review branch.
- [x] Define fail-closed VirtualBox power-state checks and isolated restore.
- [ ] Owner provisions private B2 bucket, bucket key, repository password.
- [ ] Install Restic and validate local config paths.
- [ ] Confirm a maintenance window, quiesce Wazuh, shut down all VMs normally.
- [ ] Initialize the encrypted repository, run the first complete offsite snapshot.
- [ ] Restore to isolated storage and verify guest boot plus Wazuh.
- [ ] Define and safely enable retention and recurring scheduling.
- [ ] Build sanitized/public reproducible lab images, then release via R2 + GitHub.

## Key references

- [Backblaze: Restic + B2](https://www.backblaze.com/docs/cloud-storage-integrate-restic-with-backblaze-b2)
- [Restic documentation](https://restic.readthedocs.io/)
- [GitHub repository limits](https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits)
- [Cloudflare R2 pricing](https://developers.cloudflare.com/r2/pricing/)
