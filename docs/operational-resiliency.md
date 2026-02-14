# Operational Resiliency

`storas` is a single-node object store. Built-in replication is out of scope.
Operational resiliency is achieved by external backup/recovery controls.

## Resiliency Boundaries

- `storas` guarantees local filesystem persistence and atomic write paths on one node.
- `storas` does not provide built-in multi-node replication or cross-site failover.
- Durability beyond one host/disk must be provided by operators.

## Snapshot Backup And Point-In-Time Restore

Recommended pattern:

1. Quiesce writes to reduce inconsistency windows (stop `storas` or enforce read-only traffic).
2. Create a filesystem snapshot/archive of `storage.data_dir`.
3. Store backup artifacts on independent media/location.
4. Restore by copying snapshot contents into a clean `storage.data_dir` path.
5. Start `storas` against the restored directory.
6. Run integrity verification before resuming write traffic.

Example archive flow:

```bash
# Stop writes / stop service first.
tar -C /var/lib/storas -czf /backups/storas-data-$(date +%F-%H%M%S).tgz data

# Restore into a fresh location.
mkdir -p /var/lib/storas-restore
tar -C /var/lib/storas-restore -xzf /backups/storas-data-2026-02-17-120000.tgz
```

## Host-Level Redundancy Patterns And Tradeoffs

- `RAID1/RAID10`: simple disk redundancy, does not protect from accidental deletion/corruption replicated at block level.
- `ZFS mirror/RAIDZ`: strong integrity checks and snapshot support, higher memory/operational complexity.
- `Btrfs RAID1`: snapshot/send workflows are convenient, but operational maturity and failure behavior should be validated per distro/kernel.

Tradeoff guidance:

- RAID is not backup.
- Snapshots are not off-host backup.
- Use both redundancy (availability) and independent backups (recovery).

## Post-Restore Consistency Verification

Use the built-in restore integrity flow:

```bash
make test-restore-integrity
```

This test flow validates snapshot/restore behavior over:

- bucket/object visibility after restore
- version-chain readability
- incomplete multipart upload state preservation
- metadata/payload on-disk pairing checks

Run it in CI or pre-production when changing storage layout or backup procedures.
