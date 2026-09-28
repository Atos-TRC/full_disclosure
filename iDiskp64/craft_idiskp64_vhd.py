#!/usr/bin/env python3
"""
craft_idiskp64_vhd.py

Creates a fixed-size VHD with the on-disk structures needed to activate
the iDiskp64 disk filter driver's protection features.

Disk Layout (sector size = 512 bytes):
  Sector 0        : Protective MBR (partition type 0xEE)
  Sector 1        : Primary GPT Header ("EFI PART")
  Sectors 2-33    : GPT Partition Entry Array (128 entries)
                      Entry 0: type GUID {CA47A553-9A7A-43E1-A12B-CBB2B352E928}
                               starting at LBA 2048
  Sector 2048     : "dom" magic (DWORD 0x006D6F64) — primary activation trigger
  Sectors 2049-2058: (zeros)
  Sector 2059     : "JKMS" metadata header (DWORD 0x534D4B4A)
                      +0x09: feature_enable = 1 (write protection on)
                      +0x12: partition_entry_count = 0
  Sectors 2060-2065: Continued metadata (7 sectors total: 2059-2065)
  ...
  Backup GPT entries and header at end of disk
  +512 bytes      : VHD Footer ("conectix")

The driver's InitializeDiskDevice_140007690 path:
  1. GetLBAAddress_1400050b0 searches GPT for type GUID match → partition start LBA
  2. ReadDiskSectors at LBA → checks *(DWORD*)sector == 0x6d6f64 ("dom")
  3. ReadDiskSectors at LBA+11, 7 sectors → checks *(DWORD*)data == 0x534d4b4a ("JKMS")
  4. data[9] controls EnableFeature_140003130(flag)

Usage:
  python craft_idiskp64_vhd.py [output.vhd] [--no-protect]

Mount on the VM (Administrator):
  Mount-VHD -Path "C:\\path\\to\\idiskp64_trigger.vhd"
  -- or --
  diskpart> select vdisk file="C:\\path\\to\\idiskp64_trigger.vhd"
  diskpart> attach vdisk
"""
# Mount-VHD -Path "C:\path\to\idiskp64_trigger.vhd"

import struct
import uuid
import zlib
import os
import sys
from datetime import datetime, timezone

# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════

SECTOR_SIZE = 512
DISK_SIZE_MB = 64
DISK_SIZE = DISK_SIZE_MB * 1024 * 1024
TOTAL_SECTORS = DISK_SIZE // SECTOR_SIZE  # 131072

# Custom partition type GUID used by iDiskp64 (mixed-endian, as stored on disk)
# Standard notation: {CA47A553-9A7A-43E1-A12B-CBB2B352E928}
# Read from Ghidra at DAT_14000d1d0 (16 bytes)
PARTITION_TYPE_GUID = bytes([
    0x53, 0xA5, 0x47, 0xCA,                  # LE DWORD: CA47A553
    0x7A, 0x9A,                              # LE WORD:  9A7A
    0xE1, 0x43,                              # LE WORD:  43E1
    0xA1, 0x2B,                              # BE bytes: A12B
    0xCB, 0xB2, 0xB3, 0x52, 0xE9, 0x28      # BE bytes: CBB2B352E928
])

# Magic values checked by InitializeDiskDevice_140007690
MAGIC_DOM  = 0x6D6F64      # "dom\0" — primary activation check at partition start
MAGIC_JKMS = 0x534D4B4A    # "JKMS"  — secondary metadata header at LBA+11

# GPT constants
GPT_SIGNATURE = b"EFI PART"
GPT_REVISION = 0x00010000
GPT_HEADER_SIZE = 92
PARTITION_ENTRY_SIZE = 128
NUM_PARTITION_ENTRIES = 128
PARTITION_ARRAY_SECTORS = (NUM_PARTITION_ENTRIES * PARTITION_ENTRY_SIZE) // SECTOR_SIZE  # 32

# Disk layout (all values in LBA / sectors)
PARTITION_START_LBA = 2048  # Standard 1 MiB alignment
PRIMARY_GPT_HEADER_LBA = 1
PRIMARY_GPT_ENTRIES_LBA = 2
BACKUP_GPT_HEADER_LBA = TOTAL_SECTORS - 1                          # 131071
BACKUP_GPT_ENTRIES_LBA = TOTAL_SECTORS - 1 - PARTITION_ARRAY_SECTORS  # 131039
LAST_USABLE_LBA = BACKUP_GPT_ENTRIES_LBA - 1                       # 131038
PARTITION_END_LBA = LAST_USABLE_LBA

# iDiskp64 metadata offsets (sectors relative to partition start LBA)
DOM_SECTOR_OFFSET  = 0   # "dom" at first sector of partition
JKMS_SECTOR_OFFSET = 11  # "JKMS" at partition start + 11
JKMS_NUM_SECTORS   = 7   # Driver reads 7 sectors for metadata


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def crc32(data: bytes) -> int:
    """CRC32 as used by GPT (zlib crc32, masked to uint32)."""
    return zlib.crc32(data) & 0xFFFFFFFF


# ═══════════════════════════════════════════════════════════════════════════════
# Protective MBR
# ═══════════════════════════════════════════════════════════════════════════════

def make_protective_mbr() -> bytearray:
    """
    Protective MBR with one 0xEE partition covering the entire GPT disk.
    The driver checks MBR[0x1C2] == 0xEE to detect GPT.
    """
    mbr = bytearray(SECTOR_SIZE)

    # --- Partition entry 1 at offset 0x1BE (446) ---
    entry = bytearray(16)
    entry[0] = 0x00          # Boot indicator: inactive
    entry[1] = 0x00          # CHS start: head 0
    entry[2] = 0x02          # CHS start: sector 2, cylinder 0
    entry[3] = 0x00          # CHS start: cylinder 0
    entry[4] = 0xEE          # Partition type: GPT Protective
    entry[5] = 0xFF          # CHS end (maxed out)
    entry[6] = 0xFF
    entry[7] = 0xFF
    struct.pack_into("<I", entry, 8, 1)                          # Starting LBA
    struct.pack_into("<I", entry, 12, min(TOTAL_SECTORS - 1, 0xFFFFFFFF))  # Size

    mbr[0x1BE:0x1CE] = entry
    mbr[0x1FE] = 0x55       # Boot signature
    mbr[0x1FF] = 0xAA

    return mbr


# ═══════════════════════════════════════════════════════════════════════════════
# GPT Partition Entries
# ═══════════════════════════════════════════════════════════════════════════════

def make_gpt_partition_entries() -> bytearray:
    """
    128-entry GPT partition array.  Entry 0 has the custom type GUID that
    GetLBAAddress_1400050b0 searches for via RtlCompareMemory against DAT_14000d1d0.
    """
    entries = bytearray(NUM_PARTITION_ENTRIES * PARTITION_ENTRY_SIZE)

    off = 0
    # Partition Type GUID (16 bytes, mixed-endian on disk)
    entries[off:off + 16] = PARTITION_TYPE_GUID

    # Unique Partition GUID (16 bytes, mixed-endian)
    entries[off + 16:off + 32] = uuid.uuid4().bytes_le

    # Starting LBA (uint64)
    struct.pack_into("<Q", entries, off + 32, PARTITION_START_LBA)

    # Ending LBA (uint64)
    struct.pack_into("<Q", entries, off + 40, PARTITION_END_LBA)

    # Attributes (uint64) — 0
    struct.pack_into("<Q", entries, off + 48, 0)

    # Partition Name (72 bytes, UTF-16LE, null-terminated)
    name = "iDiskp Recovery".encode("utf-16-le")
    entries[off + 56:off + 56 + len(name)] = name

    return entries


# ═══════════════════════════════════════════════════════════════════════════════
# GPT Header
# ═══════════════════════════════════════════════════════════════════════════════

def make_gpt_header(is_backup: bool, entries_crc: int, disk_guid: bytes) -> bytearray:
    """
    Build a GPT header (primary or backup).
    The driver checks *(DWORD*)sector1 == 0x20494645 ("EFI ") — the first 4 bytes
    of the 8-byte "EFI PART" signature.
    """
    hdr = bytearray(SECTOR_SIZE)

    # Signature (8 bytes)
    hdr[0:8] = GPT_SIGNATURE
    # Revision
    struct.pack_into("<I", hdr, 8, GPT_REVISION)
    # Header size
    struct.pack_into("<I", hdr, 12, GPT_HEADER_SIZE)
    # Header CRC32 (placeholder — computed below)
    struct.pack_into("<I", hdr, 16, 0)
    # Reserved
    struct.pack_into("<I", hdr, 20, 0)

    if not is_backup:
        struct.pack_into("<Q", hdr, 24, PRIMARY_GPT_HEADER_LBA)   # My LBA
        struct.pack_into("<Q", hdr, 32, BACKUP_GPT_HEADER_LBA)    # Alternate LBA
    else:
        struct.pack_into("<Q", hdr, 24, BACKUP_GPT_HEADER_LBA)
        struct.pack_into("<Q", hdr, 32, PRIMARY_GPT_HEADER_LBA)

    # First usable LBA
    struct.pack_into("<Q", hdr, 40, PRIMARY_GPT_ENTRIES_LBA + PARTITION_ARRAY_SECTORS)  # 34
    # Last usable LBA
    struct.pack_into("<Q", hdr, 48, LAST_USABLE_LBA)
    # Disk GUID (16 bytes, mixed-endian)
    hdr[56:72] = disk_guid

    if not is_backup:
        struct.pack_into("<Q", hdr, 72, PRIMARY_GPT_ENTRIES_LBA)
    else:
        struct.pack_into("<Q", hdr, 72, BACKUP_GPT_ENTRIES_LBA)

    # Number of partition entries
    struct.pack_into("<I", hdr, 80, NUM_PARTITION_ENTRIES)
    # Size of each entry
    struct.pack_into("<I", hdr, 84, PARTITION_ENTRY_SIZE)
    # CRC32 of the entire partition entry array
    struct.pack_into("<I", hdr, 88, entries_crc)

    # Now compute header CRC32 over the first 92 bytes (CRC field itself = 0)
    header_crc = crc32(bytes(hdr[:GPT_HEADER_SIZE]))
    struct.pack_into("<I", hdr, 16, header_crc)

    return hdr


# ═══════════════════════════════════════════════════════════════════════════════
# iDiskp64 Activation Sectors
# ═══════════════════════════════════════════════════════════════════════════════

def make_dom_sector() -> bytearray:
    """
    Activation sector at partition start LBA.
    InitializeDiskDevice reads 1 sector here and checks:
        if (*(DWORD*)buffer == 0x6d6f64)   // "dom\\0"
            device_extension->activated = 1;
    """
    sector = bytearray(SECTOR_SIZE)
    struct.pack_into("<I", sector, 0, MAGIC_DOM)
    return sector


def make_jkms_metadata(enable_protection: bool = True) -> bytearray:
    """
    JKMS metadata block — 7 sectors (3584 bytes) at partition start LBA + 11.
    
    InitializeDiskDevice reads 7 sectors and checks:
        if (*(DWORD*)data == 0x534d4b4a)   // "JKMS"
            parse metadata ...
        else
            deactivate device
    
    JKMS on-disk structure (GPT / g_UseAlternateFormat=1 path):
      Offset  Size  Description
      0x00    4     Magic: 0x534D4B4A ("JKMS")
      0x04    5     (reserved / unknown)
      0x09    1     Feature enable flag: 1 = enable write protection
      0x0A    8     Metadata value (QWORD, can be 0)
      0x12    1     Number of partition entries (N) — set to 0 for minimal activation
      0x13    N*49  Partition descriptor array (49 bytes each)
      ...
      0xC53   1     Secondary flag
      0xC54   128   Array of 32 DWORDs (sector map / bitmap)
    
    For minimal activation, only the magic + feature flag are required.
    """
    data = bytearray(JKMS_NUM_SECTORS * SECTOR_SIZE)

    # JKMS magic
    struct.pack_into("<I", data, 0x00, MAGIC_JKMS)

    # Feature enable flag (offset 9): controls EnableFeature_140003130(flag)
    # When DAT_14000e138[disk] == 1 → EnableFeature(1) → write protection active
    data[0x09] = 0x01 if enable_protection else 0x00

    # Number of partition entries (offset 0x12) = 0 → skip entry parsing loops
    data[0x12] = 0x00

    return data


# ═══════════════════════════════════════════════════════════════════════════════
# VHD Footer
# ═══════════════════════════════════════════════════════════════════════════════

def make_vhd_footer(disk_size: int) -> bytearray:
    """
    Fixed VHD footer (512 bytes) appended after all disk data.
    Follows the Microsoft VHD Image Format Specification.
    """
    footer = bytearray(SECTOR_SIZE)

    # Cookie (8 bytes)
    footer[0:8] = b"conectix"

    # Features (4 bytes, big-endian) — bit 1 reserved, must be set
    struct.pack_into(">I", footer, 8, 0x00000002)

    # File Format Version (4 bytes, big-endian) — 1.0
    struct.pack_into(">I", footer, 12, 0x00010000)

    # Data Offset (8 bytes, big-endian) — 0xFFFFFFFFFFFFFFFF for fixed disks
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)

    # Timestamp (4 bytes, big-endian) — seconds since 2000-01-01 00:00:00 UTC
    epoch_2000 = datetime(2000, 1, 1, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    ts = int((now - epoch_2000).total_seconds())
    struct.pack_into(">I", footer, 24, ts)

    # Creator Application (4 bytes)
    footer[28:32] = b"pyth"

    # Creator Version (4 bytes, big-endian)
    struct.pack_into(">I", footer, 32, 0x00010000)

    # Creator Host OS (4 bytes)
    footer[36:40] = b"Wi2k"

    # Original Size (8 bytes, big-endian)
    struct.pack_into(">Q", footer, 40, disk_size)

    # Current Size (8 bytes, big-endian)
    struct.pack_into(">Q", footer, 48, disk_size)

    # Disk Geometry — CHS (per VHD spec algorithm)
    total_sec = disk_size // SECTOR_SIZE
    if total_sec > 65535 * 16 * 255:
        total_sec = 65535 * 16 * 255

    if total_sec >= 65535 * 16 * 63:
        spt = 255
        heads = 16
    else:
        spt = 17
        cth = total_sec // spt
        heads = (cth + 1023) // 1024
        if heads < 4:
            heads = 4
        if cth >= heads * 1024 or heads > 16:
            spt = 31
            heads = 16
            cth = total_sec // spt
        if cth >= heads * 1024:
            spt = 63
            heads = 16
            cth = total_sec // spt

    cth = total_sec // spt
    cylinders = min(cth // heads, 65535)

    struct.pack_into(">H", footer, 56, cylinders)
    footer[58] = heads
    footer[59] = spt

    # Disk Type (4 bytes, big-endian) — 2 = Fixed hard disk
    struct.pack_into(">I", footer, 60, 2)

    # Checksum (4 bytes, big-endian) — placeholder
    struct.pack_into(">I", footer, 64, 0)

    # Unique Id (16 bytes — raw UUID bytes)
    footer[68:84] = uuid.uuid4().bytes

    # Saved State (1 byte)
    footer[84] = 0

    # Reserved (427 bytes — already zero)

    # Compute checksum: one's complement of the sum of all bytes, excluding checksum field
    total = 0
    for i, b in enumerate(footer):
        if 64 <= i < 68:
            continue
        total += b
    checksum = (~total) & 0xFFFFFFFF
    struct.pack_into(">I", footer, 64, checksum)

    return footer


# ═══════════════════════════════════════════════════════════════════════════════
# VHD Assembly
# ═══════════════════════════════════════════════════════════════════════════════

def create_vhd(output_path: str, enable_protection: bool = True):
    """Assemble all components into a complete fixed VHD file."""

    print(f"╔══════════════════════════════════════════════════════════════╗")
    print(f"║  iDiskp64 Activation VHD Builder                           ║")
    print(f"╚══════════════════════════════════════════════════════════════╝")
    print()
    print(f"  Output file       : {output_path}")
    print(f"  Disk size         : {DISK_SIZE_MB} MB ({TOTAL_SECTORS} sectors)")
    print(f"  Partition start   : LBA {PARTITION_START_LBA}")
    print(f"  Partition GUID    : {{CA47A553-9A7A-43E1-A12B-CBB2B352E928}}")
    print(f"  'dom' magic at    : LBA {PARTITION_START_LBA + DOM_SECTOR_OFFSET} "
          f"(byte offset 0x{(PARTITION_START_LBA + DOM_SECTOR_OFFSET) * SECTOR_SIZE:X})")
    print(f"  'JKMS' header at  : LBA {PARTITION_START_LBA + JKMS_SECTOR_OFFSET} "
          f"(byte offset 0x{(PARTITION_START_LBA + JKMS_SECTOR_OFFSET) * SECTOR_SIZE:X})")
    print(f"  Write protection  : {'ENABLED' if enable_protection else 'DISABLED'}")
    print()

    # Generate a random disk GUID (mixed-endian for GPT)
    disk_guid = uuid.uuid4().bytes_le

    # Build partition entry array
    entries = make_gpt_partition_entries()
    entries_crc = crc32(entries)

    # Build GPT headers
    primary_hdr = make_gpt_header(is_backup=False, entries_crc=entries_crc, disk_guid=disk_guid)
    backup_hdr  = make_gpt_header(is_backup=True,  entries_crc=entries_crc, disk_guid=disk_guid)

    # Build activation sectors
    dom_sector = make_dom_sector()
    jkms_data  = make_jkms_metadata(enable_protection)

    # Build VHD footer
    vhd_footer = make_vhd_footer(DISK_SIZE)

    # ─── Write the VHD file ──────────────────────────────────────────────────
    with open(output_path, "wb") as f:
        # Sector 0: Protective MBR
        f.write(make_protective_mbr())

        # Sector 1: Primary GPT Header
        f.write(primary_hdr)

        # Sectors 2–33: Partition Entry Array (32 sectors)
        f.write(entries)

        # Sectors 34 – (PARTITION_START_LBA-1): gap (zeros)
        f.write(b'\x00' * ((PARTITION_START_LBA - 34) * SECTOR_SIZE))

        # Sector 2048: "dom" activation magic
        f.write(dom_sector)

        # Sectors 2049–2058: gap between dom and JKMS (10 sectors of zeros)
        f.write(b'\x00' * (JKMS_SECTOR_OFFSET - DOM_SECTOR_OFFSET - 1) * SECTOR_SIZE)

        # Sectors 2059–2065: JKMS metadata (7 sectors)
        f.write(jkms_data)

        # Sectors 2066 – (BACKUP_GPT_ENTRIES_LBA-1): remaining partition data (zeros)
        current_lba = PARTITION_START_LBA + JKMS_SECTOR_OFFSET + JKMS_NUM_SECTORS
        remaining = BACKUP_GPT_ENTRIES_LBA - current_lba
        # Write in chunks to avoid massive memory allocation
        CHUNK = 4096 * SECTOR_SIZE  # 2 MB chunks
        written = 0
        total_bytes = remaining * SECTOR_SIZE
        while written < total_bytes:
            chunk_size = min(CHUNK, total_bytes - written)
            f.write(b'\x00' * chunk_size)
            written += chunk_size

        # Backup GPT Partition Entry Array (32 sectors)
        f.write(entries)

        # Backup GPT Header (last sector of disk data)
        f.write(backup_hdr)

        # VHD Footer (512 bytes after disk data)
        f.write(vhd_footer)

    # ─── Verify ──────────────────────────────────────────────────────────────
    file_size = os.path.getsize(output_path)
    expected_size = DISK_SIZE + SECTOR_SIZE  # disk data + VHD footer

    print(f"  ✓ VHD created: {file_size:,} bytes", end="")
    if file_size == expected_size:
        print(f" (OK)")
    else:
        print(f" (WARNING: expected {expected_size:,})")

    print()
    print(f"  To mount on the VM (run as Administrator):")
    print(f"    PowerShell:  Mount-VHD -Path \"{os.path.abspath(output_path)}\"")
    print(f"    diskpart:    select vdisk file=\"{os.path.abspath(output_path)}\"")
    print(f"                 attach vdisk")
    print()
    print(f"  After mounting, iDiskp64 AddDevice will fire for the new disk device.")
    print(f"  The worker thread will find the magic bytes and activate protection.")
    print(f"  Verify with: !drvobj \\Driver\\iDiskp64 2  (should show a device object)")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    output = "idiskp64_trigger.vhd"
    enable = True

    args = sys.argv[1:]
    for arg in args:
        if arg in ("--no-protect", "--disable"):
            enable = False
        elif not arg.startswith("-"):
            output = arg

    create_vhd(output, enable)
