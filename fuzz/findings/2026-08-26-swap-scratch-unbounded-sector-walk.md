# Out-of-bounds read in `find_last_sector_idx()` when resuming a swap

| | |
|---|---|
| **Component** | `boot/bootutil/src/swap_scratch.c` |
| **Affected mode** | swap-using-scratch (MCUboot's default upgrade mode) |
| **Version** | 2.2.0 (`d37d3cf71408c71b7f4557a1e905be0b9b139f5c`) |
| **Class** | CWE-125, out-of-bounds read of a global array |
| **Found by** | `McuBootSuite.BootNeverRunsUnauthenticatedImage`, `fuzz/fuzz_test.cpp` |
| **Time to find** | ~4 s of fuzzing (262 executions) |
| **Status** | Fixed locally; not yet reported upstream |

## Summary

While deciding whether an interrupted swap needs to be resumed, MCUboot reads the
size of that swap out of the image trailer and walks the slot's sector table
until it has covered that many bytes. `find_last_sector_idx()` never compared the
sector index against the number of sectors the slot actually has, so a trailer
claiming a swap larger than the slot ran the loop off the end of
`sector_buffers` (`bootutil_misc.c`).

The trailer value does not need to be attacker-chosen: an *erased* trailer word
reads back as `0xffffffff`, which is far larger than any slot.

## Sanitizer output

```
==15==ERROR: AddressSanitizer: global-buffer-overflow on address 0x608bd73e0d04
READ of size 4 at 0x608bd73e0d04 thread T0
    #0 flash_sector_get_size        fuzz/flash_map_backend/flash_map_backend.h:23:13
    #1 boot_img_sector_size         boot/bootutil/src/bootutil_priv.h:545:12
    #2 find_last_sector_idx         boot/bootutil/src/swap_scratch.c:623:35
    #3 find_swap_count              boot/bootutil/src/swap_scratch.c:653:23
    #4 boot_read_image_header       boot/bootutil/src/swap_scratch.c:1103:22
    #5 boot_read_image_headers      boot/bootutil/src/loader.c:123:18
    #6 boot_prepare_image_for_update boot/bootutil/src/loader.c:1989:14
    #8 boot_go                      boot/bootutil/src/loader.c:3075:5

0x608bd73e0d04 is located 4 bytes after global variable 'sector_buffers'
defined in 'boot/bootutil/src/bootutil_misc.c:64' of size 3072
```

`swap_run()` (`swap_scratch.c:933`) reaches `find_last_sector_idx()` the same
way and is affected identically.

## Root cause

```c
static int
find_last_sector_idx(const struct boot_loader_state *state, uint32_t copy_size)
{
    ...
    while (1) {
        if ((primary_slot_size < copy_size) ||
            (primary_slot_size < secondary_slot_size)) {
           primary_slot_size += boot_img_sector_size(state,
                                                     BOOT_SLOT_PRIMARY,
                                                     last_sector_idx_primary);
            ++last_sector_idx_primary;      /* <- never bounded */
        }
        ...
    }
}
```

The loop only terminates once the accumulated slot sizes reach `copy_size`. When
`copy_size` exceeds the total size of a slot that never happens, and
`boot_img_sector_size()` keeps indexing past the end of the sector table.

`copy_size` comes from `boot_read_swap_size()`, i.e. straight from flash, and is
used without any sanity check. Every other consumer of the sector table
(`app_max_size()`, `boot_copy_sz()`) bounds its walk by
`boot_img_num_sectors()`; this one did not.

## How the harness reached it

The fuzzer drives a device lifecycle as a sequence of operations (stage an
update, mark it pending/confirmed, reboot, lose power mid-write, corrupt a
trailer byte). The counterexample it minimised to is a *single* stray byte:

1. Primary and secondary slots hold validly signed images; the primary trailer
   is otherwise erased.
2. One byte is written into the last entry of the primary slot's swap-status
   journal. That is enough for `swap_status_source()` to report a swap in
   progress.
3. `swap_read_status()` then reads the swap size from the trailer-info block,
   which was never written and so reads back as `0xffffffff`.
4. `boot_go()` → `boot_read_image_header()` → `find_swap_count()` →
   out-of-bounds read.

Reproducer, kept as `McuBootSuite.TrailerSwapSizeIsBoundedBySlotSize`:

```cpp
ProvisionPrimaryAndCandidate();

const struct flash_area *primary = Area(kPrimaryAreaId);
uint32_t swap_size_off = boot_swap_info_off(primary) - BOOT_MAX_ALIGN;
flash_sim_get_mem()[primary->fa_off + swap_size_off - 1] = 0x01;

RunBoot();
```

## Impact

**Severity: medium.** Permanent denial of service (unbootable device), no memory
write and no signature-verification bypass.

The read is unbounded, not a small overread. `sector_buffers` is

```c
struct boot_sector_buffer {
    boot_sector_t primary[BOOT_IMAGE_NUMBER][BOOT_MAX_IMG_SECTORS];
    boot_sector_t secondary[BOOT_IMAGE_NUMBER][BOOT_MAX_IMG_SECTORS];
    boot_sector_t scratch[BOOT_MAX_IMG_SECTORS];
};
```

`BOOT_MAX_IMG_SECTORS` is 128 here while the slot only has 32 real sectors, so
entries past the real count are zero. `primary_slot_size` therefore stops
growing while the index keeps incrementing, and the loop's exit condition
(`primary_slot_size >= copy_size`) can never be met for `copy_size ==
0xffffffff`. The walk climbs through `secondary[]`, through `scratch[]`, and
then off the end of the object — ASan trapped it 4 bytes past `sector_buffers`.

On a real target this is an ascending read of arbitrary addresses that ends in a
BusFault/HardFault or a watchdog reset. Because the faulting state lives in
flash, it recurs on every subsequent boot: the device is bricked and cannot be
recovered over the air.

What it is *not*:

- No write primitive. The out-of-bounds values only feed a sum and a sector
  index. Even if the loop terminated with a bogus index, the resulting
  `img_off` is passed to `flash_area_read/write/erase`, which bounds-check
  against the flash area (in both this simulator and Zephyr's flash_map), so it
  does not become an out-of-bounds flash write.
- No authentication bypass. Nothing here lets an unsigned image boot;
  `MCUBOOT_VALIDATE_PRIMARY_SLOT` still gates the boot decision.
- Not remotely triggerable on its own — it needs a specific flash state (below).

## Exploitability

**Hard to exploit for gain, easy to trigger by accident.**

The precondition is weaker than it first appears. The fourth entry of
`boot_status_tables` maps *magic Unset + copy-done Unset* to
`BOOT_STATUS_SOURCE_PRIMARY_SLOT`, with the comment "No swaps ever (no status to
read, so no harm in checking)". So a completely erased trailer — a device that
has never performed a swap — still has its status journal scanned. All that is
then needed is:

- **one non-`0xff` byte** anywhere in the ~384-byte swap-status region of the
  primary slot's trailer (`swap_read_status_bytes()` sets `found` on the first
  such byte), while
- the trailer-info block above it is still erased, so the swap size reads back
  as `0xffffffff`.

Plausible ways to arrive there without any attacker:

- A factory/recovery image programmed as a full-slot flash dump, leaving
  non-erased bytes in the trailer region.
- Bit rot or a retention failure flipping a single 1→0 in that region.
- An application that shares the flash driver writing past its own image.

For a deliberate attacker it is a weak primitive: it requires an existing
arbitrary-flash-write capability (at which point the trailer is the least
interesting target), and yields only a crash. Its realistic value is as a
persistent, un-recoverable brick — a fleet-wide DoS if a bad OTA payload or a
buggy application can put a byte in that window.

MCUboot itself never produces this state: `swap_status_init()` writes the swap
size before the magic, so a clean power cut cannot leave a journal entry with an
erased size. The bug is a robustness failure — trusting a length read from flash
— rather than a flaw in the swap protocol.

## Fix

Bound the walk by the sector counts and report failure; both callers already
treat a negative index as "nothing to swap".

```c
+    num_sectors_primary = (int)boot_img_num_sectors(state, BOOT_SLOT_PRIMARY);
+    num_sectors_secondary = (int)boot_img_num_sectors(state, BOOT_SLOT_SECONDARY);
     while (1) {
+        /* copy_size can come from an image trailer, so it is not necessarily
+         * trustworthy; refuse to walk off the end of the sector tables.
+         */
+        if (last_sector_idx_primary >= num_sectors_primary ||
+            last_sector_idx_secondary >= num_sectors_secondary) {
+            BOOT_LOG_ERR("Swap size %u does not fit in the image slots",
+                         (unsigned)copy_size);
+            return -1;
+        }
```

With the fix, the bogus trailer is ignored and the image already in the primary
slot boots normally.

## Verification

- `McuBootSuite.TrailerSwapSizeIsBoundedBySlotSize` passes.
- The existing swap lifecycle and power-cut walk tests
  (`SwapResumesAfterPowerCutAtAnyStage`, `SwapResumesAfterTornWriteAtAnyStage`,
  `Upgrade*`, `PermanentUpgradeNeedsNoConfirmation`) are unchanged and pass, so
  the bound does not affect well-formed swaps.
- `BootNeverRunsUnauthenticatedImage` subsequently ran 36 469 executions /
  607 edges with no further findings.

## Follow-ups

- Report upstream (`mcu-tools/mcuboot`).
- `swap_move.c` and `swap_offset.c` were not built in this configuration; they
  should be checked for the same unbounded pattern.
