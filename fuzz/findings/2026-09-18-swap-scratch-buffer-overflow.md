# Buffer Overflow in `find_last_sector_idx`

## Summary

After merging main into the fuzz branch, AddressSanitizer detected a global-buffer-overflow in `find_last_sector_idx` when called with a malformed image that contains an arbitrarily large `copy_size` value in its trailer.

## Root Cause

Main branch removed the bounds check from `find_last_sector_idx` in `boot/bootutil/src/swap_scratch.c` (commit range between 186adeb4 and c85af35b). This function iterates over flash sectors to find the last sector index that needs swapping, based on a `copy_size` parameter that comes from the image trailer.

When `copy_size` is very large (or malformed), the function increments `last_sector_idx_primary` and `last_sector_idx_secondary` beyond the valid sector range, causing out-of-bounds access when calling `boot_img_sector_size(state, slot, sector)`, which directly accesses `BOOT_IMG(state, slot).sectors[sector]`.

## Vulnerability

```c
while (1) {
    if ((primary_slot_size < copy_size) ||
        (primary_slot_size < secondary_slot_size)) {
       primary_slot_size += boot_img_sector_size(state,
                                                BOOT_SLOT_PRIMARY,
                                                last_sector_idx_primary);
        ++last_sector_idx_primary;  /* Can exceed num_sectors */
    }
    /* ... */
}
```

When `last_sector_idx_primary` or `last_sector_idx_secondary` exceeds the number of sectors in the slot, `boot_img_sector_size` reads from memory beyond the `sectors` array, causing a buffer overflow.

## Fix

Re-add the bounds check that was previously removed:

```c
int num_sectors_primary = (int)boot_img_num_sectors(state, BOOT_SLOT_PRIMARY);
int num_sectors_secondary = (int)boot_img_num_sectors(state, BOOT_SLOT_SECONDARY);

while (1) {
    if (last_sector_idx_primary >= num_sectors_primary ||
        last_sector_idx_secondary >= num_sectors_secondary) {
        BOOT_LOG_ERR("Swap size %u does not fit in the image slots",
                     (unsigned)copy_size);
        return -1;
    }
    /* ... */
}
```

## Impact

This vulnerability allows an attacker to craft a malicious image that:
1. Passes initial header validation
2. Contains an arbitrarily large `copy_size` in its trailer
3. Causes `find_last_sector_idx` to read beyond the sector table
4. Potentially leaks memory contents or causes undefined behavior

## Test Case

Fuzzing with `McuBootSuite.BootNeverRunsUnauthenticatedImage` found this issue with:
- FlashGeometry: {sector_log2=14, align_log2=2, needs_erase=true} (16KB sectors, 4-byte alignment)
- Device steps: {DeviceOp{9}, 33515, 243}, {DeviceOp{3}, 0, 0}, {DeviceOp{0}, 0, 0}

## Note

The original fuzz branch had previously identified and fixed a similar unbounded sector walk vulnerability (see commit b98cb103 and findings/2026-08-26-swap-scratch-unbounded-sector-walk.md). Main's refactoring inadvertently re-introduced a variant of this vulnerability by removing the bounds check while keeping the loop that could walk off the end of the sector table.
