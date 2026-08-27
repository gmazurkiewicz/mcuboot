/* Simple backend simulating flash memory in a RAM buffer.
 * Implements functions from flash_map.h for mcuboot testing.
 *
 * Behavior and assumptions:
 * - There is a single "flash device" backed by the global buffer `flash_mem`.
 * - Flash areas are defined by a static table `areas` (fa_id, device_id, off, size).
 * - Erased memory value is 0xFF.
 * - Erase sets a range of bytes to 0xFF.
 * - Write cannot flip bits from 0->1 (requires erase first). Before writing, it checks that
 *   (dest_byte & src_byte) == src_byte for every byte. If not, it returns error.
 * - Read copies from the buffer into dst.
 * - Sectors are defined with a constant size (SECTOR_SIZE).
 *
 * This file is simple and intended for testing only.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "flash_map.h"
#include <stdio.h>

/* Parameters of the simulated flash */
#define DEVICE_FLASH_SIZE   (3 * 128 * 1024) /* 3 * 128 KB */
#define SECTOR_SIZE         4096             /* 4 KB */
#define ERASED_VAL          0xFF

/* Global memory simulating flash */
static uint8_t flash_mem[DEVICE_FLASH_SIZE];

/* Device geometry; see flash_sim_init_with_geometry(). */
static uint32_t sector_size = SECTOR_SIZE;
static uint32_t write_align = 1;
static int requires_erase = 1;
static unsigned long misaligned_ops;

/* Power-cut fault injection state; see flash_map.h. */
static unsigned long op_count;
static unsigned long cut_at;
static int cut_partial;
static int cut_happened;
static jmp_buf cut_jmpbuf;

/* Returns the number of bytes the caller may apply before power is lost, or
 * -1 when the operation is allowed to complete. */
static long power_cut_prefix(uint32_t len)
{
    ++op_count;
    if (cut_at == 0 || op_count != cut_at) {
        return -1;
    }
    return cut_partial ? (long)(len / 2) : 0;
}

static void power_cut(void)
{
    cut_happened = 1;
    cut_at = 0;
    longjmp(cut_jmpbuf, 1);
}

void flash_sim_reset_op_count(void)
{
    op_count = 0;
}

unsigned long flash_sim_op_count(void)
{
    return op_count;
}

void flash_sim_arm_power_cut(unsigned long op_index, int partial)
{
    cut_at = op_index;
    cut_partial = partial;
    cut_happened = 0;
}

void flash_sim_disarm_power_cut(void)
{
    cut_at = 0;
}

int flash_sim_power_cut_happened(void)
{
    return cut_happened;
}

jmp_buf *flash_sim_power_cut_jmpbuf(void)
{
    return &cut_jmpbuf;
}

/* Simple flash area map (three image slots). fa_id must be unique and start from 1. */
static struct flash_area areas[] = {
    /* fa_id, fa_device_id, pad16, fa_off, fa_size */
    { 1, 0, 0, 0x00000, 128 * 1024 }, /* slot 0: 128KB starting at offset 0 */
    { 2, 0, 0, 0x20000, 128 * 1024 }, /* slot 1: 128KB starting at offset 0x20000 */
    { 3, 0, 0, 0x40000, 128 * 1024 }, /* slot 2: 128KB starting at offset 0x40000 */
};
static const int areas_cnt = sizeof(areas) / sizeof(areas[0]);

/* Helper: check if area and range are within device memory */
static int check_range(const struct flash_area *fa, uint32_t off, uint32_t len)
{
    if (fa == NULL) {
        return -1;
    }
    if (off + len > fa->fa_size) {
        return -1;
    }
    if ((size_t)fa->fa_off + (size_t)off + (size_t)len > DEVICE_FLASH_SIZE) {
        return -1;
    }
    return 0;
}

/* Return base offset of the device (for simplicity always 0). */
int flash_device_base(uint8_t fd_id, uintptr_t *ret)
{
    (void)fd_id;
    if (!ret) {
        return -1;
    }
    *ret = 0;
    return 0;
}

/* Open an area with given fa_id and return a pointer to static structure */
int flash_area_open(uint8_t id, const struct flash_area **fa)
{
    if (!fa) return -1;
    for (int i = 0; i < areas_cnt; ++i) {
        if (areas[i].fa_id == id) {
            *fa = &areas[i];
            return 0;
        }
    }
    return -1;
}

void flash_area_close(const struct flash_area *fa)
{
    (void)fa; /* nothing to do for static array */
}

int flash_area_read(const struct flash_area *fa, uint32_t off, void *dst, uint32_t len)
{
    if (check_range(fa, off, len) != 0) return -1;
    memcpy(dst, &flash_mem[fa->fa_off + off], len);
    return 0;
}

int flash_area_write(const struct flash_area *fa, uint32_t off, const void *src, uint32_t len)
{
    if (check_range(fa, off, len) != 0) return -1;
    const uint8_t *s = (const uint8_t *)src;
    uint8_t *d = &flash_mem[fa->fa_off + off];
    /* A real driver would reject this outright; count it instead so the
     * violation is reported as a test failure rather than cascading into
     * unrelated swap failures. */
    if ((off % write_align) != 0 || (len % write_align) != 0) {
        ++misaligned_ops;
    }
    /* NOR flash can only clear bits; a part that needs no explicit erase can
     * write any value over any other. */
    if (requires_erase) {
        for (uint32_t i = 0; i < len; ++i) {
            if ((d[i] & s[i]) != s[i]) {
                return -1;
            }
        }
    }
    long cut = power_cut_prefix(len);
    uint32_t applied = (cut < 0) ? len : (uint32_t)cut;
    for (uint32_t i = 0; i < applied; ++i) {
        d[i] = requires_erase ? (uint8_t)(d[i] & s[i]) : s[i];
    }
    if (cut >= 0) {
        power_cut();
    }
    return 0;
}

int flash_area_erase(const struct flash_area *fa, uint32_t off, uint32_t len)
{
    if (check_range(fa, off, len) != 0) return -1;
    long cut = power_cut_prefix(len);
    memset(&flash_mem[fa->fa_off + off], ERASED_VAL, (cut < 0) ? len : (size_t)cut);
    if (cut >= 0) {
        power_cut();
    }
    return 0;
}

uint32_t flash_area_align(const struct flash_area *fa)
{
    (void)fa;
    return write_align;
}

uint8_t flash_area_erased_val(const struct flash_area *fa)
{
    (void)fa;
    return (uint8_t)ERASED_VAL;
}

int flash_area_get_sectors(int fa_id, uint32_t *count, struct flash_sector *sectors)
{
    if (!count || !sectors) return -1;
    const struct flash_area *fa = NULL;
    if (flash_area_open((uint8_t)fa_id, &fa) != 0) return -1;
    uint32_t n = (fa->fa_size + sector_size - 1) / sector_size;
    /* *count is the caller's array capacity on entry. */
    if (n > *count) {
        return -1;
    }
    *count = n;
    for (uint32_t i = 0; i < n; ++i) {
        sectors[i].fs_off = i * sector_size;
        sectors[i].fs_size = (i == n - 1) ? (fa->fa_size - i * sector_size) : sector_size;
    }
    return 0;
}

int flash_area_sector_from_off(uint32_t off, struct flash_sector *sector)
{
    if (!sector) return -1;
    if (off >= DEVICE_FLASH_SIZE) return -1;
    uint32_t idx = off / sector_size;
    sector->fs_off = idx * sector_size;
    sector->fs_size = sector_size;
    return 0;
}

int flash_area_get_sector(const struct flash_area *fa, uint32_t off, struct flash_sector *sector)
{
    if (!fa || !sector) return -1;
    if (off >= fa->fa_size) return -1;
    uint32_t idx = off / sector_size;
    sector->fs_off = idx * sector_size;
    sector->fs_size = (idx == (fa->fa_size / sector_size)) ? (fa->fa_size - idx * sector_size) : sector_size;
    return 0;
}


/* Simple mapping from image slots to area ids.
 */
int flash_area_id_from_image_slot(int slot)
{
    if (slot == 0) return 1;
    if (slot == 1) return 2;
    if (slot == 2) return 3;
    return -1;
}

int flash_area_id_from_multi_image_slot(int image_index, int slot)
{
    (void)image_index;
    return flash_area_id_from_image_slot(slot);
}

int flash_area_id_to_multi_image_slot(int image_index, int area_id)
{
    (void)image_index;
    if (area_id == 1) return 0;
    if (area_id == 2) return 1;
    if (area_id == 3) return 2;
    return -1;
}

/* Initialization: set memory to erased value. Call this from test code. */
void flash_sim_init(void)
{
    flash_sim_init_with_geometry(SECTOR_SIZE, 1, 1);
}

void flash_sim_init_with_geometry(uint32_t sector_sz, uint32_t align, int erase_required)
{
    memset(flash_mem, ERASED_VAL, sizeof(flash_mem));
    op_count = 0;
    cut_at = 0;
    cut_partial = 0;
    cut_happened = 0;
    misaligned_ops = 0;
    sector_size = sector_sz ? sector_sz : SECTOR_SIZE;
    write_align = align ? align : 1;
    requires_erase = erase_required;
}

bool flash_area_erase_required(const struct flash_area *fa)
{
    (void)fa;
    return requires_erase != 0;
}

uint32_t flash_sim_get_sector_size(void)
{
    return sector_size;
}

unsigned long flash_sim_misaligned_ops(void)
{
    return misaligned_ops;
}

/* Extra helper: return pointer to raw simulated memory (for debug/testing). */
uint8_t *flash_sim_get_mem(void)
{
    return flash_mem;
}

/* Extra helper: total size of the simulated flash buffer, for callers that
 * need to bound writes into it. */
size_t flash_sim_get_size(void)
{
    return sizeof(flash_mem);
}
