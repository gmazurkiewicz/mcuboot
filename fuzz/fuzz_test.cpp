#include <algorithm>
#include <array>
#include <csetjmp>
#include <cstddef>
#include <cstring>
#include <optional>
#include <vector>

#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"
#include "bootutil/bootutil.h"
#include "bootutil/bootutil_public.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil/image.h"
#include "storage/flash_map.h"

/* Known-good signed image (64B header + 128B payload + 336B TLVs = 528B),
 * used to seed the fuzzer and as the mutation template below. */
uint8_t img_out[] =
{
    0x3d, 0xb8, 0xf3, 0x96, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x0d, 0x5c, 0xc6, 0x55, 0x5d, 0xda, 0x74, 0xd1, 0x1e, 0x48, 0x91, 0x11, 0x42, 0x0c, 0x18, 0xff,
    0x0e, 0x27, 0x3f, 0x4a, 0x4b, 0x5c, 0x94, 0x0d, 0x42, 0x6a, 0x1c, 0x87, 0xeb, 0x3b, 0xa3, 0xb6,
    0x67, 0x8a, 0x74, 0x9e, 0x78, 0x28, 0x4e, 0x87, 0xfd, 0x7d, 0x35, 0x61, 0x50, 0x30, 0xc0, 0xac,
    0x96, 0xdc, 0x3e, 0x24, 0x0d, 0xec, 0x03, 0x39, 0xfe, 0x49, 0xe7, 0x7e, 0xcb, 0x51, 0x86, 0x30,
    0x0b, 0xa4, 0xc6, 0xf7, 0x45, 0xaf, 0x74, 0xc6, 0x2d, 0xf6, 0x62, 0x9e, 0xec, 0x87, 0xde, 0x82,
    0x67, 0xe1, 0xd1, 0x44, 0x58, 0x02, 0xc1, 0xa4, 0xe6, 0x2b, 0x7a, 0xb0, 0xe7, 0x78, 0xc6, 0xd6,
    0x6d, 0x0b, 0x1c, 0xb0, 0x29, 0x21, 0x8f, 0x77, 0x29, 0x97, 0x0a, 0x95, 0x4f, 0x34, 0xcc, 0x0c,
    0xc0, 0x94, 0x9d, 0x71, 0xda, 0x75, 0xe7, 0xcb, 0x84, 0xbf, 0xd2, 0xc6, 0x58, 0xa3, 0x87, 0xbd,
    0x07, 0x69, 0x50, 0x01, 0x10, 0x00, 0x20, 0x00, 0xaf, 0x35, 0x7f, 0x64, 0xb8, 0xcc, 0x53, 0xcf,
    0x7a, 0x57, 0xe0, 0xb3, 0xfc, 0xce, 0x71, 0xd3, 0xdf, 0xcc, 0xe4, 0xd1, 0xe6, 0x01, 0x35, 0xc9,
    0x3f, 0x74, 0x94, 0x96, 0xfa, 0x2c, 0x50, 0x83, 0x01, 0x00, 0x20, 0x00, 0xfc, 0x57, 0x01, 0xdc,
    0x61, 0x35, 0xe1, 0x32, 0x38, 0x47, 0xbd, 0xc4, 0x0f, 0x04, 0xd2, 0xe5, 0xbe, 0xe5, 0x83, 0x3b,
    0x23, 0xc2, 0x9f, 0x93, 0x59, 0x3d, 0x00, 0x01, 0x8c, 0xfa, 0x99, 0x94, 0x20, 0x00, 0x00, 0x01,
    0x19, 0xee, 0x07, 0x69, 0x1c, 0xeb, 0x9c, 0xf2, 0x9b, 0xf3, 0xb1, 0x0d, 0x64, 0x1c, 0x60, 0x36,
    0x1a, 0xea, 0x31, 0xb4, 0x99, 0xd9, 0x12, 0x20, 0x3e, 0x9d, 0x45, 0xcc, 0x65, 0xe6, 0x5a, 0xb8,
    0xfc, 0xc1, 0x50, 0xfa, 0x8d, 0x00, 0x2e, 0xf8, 0xdc, 0x9b, 0xc5, 0x9d, 0xb6, 0xb9, 0x55, 0x91,
    0x4b, 0xbd, 0x0c, 0x53, 0xca, 0xca, 0xbc, 0x08, 0x31, 0x8f, 0x70, 0xae, 0xc4, 0x13, 0x07, 0xff,
    0xae, 0xf3, 0x32, 0x16, 0x7b, 0x63, 0x5a, 0xf0, 0x26, 0x91, 0x74, 0x7e, 0x83, 0xf1, 0xe5, 0x9e,
    0x10, 0x7c, 0x1f, 0x33, 0x72, 0x2b, 0x68, 0x4b, 0x03, 0xd8, 0xb0, 0x7c, 0x32, 0xa0, 0xca, 0x9b,
    0xf9, 0x2f, 0x42, 0x9b, 0x5f, 0x13, 0x66, 0x5d, 0x83, 0xaa, 0xbe, 0xf7, 0x3f, 0xf1, 0xf3, 0xd9,
    0x0b, 0xa2, 0xc4, 0x7d, 0xe1, 0x56, 0x05, 0x79, 0x1a, 0x24, 0xb2, 0x21, 0x2c, 0x00, 0x58, 0x6d,
    0x8b, 0x21, 0x83, 0xab, 0x89, 0xfe, 0x96, 0x38, 0x84, 0x60, 0x6a, 0x1d, 0xc7, 0x70, 0x13, 0x42,
    0x2f, 0xed, 0x27, 0x61, 0x9a, 0x4d, 0x81, 0x2e, 0x68, 0x8b, 0xf4, 0xb6, 0xd7, 0x83, 0xf7, 0x5b,
    0x3d, 0xf2, 0x53, 0xd0, 0x4d, 0x2c, 0xe9, 0xae, 0x20, 0x93, 0x00, 0xa3, 0xd4, 0xd5, 0x95, 0x44,
    0x64, 0xe4, 0x05, 0xff, 0x1e, 0xd1, 0x49, 0xf7, 0x62, 0xd7, 0xa9, 0xfe, 0x44, 0xe6, 0xf4, 0x24,
    0x34, 0x31, 0x41, 0x60, 0xd7, 0x58, 0x5e, 0x50, 0xf3, 0x76, 0x30, 0x31, 0x87, 0xd3, 0x78, 0xc9,
    0x62, 0x82, 0x7d, 0x62, 0xba, 0xaf, 0x9c, 0x57, 0x2b, 0xd4, 0x35, 0x4e, 0x5e, 0x7a, 0x79, 0x3b,
    0x84, 0x92, 0xa8, 0xe0, 0x50, 0x0f, 0x3b, 0x4c, 0x61, 0x19, 0x54, 0x89, 0x92, 0x21, 0xb8, 0x51,
    0x4a, 0xc1, 0x47, 0x07, 0x4b, 0x34, 0x54, 0x07, 0x5f, 0x14, 0xee, 0xe2, 0xfe, 0x6e, 0xc1, 0x3d,
};


/* Must not exceed slot 0's size in storage/flash_map.c's areas[] table. */
constexpr size_t kMaxImageSize = 128 * 1024;

/* Area ids from sysflash/sysflash.h, mapped by storage/flash_map.c. */
constexpr uint8_t kPrimaryAreaId = 1;
constexpr uint8_t kSecondaryAreaId = 2;
constexpr uint8_t kScratchAreaId = 3;

const struct flash_area *Area(uint8_t area_id)
{
    const struct flash_area *fa = nullptr;
    return flash_area_open(area_id, &fa) == 0 ? fa : nullptr;
}

void WriteArea(uint8_t area_id, const uint8_t *bytes, size_t len)
{
    const struct flash_area *fa = Area(area_id);
    if (fa != nullptr && len <= fa->fa_size) {
        memcpy(flash_sim_get_mem() + fa->fa_off, bytes, len);
    }
}

bool AreaMatches(uint8_t area_id, const uint8_t *expected, size_t len)
{
    const struct flash_area *fa = Area(area_id);
    return fa != nullptr && memcmp(flash_sim_get_mem() + fa->fa_off, expected, len) == 0;
}

/* Runs one simulated boot, optionally losing power just as the `cut_op`-th
 * flash write/erase is applied (0 = let the boot run to completion). */
struct BootOutcome {
    bool booted;
    bool power_cut;
    unsigned long flash_ops;
};

BootOutcome RunBoot(unsigned long cut_op = 0, bool torn = false)
{
    volatile bool booted = false;

    flash_sim_reset_op_count();
    flash_sim_arm_power_cut(cut_op, torn ? 1 : 0);
    if (setjmp(*flash_sim_power_cut_jmpbuf()) == 0) {
        struct boot_rsp rsp = {};
        fih_ret rc = boot_go(&rsp);
        booted = FIH_EQ(rc, FIH_SUCCESS);
    }
    flash_sim_disarm_power_cut();

    return BootOutcome{booted, flash_sim_power_cut_happened() != 0, flash_sim_op_count()};
}

void InvokeBootGo(const std::vector<uint8_t> &image)
{
    flash_sim_init();
    size_t len = std::min(image.size(), flash_sim_get_size());
    if (len > 0) {
        memcpy(flash_sim_get_mem(), image.data(), len);
    }
    struct boot_rsp rsp = {};
    boot_go(&rsp);
}
FUZZ_TEST(McuBootSuite, InvokeBootGo)
    .WithDomains(fuzztest::Arbitrary<std::vector<uint8_t>>().WithMaxSize(kMaxImageSize))
    .WithSeeds({{std::vector<uint8_t>(img_out, img_out + sizeof(img_out))}});

/* Byte layout of img_out (528B = 64B header + 128B payload + 336B TLV area),
 * as produced by build.sh's `imgtool sign -H 64 --pad-header`: tlv_info at
 * 192, first TLV header at 196, SHA256 TLV value at 200, KEYHASH TLV value at
 * 236, RSA2048_PSS signature value at 272. */
constexpr size_t kTemplateSize = 528;
constexpr size_t kPayloadOff = 64;
constexpr size_t kPayloadSize = 128;
constexpr size_t kTlvInfoOff = 192;
constexpr size_t kTlvHdrOff = 196;
constexpr size_t kShaValueOff = 200;
constexpr size_t kShaValueSize = 32;
constexpr size_t kKeyhashValueOff = 236;
constexpr size_t kKeyhashValueSize = 32;
constexpr size_t kSigValueOff = 272;
constexpr size_t kSigValueSize = 256;
static_assert(sizeof(img_out) == kTemplateSize,
              "img_out layout changed; TLV offsets above need updating");

/* A second, independently-signed image (different payload, version 5.0.0),
 * used as a genuinely different "upgrade candidate" so tests can tell
 * whether a swap actually happened by comparing raw slot bytes. */
uint8_t img_candidate[] =
{
    0x3d, 0xb8, 0xf3, 0x96, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x55, 0xeb, 0xd4, 0x82, 0xb6, 0x85, 0x5d, 0xd0, 0x28, 0x7b, 0xba, 0x81, 0xf6, 0xe1, 0xa8, 0xc3,
    0xbf, 0x27, 0xbb, 0xe6, 0x69, 0x41, 0x09, 0x90, 0xc6, 0x10, 0xf5, 0xfc, 0x4f, 0xfe, 0xb9, 0xe3,
    0xa0, 0x79, 0x62, 0x4c, 0x53, 0x0a, 0xa3, 0x59, 0x56, 0x94, 0xbc, 0x48, 0xb2, 0xa2, 0xfc, 0x7a,
    0x69, 0x49, 0x80, 0xb8, 0x57, 0x87, 0x99, 0x89, 0xda, 0x74, 0x7e, 0xbe, 0xf4, 0x28, 0xdb, 0x40,
    0x88, 0x79, 0xaa, 0x79, 0x3b, 0x3f, 0x25, 0xfb, 0xe7, 0x7e, 0x89, 0xff, 0xc3, 0x43, 0x0e, 0xa7,
    0x3b, 0x7e, 0x30, 0x22, 0x48, 0xdd, 0xee, 0x69, 0xf6, 0x2c, 0xaf, 0xca, 0xce, 0x63, 0x5e, 0xda,
    0xad, 0xb4, 0xe2, 0x89, 0x70, 0x6f, 0x3b, 0xe4, 0x91, 0x71, 0x00, 0x96, 0x0e, 0xef, 0x51, 0x0f,
    0xfc, 0x8e, 0x0f, 0xbb, 0xe3, 0x7e, 0xf6, 0x39, 0x39, 0xf0, 0x38, 0x4a, 0x6d, 0x8b, 0xd9, 0x4a,
    0x07, 0x69, 0x50, 0x01, 0x10, 0x00, 0x20, 0x00, 0x9d, 0xe9, 0x28, 0xc2, 0x3a, 0x8c, 0x4d, 0x72,
    0xa0, 0x57, 0x47, 0xa5, 0x50, 0xfe, 0xf2, 0x7d, 0x98, 0xa4, 0x87, 0x88, 0xb8, 0xc9, 0xab, 0xeb,
    0xeb, 0x7a, 0x6c, 0x6c, 0xb2, 0x90, 0x99, 0x14, 0x01, 0x00, 0x20, 0x00, 0xfc, 0x57, 0x01, 0xdc,
    0x61, 0x35, 0xe1, 0x32, 0x38, 0x47, 0xbd, 0xc4, 0x0f, 0x04, 0xd2, 0xe5, 0xbe, 0xe5, 0x83, 0x3b,
    0x23, 0xc2, 0x9f, 0x93, 0x59, 0x3d, 0x00, 0x01, 0x8c, 0xfa, 0x99, 0x94, 0x20, 0x00, 0x00, 0x01,
    0x8d, 0x51, 0x0c, 0x25, 0x26, 0xc9, 0x0d, 0xa4, 0x9d, 0x6c, 0x93, 0xda, 0xc7, 0xf0, 0x02, 0x90,
    0xa3, 0xb7, 0xcd, 0xce, 0xfb, 0xf7, 0x99, 0x0b, 0x1f, 0x69, 0xe7, 0x67, 0xb1, 0xad, 0xb4, 0x04,
    0x1b, 0x2c, 0x9d, 0xf4, 0x39, 0xe5, 0xeb, 0x11, 0x81, 0x0b, 0xf8, 0x32, 0x8b, 0xd7, 0x8a, 0xc0,
    0x64, 0x31, 0xf0, 0x57, 0x13, 0xc1, 0xa7, 0x99, 0xb4, 0x59, 0x27, 0x67, 0xb7, 0x4f, 0x34, 0x48,
    0x85, 0x97, 0xa2, 0x6d, 0x85, 0x4e, 0x9a, 0x50, 0x2a, 0x79, 0x8e, 0x1a, 0xc0, 0xd3, 0xd3, 0x64,
    0x44, 0xd6, 0xa2, 0xd8, 0x07, 0x02, 0x75, 0x9b, 0x32, 0x02, 0x0d, 0x4e, 0xfa, 0xf2, 0x53, 0xd1,
    0x18, 0x71, 0x48, 0x1f, 0xed, 0x08, 0xa2, 0x47, 0x2b, 0xb5, 0xcb, 0x08, 0x6c, 0x46, 0x09, 0x97,
    0xd8, 0xa7, 0x8a, 0x41, 0x15, 0x38, 0xea, 0x5e, 0x66, 0x7b, 0x8b, 0xdd, 0x09, 0x08, 0x7b, 0x39,
    0x72, 0x3a, 0x14, 0x35, 0xf0, 0x94, 0x0f, 0xa4, 0xfe, 0x35, 0x31, 0x2c, 0x63, 0x61, 0x25, 0x0a,
    0xdc, 0x74, 0xa1, 0x58, 0xa3, 0xae, 0x1d, 0xa4, 0x72, 0x42, 0x1c, 0x72, 0x50, 0x5a, 0xf7, 0xd2,
    0xbf, 0x53, 0x23, 0x80, 0xa1, 0x60, 0xa7, 0xad, 0x7a, 0x48, 0xa9, 0x4c, 0x45, 0xca, 0x01, 0xfe,
    0x6a, 0x06, 0x45, 0xea, 0x86, 0x72, 0x60, 0x8f, 0xad, 0x4c, 0x1a, 0xe2, 0xe0, 0xc0, 0x9e, 0x0c,
    0x54, 0xa1, 0xe6, 0x1b, 0xd5, 0x1f, 0x5a, 0x10, 0xc5, 0x8b, 0x71, 0x6d, 0x86, 0x92, 0xec, 0x9f,
    0x67, 0x87, 0xec, 0xb2, 0x5b, 0x19, 0x2b, 0x72, 0x8d, 0xe7, 0x91, 0x5d, 0xc7, 0xaa, 0x35, 0xf2,
    0x94, 0x2b, 0xa5, 0x93, 0x3d, 0xb4, 0x13, 0x49, 0xcd, 0x74, 0xf8, 0xeb, 0x02, 0x1e, 0x8d, 0x36,
    0x87, 0xb8, 0x46, 0x3e, 0x5a, 0xc5, 0x7e, 0x9e, 0x21, 0x30, 0x49, 0x68, 0x53, 0x8f, 0x32, 0x7c,
};
static_assert(sizeof(img_candidate) == kTemplateSize,
              "img_candidate layout changed; regenerate it (see fuzz/README)");

/* A third validly-signed image, this one carrying a protected TLV section
 * (imgtool --security-counter). None of the images above have one, so without
 * it tlv.c's protected-section handling is never reached by an image that
 * makes it past signature verification. */
uint8_t img_protected[] =
{
    0x3d, 0xb8, 0xf3, 0x96, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0c, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x11, 0x31, 0xd9, 0x35, 0x10, 0xc1, 0x4b, 0x88, 0x79, 0xee, 0x63, 0x4a, 0x1b, 0x9e, 0x36, 0x96,
    0x0f, 0xd6, 0x0a, 0x39, 0xa8, 0x42, 0xf2, 0x48, 0x17, 0xcb, 0x2d, 0xed, 0xe8, 0x9a, 0x15, 0x65,
    0x59, 0xd5, 0xa1, 0xa2, 0x80, 0x4f, 0xaa, 0xab, 0x92, 0x21, 0x42, 0xea, 0x2c, 0x15, 0x7d, 0x72,
    0x96, 0x39, 0xe6, 0x76, 0x93, 0xa9, 0x7f, 0x1a, 0xaa, 0x80, 0x3e, 0xb5, 0x8f, 0x50, 0xbb, 0x72,
    0x26, 0x9c, 0x95, 0x01, 0x75, 0xd7, 0x45, 0x82, 0xce, 0xfc, 0x92, 0x9c, 0xcf, 0x79, 0x8d, 0x04,
    0x4e, 0x3a, 0xee, 0x4e, 0xd1, 0x19, 0xd9, 0xb0, 0x1b, 0x02, 0x76, 0xf2, 0xc7, 0xfd, 0x6e, 0x0d,
    0xbf, 0x5b, 0xe1, 0x6a, 0x07, 0x87, 0x42, 0xac, 0xc9, 0xa5, 0xac, 0xa1, 0xeb, 0x10, 0xd6, 0x21,
    0xa9, 0x5b, 0xfc, 0x5c, 0xe9, 0x2b, 0x81, 0xcf, 0xac, 0x3b, 0xae, 0x15, 0xd7, 0x60, 0x98, 0xc7,
    0x08, 0x69, 0x0c, 0x00, 0x50, 0x00, 0x04, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x07, 0x69, 0x50, 0x01,
    0x10, 0x00, 0x20, 0x00, 0xf4, 0xd0, 0x29, 0x25, 0xdc, 0xf7, 0xc2, 0xa5, 0x74, 0x8c, 0x08, 0x19,
    0xa9, 0xe6, 0x6d, 0x66, 0xa7, 0xf2, 0x4a, 0x3f, 0x92, 0x28, 0xaa, 0x9c, 0x06, 0xd5, 0x9d, 0x2c,
    0x75, 0x94, 0xcd, 0xf2, 0x01, 0x00, 0x20, 0x00, 0xfc, 0x57, 0x01, 0xdc, 0x61, 0x35, 0xe1, 0x32,
    0x38, 0x47, 0xbd, 0xc4, 0x0f, 0x04, 0xd2, 0xe5, 0xbe, 0xe5, 0x83, 0x3b, 0x23, 0xc2, 0x9f, 0x93,
    0x59, 0x3d, 0x00, 0x01, 0x8c, 0xfa, 0x99, 0x94, 0x20, 0x00, 0x00, 0x01, 0x7a, 0xda, 0x14, 0xd6,
    0xf9, 0x1b, 0x7c, 0xe5, 0xcb, 0x28, 0xff, 0xed, 0x78, 0xe5, 0x24, 0x49, 0xcb, 0x69, 0xe4, 0x3c,
    0x5d, 0x6d, 0x1a, 0x1d, 0xa8, 0xc1, 0xd5, 0x64, 0xf1, 0xfa, 0x26, 0xf2, 0x50, 0xa6, 0x2b, 0x53,
    0xd2, 0x7d, 0x5c, 0xcd, 0x76, 0xcc, 0xf7, 0x6e, 0x07, 0x32, 0xcb, 0xb2, 0x3f, 0xd6, 0x95, 0xfb,
    0x89, 0xec, 0x48, 0x30, 0xf7, 0x47, 0xf3, 0x70, 0xfd, 0x4a, 0x57, 0xc2, 0xf2, 0x30, 0x7d, 0x4c,
    0x79, 0xbd, 0x7f, 0xdb, 0x8b, 0x80, 0xbc, 0x76, 0xe2, 0xeb, 0xdf, 0xdf, 0x49, 0xe4, 0xc9, 0xac,
    0x05, 0x29, 0x42, 0x87, 0x5b, 0xc1, 0x26, 0x47, 0xda, 0x1c, 0x4d, 0x0c, 0x98, 0xd8, 0xfa, 0x37,
    0xd8, 0x90, 0x3c, 0xe2, 0x89, 0x0a, 0xf5, 0x8b, 0xf4, 0x0a, 0x63, 0x4a, 0xe2, 0x05, 0x87, 0xcb,
    0xc4, 0xd2, 0x7d, 0xa9, 0x87, 0xce, 0xba, 0x41, 0xeb, 0x71, 0x9f, 0x77, 0xcf, 0x53, 0xc1, 0xb7,
    0xc7, 0xf6, 0xe3, 0x01, 0x1f, 0x00, 0x69, 0x59, 0x2a, 0x9c, 0xb6, 0x83, 0xc3, 0xc3, 0x17, 0x78,
    0x81, 0x31, 0xdc, 0xfa, 0x91, 0x56, 0xfd, 0x1d, 0xca, 0xbc, 0xc0, 0x45, 0x06, 0x5f, 0x2c, 0xaf,
    0xfb, 0xa5, 0x17, 0xec, 0x81, 0xc7, 0xc7, 0x05, 0x77, 0xce, 0x41, 0x3e, 0xb7, 0x6b, 0x3a, 0xa8,
    0x4f, 0x91, 0x21, 0x9e, 0x26, 0x82, 0xca, 0x51, 0x4c, 0x36, 0x1e, 0x7b, 0x04, 0xcd, 0xad, 0xda,
    0xaf, 0x35, 0xc4, 0x4a, 0xe3, 0x67, 0x1b, 0x3e, 0x1c, 0xef, 0x4b, 0x44, 0xfb, 0x68, 0x32, 0x73,
    0x7a, 0x68, 0xc8, 0x45, 0x13, 0x52, 0xa3, 0xbd, 0x32, 0x57, 0xb8, 0xb9, 0xf6, 0xc2, 0xcd, 0x04,
    0x9b, 0x1d, 0x1f, 0x1a, 0x66, 0x89, 0xb6, 0xcc, 0x9f, 0x93, 0x09, 0x4f, 0xdc, 0xc6, 0xf2, 0x1a,
    0xdf, 0x76, 0xa8, 0xe1, 0xbf, 0x37, 0x8d, 0x22, 0x43, 0x4d, 0xb2, 0xb8,
};
constexpr size_t kProtectedImageSize = 540;
static_assert(sizeof(img_protected) == kProtectedImageSize,
              "img_protected layout changed; regenerate it (see fuzz/README)");

/* Field-level mutation of a copy of img_out: each std::nullopt field leaves
 * the template byte(s) untouched, keeping the rest of the image well-formed. */
struct CandidateMutation {
    std::optional<uint32_t> magic;
    std::optional<uint32_t> load_addr;
    std::optional<uint16_t> hdr_size;
    std::optional<uint16_t> protect_tlv_size;
    std::optional<uint32_t> img_size;
    std::optional<uint32_t> flags;
    std::optional<uint8_t> ver_major;
    std::optional<uint8_t> ver_minor;
    std::optional<uint16_t> ver_revision;
    std::optional<uint32_t> ver_build;
    std::optional<uint16_t> tlv_magic;
    std::optional<uint16_t> tlv_total;
    std::optional<uint16_t> tlv_type;
    std::optional<uint16_t> tlv_len;
    std::optional<uint8_t> payload_byte_idx;
    uint8_t payload_byte_val;
    std::optional<uint8_t> hash_byte_idx;
    uint8_t hash_byte_val;
    std::optional<uint8_t> keyhash_byte_idx;
    uint8_t keyhash_byte_val;
    std::optional<uint8_t> sig_byte_idx;
    uint8_t sig_byte_val;
};

template <typename T>
void WriteLE(std::array<uint8_t, kTemplateSize> &bytes, size_t off, T value)
{
    memcpy(bytes.data() + off, &value, sizeof(value));
}

std::array<uint8_t, kTemplateSize> BuildCandidateImage(const CandidateMutation &m)
{
    std::array<uint8_t, kTemplateSize> bytes;
    memcpy(bytes.data(), img_out, kTemplateSize);

    if (m.magic) WriteLE(bytes, offsetof(struct image_header, ih_magic), *m.magic);
    if (m.load_addr) WriteLE(bytes, offsetof(struct image_header, ih_load_addr), *m.load_addr);
    if (m.hdr_size) WriteLE(bytes, offsetof(struct image_header, ih_hdr_size), *m.hdr_size);
    if (m.protect_tlv_size) WriteLE(bytes, offsetof(struct image_header, ih_protect_tlv_size), *m.protect_tlv_size);
    if (m.img_size) WriteLE(bytes, offsetof(struct image_header, ih_img_size), *m.img_size);
    if (m.flags) WriteLE(bytes, offsetof(struct image_header, ih_flags), *m.flags);
    if (m.ver_major) WriteLE(bytes, offsetof(struct image_header, ih_ver) + offsetof(struct image_version, iv_major), *m.ver_major);
    if (m.ver_minor) WriteLE(bytes, offsetof(struct image_header, ih_ver) + offsetof(struct image_version, iv_minor), *m.ver_minor);
    if (m.ver_revision) WriteLE(bytes, offsetof(struct image_header, ih_ver) + offsetof(struct image_version, iv_revision), *m.ver_revision);
    if (m.ver_build) WriteLE(bytes, offsetof(struct image_header, ih_ver) + offsetof(struct image_version, iv_build_num), *m.ver_build);

    if (m.tlv_magic) WriteLE(bytes, kTlvInfoOff + offsetof(struct image_tlv_info, it_magic), *m.tlv_magic);
    if (m.tlv_total) WriteLE(bytes, kTlvInfoOff + offsetof(struct image_tlv_info, it_tlv_tot), *m.tlv_total);
    if (m.tlv_type) WriteLE(bytes, kTlvHdrOff + offsetof(struct image_tlv, it_type), *m.tlv_type);
    if (m.tlv_len) WriteLE(bytes, kTlvHdrOff + offsetof(struct image_tlv, it_len), *m.tlv_len);

    if (m.payload_byte_idx) bytes[kPayloadOff + *m.payload_byte_idx] = m.payload_byte_val;
    if (m.hash_byte_idx) bytes[kShaValueOff + *m.hash_byte_idx] = m.hash_byte_val;
    if (m.keyhash_byte_idx) bytes[kKeyhashValueOff + *m.keyhash_byte_idx] = m.keyhash_byte_val;
    if (m.sig_byte_idx) bytes[kSigValueOff + *m.sig_byte_idx] = m.sig_byte_val;

    return bytes;
}

/* Ground truth for the invariant checks. Deliberately compares the produced
 * bytes rather than asking which fields were set: the fuzzer regularly writes
 * a field back to the value it already held (a 1-in-256 chance per byte-sized
 * field), which leaves a perfectly valid image behind. */
bool IsTemplateImage(const std::array<uint8_t, kTemplateSize> &bytes)
{
    return memcmp(bytes.data(), img_out, kTemplateSize) == 0;
}

bool PrimaryMatches(const uint8_t *expected, size_t len)
{
    return AreaMatches(kPrimaryAreaId, expected, len);
}

/* The only images the trusted key ever signed; anything else appearing in the
 * primary slot after a successful boot means MCUboot was talked into running
 * unauthenticated code. */
bool PrimaryIsAuthentic()
{
    return PrimaryMatches(img_out, kTemplateSize) ||
           PrimaryMatches(img_candidate, kTemplateSize) ||
           PrimaryMatches(img_protected, kProtectedImageSize);
}

/* Simulates: a known-good image already running in the primary slot, and a
 * candidate update (fuzzed) staged in the secondary slot. Walks through
 * boot_go() twice (initial swap decision, then a simulated reboot after
 * optionally confirming) the way a real device would during a firmware
 * upgrade, and checks that a bad candidate is never actually booted. */
void InvokeBootUpgradeLifecycle(const CandidateMutation &mutation, bool confirm_after_swap,
                                bool permanent)
{
    flash_sim_init();
    WriteArea(kPrimaryAreaId, img_out, kTemplateSize);

    std::array<uint8_t, kTemplateSize> candidate = BuildCandidateImage(mutation);
    ASSERT_NE(Area(kSecondaryAreaId), nullptr);
    WriteArea(kSecondaryAreaId, candidate.data(), candidate.size());

    bool expected_valid = IsTemplateImage(candidate);
    auto assert_primary_consistent = [&](const char *stage) {
        bool matches_template = PrimaryMatches(img_out, kTemplateSize);
        bool matches_candidate = PrimaryMatches(candidate.data(), kTemplateSize);
        ASSERT_TRUE(matches_template || matches_candidate)
            << stage << ": primary slot holds neither the original nor the candidate image verbatim";
        if (!expected_valid) {
            ASSERT_TRUE(matches_template) << stage << ": an invalid candidate must never be booted";
        }
    };

    ASSERT_EQ(boot_set_pending(permanent ? 1 : 0), 0);

    RunBoot();
    assert_primary_consistent("after first boot_go (swap decision)");

    if (confirm_after_swap) {
        boot_set_confirmed();
    }

    RunBoot();
    assert_primary_consistent("after second boot_go (simulated reboot)");
}
FUZZ_TEST(McuBootSuite, InvokeBootUpgradeLifecycle)
    .WithDomains(
        fuzztest::StructOf<CandidateMutation>(
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint32_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint32_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint16_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint16_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint32_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint32_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint8_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint8_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint16_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint32_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint16_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint16_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint16_t>()),
            fuzztest::OptionalOf(fuzztest::Arbitrary<uint16_t>()),
            fuzztest::OptionalOf(fuzztest::InRange<uint8_t>(0, kPayloadSize - 1)),
            fuzztest::Arbitrary<uint8_t>(),
            fuzztest::OptionalOf(fuzztest::InRange<uint8_t>(0, kShaValueSize - 1)),
            fuzztest::Arbitrary<uint8_t>(),
            fuzztest::OptionalOf(fuzztest::InRange<uint8_t>(0, kKeyhashValueSize - 1)),
            fuzztest::Arbitrary<uint8_t>(),
            fuzztest::OptionalOf(fuzztest::InRange<uint8_t>(0, kSigValueSize - 1)),
            fuzztest::Arbitrary<uint8_t>()),
        fuzztest::Arbitrary<bool>(),
        fuzztest::Arbitrary<bool>())
    .WithSeeds({{CandidateMutation{}, true, false},
                {CandidateMutation{}, false, false},
                {CandidateMutation{}, false, true}});

/* --------------------------------------------------------------------------
 * Interrupted swaps.
 *
 * The build under test uses MCUboot's default upgrade mode, swap-using-
 * scratch, which is by far its most intricate one: each sector of the two
 * slots is rotated through a third "scratch" area, and the progress of that
 * rotation is journalled into the image trailer so a boot that is cut short
 * by a power failure can pick up where it left off. That resume logic
 * (swap_scratch.c's swap_run() plus swap_misc.c's status handling) is where
 * an inconsistency turns into a bricked or - much worse - an unauthenticated
 * device, and it is unreachable unless the harness can actually cut power
 * mid-swap. The flash simulator therefore longjmp()s out of a chosen
 * write/erase, leaving flash exactly as half-written as a real device would.
 * ------------------------------------------------------------------------ */

struct FlashGeometry {
    uint8_t sector_log2; /* 9..16: 512 B .. 64 KB erase sectors */
    uint8_t align_log2;  /* 0..3: 1, 2, 4 or 8 byte write blocks */
    bool needs_erase;    /* false models RRAM/MRAM, which is a separate code path */
};

uint32_t SectorSize(const FlashGeometry &g) { return 1u << g.sector_log2; }
uint32_t WriteAlign(const FlashGeometry &g) { return 1u << g.align_log2; }

/* A slot needing more sector descriptors than MCUboot was built for cannot be
 * swapped; the bootloader is expected to say so rather than misbehave. */
bool GeometryIsSwappable(const FlashGeometry &g)
{
    const struct flash_area *primary = Area(kPrimaryAreaId);
    return primary != nullptr &&
           (primary->fa_size / SectorSize(g)) <= MCUBOOT_MAX_IMG_SECTORS;
}

constexpr FlashGeometry kDefaultGeometry{12, 0, true};

void ProvisionWithGeometry(const FlashGeometry &g)
{
    flash_sim_init_with_geometry(SectorSize(g), WriteAlign(g), g.needs_erase ? 1 : 0);
    WriteArea(kPrimaryAreaId, img_out, kTemplateSize);
    WriteArea(kSecondaryAreaId, img_candidate, kTemplateSize);
}

void ProvisionPrimaryAndCandidate()
{
    ProvisionWithGeometry(kDefaultGeometry);
}

/* Lets the bootloader settle after an interruption, the way a device would
 * once power is restored. Returns true once a boot completes. */
bool BootUntilStable(int max_reboots = 4)
{
    for (int i = 0; i < max_reboots; i++) {
        if (RunBoot().booted) {
            return true;
        }
    }
    return false;
}

struct PowerCutPlan {
    std::vector<uint16_t> cut_ops;
    bool permanent;
    bool torn_writes;
    FlashGeometry geometry;
};

void BootSurvivesPowerCutsDuringSwap(const PowerCutPlan &plan)
{
    ProvisionWithGeometry(plan.geometry);
    boot_set_pending(plan.permanent ? 1 : 0);

    for (uint16_t cut : plan.cut_ops) {
        BootOutcome outcome = RunBoot(cut, plan.torn_writes);
        if (outcome.booted) {
            ASSERT_TRUE(PrimaryIsAuthentic())
                << "booted a primary slot that is none of the signed images";
        }
    }

    bool settled = BootUntilStable();
    if (settled) {
        ASSERT_TRUE(PrimaryIsAuthentic())
            << "settled on a primary slot that is none of the signed images";
    } else {
        ASSERT_FALSE(GeometryIsSwappable(plan.geometry))
            << "bootloader never reached a bootable state after the interrupted swaps";
    }
    ASSERT_EQ(flash_sim_misaligned_ops(), 0u)
        << "MCUboot issued a flash write that violates the device's write block size";
}
FUZZ_TEST(McuBootSuite, BootSurvivesPowerCutsDuringSwap)
    .WithDomains(
        fuzztest::StructOf<PowerCutPlan>(
            fuzztest::VectorOf(fuzztest::InRange<uint16_t>(1, 3000)).WithMaxSize(5),
            fuzztest::Arbitrary<bool>(),
            fuzztest::Arbitrary<bool>(),
            fuzztest::StructOf<FlashGeometry>(fuzztest::InRange<uint8_t>(9, 16),
                                              fuzztest::InRange<uint8_t>(0, 3),
                                              fuzztest::Arbitrary<bool>())))
    .WithSeeds({{PowerCutPlan{{1}, false, false, kDefaultGeometry}},
                {PowerCutPlan{{17, 5}, false, false, kDefaultGeometry}},
                {PowerCutPlan{{40, 40, 40}, true, false, kDefaultGeometry}},
                {PowerCutPlan{{9}, false, true, kDefaultGeometry}},
                {PowerCutPlan{{23}, false, false, FlashGeometry{11, 3, true}}},
                {PowerCutPlan{{23}, false, false, FlashGeometry{11, 3, false}}}});

/* --------------------------------------------------------------------------
 * Whole-device lifecycle.
 *
 * Instead of a fixed two-boot script, drive MCUboot's public API and its
 * on-flash trailers with a fuzzer-chosen sequence of the things that can
 * happen to a real device: staging updates, marking them pending or
 * confirmed, rebooting, losing power, and having stray bytes land in a
 * trailer (a bit-rot or a rogue application writing over its own trailer).
 * The oracle is deliberately narrow and security-relevant: whenever MCUboot
 * reports that it is about to boot, the primary slot must hold one of the two
 * images actually signed with the trusted key.
 * ------------------------------------------------------------------------ */

enum class DeviceOp : uint8_t {
    Reboot,
    RebootWithPowerCut,
    SetPendingTest,
    SetPendingPermanent,
    ConfirmPrimary,
    StageValidCandidate,
    StageProtectedCandidate,
    StageCorruptCandidate,
    EraseSecondary,
    PokePrimaryTrailer,
    PokeSecondaryTrailer,
    PokeScratchTrailer,
};

struct DeviceStep {
    DeviceOp op;
    uint16_t param;
    uint8_t value;
};

/* The trailer (magic, flags and the swap status journal) lives at the end of
 * an area; the last sector comfortably covers it. */
constexpr size_t kTrailerWindow = 4096;

void PokeTrailer(uint8_t area_id, uint16_t offset_from_end, uint8_t value)
{
    const struct flash_area *fa = Area(area_id);
    if (fa == nullptr) {
        return;
    }
    size_t window = std::min<size_t>(kTrailerWindow, fa->fa_size);
    size_t off = fa->fa_off + fa->fa_size - 1 - (offset_from_end % window);
    flash_sim_get_mem()[off] = value;
}

void EraseArea(uint8_t area_id)
{
    const struct flash_area *fa = Area(area_id);
    if (fa != nullptr) {
        memset(flash_sim_get_mem() + fa->fa_off, 0xff, fa->fa_size);
    }
}

void BootNeverRunsUnauthenticatedImage(const FlashGeometry &geometry,
                                       const std::vector<DeviceStep> &steps)
{
    ProvisionWithGeometry(geometry);

    for (const DeviceStep &step : steps) {
        switch (step.op) {
        case DeviceOp::Reboot:
        case DeviceOp::RebootWithPowerCut: {
            unsigned long cut =
                step.op == DeviceOp::RebootWithPowerCut ? (step.param % 512) + 1 : 0;
            if (RunBoot(cut, step.value & 1).booted) {
                ASSERT_TRUE(PrimaryIsAuthentic())
                    << "MCUboot reported a bootable image that was never signed with the trusted key";
            }
            break;
        }
        case DeviceOp::SetPendingTest:
            boot_set_pending(0);
            break;
        case DeviceOp::SetPendingPermanent:
            boot_set_pending(1);
            break;
        case DeviceOp::ConfirmPrimary:
            boot_set_confirmed();
            break;
        case DeviceOp::StageValidCandidate:
            WriteArea(kSecondaryAreaId, img_candidate, kTemplateSize);
            break;
        case DeviceOp::StageProtectedCandidate:
            WriteArea(kSecondaryAreaId, img_protected, kProtectedImageSize);
            break;
        case DeviceOp::StageCorruptCandidate: {
            std::array<uint8_t, kTemplateSize> corrupt;
            memcpy(corrupt.data(), img_candidate, kTemplateSize);
            corrupt[step.param % kTemplateSize] ^= (step.value | 1);
            WriteArea(kSecondaryAreaId, corrupt.data(), corrupt.size());
            break;
        }
        case DeviceOp::EraseSecondary:
            EraseArea(kSecondaryAreaId);
            break;
        case DeviceOp::PokePrimaryTrailer:
            PokeTrailer(kPrimaryAreaId, step.param, step.value);
            break;
        case DeviceOp::PokeSecondaryTrailer:
            PokeTrailer(kSecondaryAreaId, step.param, step.value);
            break;
        case DeviceOp::PokeScratchTrailer:
            PokeTrailer(kScratchAreaId, step.param, step.value);
            break;
        }
    }
}
FUZZ_TEST(McuBootSuite, BootNeverRunsUnauthenticatedImage)
    .WithDomains(fuzztest::StructOf<FlashGeometry>(fuzztest::InRange<uint8_t>(9, 16),
                                                   fuzztest::InRange<uint8_t>(0, 3),
                                                   fuzztest::Arbitrary<bool>()),
                 fuzztest::VectorOf(
                     fuzztest::StructOf<DeviceStep>(
                         fuzztest::ElementOf<DeviceOp>({
                             DeviceOp::Reboot,
                             DeviceOp::RebootWithPowerCut,
                             DeviceOp::SetPendingTest,
                             DeviceOp::SetPendingPermanent,
                             DeviceOp::ConfirmPrimary,
                             DeviceOp::StageValidCandidate,
                             DeviceOp::StageProtectedCandidate,
                             DeviceOp::StageCorruptCandidate,
                             DeviceOp::EraseSecondary,
                             DeviceOp::PokePrimaryTrailer,
                             DeviceOp::PokeSecondaryTrailer,
                             DeviceOp::PokeScratchTrailer,
                         }),
                         fuzztest::Arbitrary<uint16_t>(),
                         fuzztest::Arbitrary<uint8_t>()))
                     .WithMaxSize(12))
    .WithSeeds({
        {kDefaultGeometry,
         {{DeviceOp::SetPendingTest, 0, 0}, {DeviceOp::Reboot, 0, 0}, {DeviceOp::Reboot, 0, 0}}},
        {kDefaultGeometry,
         {{DeviceOp::SetPendingTest, 0, 0},
          {DeviceOp::Reboot, 0, 0},
          {DeviceOp::ConfirmPrimary, 0, 0},
          {DeviceOp::Reboot, 0, 0}}},
        {kDefaultGeometry,
         {{DeviceOp::SetPendingPermanent, 0, 0},
          {DeviceOp::RebootWithPowerCut, 23, 0},
          {DeviceOp::Reboot, 0, 0}}},
        {kDefaultGeometry,
         {{DeviceOp::StageCorruptCandidate, 300, 0xff},
          {DeviceOp::SetPendingTest, 0, 0},
          {DeviceOp::Reboot, 0, 0}}},
        {FlashGeometry{11, 3, false},
         {{DeviceOp::StageProtectedCandidate, 0, 0},
          {DeviceOp::SetPendingPermanent, 0, 0},
          {DeviceOp::Reboot, 0, 0}}},
    });

/* Regular (non-fuzzed) regression tests: run the same lifecycles with two
 * genuinely different, validly-signed images so a swap is actually
 * observable, proving the sequences behave correctly on known-good input
 * rather than only being exercised incidentally by the fuzzer. */

TEST(McuBootSuite, UpgradeConfirmedSwapPersists)
{
    ProvisionPrimaryAndCandidate();
    ASSERT_EQ(boot_set_pending(/*permanent=*/0), 0);

    ASSERT_TRUE(RunBoot().booted);
    ASSERT_TRUE(PrimaryMatches(img_candidate, kTemplateSize))
        << "a valid pending candidate must be swapped into the primary slot";

    ASSERT_EQ(boot_set_confirmed(), 0);

    ASSERT_TRUE(RunBoot().booted);
    EXPECT_TRUE(PrimaryMatches(img_candidate, kTemplateSize))
        << "a confirmed swap must remain in place after a simulated reboot";
}

TEST(McuBootSuite, UpgradeUnconfirmedSwapReverts)
{
    ProvisionPrimaryAndCandidate();
    ASSERT_EQ(boot_set_pending(/*permanent=*/0), 0);

    ASSERT_TRUE(RunBoot().booted);
    ASSERT_TRUE(PrimaryMatches(img_candidate, kTemplateSize))
        << "a valid pending candidate must be swapped into the primary slot";

    ASSERT_TRUE(RunBoot().booted);
    EXPECT_TRUE(PrimaryMatches(img_out, kTemplateSize))
        << "an unconfirmed test-swap must revert to the original image on reboot";
}

TEST(McuBootSuite, PermanentUpgradeNeedsNoConfirmation)
{
    ProvisionPrimaryAndCandidate();
    ASSERT_EQ(boot_set_pending(/*permanent=*/1), 0);

    ASSERT_TRUE(RunBoot().booted);
    ASSERT_TRUE(PrimaryMatches(img_candidate, kTemplateSize));

    ASSERT_TRUE(RunBoot().booted);
    EXPECT_TRUE(PrimaryMatches(img_candidate, kTemplateSize))
        << "a permanent upgrade must not revert on the next boot";
}

/* Drives an image that carries a protected TLV section all the way through
 * verification and a swap, so tlv.c's protected-section iteration runs on an
 * image that actually passes the signature check. */
TEST(McuBootSuite, ProtectedTlvImageIsVerifiedAndSwapped)
{
    flash_sim_init();
    WriteArea(kPrimaryAreaId, img_out, kTemplateSize);
    WriteArea(kSecondaryAreaId, img_protected, kProtectedImageSize);

    ASSERT_EQ(boot_set_pending(/*permanent=*/1), 0);
    ASSERT_TRUE(RunBoot().booted);
    EXPECT_TRUE(PrimaryMatches(img_protected, kProtectedImageSize))
        << "an image with a protected TLV section must verify and swap in";

    ASSERT_TRUE(RunBoot().booted);
    EXPECT_TRUE(PrimaryMatches(img_protected, kProtectedImageSize));
}

/* The protected section is covered by the signature, so tampering with it must
 * be rejected even though the unprotected TLVs are untouched. */
TEST(McuBootSuite, TamperedProtectedTlvIsRejected)
{
    flash_sim_init();
    std::vector<uint8_t> tampered(img_protected, img_protected + kProtectedImageSize);
    /* Security counter value, TLV type 0x50, at offset 200. */
    tampered[200] ^= 0xff;

    WriteArea(kPrimaryAreaId, img_out, kTemplateSize);
    WriteArea(kSecondaryAreaId, tampered.data(), tampered.size());

    ASSERT_EQ(boot_set_pending(/*permanent=*/1), 0);
    RunBoot();
    EXPECT_TRUE(PrimaryMatches(img_out, kTemplateSize))
        << "an image with a tampered protected TLV must never be booted";
}

/* Minimised counterexample produced by BootNeverRunsUnauthenticatedImage.
 *
 * A single stray byte at the end of the primary slot's swap-status journal is
 * enough to make MCUboot believe a swap is in progress. It then reads the
 * size of that swap out of the trailer - which, never having been written, is
 * still erased and so reads back as 0xffffffff - and walks the slot's sector
 * table until it has covered that many bytes. find_last_sector_idx() never
 * compared the index against the number of sectors the slot actually has, so
 * the walk ran off the end of boot_data's sector array (ASan:
 * global-buffer-overflow in flash_sector_get_size, reached via
 * find_swap_count() and swap_run()). */
TEST(McuBootSuite, TrailerSwapSizeIsBoundedBySlotSize)
{
    ProvisionPrimaryAndCandidate();

    const struct flash_area *primary = Area(kPrimaryAreaId);
    ASSERT_NE(primary, nullptr);
    /* Trailer layout, see bootutil_priv.h: the swap size word sits one
     * BOOT_MAX_ALIGN below the swap info byte, directly above the last entry
     * of the swap-status journal. */
    uint32_t swap_size_off = boot_swap_info_off(primary) - BOOT_MAX_ALIGN;
    flash_sim_get_mem()[primary->fa_off + swap_size_off - 1] = 0x01;

    /* The assertion that matters is ASan's; MCUboot is expected to shrug the
     * bogus trailer off and boot the image that is still in the primary slot. */
    EXPECT_TRUE(RunBoot().booted);
    EXPECT_TRUE(PrimaryMatches(img_out, kTemplateSize));
}

/* Walks the power-cut point across the whole swap rather than sampling it
 * randomly, so every stage of the scratch rotation and of its resume path is
 * exercised deterministically on every CI run. */
TEST(McuBootSuite, SwapResumesAfterPowerCutAtAnyStage)
{
    ProvisionPrimaryAndCandidate();
    ASSERT_EQ(boot_set_pending(/*permanent=*/0), 0);
    BootOutcome uninterrupted = RunBoot();
    ASSERT_TRUE(uninterrupted.booted);
    ASSERT_GT(uninterrupted.flash_ops, 1u);

    const unsigned long total_ops = uninterrupted.flash_ops;
    const unsigned long stride = std::max(1UL, total_ops / 64);

    for (unsigned long cut = 1; cut <= total_ops; cut += stride) {
        SCOPED_TRACE(testing::Message()
                     << "power cut at flash op " << cut << " of " << total_ops);

        ProvisionPrimaryAndCandidate();
        ASSERT_EQ(boot_set_pending(/*permanent=*/0), 0);

        BootOutcome interrupted = RunBoot(cut);
        ASSERT_TRUE(interrupted.power_cut) << "the swap finished before reaching this op";

        ASSERT_TRUE(BootUntilStable()) << "the interrupted swap was never resumed";
        EXPECT_TRUE(PrimaryIsAuthentic())
            << "resuming the interrupted swap produced an image nobody signed";
    }
}

/* Same walk, but with the interrupted write partially applied, which is what
 * a flash device does when power drops in the middle of programming a page. */
TEST(McuBootSuite, SwapResumesAfterTornWriteAtAnyStage)
{
    ProvisionPrimaryAndCandidate();
    ASSERT_EQ(boot_set_pending(/*permanent=*/0), 0);
    BootOutcome uninterrupted = RunBoot();
    ASSERT_TRUE(uninterrupted.booted);

    const unsigned long total_ops = uninterrupted.flash_ops;
    const unsigned long stride = std::max(1UL, total_ops / 64);

    for (unsigned long cut = 1; cut <= total_ops; cut += stride) {
        SCOPED_TRACE(testing::Message()
                     << "torn write at flash op " << cut << " of " << total_ops);

        ProvisionPrimaryAndCandidate();
        ASSERT_EQ(boot_set_pending(/*permanent=*/0), 0);

        RunBoot(cut, /*torn=*/true);

        ASSERT_TRUE(BootUntilStable()) << "the torn swap was never resumed";
        EXPECT_TRUE(PrimaryIsAuthentic())
            << "resuming the torn swap produced an image nobody signed";
    }
}

/* --------------------------------------------------------------------------
 * Device geometry.
 *
 * Everything above runs on one hard-coded flash layout: 4 KB erase sectors and
 * a write block size of 1, which is the friendliest case there is. Real parts
 * range from 512 B sectors (256 of them per slot, more than
 * MCUBOOT_MAX_IMG_SECTORS) up to 64 KB, and write block sizes of 2, 4 or 8
 * change the size of every field in the trailer and of every entry in the swap
 * status journal. That arithmetic - boot_trailer_sz(), boot_status_off(), the
 * ALIGN_UP/ALIGN_DOWN in bootutil_area.c - is only ever exercised at its
 * identity values otherwise. FlashGeometry and its helpers are defined further
 * up, next to the lifecycle harnesses that also take a geometry.
 * ------------------------------------------------------------------------ */

void SwapSurvivesAnyFlashGeometry(const FlashGeometry &geometry, bool permanent,
                                  uint16_t cut_op)
{
    ProvisionWithGeometry(geometry);
    boot_set_pending(permanent ? 1 : 0);

    BootOutcome first = RunBoot(cut_op);
    if (first.booted) {
        ASSERT_TRUE(PrimaryIsAuthentic());
    }

    bool settled = BootUntilStable();
    if (settled) {
        ASSERT_TRUE(PrimaryIsAuthentic());
    }
    if (cut_op == 0 && GeometryIsSwappable(geometry)) {
        ASSERT_TRUE(settled) << "an uninterrupted swap on a supported geometry must boot";
    }

    ASSERT_EQ(flash_sim_misaligned_ops(), 0u)
        << "MCUboot issued a flash write that violates the device's write block size";
}
FUZZ_TEST(McuBootSuite, SwapSurvivesAnyFlashGeometry)
    .WithDomains(fuzztest::StructOf<FlashGeometry>(fuzztest::InRange<uint8_t>(9, 16),
                                                   fuzztest::InRange<uint8_t>(0, 3),
                                                   fuzztest::Arbitrary<bool>()),
                 fuzztest::Arbitrary<bool>(),
                 fuzztest::InRange<uint16_t>(0, 3000))
    .WithSeeds({{FlashGeometry{12, 0, true}, false, 0},
                {FlashGeometry{11, 3, true}, false, 0},
                {FlashGeometry{9, 3, true}, false, 0},
                {FlashGeometry{16, 2, true}, true, 0},
                {FlashGeometry{12, 0, false}, false, 0},
                {FlashGeometry{11, 3, false}, true, 0},
                {FlashGeometry{11, 3, true}, false, 37},
                {FlashGeometry{12, 2, false}, false, 37}});

TEST(McuBootSuite, SwapWorksAcrossFlashGeometries)
{
    for (uint8_t sector_log2 = 9; sector_log2 <= 16; ++sector_log2) {
        for (uint8_t align_log2 = 0; align_log2 <= 3; ++align_log2) {
            for (bool needs_erase : {true, false}) {
                FlashGeometry g{sector_log2, align_log2, needs_erase};
                SCOPED_TRACE(testing::Message()
                             << "sector " << SectorSize(g) << " B, write block "
                             << WriteAlign(g) << " B, "
                             << (needs_erase ? "needs erase" : "no explicit erase"));
                ProvisionWithGeometry(g);

                if (!GeometryIsSwappable(g)) {
                    EXPECT_FALSE(RunBoot().booted)
                        << "a slot with more sectors than MCUBOOT_MAX_IMG_SECTORS must be refused";
                    continue;
                }

                ASSERT_EQ(boot_set_pending(/*permanent=*/0), 0);
                ASSERT_TRUE(RunBoot().booted);
                EXPECT_TRUE(PrimaryMatches(img_candidate, kTemplateSize))
                    << "the candidate was not swapped in on this geometry";

                ASSERT_TRUE(RunBoot().booted);
                EXPECT_TRUE(PrimaryMatches(img_out, kTemplateSize))
                    << "the unconfirmed swap did not revert on this geometry";

                EXPECT_EQ(flash_sim_misaligned_ops(), 0u);
            }
        }
    }
}

/* Repeats the power-cut walk on a geometry where the trailer arithmetic is not
 * the identity: 2 KB sectors and 8-byte write blocks, so every status entry is
 * 8 bytes and the trailer fields are padded. */
TEST(McuBootSuite, SwapResumesAfterPowerCutOnAlignedDevice)
{
    const FlashGeometry g{11, 3, true};

    ProvisionWithGeometry(g);
    ASSERT_EQ(boot_set_pending(/*permanent=*/0), 0);
    BootOutcome uninterrupted = RunBoot();
    ASSERT_TRUE(uninterrupted.booted);

    const unsigned long total_ops = uninterrupted.flash_ops;
    const unsigned long stride = std::max(1UL, total_ops / 64);

    for (unsigned long cut = 1; cut <= total_ops; cut += stride) {
        SCOPED_TRACE(testing::Message() << "power cut at flash op " << cut);

        ProvisionWithGeometry(g);
        ASSERT_EQ(boot_set_pending(/*permanent=*/0), 0);
        RunBoot(cut);

        ASSERT_TRUE(BootUntilStable()) << "the interrupted swap was never resumed";
        EXPECT_TRUE(PrimaryIsAuthentic());
        EXPECT_EQ(flash_sim_misaligned_ops(), 0u);
    }
}

/* --------------------------------------------------------------------------
 * TLV area parsing.
 *
 * The images above carry one fixed, well-formed TLV area and no protected TLV
 * section at all, so tlv.c's iterator only ever sees the happy path. Here the
 * whole TLV area is synthesised from a fuzzer-chosen list of entries, with the
 * section headers optionally contradicting them, which is what an attacker
 * controls when they hand the device an update to parse. Nothing built here is
 * expected to boot - the signature will not match - so the invariant is simply
 * that parsing stays in bounds and terminates.
 * ------------------------------------------------------------------------ */

struct TlvEntry {
    uint16_t type;
    uint16_t len;
    uint8_t fill;
};

struct TlvImageSpec {
    std::vector<TlvEntry> protected_tlvs;
    std::vector<TlvEntry> tlvs;
    std::optional<uint16_t> prot_size_override;
    std::optional<uint16_t> tlv_total_override;
    std::optional<uint16_t> prot_magic_override;
    std::optional<uint16_t> tlv_magic_override;
    std::optional<uint32_t> img_size_override;
};

void AppendLE16(std::vector<uint8_t> &out, uint16_t v)
{
    out.push_back(static_cast<uint8_t>(v));
    out.push_back(static_cast<uint8_t>(v >> 8));
}

void AppendTlvSection(std::vector<uint8_t> &out, uint16_t magic,
                      const std::vector<TlvEntry> &entries,
                      std::optional<uint16_t> total_override)
{
    size_t total = sizeof(struct image_tlv_info);
    for (const TlvEntry &e : entries) {
        total += sizeof(struct image_tlv) + e.len;
    }

    AppendLE16(out, magic);
    AppendLE16(out, total_override ? *total_override : static_cast<uint16_t>(total));
    for (const TlvEntry &e : entries) {
        AppendLE16(out, e.type);
        AppendLE16(out, e.len);
        out.insert(out.end(), e.len, e.fill);
    }
}

void BootParsesArbitraryTlvArea(const TlvImageSpec &spec)
{
    std::vector<uint8_t> image(img_out, img_out + kPayloadOff + kPayloadSize);

    std::vector<uint8_t> protected_section;
    if (!spec.protected_tlvs.empty() || spec.prot_size_override) {
        AppendTlvSection(protected_section,
                         spec.prot_magic_override ? *spec.prot_magic_override
                                                  : IMAGE_TLV_PROT_INFO_MAGIC,
                         spec.protected_tlvs, std::nullopt);
    }

    uint16_t prot_size = spec.prot_size_override
                             ? *spec.prot_size_override
                             : static_cast<uint16_t>(protected_section.size());
    memcpy(image.data() + offsetof(struct image_header, ih_protect_tlv_size),
           &prot_size, sizeof(prot_size));
    if (spec.img_size_override) {
        uint32_t img_size = *spec.img_size_override;
        memcpy(image.data() + offsetof(struct image_header, ih_img_size),
               &img_size, sizeof(img_size));
    }

    image.insert(image.end(), protected_section.begin(), protected_section.end());
    AppendTlvSection(image,
                     spec.tlv_magic_override ? *spec.tlv_magic_override : IMAGE_TLV_INFO_MAGIC,
                     spec.tlvs, spec.tlv_total_override);

    flash_sim_init();
    WriteArea(kPrimaryAreaId, image.data(), std::min(image.size(), kMaxImageSize));

    EXPECT_FALSE(RunBoot().booted)
        << "an image whose TLV area was rewritten must not pass verification";
}
FUZZ_TEST(McuBootSuite, BootParsesArbitraryTlvArea)
    .WithDomains(fuzztest::StructOf<TlvImageSpec>(
        fuzztest::VectorOf(fuzztest::StructOf<TlvEntry>(fuzztest::Arbitrary<uint16_t>(),
                                                        fuzztest::InRange<uint16_t>(0, 512),
                                                        fuzztest::Arbitrary<uint8_t>()))
            .WithMaxSize(6),
        fuzztest::VectorOf(fuzztest::StructOf<TlvEntry>(fuzztest::Arbitrary<uint16_t>(),
                                                        fuzztest::InRange<uint16_t>(0, 512),
                                                        fuzztest::Arbitrary<uint8_t>()))
            .WithMaxSize(6),
        fuzztest::OptionalOf(fuzztest::Arbitrary<uint16_t>()),
        fuzztest::OptionalOf(fuzztest::Arbitrary<uint16_t>()),
        fuzztest::OptionalOf(fuzztest::Arbitrary<uint16_t>()),
        fuzztest::OptionalOf(fuzztest::Arbitrary<uint16_t>()),
        fuzztest::OptionalOf(fuzztest::Arbitrary<uint32_t>())))
    .WithSeeds({
        {TlvImageSpec{{}, {{0x10, 32, 0xaa}, {0x01, 32, 0xbb}, {0x20, 256, 0xcc}}, {}, {}, {}, {}, {}}},
        {TlvImageSpec{{{0x50, 4, 0x01}}, {{0x10, 32, 0xaa}, {0x20, 256, 0xcc}}, {}, {}, {}, {}, {}}},
        {TlvImageSpec{{{0x50, 4, 0x01}}, {}, uint16_t{0xffff}, {}, {}, {}, {}}},
    });
