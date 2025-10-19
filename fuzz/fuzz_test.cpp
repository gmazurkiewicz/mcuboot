#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"
#include "bootutil/bootutil.h"

void InvokeBootGo()
{
    struct boot_rsp *rsp;
    int res;
    res = boot_go(rsp);
}
FUZZ_TEST(McuBootSuite, InvokeBootGo);
