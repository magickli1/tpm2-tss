/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Sys integration test main for wolfTPM fwTPM.
 *
 * Skips TPM state snapshot checks (pre/post dumpstate) that assume the MS
 * simulator PCR capability layout; wolfTPM may return PCR selection sizes the
 * MU layer rejects. Startup + test_invoke + teardown remain.
 */
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>

#define LOGMODULE test
#include "test-common.h"
#include "test.h"
#include "tss2_common.h"
#include "util/aux_util.h"
#include "util/log.h"

int
main(int argc, char *argv[]) {
    TSS2_TEST_SYS_CONTEXT *test_sys_ctx;
    int                    ret;

    UNUSED(argc);
    UNUSED(argv);

    ret = test_sys_setup(&test_sys_ctx);
    if (ret != 0) {
        return ret;
    }

    ret = test_invoke(test_sys_ctx->sys_ctx);
    if (ret != 0 && ret != 77) {
        test_sys_teardown(test_sys_ctx);
        LOG_ERROR("Test returned %08x", ret);
        return EXIT_FAILURE;
    }

    test_sys_teardown(test_sys_ctx);
    return EXIT_SUCCESS;
}
