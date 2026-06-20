/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright (c) 2026, tpm2-tss contributors
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../helper/cmocka_all.h"
#include "tpm_json_deserialize.h"
#include "tpm_json_serialize.h"
#include "tss2_common.h"
#include "tss2_tpm2_types.h"

#define LOGMODULE tests
#include "util/log.h"

#define CHECK_JSON_SIMPLE(TYPE, SRC, DST)                                                          \
    {                                                                                              \
        TYPE         out;                                                                          \
        TSS2_RC      rc;                                                                           \
        json_object *jso = json_tokener_parse((SRC));                                              \
        assert_non_null(jso);                                                                      \
        rc = ifapi_json_##TYPE##_deserialize(jso, &out);                                         \
        assert_int_equal(rc, TSS2_RC_SUCCESS);                                                     \
        json_object_put(jso);                                                                      \
        jso = NULL;                                                                                \
        rc = ifapi_json_##TYPE##_serialize(out, &jso);                                             \
        assert_int_equal(rc, TSS2_RC_SUCCESS);                                                     \
        assert_non_null(jso);                                                                      \
        const char *jso_string = json_object_to_json_string(jso);                                  \
        assert_string_equal(jso_string, (DST));                                                    \
        json_object_put(jso);                                                                      \
    }

static void
check_pqc_algorithm_ids(void **state)
{
    (void)state;

    CHECK_JSON_SIMPLE(TPMI_ALG_PUBLIC, "\"mlkem\"", "\"mlkem\"");
    CHECK_JSON_SIMPLE(TPMI_ALG_PUBLIC, "\"MLKEM\"", "\"mlkem\"");
    CHECK_JSON_SIMPLE(TPMI_ALG_PUBLIC, "\"mldsa\"", "\"mldsa\"");
    CHECK_JSON_SIMPLE(TPMI_ALG_PUBLIC, "\"hash_mldsa\"", "\"hash_mldsa\"");

    CHECK_JSON_SIMPLE(TPMI_ALG_SIG_SCHEME, "\"mldsa\"", "\"mldsa\"");
    CHECK_JSON_SIMPLE(TPMI_ALG_SIG_SCHEME, "\"hash_mldsa\"", "\"hash_mldsa\"");
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(check_pqc_algorithm_ids),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
