/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 确定性冒烟用例：反复调用已落地的版本接口，验证无状态残留与稳定返回。
 * 真实 fuzz harness 待 libFuzzer 接入后替换本用例的注册方式。
 */
#include <asn1/asn1.h>

#include "check.h"

int main(void)
{
    unsigned i;

    for (i = 0; i < 1000u; ++i) {
        asn1_version_info_t info;
        info.struct_size = sizeof(info);
        ASN1_TEST_CHECK(asn1_version(&info) == ASN1_OK);
        ASN1_TEST_CHECK(info.major == ASN1_VERSION_MAJOR);
        ASN1_TEST_CHECK(asn1_has_capability(0) == 0);
    }

    return 0;
}
