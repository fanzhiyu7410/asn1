/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 验证测试辅助头与生成版本宏可用。
 */
#include <asn1/asn1.h>

#include "check.h"

int main(void)
{
    ASN1_TEST_CHECK(ASN1_VERSION_STRING[0] != '\0');
    ASN1_TEST_CHECK(ASN1_VERSION_ENCODED ==
                    ((ASN1_VERSION_MAJOR << 16) | (ASN1_VERSION_MINOR << 8) |
                     ASN1_VERSION_PATCH));
    return 0;
}
