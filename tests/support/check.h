/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 无第三方依赖的测试断言辅助。断言失败时输出位置并返回 1。
 */
#ifndef ASN1_TESTS_SUPPORT_CHECK_H_INCLUDED
#define ASN1_TESTS_SUPPORT_CHECK_H_INCLUDED

#include <stdio.h>

#define ASN1_TEST_CHECK(condition)                                            \
    do {                                                                      \
        if (!(condition)) {                                                   \
            fprintf(stderr, "%s:%d: check failed: %s\n",                     \
                    __FILE__, __LINE__, #condition);                          \
            return 1;                                                         \
        }                                                                     \
    } while (0)

#endif /* ASN1_TESTS_SUPPORT_CHECK_H_INCLUDED */
