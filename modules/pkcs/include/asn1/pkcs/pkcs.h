/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-pkcs 公共头文件（占位骨架）。
 *
 * 本模块承载 RFC 8017（PKCS#1）、RFC 5208（PKCS#8）、RFC 2986（PKCS#10）
 * 与 RFC 7292（PKCS#12）的描述表与字段访问 API。
 * 占位阶段只提供版本查询与导出宏，具体函数在二期设计后填入。
 */

#ifndef ASN1_PKCS_PKCS_H_INCLUDED
#define ASN1_PKCS_PKCS_H_INCLUDED

/* 由 CMake 从 project(asn1-pkcs VERSION ...) 生成，源码树中不手写版本宏。 */
#include <asn1/pkcs/pkcs_version.h>

#if defined(ASN1_PKCS_STATIC)
#define ASN1_PKCS_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASN1_PKCS_BUILDING_LIBRARY)
#define ASN1_PKCS_API __declspec(dllexport)
#else
#define ASN1_PKCS_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASN1_PKCS_API __attribute__((visibility("default")))
#else
#define ASN1_PKCS_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 返回模块版本字符串；静态存储，调用方不得释放。 */
ASN1_PKCS_API const char *asn1_pkcs_version_string(void);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_PKCS_PKCS_H_INCLUDED */
