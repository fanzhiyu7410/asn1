/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 核心导出宏。共享库构建时导出符号，消费时导入；静态库构建与消费时为空。
 * 语义见 docs/06-构建与移植.md 与 docs/02-C-API规范.md。
 */
#ifndef ASN1_ASN1_EXPORT_H_INCLUDED
#define ASN1_ASN1_EXPORT_H_INCLUDED

#if defined(ASN1_STATIC)
#define ASN1_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASN1_BUILDING_LIBRARY)
#define ASN1_API __declspec(dllexport)
#else
#define ASN1_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASN1_API __attribute__((visibility("default")))
#else
#define ASN1_API
#endif

#endif /* ASN1_ASN1_EXPORT_H_INCLUDED */
