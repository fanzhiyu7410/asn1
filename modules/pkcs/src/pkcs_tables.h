/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-pkcs 描述表访问（模块私有）。
 *
 * 生成头中的数组符号由模块名派生，同一模块的多张表符号相同；每个编译
 * 单元只包含一张表，函数把内部链接的数组暴露给模块实现，避免符号冲突。
 */

#ifndef ASN1_PKCS_TABLES_H_INCLUDED
#define ASN1_PKCS_TABLES_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

struct pkcs_table_view {
    const uint8_t *data;
    size_t size;
};

pkcs_table_view pkcs8PrivateKeyInfoTable();
pkcs_table_view pkcs8EncryptedPrivateKeyInfoTable();
pkcs_table_view pkcs1RsaPublicKeyTable();
pkcs_table_view pkcs1RsaPrivateKeyTable();
pkcs_table_view pkcs10CertificationRequestTable();
pkcs_table_view pkcs10CertificationRequestInfoTable();
pkcs_table_view pkcs12PfxTable();
pkcs_table_view pkcs12AuthenticatedSafeTable();
pkcs_table_view pkcs12SafeContentsTable();
pkcs_table_view pkcs12CertBagTable();

#endif /* ASN1_PKCS_TABLES_H_INCLUDED */
