/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 测试专用 schema 探针：把内部类型树投影为 C 可见的扁平结构。
 * 仅位于 tests/ 下，不是公共 ABI。
 */
#ifndef ASN1_TESTS_SUPPORT_SCHEMA_PROBE_H_INCLUDED
#define ASN1_TESTS_SUPPORT_SCHEMA_PROBE_H_INCLUDED

#include <asn1/asn1.h>

#include <stddef.h>
#include <stdint.h>

#define ASN1_TEST_MAX_NAME 64
#define ASN1_TEST_MAX_CONSTRAINTS 8
#define ASN1_TEST_MAX_ENUM 16
#define ASN1_TEST_MAX_DECIMAL 64

#ifdef __cplusplus
extern "C" {
#endif

typedef struct asn1_test_bound_info {
    int32_t is_unbounded;
    int64_t value;
    char decimal[ASN1_TEST_MAX_DECIMAL];
    size_t decimal_size;
} asn1_test_bound_info;

typedef struct asn1_test_constraint_info {
    uint32_t kind;
    int32_t lower_unbounded;
    int32_t upper_unbounded;
    asn1_test_bound_info lower;
    asn1_test_bound_info upper;
    uint32_t enum_count;
    int64_t enum_values[ASN1_TEST_MAX_ENUM];
} asn1_test_constraint_info;

typedef struct asn1_test_field_info {
    char name[ASN1_TEST_MAX_NAME];
    uint32_t type_id;
    uint32_t flags;
    size_t default_size;
    uint32_t constraint_count;
} asn1_test_field_info;

typedef struct asn1_test_type_info {
    char name[ASN1_TEST_MAX_NAME];
    uint32_t kind;
    uint32_t tag_class;
    uint32_t tag_number;
    uint32_t tag_mode;
    uint32_t element_type_id;
    uint32_t flags;
    uint32_t field_count;
    uint32_t constraint_count;
} asn1_test_type_info;

uint32_t asn1_test_schema_type_count(const asn1_schema_t *schema);
uint32_t asn1_test_schema_module_tag_mode(const asn1_schema_t *schema);
uint32_t asn1_test_schema_root_type_id(const asn1_schema_t *schema);
int asn1_test_schema_sealed(const asn1_schema_t *schema);

int asn1_test_schema_type_info(const asn1_schema_t *schema, uint32_t type_id,
                               asn1_test_type_info *out);
int asn1_test_schema_field_info(const asn1_schema_t *schema, uint32_t type_id,
                                uint32_t index, asn1_test_field_info *out);
int asn1_test_schema_type_constraint(const asn1_schema_t *schema,
                                     uint32_t type_id, uint32_t index,
                                     asn1_test_constraint_info *out);
int asn1_test_schema_field_constraint(const asn1_schema_t *schema,
                                      uint32_t type_id, uint32_t field_index,
                                      uint32_t index,
                                      asn1_test_constraint_info *out);
const uint8_t *asn1_test_schema_field_default(const asn1_schema_t *schema,
                                              uint32_t type_id,
                                              uint32_t field_index,
                                              size_t *out_size);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_TESTS_SUPPORT_SCHEMA_PROBE_H_INCLUDED */
