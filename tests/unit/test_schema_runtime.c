/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * schema 运行时注册路径：描述符校验、类型/字段追加与封存检查。
 */

#include <asn1/asn1.h>

#include <string.h>

#include "check.h"
#include "schema_probe.h"

static asn1_type_desc_t makeType(const char *name, asn1_type_kind_t kind,
                                 asn1_tag_class_t tagClass, uint32_t tagNumber,
                                 asn1_tag_mode_t tagMode,
                                 uint32_t elementTypeId)
{
    asn1_type_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.kind = kind;
    desc.tag_class = tagClass;
    desc.tag_number = tagNumber;
    desc.tag_mode = tagMode;
    desc.element_type_id = elementTypeId;
    return desc;
}

static asn1_field_desc_t makeField(const char *name, uint32_t typeId)
{
    asn1_field_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.type_id = typeId;
    return desc;
}

static asn1_bound_t makeBound(int64_t value, int32_t unbounded)
{
    asn1_bound_t bound;
    memset(&bound, 0, sizeof(bound));
    bound.struct_size = sizeof(bound);
    bound.is_unbounded = unbounded;
    bound.value = value;
    return bound;
}

static asn1_constraint_t makeRange(int64_t lower, int64_t upper)
{
    asn1_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASN1_CONSTRAINT_RANGE;
    constraint.lower = makeBound(lower, 0);
    constraint.upper = makeBound(upper, 0);
    return constraint;
}

static asn1_constraint_t makeSize(int64_t lower, int64_t upper)
{
    asn1_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASN1_CONSTRAINT_SIZE;
    constraint.lower = makeBound(lower, 0);
    constraint.upper = makeBound(upper, 0);
    return constraint;
}

static asn1_constraint_t makeMaxConstraint(void)
{
    asn1_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASN1_CONSTRAINT_MAX;
    constraint.lower = makeBound(0, 0);
    constraint.upper = makeBound(0, 1);
    return constraint;
}

static asn1_constraint_t makeEnumConstraint(const int64_t *values,
                                            uint32_t count)
{
    asn1_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASN1_CONSTRAINT_ENUM;
    constraint.enum_values = values;
    constraint.enum_count = count;
    return constraint;
}

static asn1_constraint_t makeBigintConstraint(const char *lower,
                                              size_t lowerSize,
                                              const char *upper,
                                              size_t upperSize)
{
    asn1_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASN1_CONSTRAINT_BIGINT_RANGE;
    constraint.lower = makeBound(0, 0);
    constraint.lower.decimal = lower;
    constraint.lower.decimal_size = lowerSize;
    constraint.upper = makeBound(0, 0);
    constraint.upper.decimal = upper;
    constraint.upper.decimal_size = upperSize;
    return constraint;
}

static int addTypeOk(asn1_schema_t *schema, const asn1_type_desc_t *desc,
                     uint32_t *outId)
{
    return asn1_schema_add_type(schema, desc, outId) == ASN1_OK;
}

int main(void)
{
    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);
    asn1_ctx_t *ctx = NULL;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);

    /* 入口参数与默认标注方式。 */
    asn1_schema_t *schema = NULL;
    ASN1_TEST_CHECK(asn1_schema_create(NULL, ASN1_TAG_MODE_EXPLICIT,
                                       &schema) == ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_EXPLICIT,
                                       NULL) == ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_schema_create(ctx, (asn1_tag_mode_t)3,
                                       &schema) == ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(schema == NULL);

    /* 正常注册：INTEGER、UTF8String、SEQUENCE。 */
    ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_EXPLICIT,
                                       &schema) == ASN1_OK);
    ASN1_TEST_CHECK(schema != NULL);

    uint32_t idInt = 0;
    uint32_t idText = 0;
    uint32_t idSeq = 0;
    asn1_type_desc_t intDesc = makeType("IntType", ASN1_TYPE_KIND_SIMPLE,
                                        ASN1_TAG_UNIVERSAL, 2,
                                        ASN1_TAG_MODE_DEFAULT, 0);
    asn1_type_desc_t textDesc = makeType("TextType", ASN1_TYPE_KIND_SIMPLE,
                                         ASN1_TAG_UNIVERSAL, 12,
                                         ASN1_TAG_MODE_DEFAULT, 0);
    asn1_type_desc_t seqDesc = makeType("SeqType", ASN1_TYPE_KIND_SEQUENCE,
                                        ASN1_TAG_UNIVERSAL, 0,
                                        ASN1_TAG_MODE_DEFAULT, 0);
    seqDesc.flags = ASN1_TYPE_EXTENSIBLE;
    ASN1_TEST_CHECK(addTypeOk(schema, &intDesc, &idInt));
    ASN1_TEST_CHECK(idInt == 1);
    ASN1_TEST_CHECK(addTypeOk(schema, &textDesc, &idText));
    ASN1_TEST_CHECK(idText == 2);
    ASN1_TEST_CHECK(addTypeOk(schema, &seqDesc, &idSeq));
    ASN1_TEST_CHECK(idSeq == 3);
    ASN1_TEST_CHECK(asn1_test_schema_type_count(schema) == 3);

    /* 类型名重复。 */
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intDesc, &idInt) ==
                    ASN1_E_SCHEMA_TYPE);

    /* 字段表：可选字段 + 默认值 DER TLV。 */
    const uint8_t defaultText[] = {0x0C, 0x03, 'a', 'b', 'c'};
    asn1_field_desc_t fieldInt = makeField("value", 1);
    asn1_field_desc_t fieldText = makeField("label", 2);
    fieldText.flags = ASN1_FIELD_OPTIONAL;
    fieldText.default_value = defaultText;
    fieldText.default_value_size = sizeof(defaultText);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, 3, &fieldInt) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, 3, &fieldText) == ASN1_OK);

    asn1_test_field_info textInfo;
    ASN1_TEST_CHECK(asn1_test_schema_field_info(schema, 3, 1, &textInfo) == 1);
    ASN1_TEST_CHECK(strcmp(textInfo.name, "label") == 0);
    ASN1_TEST_CHECK(textInfo.type_id == 2);
    ASN1_TEST_CHECK(textInfo.flags == ASN1_FIELD_OPTIONAL);
    ASN1_TEST_CHECK(textInfo.default_size == sizeof(defaultText));
    size_t defaultSize = 0;
    const uint8_t *defaultBytes =
        asn1_test_schema_field_default(schema, 3, 1, &defaultSize);
    ASN1_TEST_CHECK(defaultBytes != NULL);
    ASN1_TEST_CHECK(defaultSize == sizeof(defaultText));
    ASN1_TEST_CHECK(memcmp(defaultBytes, defaultText, sizeof(defaultText)) == 0);

    /* 根类型：越界/清除/设置。 */
    ASN1_TEST_CHECK(asn1_schema_set_root(NULL, 1) == ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_schema_set_root(schema, 4) == ASN1_E_SCHEMA_TYPE);
    ASN1_TEST_CHECK(asn1_test_schema_root_type_id(schema) == 0);
    ASN1_TEST_CHECK(asn1_schema_set_root(schema, 2) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_test_schema_root_type_id(schema) == 2);
    ASN1_TEST_CHECK(asn1_schema_set_root(schema, 0) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_test_schema_root_type_id(schema) == 0);
    ASN1_TEST_CHECK(asn1_schema_set_root(schema, 3) == ASN1_OK);

    /* 封存成功且幂等。 */
    ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_test_schema_sealed(schema) == 1);
    ASN1_TEST_CHECK(asn1_test_schema_root_type_id(schema) == 3);
    ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

    /* 封存后不得追加或改根。 */
    ASN1_TEST_CHECK(asn1_schema_set_root(schema, 1) == ASN1_E_INVALID_STATE);
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intDesc, &idInt) ==
                    ASN1_E_INVALID_STATE);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, 3, &fieldInt) ==
                    ASN1_E_INVALID_STATE);
    asn1_schema_destroy(schema);

    /* 类型组合冲突。 */
    ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_EXPLICIT,
                                       &schema) == ASN1_OK);
    asn1_type_desc_t choiceImplicit =
        makeType("BadChoice1", ASN1_TYPE_KIND_CHOICE, ASN1_TAG_UNIVERSAL, 0,
                 ASN1_TAG_MODE_IMPLICIT, 0);
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &choiceImplicit, &idInt) ==
                    ASN1_E_SCHEMA_TYPE);
    asn1_type_desc_t choiceTagged =
        makeType("BadChoice2", ASN1_TYPE_KIND_CHOICE, ASN1_TAG_CONTEXT, 0,
                 ASN1_TAG_MODE_DEFAULT, 0);
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &choiceTagged, &idInt) ==
                    ASN1_E_SCHEMA_TYPE);
    asn1_type_desc_t choiceExplicitUniversal =
        makeType("BadChoice3", ASN1_TYPE_KIND_CHOICE, ASN1_TAG_UNIVERSAL, 0,
                 ASN1_TAG_MODE_EXPLICIT, 0);
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &choiceExplicitUniversal,
                                         &idInt) == ASN1_E_SCHEMA_TYPE);
    asn1_type_desc_t simpleZero =
        makeType("BadSimple", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 0,
                 ASN1_TAG_MODE_DEFAULT, 0);
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &simpleZero, &idInt) ==
                    ASN1_E_SCHEMA_TYPE);
    asn1_type_desc_t universalExplicit =
        makeType("BadUniversalExplicit", ASN1_TYPE_KIND_SIMPLE,
                 ASN1_TAG_UNIVERSAL, 2, ASN1_TAG_MODE_EXPLICIT, 0);
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &universalExplicit, &idInt) ==
                    ASN1_E_SCHEMA_TYPE);

    /* OF 元素引用。 */
    asn1_type_desc_t ofType = makeType("OfType", ASN1_TYPE_KIND_SEQUENCE_OF,
                                       ASN1_TAG_UNIVERSAL, 0,
                                       ASN1_TAG_MODE_DEFAULT, 0);
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &ofType, &idInt) ==
                    ASN1_E_SCHEMA_TYPE);
    ofType.element_type_id = 99;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &ofType, &idInt) ==
                    ASN1_E_SCHEMA_TYPE);
    asn1_type_desc_t simpleWithElement =
        makeType("BadElement", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                 ASN1_TAG_MODE_DEFAULT, 1);
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &simpleWithElement,
                                         &idInt) == ASN1_E_SCHEMA_TYPE);

    /* 描述符结构错误。 */
    asn1_type_desc_t badSize = intDesc;
    badSize.struct_size = sizeof(badSize) - 1;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &badSize, &idInt) ==
                    ASN1_E_INVALID_CONFIG);
    asn1_type_desc_t badFlags = intDesc;
    badFlags.flags = 0x80u;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &badFlags, &idInt) ==
                    ASN1_E_INVALID_CONFIG);
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, NULL, &idInt) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intDesc, NULL) ==
                    ASN1_E_INVALID_ARG);

    /* 约束合法性规则（本轮不按类型求值）。 */
    asn1_constraint_t badRange = makeRange(10, 1);
    asn1_type_desc_t rangeDesc = intDesc;
    rangeDesc.constraints = &badRange;
    rangeDesc.constraint_count = 1;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASN1_E_SCHEMA_CONSTRAINT);

    asn1_constraint_t maxWithLower = makeMaxConstraint();
    maxWithLower.lower = makeBound(5, 0);
    rangeDesc.constraints = &maxWithLower;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASN1_E_SCHEMA_CONSTRAINT);

    asn1_constraint_t maxWithLowerText = makeMaxConstraint();
    maxWithLowerText.lower.decimal = "0";
    maxWithLowerText.lower.decimal_size = 1;
    rangeDesc.constraints = &maxWithLowerText;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASN1_E_SCHEMA_CONSTRAINT);

    asn1_constraint_t emptyEnum = makeEnumConstraint(NULL, 0);
    rangeDesc.constraints = &emptyEnum;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASN1_E_SCHEMA_CONSTRAINT);

    const int64_t duplicateEnumValues[] = {1, 2, 1};
    asn1_constraint_t duplicateEnum =
        makeEnumConstraint(duplicateEnumValues, 3);
    rangeDesc.constraints = &duplicateEnum;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASN1_E_SCHEMA_CONSTRAINT);

    asn1_constraint_t leadingZero =
        makeBigintConstraint("01", 2, "99", 2);
    rangeDesc.constraints = &leadingZero;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASN1_E_SCHEMA_CONSTRAINT);

    asn1_constraint_t negativeZero =
        makeBigintConstraint("-0", 2, "9", 1);
    rangeDesc.constraints = &negativeZero;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASN1_E_SCHEMA_CONSTRAINT);

    asn1_constraint_t reversedBigint =
        makeBigintConstraint("10", 2, "9", 1);
    rangeDesc.constraints = &reversedBigint;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASN1_E_SCHEMA_CONSTRAINT);

    asn1_constraint_t noDecimalBigint = makeMaxConstraint();
    noDecimalBigint.kind = ASN1_CONSTRAINT_BIGINT_RANGE;
    rangeDesc.constraints = &noDecimalBigint;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASN1_E_SCHEMA_CONSTRAINT);

    asn1_constraint_t negativeSize = makeSize(-1, 5);
    rangeDesc.constraints = &negativeSize;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASN1_E_SCHEMA_CONSTRAINT);

    asn1_schema_destroy(schema);

    /* 合法约束：MAX、ENUM、BIGINT 数值比较、SIZE 单位中立存储。 */
    ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_EXPLICIT,
                                       &schema) == ASN1_OK);
    const int64_t enumValues[] = {10, 20, 30};
    asn1_constraint_t constraints[4];
    constraints[0] = makeMaxConstraint();
    constraints[1] = makeEnumConstraint(enumValues, 3);
    constraints[2] = makeBigintConstraint("-100", 4, "100", 3);
    constraints[3] = makeSize(0, 10);
    asn1_type_desc_t constrainedInt = intDesc;
    constrainedInt.name = "ConstrainedInt";
    constrainedInt.constraints = constraints;
    constrainedInt.constraint_count = 4;
    ASN1_TEST_CHECK(addTypeOk(schema, &constrainedInt, &idInt));

    /* SIZE 对字符串按字节数、对 OF 按元素数；本轮只存储单位无关的区间。 */
    asn1_type_desc_t sizedText = textDesc;
    sizedText.name = "SizedText";
    sizedText.constraints = &constraints[3];
    sizedText.constraint_count = 1;
    uint32_t idSizedText = 0;
    ASN1_TEST_CHECK(addTypeOk(schema, &sizedText, &idSizedText));
    asn1_type_desc_t sizedOf = makeType("SizedSeqOf", ASN1_TYPE_KIND_SEQUENCE_OF,
                                        ASN1_TAG_UNIVERSAL, 0,
                                        ASN1_TAG_MODE_DEFAULT, 2);
    sizedOf.constraints = &constraints[3];
    sizedOf.constraint_count = 1;
    uint32_t idSizedOf = 0;
    ASN1_TEST_CHECK(addTypeOk(schema, &sizedOf, &idSizedOf));
    ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

    asn1_test_constraint_info info;
    ASN1_TEST_CHECK(asn1_test_schema_type_constraint(schema, 1, 1,
                                                     &info) == 1);
    ASN1_TEST_CHECK(info.kind == ASN1_CONSTRAINT_ENUM);
    ASN1_TEST_CHECK(info.enum_count == 3);
    ASN1_TEST_CHECK(info.enum_values[0] == 10);
    ASN1_TEST_CHECK(asn1_test_schema_type_constraint(schema, 1, 2,
                                                     &info) == 1);
    ASN1_TEST_CHECK(info.kind == ASN1_CONSTRAINT_BIGINT_RANGE);
    ASN1_TEST_CHECK(info.lower.decimal_size == 4);
    ASN1_TEST_CHECK(strcmp(info.lower.decimal, "-100") == 0);
    ASN1_TEST_CHECK(info.upper.decimal_size == 3);
    ASN1_TEST_CHECK(strcmp(info.upper.decimal, "100") == 0);
    ASN1_TEST_CHECK(asn1_test_schema_type_constraint(schema, 3, 0,
                                                     &info) == 1);
    ASN1_TEST_CHECK(info.lower.value == 0);
    ASN1_TEST_CHECK(info.upper.value == 10);
    asn1_schema_destroy(schema);

    /* 字段错误。 */
    ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_EXPLICIT,
                                       &schema) == ASN1_OK);
    ASN1_TEST_CHECK(addTypeOk(schema, &intDesc, &idInt));
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, 0, &fieldInt) ==
                    ASN1_E_SCHEMA_TYPE);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, 1, NULL) ==
                    ASN1_E_INVALID_ARG);
    asn1_field_desc_t badTypeId = makeField("badType", 0);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, 1, &badTypeId) ==
                    ASN1_E_SCHEMA_TYPE);
    asn1_field_desc_t badFieldFlags = makeField("badFlags", 1);
    badFieldFlags.flags = 0x80u;
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, 1, &badFieldFlags) ==
                    ASN1_E_INVALID_CONFIG);
    asn1_field_desc_t nullDefault = makeField("nullDefault", 1);
    nullDefault.default_value_size = 3;
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, 1, &nullDefault) ==
                    ASN1_E_SCHEMA_DEFAULT);
    asn1_field_desc_t shortDefault = makeField("shortDefault", 1);
    const uint8_t truncated[] = {0x0C, 0x05, 'a'};
    shortDefault.default_value = truncated;
    shortDefault.default_value_size = sizeof(truncated);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, 1, &shortDefault) ==
                    ASN1_E_SCHEMA_DEFAULT);
    asn1_field_desc_t nonCanonical = makeField("nonCanonical", 1);
    const uint8_t longLength[] = {0x0C, 0x81, 0x03, 'a', 'b', 'c'};
    nonCanonical.default_value = longLength;
    nonCanonical.default_value_size = sizeof(longLength);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, 1, &nonCanonical) ==
                    ASN1_E_SCHEMA_DEFAULT);
    asn1_field_desc_t badFieldSize = makeField("badSize", 1);
    badFieldSize.struct_size = sizeof(badFieldSize) - 1;
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, 1, &badFieldSize) ==
                    ASN1_E_INVALID_CONFIG);
    asn1_schema_destroy(schema);

    /* CHOICE 分支不得可选/带默认/扩展；OF 不得有字段。 */
    ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_EXPLICIT,
                                       &schema) == ASN1_OK);
    ASN1_TEST_CHECK(addTypeOk(schema, &intDesc, &idInt));
    asn1_type_desc_t choiceDefault = makeType(
        "ChoiceDefault", ASN1_TYPE_KIND_CHOICE, ASN1_TAG_UNIVERSAL, 0,
        ASN1_TAG_MODE_DEFAULT, 0);
    uint32_t idChoice = 0;
    ASN1_TEST_CHECK(addTypeOk(schema, &choiceDefault, &idChoice));
    asn1_field_desc_t optionalBranch = makeField("branch", 1);
    optionalBranch.flags = ASN1_FIELD_OPTIONAL;
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idChoice,
                                          &optionalBranch) ==
                    ASN1_E_SCHEMA_FIELD);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idChoice, &fieldInt) ==
                    ASN1_OK);
    ofType.element_type_id = 1;
    ofType.name = "SeqOf";
    uint32_t idOf = 0;
    ASN1_TEST_CHECK(addTypeOk(schema, &ofType, &idOf));
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idOf, &fieldInt) ==
                    ASN1_E_SCHEMA_FIELD);
    asn1_field_desc_t duplicate = makeField("branch", 1);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idChoice, &duplicate) ==
                    ASN1_OK);
    asn1_field_desc_t duplicateAgain = makeField("branch", 1);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idChoice,
                                          &duplicateAgain) ==
                    ASN1_E_SCHEMA_FIELD);
    asn1_schema_destroy(schema);

    /* 封存期冲突检查：SET 重复标签、SEQUENCE 可选后继冲突、CHOICE 分支冲突。 */
    ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_EXPLICIT,
                                       &schema) == ASN1_OK);
    ASN1_TEST_CHECK(addTypeOk(schema, &intDesc, &idInt));
    asn1_type_desc_t setDesc = makeType("SetDup", ASN1_TYPE_KIND_SET,
                                        ASN1_TAG_UNIVERSAL, 0,
                                        ASN1_TAG_MODE_DEFAULT, 0);
    uint32_t idSet = 0;
    ASN1_TEST_CHECK(addTypeOk(schema, &setDesc, &idSet));
    asn1_field_desc_t setA = makeField("a", 1);
    asn1_field_desc_t setB = makeField("b", 1);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idSet, &setA) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idSet, &setB) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_E_SCHEMA_TYPE);
    asn1_schema_destroy(schema);

    ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_EXPLICIT,
                                       &schema) == ASN1_OK);
    ASN1_TEST_CHECK(addTypeOk(schema, &intDesc, &idInt));
    seqDesc.name = "SeqOptionalDup";
    uint32_t idSeq2 = 0;
    ASN1_TEST_CHECK(addTypeOk(schema, &seqDesc, &idSeq2));
    asn1_field_desc_t seqA = makeField("a", 1);
    seqA.flags = ASN1_FIELD_OPTIONAL;
    asn1_field_desc_t seqB = makeField("b", 1);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idSeq2, &seqA) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idSeq2, &seqB) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_E_SCHEMA_TYPE);
    asn1_schema_destroy(schema);

    ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_EXPLICIT,
                                       &schema) == ASN1_OK);
    ASN1_TEST_CHECK(addTypeOk(schema, &intDesc, &idInt));
    choiceDefault.name = "ChoiceDup";
    ASN1_TEST_CHECK(addTypeOk(schema, &choiceDefault, &idChoice));
    asn1_field_desc_t branchA = makeField("a", 1);
    asn1_field_desc_t branchB = makeField("b", 1);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idChoice, &branchA) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idChoice, &branchB) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_E_SCHEMA_TYPE);
    asn1_schema_destroy(schema);

    /* 合法的 SET 与约束存储。 */
    ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_EXPLICIT,
                                       &schema) == ASN1_OK);
    asn1_constraint_t range = makeRange(-128, 127);
    asn1_type_desc_t intRange = intDesc;
    intRange.constraints = &range;
    intRange.constraint_count = 1;
    ASN1_TEST_CHECK(addTypeOk(schema, &intRange, &idInt));
    asn1_type_desc_t boolDesc = makeType("BoolType", ASN1_TYPE_KIND_SIMPLE,
                                         ASN1_TAG_UNIVERSAL, 1,
                                         ASN1_TAG_MODE_DEFAULT, 0);
    uint32_t idBool = 0;
    ASN1_TEST_CHECK(addTypeOk(schema, &boolDesc, &idBool));
    setDesc.name = "SetOk";
    ASN1_TEST_CHECK(addTypeOk(schema, &setDesc, &idSet));
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idSet, &setA) == ASN1_OK);
    asn1_field_desc_t setB2 = makeField("b", idBool);
    ASN1_TEST_CHECK(asn1_schema_add_field(schema, idSet, &setB2) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

    asn1_test_constraint_info rangeInfo;
    ASN1_TEST_CHECK(asn1_test_schema_type_constraint(schema, 1, 0,
                                                     &rangeInfo) == 1);
    ASN1_TEST_CHECK(rangeInfo.kind == ASN1_CONSTRAINT_RANGE);
    ASN1_TEST_CHECK(rangeInfo.lower.value == -128);
    ASN1_TEST_CHECK(rangeInfo.upper.value == 127);
    ASN1_TEST_CHECK(rangeInfo.enum_count == 0);
    asn1_schema_destroy(schema);

    /* destroy(NULL) 空操作；销毁上下文时兜底回收未销毁 schema。 */
    asn1_schema_destroy(NULL);
    ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                       &schema) == ASN1_OK);
    asn1_ctx_destroy(ctx);
    return 0;
}
