/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * `.asn1` 文本的抽象语法树（一期子集）。
 * 所有节点携带 1 基行列位置，供诊断输出使用。
 */
#ifndef ASN1C_AST_H_INCLUDED
#define ASN1C_AST_H_INCLUDED

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace asn1c {

struct Pos {
    uint32_t line = 0;
    uint32_t column = 0;
};

enum class TagModeSpec { Bare, Explicit, Implicit };

struct TagSpec {
    bool present = false;
    uint32_t number = 0;
    TagModeSpec mode = TagModeSpec::Bare;
    Pos pos;
};

struct NamedNumberAst {
    std::string name;
    int64_t value = 0;
    Pos pos;
};

struct ConstraintBoundAst {
    bool hasValue = false;
    bool isMax = false;
    bool isMin = false;
    int64_t value = 0;
    std::string refName;
    Pos pos;
};

struct ConstraintAst {
    enum class Kind { Range, Size };
    Kind kind = Kind::Range;
    bool single = false;
    ConstraintBoundAst lower;
    ConstraintBoundAst upper;
    Pos pos;
};

struct TypeAst;
struct ValueAst;

struct FieldAst {
    std::string name;
    Pos pos;
    std::unique_ptr<TypeAst> type;
    bool optional = false;
    bool extension = false;
    std::unique_ptr<ValueAst> defaultValue;
};

struct BracePartAst {
    bool hasName = false;
    std::string name;
    bool hasNumber = false;
    uint64_t number = 0;
    Pos pos;
};

struct ValueAst {
    enum class Kind { Boolean, Integer, Oid, String, Reference, Null };
    Kind kind = Kind::Integer;
    bool boolValue = false;
    int64_t intValue = 0;
    std::vector<BracePartAst> parts;
    std::string text;
    Pos pos;
};

struct TypeAst {
    enum class Class {
        Reference,
        Boolean,
        Integer,
        Enumerated,
        BitString,
        OctetString,
        Null,
        ObjectIdentifier,
        Utf8String,
        PrintableString,
        Ia5String,
        VisibleString,
        NumericString,
        TeletexString,
        BmpString,
        UniversalString,
        UtcTime,
        GeneralizedTime,
        Any,
        Sequence,
        Set,
        Choice,
        SequenceOf,
        SetOf
    };

    Class cls = Class::Reference;
    Pos pos;
    std::string refName;
    std::vector<FieldAst> fields;
    std::unique_ptr<TypeAst> element;
    std::vector<ConstraintAst> constraints;
    std::vector<NamedNumberAst> namedNumbers;
    size_t rootNamedCount = 0;
    TagSpec tag;
    bool extensible = false;
};

struct TypeAssignment {
    std::string name;
    Pos pos;
    std::unique_ptr<TypeAst> type;
};

struct ValueAssignment {
    std::string name;
    Pos pos;
    std::unique_ptr<TypeAst> type;
    std::unique_ptr<ValueAst> value;
};

struct ModuleAst {
    std::string name;
    /* 0 = AUTOMATIC，1 = EXPLICIT，2 = IMPLICIT，3 = 未声明。 */
    int tagMode = 3;
    std::vector<TypeAssignment> types;
    std::vector<ValueAssignment> values;
};

} /* namespace asn1c */

#endif /* ASN1C_AST_H_INCLUDED */
