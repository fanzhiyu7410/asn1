/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

#include "semantic.h"

#include <algorithm>
#include <map>
#include <set>
#include <utility>

namespace asn1c {
namespace {

constexpr uint32_t kTypeFlagExtensible = 1u;
constexpr uint16_t kFieldFlagOptional = 1u;
constexpr uint16_t kFieldFlagExtension = 2u;

constexpr uint8_t kTagModeDefault = 0;
constexpr uint8_t kTagModeExplicit = 1;
constexpr uint8_t kTagModeImplicit = 2;
constexpr uint8_t kTagClassUniversal = 0;
constexpr uint8_t kTagClassContext = 2;

uint32_t universalTagForClass(TypeAst::Class cls) noexcept
{
    switch (cls) {
    case TypeAst::Class::Boolean:
        return 1;
    case TypeAst::Class::Integer:
        return 2;
    case TypeAst::Class::Enumerated:
        return 10;
    case TypeAst::Class::BitString:
        return 3;
    case TypeAst::Class::OctetString:
        return 4;
    case TypeAst::Class::Null:
        return 5;
    case TypeAst::Class::ObjectIdentifier:
        return 6;
    case TypeAst::Class::Utf8String:
        return 12;
    case TypeAst::Class::NumericString:
        return 18;
    case TypeAst::Class::PrintableString:
        return 19;
    case TypeAst::Class::TeletexString:
        return 20;
    case TypeAst::Class::Ia5String:
        return 22;
    case TypeAst::Class::UtcTime:
        return 23;
    case TypeAst::Class::GeneralizedTime:
        return 24;
    case TypeAst::Class::VisibleString:
        return 26;
    case TypeAst::Class::UniversalString:
        return 28;
    case TypeAst::Class::BmpString:
        return 30;
    default:
        return 0;
    }
}

void appendTag(std::vector<uint8_t> &out, uint8_t tagClass, uint32_t number,
               bool constructed)
{
    uint8_t first = static_cast<uint8_t>((tagClass & 0x03u) << 6);
    if (constructed) {
        first = static_cast<uint8_t>(first | 0x20u);
    }
    if (number < 31) {
        first = static_cast<uint8_t>(first | static_cast<uint8_t>(number));
        out.push_back(first);
        return;
    }
    out.push_back(static_cast<uint8_t>(first | 0x1Fu));
    uint32_t value = number;
    uint8_t parts[5];
    uint32_t count = 0;
    parts[count++] = static_cast<uint8_t>(value & 0x7Fu);
    value >>= 7;
    while (value != 0) {
        parts[count++] = static_cast<uint8_t>((value & 0x7Fu) | 0x80u);
        value >>= 7;
    }
    while (count > 0) {
        --count;
        out.push_back(parts[count]);
    }
}

void appendLength(std::vector<uint8_t> &out, size_t length)
{
    if (length < 128) {
        out.push_back(static_cast<uint8_t>(length));
        return;
    }
    uint8_t bytes[8];
    uint32_t count = 0;
    size_t value = length;
    while (value != 0) {
        bytes[count++] = static_cast<uint8_t>(value & 0xFFu);
        value >>= 8;
    }
    out.push_back(static_cast<uint8_t>(0x80u | count));
    while (count > 0) {
        --count;
        out.push_back(bytes[count]);
    }
}

std::vector<uint8_t> encodeIntegerContent(int64_t value)
{
    std::vector<uint8_t> little;
    int64_t current = value;
    while (true) {
        little.push_back(static_cast<uint8_t>(
            static_cast<uint64_t>(current) & UINT64_C(0xFF)));
        current >>= 8;
        const uint8_t last = little.back();
        if ((current == 0 && (last & 0x80u) == 0) ||
            (current == -1 && (last & 0x80u) != 0)) {
            break;
        }
    }
    std::reverse(little.begin(), little.end());
    return little;
}

bool encodeOidContent(const std::vector<uint64_t> &arcs,
                      std::vector<uint8_t> &out)
{
    if (arcs.size() < 2 || arcs[0] > 2) {
        return false;
    }
    std::vector<uint64_t> numbers;
    numbers.push_back(arcs[0] * 40u + arcs[1]);
    for (size_t i = 2; i < arcs.size(); ++i) {
        numbers.push_back(arcs[i]);
    }
    for (uint64_t number : numbers) {
        uint8_t chunks[10];
        uint32_t count = 0;
        chunks[count++] = static_cast<uint8_t>(number & 0x7Fu);
        number >>= 7;
        while (number != 0) {
            chunks[count++] =
                static_cast<uint8_t>((number & 0x7Fu) | 0x80u);
            number >>= 7;
        }
        while (count > 0) {
            --count;
            out.push_back(chunks[count]);
        }
    }
    return true;
}

struct TagId {
    uint32_t tagClass = 0;
    uint32_t tagNumber = 0;
};

bool collectTags(const TypeNode *node, std::vector<TagId> &out,
                 uint32_t depth)
{
    if (node == nullptr || depth > 32) {
        return false;
    }
    if (node->kind == TypeKind::Any) {
        if (node->tagMode == kTagModeExplicit) {
            out.push_back(TagId{node->tagClass, node->tagNumber});
            return true;
        }
        return false;
    }
    if (node->kind == TypeKind::Choice) {
        if (node->tagMode == kTagModeExplicit) {
            out.push_back(TagId{node->tagClass, node->tagNumber});
            return true;
        }
        if (node->tagMode != kTagModeDefault) {
            return false;
        }
        bool any = false;
        for (const Field &field : node->fields) {
            std::vector<TagId> branch;
            if (!collectTags(field.type, branch, depth + 1u)) {
                return false;
            }
            for (const TagId &tag : branch) {
                out.push_back(tag);
            }
            any = true;
        }
        return any;
    }
    uint32_t tagClass = node->tagClass;
    uint32_t tagNumber = node->tagNumber;
    if (tagClass == kTagClassUniversal && tagNumber == 0) {
        if (node->kind == TypeKind::Simple ||
            node->kind == TypeKind::Any) {
            return false;
        }
        tagNumber = (node->kind == TypeKind::Sequence ||
                     node->kind == TypeKind::SequenceOf)
                        ? 16u
                        : 17u;
    }
    out.push_back(TagId{tagClass, tagNumber});
    return true;
}

class Analyzer {
public:
    Analyzer(const std::string &file, const ModuleAst &module,
             Diagnostics &diagnostics, SchemaModel *model)
        : file_(file), module_(module), diagnostics_(diagnostics),
          model_(model)
    {
    }

    void run(const std::string &rootName)
    {
        model_->moduleTagMode = static_cast<uint32_t>(module_.tagMode);
        registerNamedTypes();
        processValues();
        for (size_t i = 0; i < model_->named.size(); ++i) {
            resolveNamed(static_cast<uint32_t>(i));
        }
        checkNamedValues();
        checkStructure();
        assignIds();
        if (!rootName.empty()) {
            std::map<std::string, uint32_t>::const_iterator it =
                typeIndex_.find(rootName);
            if (it == typeIndex_.end()) {
                diagnostics_.add(file_, 0, 0, Severity::Error,
                                 DiagCode::UndefinedType,
                                 "root type '" + rootName +
                                     "' is not defined");
            } else {
                model_->rootTypeId = resolveNamed(it->second)->id;
            }
        }
    }

private:
    struct ValueSymbol {
        bool isOid = false;
        bool isInteger = false;
        std::vector<uint64_t> oid;
        int64_t integer = 0;
    };

    struct BoundValue {
        bool unbounded = false;
        int64_t value = 0;
    };

    enum class ValueClass { Oid, Integer, Other, Undefined };

    void error(const Pos &pos, DiagCode code, const std::string &message)
    {
        diagnostics_.add(file_, pos.line, pos.column, Severity::Error, code,
                         message);
    }

    void registerNamedTypes()
    {
        for (const TypeAssignment &assignment : module_.types) {
            std::map<std::string, uint32_t>::const_iterator existing =
                typeIndex_.find(assignment.name);
            if (existing != typeIndex_.end()) {
                error(assignment.pos, DiagCode::DuplicateType,
                      "duplicate type name '" + assignment.name + "'");
                continue;
            }
            std::unique_ptr<TypeNode> node = std::make_unique<TypeNode>();
            node->name = assignment.name;
            node->synthetic = false;
            model_->nodes.push_back(std::move(node));
            TypeNode *pointer = model_->nodes.back().get();
            const uint32_t index =
                static_cast<uint32_t>(model_->named.size());
            model_->named.push_back(pointer);
            namedAsts_.push_back(assignment.type.get());
            namedState_.push_back(0);
            typeIndex_[assignment.name] = index;
        }
    }

    ValueClass classifyValueType(const TypeAst *ast) const
    {
        const TypeAst *current = ast;
        for (uint32_t depth = 0; depth < 32 && current != nullptr; ++depth) {
            if (current->cls == TypeAst::Class::ObjectIdentifier) {
                return ValueClass::Oid;
            }
            if (current->cls == TypeAst::Class::Integer) {
                return ValueClass::Integer;
            }
            if (current->cls != TypeAst::Class::Reference) {
                return ValueClass::Other;
            }
            std::map<std::string, uint32_t>::const_iterator it =
                typeIndex_.find(current->refName);
            if (it == typeIndex_.end()) {
                return ValueClass::Undefined;
            }
            current = namedAsts_[it->second];
        }
        return ValueClass::Other;
    }

    void processValues()
    {
        for (const ValueAssignment &assignment : module_.values) {
            ValueClass valueClass =
                classifyValueType(assignment.type.get());
            if (valueClass == ValueClass::Undefined) {
                /* 单模块内所有类型均已登记；值赋值的类型仍不存在时，
                 * 通常来自被裁剪的信息对象类（如 ATTRIBUTE），按不支持构造报出。 */
                error(assignment.type->pos,
                      DiagCode::UnsupportedConstruct,
                      "information object/object set or CLASS-based type "
                      "reference '" +
                          assignment.type->refName +
                          "' is not supported");
                continue;
            }
            ValueSymbol symbol;
            if (assignment.value->kind == ValueAst::Kind::Oid) {
                if (!evaluateOid(*assignment.value, symbol.oid,
                                 DiagCode::ConstraintInvalid)) {
                    continue;
                }
                symbol.isOid = true;
            } else if (assignment.value->kind == ValueAst::Kind::Integer) {
                symbol.isInteger = true;
                symbol.integer = assignment.value->intValue;
            } else if (assignment.value->kind == ValueAst::Kind::Reference) {
                if (!lookupInteger(assignment.value->text,
                                   symbol.integer)) {
                    error(assignment.value->pos, DiagCode::UndefinedType,
                          "undefined integer value '" +
                              assignment.value->text + "'");
                    continue;
                }
                symbol.isInteger = true;
            }
            values_[assignment.name] = symbol;
        }
    }

    bool lookupInteger(const std::string &name, int64_t &out) const
    {
        std::map<std::string, ValueSymbol>::const_iterator it =
            values_.find(name);
        if (it == values_.end() || !it->second.isInteger) {
            return false;
        }
        out = it->second.integer;
        return true;
    }

    bool evaluateOid(const ValueAst &value, std::vector<uint64_t> &arcs,
                     DiagCode unresolvedCode)
    {
        for (const BracePartAst &part : value.parts) {
            if (part.hasNumber) {
                arcs.push_back(part.number);
                continue;
            }
            std::map<std::string, ValueSymbol>::const_iterator it =
                values_.find(part.name);
            if (it == values_.end() || !it->second.isOid) {
                error(part.pos, unresolvedCode,
                      "undefined OBJECT IDENTIFIER value '" + part.name +
                          "'");
                return false;
            }
            for (uint64_t arc : it->second.oid) {
                arcs.push_back(arc);
            }
        }
        return true;
    }

    TypeNode *resolveNamed(uint32_t index)
    {
        TypeNode *node = model_->named[index];
        if (namedState_[index] == 2) {
            return node;
        }
        if (namedState_[index] == 1) {
            error(namedAsts_[index]->pos, DiagCode::UndefinedType,
                  "cyclic type alias involving '" + node->name + "'");
            return node;
        }
        namedState_[index] = 1;
        fillNode(node, *namedAsts_[index]);
        namedState_[index] = 2;
        return node;
    }

    TypeNode *ensureNamed(const std::string &name, const Pos &pos)
    {
        std::map<std::string, uint32_t>::const_iterator it =
            typeIndex_.find(name);
        if (it == typeIndex_.end()) {
            error(pos, DiagCode::UndefinedType, "undefined type '" + name +
                                                     "'");
            return nullptr;
        }
        return resolveNamed(it->second);
    }

    TypeNode *newSynthetic(const std::string &hint)
    {
        std::unique_ptr<TypeNode> node = std::make_unique<TypeNode>();
        node->synthetic = true;
        node->name = "$" + sanitize(hint) + "_" +
                     std::to_string(syntheticCounter_);
        ++syntheticCounter_;
        model_->nodes.push_back(std::move(node));
        TypeNode *pointer = model_->nodes.back().get();
        model_->synthetic.push_back(pointer);
        return pointer;
    }

    static std::string sanitize(const std::string &hint)
    {
        std::string result;
        for (char c : hint) {
            const bool keep = (c >= 'A' && c <= 'Z') ||
                              (c >= 'a' && c <= 'z') ||
                              (c >= '0' && c <= '9');
            result.push_back(keep ? c : '_');
        }
        if (result.empty()) {
            result = "anon";
        }
        return result;
    }

    TypeNode *sharedAny()
    {
        if (model_->anyNode == nullptr) {
            TypeNode *node = newSynthetic("ANY");
            node->kind = TypeKind::Any;
            node->tagMode = kTagModeDefault;
            node->tagClass = kTagClassUniversal;
            node->tagNumber = 0;
            node->baseTagNumber = 0;
            node->flags = 0;
            model_->anyNode = node;
        }
        return model_->anyNode;
    }

    static void copyNode(const TypeNode *source, TypeNode *target)
    {
        if (source == target) {
            return;
        }
        target->kind = source->kind;
        target->tagMode = source->tagMode;
        target->tagClass = source->tagClass;
        target->tagNumber = source->tagNumber;
        target->baseTagNumber = source->baseTagNumber;
        target->flags = source->flags;
        target->element = source->element;
        target->fields = source->fields;
        target->constraints = source->constraints;
        target->namedValues = source->namedValues;
    }

    bool applyTag(TypeNode *node, const TagSpec &tag)
    {
        uint8_t mode = kTagModeDefault;
        if (tag.mode == TagModeSpec::Explicit) {
            mode = kTagModeExplicit;
        } else if (tag.mode == TagModeSpec::Implicit) {
            mode = kTagModeImplicit;
        } else {
            if (model_->moduleTagMode == 1) {
                mode = kTagModeExplicit;
            } else if (model_->moduleTagMode == 2 ||
                       model_->moduleTagMode == 0) {
                mode = kTagModeImplicit;
            } else {
                mode = kTagModeExplicit;
            }
        }

        if (node->kind == TypeKind::Choice && mode == kTagModeImplicit) {
            if (tag.mode == TagModeSpec::Implicit) {
                error(tag.pos, DiagCode::TagConflict,
                      "IMPLICIT tagging cannot be applied to CHOICE");
                return false;
            }
            /* 自动标注时 CHOICE 必须显式包装。 */
            mode = kTagModeExplicit;
        }
        if (node->kind == TypeKind::Any && mode == kTagModeImplicit) {
            error(tag.pos, DiagCode::TagConflict,
                  "IMPLICIT tagging cannot be applied to ANY");
            return false;
        }
        node->tagMode = mode;
        node->tagClass = kTagClassContext;
        node->tagNumber = tag.number;
        return true;
    }

    bool fillNode(TypeNode *node, const TypeAst &ast)
    {
        if (ast.cls == TypeAst::Class::Reference) {
            TypeNode *target = ensureNamed(ast.refName, ast.pos);
            if (target == nullptr) {
                return false;
            }
            if (target == node) {
                error(ast.pos, DiagCode::UndefinedType,
                      "cyclic type alias involving '" + ast.refName + "'");
                return false;
            }
            copyNode(target, node);
            if (ast.tag.present && !applyTag(node, ast.tag)) {
                return false;
            }
            return buildConstraints(ast.constraints, node->constraints,
                                    ast.pos);
        }

        if (ast.cls == TypeAst::Class::Any) {
            TypeNode *source = sharedAny();
            copyNode(source, node);
        } else if (ast.cls == TypeAst::Class::Sequence ||
                   ast.cls == TypeAst::Class::Set ||
                   ast.cls == TypeAst::Class::Choice) {
            node->tagMode = kTagModeDefault;
            node->tagClass = kTagClassUniversal;
            node->tagNumber = 0;
            node->baseTagNumber = 0;
            if (ast.cls == TypeAst::Class::Sequence) {
                node->kind = TypeKind::Sequence;
                node->baseTagNumber = 16;
            } else if (ast.cls == TypeAst::Class::Set) {
                node->kind = TypeKind::Set;
                node->baseTagNumber = 17;
            } else {
                node->kind = TypeKind::Choice;
            }
            node->flags = ast.extensible ? kTypeFlagExtensible : 0u;
            if (!resolveFields(node, ast)) {
                return false;
            }
        } else if (ast.cls == TypeAst::Class::SequenceOf ||
                   ast.cls == TypeAst::Class::SetOf) {
            node->tagMode = kTagModeDefault;
            node->tagClass = kTagClassUniversal;
            node->tagNumber = 0;
            node->baseTagNumber =
                ast.cls == TypeAst::Class::SequenceOf ? 16u : 17u;
            node->kind = ast.cls == TypeAst::Class::SequenceOf
                             ? TypeKind::SequenceOf
                             : TypeKind::SetOf;
            node->flags = ast.extensible ? kTypeFlagExtensible : 0u;
            if (ast.element == nullptr ||
                !resolveElement(*ast.element, node->name + ".element",
                                node->element)) {
                return false;
            }
        } else {
            const uint32_t tag = universalTagForClass(ast.cls);
            if (tag == 0) {
                error(ast.pos, DiagCode::Internal,
                      "internal error: unknown primitive type");
                return false;
            }
            node->kind = TypeKind::Simple;
            node->tagMode = kTagModeDefault;
            node->tagClass = kTagClassUniversal;
            node->tagNumber = tag;
            node->baseTagNumber = tag;
            node->flags = ast.extensible ? kTypeFlagExtensible : 0u;
            node->namedValues.clear();
            for (size_t i = 0; i < ast.namedNumbers.size(); ++i) {
                const NamedNumberAst &named = ast.namedNumbers[i];
                node->namedValues.push_back(
                    NamedValue{named.name, named.value,
                               i >= ast.rootNamedCount, named.pos});
            }
            if ((ast.cls == TypeAst::Class::Integer ||
                 ast.cls == TypeAst::Class::Enumerated) &&
                ast.rootNamedCount > 0) {
                if (!addEnumConstraint(node, ast)) {
                    return false;
                }
            }
        }

        if (!buildConstraints(ast.constraints, node->constraints, ast.pos)) {
            return false;
        }
        if (ast.cls == TypeAst::Class::Any && !ast.constraints.empty()) {
            error(ast.pos, DiagCode::ConstraintInvalid,
                  "ANY cannot carry constraints");
            return false;
        }
        if (ast.tag.present && !applyTag(node, ast.tag)) {
            return false;
        }
        return true;
    }

    bool addEnumConstraint(TypeNode *node, const TypeAst &ast)
    {
        Constraint constraint;
        constraint.kind = 2;
        for (size_t i = 0; i < ast.rootNamedCount &&
                            i < ast.namedNumbers.size();
             ++i) {
            constraint.enumValues.push_back(ast.namedNumbers[i].value);
        }
        if (!constraint.enumValues.empty()) {
            node->constraints.push_back(std::move(constraint));
        }
        return true;
    }

    bool resolveFields(TypeNode *owner, const TypeAst &ast)
    {
        for (const FieldAst &fieldAst : ast.fields) {
            Field field;
            field.name = fieldAst.name;
            field.line = fieldAst.pos.line;
            field.column = fieldAst.pos.column;
            if (fieldAst.optional) {
                field.flags = static_cast<uint16_t>(
                    field.flags | kFieldFlagOptional);
            }
            if (fieldAst.extension && owner->kind != TypeKind::Choice) {
                field.flags = static_cast<uint16_t>(
                    field.flags | kFieldFlagExtension);
            }
            if (!resolveFieldType(fieldAst, owner->name, field)) {
                return false;
            }
            if (fieldAst.defaultValue != nullptr) {
                if (!encodeDefault(field, *fieldAst.defaultValue,
                                   fieldAst.pos)) {
                    return false;
                }
            }
            owner->fields.push_back(std::move(field));
        }
        return true;
    }

    bool resolveFieldType(const FieldAst &fieldAst, const std::string &owner,
                          Field &field)
    {
        const TypeAst &ast = *fieldAst.type;
        if (ast.cls == TypeAst::Class::Reference && !ast.tag.present) {
            TypeNode *target = ensureNamed(ast.refName, ast.pos);
            if (target == nullptr) {
                return false;
            }
            field.type = target;
            if (!ast.constraints.empty()) {
                return buildConstraints(ast.constraints, field.constraints,
                                        ast.pos);
            }
            return true;
        }
        if (ast.cls == TypeAst::Class::Any && !ast.tag.present) {
            if (!ast.constraints.empty()) {
                error(ast.pos, DiagCode::ConstraintInvalid,
                      "ANY cannot carry constraints");
                return false;
            }
            field.type = sharedAny();
            return true;
        }
        TypeNode *node =
            resolveExprToNode(ast, owner + "." + fieldAst.name);
        if (node == nullptr) {
            return false;
        }
        field.type = node;
        return true;
    }

    TypeNode *resolveExprToNode(const TypeAst &ast, const std::string &hint)
    {
        TypeNode *node = newSynthetic(hint);
        if (!fillNode(node, ast)) {
            return nullptr;
        }
        return node;
    }

    bool resolveElement(const TypeAst &ast, const std::string &hint,
                        TypeNode *&out)
    {
        if (ast.cls == TypeAst::Class::Reference && !ast.tag.present &&
            ast.constraints.empty()) {
            out = ensureNamed(ast.refName, ast.pos);
            return out != nullptr;
        }
        if (ast.cls == TypeAst::Class::Any && !ast.tag.present) {
            if (!ast.constraints.empty()) {
                error(ast.pos, DiagCode::ConstraintInvalid,
                      "ANY cannot carry constraints");
                return false;
            }
            out = sharedAny();
            return true;
        }
        out = resolveExprToNode(ast, hint);
        return out != nullptr;
    }

    bool buildConstraints(const std::vector<ConstraintAst> &source,
                          std::vector<Constraint> &target,
                          const Pos &pos)
    {
        for (const ConstraintAst &item : source) {
            BoundValue lower;
            BoundValue upper;
            if (!resolveBound(item.lower, true, lower, pos)) {
                return false;
            }
            if (!resolveBound(item.upper, false, upper, pos)) {
                return false;
            }
            if (item.single && item.lower.isMax) {
                error(pos, DiagCode::ConstraintInvalid,
                      "constraint cannot have a single MAX bound");
                return false;
            }
            Constraint constraint;
            if (item.kind == ConstraintAst::Kind::Size) {
                if (lower.unbounded) {
                    error(pos, DiagCode::ConstraintInvalid,
                          "SIZE lower bound must be finite");
                    return false;
                }
                if (lower.value < 0) {
                    error(pos, DiagCode::ConstraintInvalid,
                          "SIZE lower bound must be non-negative");
                    return false;
                }
                constraint.kind = 1;
                constraint.lower = lower.value;
                if (upper.unbounded) {
                    constraint.upperUnbounded = true;
                } else {
                    if (upper.value < lower.value) {
                        error(pos, DiagCode::ConstraintInvalid,
                              "SIZE upper bound is below lower bound");
                        return false;
                    }
                    constraint.upper = upper.value;
                }
                target.push_back(std::move(constraint));
                continue;
            }
            constraint.kind = 0;
            if (lower.unbounded) {
                constraint.lowerUnbounded = true;
            } else {
                constraint.lower = lower.value;
            }
            if (upper.unbounded) {
                constraint.upperUnbounded = true;
            } else {
                constraint.upper = upper.value;
            }
            if (!constraint.lowerUnbounded &&
                !constraint.upperUnbounded &&
                constraint.lower > constraint.upper) {
                error(pos, DiagCode::ConstraintInvalid,
                      "constraint lower bound exceeds upper bound");
                return false;
            }
            if (!constraint.lowerUnbounded && constraint.lower == 0 &&
                constraint.upperUnbounded) {
                constraint.kind = 3; /* MAX */
            }
            target.push_back(std::move(constraint));
        }
        return true;
    }

    bool resolveBound(const ConstraintBoundAst &bound, bool lowerBound,
                      BoundValue &out, const Pos &pos)
    {
        out = BoundValue();
        if (bound.isMax) {
            if (lowerBound) {
                error(pos, DiagCode::ConstraintInvalid,
                      "lower bound cannot be MAX");
                return false;
            }
            out.unbounded = true;
            return true;
        }
        if (bound.isMin) {
            if (!lowerBound) {
                error(pos, DiagCode::ConstraintInvalid,
                      "upper bound cannot be MIN");
                return false;
            }
            out.unbounded = true;
            return true;
        }
        if (bound.hasValue) {
            out.value = bound.value;
            return true;
        }
        if (!bound.refName.empty()) {
            int64_t value = 0;
            if (!lookupInteger(bound.refName, value)) {
                error(bound.pos, DiagCode::ConstraintInvalid,
                      "undefined value '" + bound.refName +
                          "' in constraint");
                return false;
            }
            out.value = value;
            return true;
        }
        error(pos, DiagCode::ConstraintInvalid,
              "missing constraint bound");
        return false;
    }

    bool resolveInteger(const TypeNode *type, const ValueAst &value,
                        const Pos &pos, int64_t &out)
    {
        if (value.kind == ValueAst::Kind::Integer) {
            out = value.intValue;
            return true;
        }
        if (value.kind == ValueAst::Kind::Reference) {
            for (const NamedValue &named : type->namedValues) {
                if (named.name == value.text) {
                    out = named.value;
                    return true;
                }
            }
            if (lookupInteger(value.text, out)) {
                return true;
            }
            error(pos, DiagCode::ConstraintInvalid,
                  "cannot resolve DEFAULT value '" + value.text + "'");
            return false;
        }
        error(pos, DiagCode::ConstraintInvalid,
              "DEFAULT value is not an integer");
        return false;
    }

    bool encodeSimpleContent(const TypeNode *type, const ValueAst &value,
                             const Pos &pos, std::vector<uint8_t> &content)
    {
        switch (type->baseTagNumber) {
        case 1: { /* BOOLEAN */
            bool flag = false;
            if (value.kind == ValueAst::Kind::Boolean) {
                flag = value.boolValue;
            } else if (value.kind == ValueAst::Kind::Integer &&
                       (value.intValue == 0 || value.intValue == 1)) {
                flag = value.intValue == 1;
            } else {
                error(pos, DiagCode::ConstraintInvalid,
                      "DEFAULT value is not a BOOLEAN");
                return false;
            }
            content.push_back(flag ? 0xFFu : 0x00u);
            return true;
        }
        case 2:   /* INTEGER */
        case 10: { /* ENUMERATED */
            int64_t number = 0;
            if (!resolveInteger(type, value, pos, number)) {
                return false;
            }
            content = encodeIntegerContent(number);
            return true;
        }
        case 3: { /* BIT STRING */
            if (value.kind == ValueAst::Kind::Oid) {
                uint64_t highest = 0;
                bool any = false;
                for (const BracePartAst &part : value.parts) {
                    uint64_t bit = 0;
                    if (part.hasName) {
                        bool found = false;
                        for (const NamedValue &named : type->namedValues) {
                            if (named.name == part.name && named.value >= 0) {
                                bit = static_cast<uint64_t>(named.value);
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            error(part.pos, DiagCode::ConstraintInvalid,
                                  "unknown named bit '" + part.name +
                                      "'");
                            return false;
                        }
                    } else {
                        bit = part.number;
                    }
                    any = true;
                    if (bit > highest) {
                        highest = bit;
                    }
                }
                if (any) {
                    const size_t bytes =
                        static_cast<size_t>(highest / 8u) + 1u;
                    content.assign(bytes, 0u);
                    for (const BracePartAst &part : value.parts) {
                        uint64_t bit = part.number;
                        if (part.hasName) {
                            for (const NamedValue &named : type->namedValues) {
                                if (named.name == part.name) {
                                    bit = static_cast<uint64_t>(named.value);
                                    break;
                                }
                            }
                        }
                        content[static_cast<size_t>(bit / 8u)] |=
                            static_cast<uint8_t>(0x80u >> (bit % 8u));
                    }
                }
                return true;
            }
            error(pos, DiagCode::ConstraintInvalid,
                  "DEFAULT value is not a BIT STRING");
            return false;
        }
        case 4: /* OCTET STRING */
        case 12:
        case 18:
        case 19:
        case 20:
        case 22:
        case 23:
        case 24:
        case 26:
        case 28:
        case 30: {
            if (value.kind != ValueAst::Kind::String) {
                error(pos, DiagCode::ConstraintInvalid,
                      "DEFAULT value is not a string");
                return false;
            }
            content.assign(value.text.begin(), value.text.end());
            return true;
        }
        case 5: { /* NULL */
            if (value.kind != ValueAst::Kind::Null) {
                error(pos, DiagCode::ConstraintInvalid,
                      "DEFAULT value is not NULL");
                return false;
            }
            return true;
        }
        case 6: { /* OBJECT IDENTIFIER */
            if (value.kind != ValueAst::Kind::Oid) {
                error(pos, DiagCode::ConstraintInvalid,
                      "DEFAULT value is not an OBJECT IDENTIFIER");
                return false;
            }
            std::vector<uint64_t> arcs;
            if (!evaluateOid(value, arcs, DiagCode::ConstraintInvalid)) {
                return false;
            }
            return encodeOidContent(arcs, content);
        }
        default:
            error(pos, DiagCode::ConstraintInvalid,
                  "DEFAULT is not supported for this type");
            return false;
        }
    }

    bool encodeDefault(Field &field, const ValueAst &value, const Pos &pos)
    {
        const TypeNode *type = field.type;
        if (type == nullptr) {
            return false;
        }
        if (type->kind != TypeKind::Simple) {
            error(pos, DiagCode::ConstraintInvalid,
                  "DEFAULT is not supported for this type");
            return false;
        }
        std::vector<uint8_t> content;
        if (!encodeSimpleContent(type, value, pos, content)) {
            return false;
        }

        std::vector<uint8_t> tlv;
        const uint32_t innerTag = type->baseTagNumber;
        if (type->tagMode == kTagModeImplicit) {
            appendTag(tlv, type->tagClass, type->tagNumber, false);
            appendLength(tlv, content.size());
            tlv.insert(tlv.end(), content.begin(), content.end());
        } else if (type->tagMode == kTagModeExplicit) {
            std::vector<uint8_t> inner;
            appendTag(inner, kTagClassUniversal, innerTag, false);
            appendLength(inner, content.size());
            inner.insert(inner.end(), content.begin(), content.end());
            appendTag(tlv, type->tagClass, type->tagNumber, true);
            appendLength(tlv, inner.size());
            tlv.insert(tlv.end(), inner.begin(), inner.end());
        } else {
            appendTag(tlv, kTagClassUniversal, innerTag, false);
            appendLength(tlv, content.size());
            tlv.insert(tlv.end(), content.begin(), content.end());
        }

        field.hasDefault = true;
        field.defaultTlv = std::move(tlv);
        return true;
    }

    static void noteFiniteSize(const std::vector<Constraint> &list,
                               bool &found, int64_t &upper)
    {
        for (const Constraint &constraint : list) {
            if (constraint.kind != 1 || constraint.upperUnbounded) {
                continue;
            }
            if (!found || constraint.upper < upper) {
                upper = constraint.upper;
                found = true;
            }
        }
    }

    bool finiteSizeUpperBound(const TypeNode &type, int64_t &upper) const
    {
        bool found = false;
        upper = 0;
        noteFiniteSize(type.constraints, found, upper);
        for (const std::unique_ptr<TypeNode> &owner : model_->nodes) {
            for (const Field &field : owner->fields) {
                if (field.type == &type) {
                    noteFiniteSize(field.constraints, found, upper);
                }
            }
        }
        return found;
    }

    /* 0 = BIT_NAME、1 = NUMBER_NAME；无法由名称表表达时返回 2。 */
    uint32_t namedKindFor(const TypeNode &node) const
    {
        if (node.kind != TypeKind::Simple ||
            node.tagClass != kTagClassUniversal) {
            return 2;
        }
        if (node.tagNumber == 3 && node.baseTagNumber == 3) {
            return 0;
        }
        if ((node.tagNumber == 2 || node.tagNumber == 10) &&
            node.tagNumber == node.baseTagNumber) {
            return 1;
        }
        return 2;
    }

    void checkNamedValues()
    {
        for (const std::unique_ptr<TypeNode> &node : model_->nodes) {
            if (node->namedValues.empty()) {
                continue;
            }
            const uint32_t kind = namedKindFor(*node);
            if (kind == 2) {
                /* 带标签的克隆类型无法由名称表表达（核心要求 UNIVERSAL），
                 * 名称仍由基础类型拥有；只有语法上不可能的组合才报内部错误。 */
                const bool primitive =
                    node->baseTagNumber == 2 || node->baseTagNumber == 3 ||
                    node->baseTagNumber == 10;
                if (node->kind != TypeKind::Simple || !primitive) {
                    error(node->namedValues[0].pos, DiagCode::Internal,
                          "internal error: cannot classify named values for "
                          "type '" +
                              node->name + "'");
                }
                continue;
            }
            int64_t upper = 0;
            const bool hasUpper = kind == 0 &&
                                  finiteSizeUpperBound(*node, upper);
            std::set<std::string> names;
            std::set<int64_t> values;
            for (const NamedValue &named : node->namedValues) {
                if (!names.insert(named.name).second) {
                    error(named.pos, DiagCode::DuplicateField,
                          "duplicate named value '" + named.name +
                              "' in type '" + node->name + "'");
                }
                if (!values.insert(named.value).second) {
                    error(named.pos, DiagCode::DuplicateField,
                          "duplicate named value number " +
                              std::to_string(named.value) + " in type '" +
                              node->name + "'");
                }
                if (kind == 0) {
                    const bool outOfRange =
                        named.value < 0 || named.value > 65535 ||
                        (hasUpper && named.value >= upper);
                    if (outOfRange) {
                        error(named.pos, DiagCode::ConstraintInvalid,
                              "named bit '" + named.name +
                                  "' is out of range for BIT STRING type '" +
                                  node->name + "'");
                    }
                } else if (named.extension &&
                           (node->baseTagNumber != 10 ||
                            (node->flags & kTypeFlagExtensible) == 0u)) {
                    error(named.pos, DiagCode::ConstraintInvalid,
                          "extension named value '" + named.name +
                              "' requires an EXTENSIBLE ENUMERATED type");
                }
            }
        }
    }

    void checkStructure()
    {
        for (const std::unique_ptr<TypeNode> &node : model_->nodes) {
            checkDuplicateFields(*node);
            if (node->kind == TypeKind::Set ||
                node->kind == TypeKind::Choice) {
                checkTagConflicts(*node);
            }
        }
    }

    void checkDuplicateFields(const TypeNode &node)
    {
        for (size_t i = 0; i < node.fields.size(); ++i) {
            for (size_t j = i + 1; j < node.fields.size(); ++j) {
                if (node.fields[i].name == node.fields[j].name) {
                    diagnostics_.add(
                        file_, node.fields[j].line, node.fields[j].column,
                        Severity::Error, DiagCode::DuplicateField,
                        "duplicate field name '" + node.fields[j].name +
                            "'");
                }
            }
        }
    }

    void checkTagConflicts(const TypeNode &node)
    {
        for (size_t i = 0; i < node.fields.size(); ++i) {
            std::vector<TagId> first;
            if (!collectTags(node.fields[i].type, first, 0)) {
                reportUnresolvedTag(node.fields[i]);
                continue;
            }
            for (size_t j = i + 1; j < node.fields.size(); ++j) {
                std::vector<TagId> second;
                if (!collectTags(node.fields[j].type, second, 0)) {
                    reportUnresolvedTag(node.fields[j]);
                    return;
                }
                bool conflict = false;
                for (const TagId &a : first) {
                    for (const TagId &b : second) {
                        if (a.tagClass == b.tagClass &&
                            a.tagNumber == b.tagNumber) {
                            conflict = true;
                        }
                    }
                }
                if (conflict) {
                    diagnostics_.add(
                        file_, node.fields[j].line, node.fields[j].column,
                        Severity::Error, DiagCode::TagConflict,
                        "effective tag of field '" +
                            node.fields[j].name +
                            "' conflicts with field '" +
                            node.fields[i].name + "'");
                    return;
                }
            }
        }
    }

    void reportUnresolvedTag(const Field &field)
    {
        diagnostics_.add(file_, field.line, field.column, Severity::Error,
                         DiagCode::TagConflict,
                         "cannot determine effective tag for field '" +
                             field.name + "'");
    }

    void assignIds()
    {
        uint32_t id = 1;
        for (const std::unique_ptr<TypeNode> &node : model_->nodes) {
            node->id = id;
            ++id;
        }
    }

    const std::string &file_;
    const ModuleAst &module_;
    Diagnostics &diagnostics_;
    SchemaModel *model_;
    std::vector<const TypeAst *> namedAsts_;
    std::vector<uint8_t> namedState_;
    std::map<std::string, uint32_t> typeIndex_;
    std::map<std::string, ValueSymbol> values_;
    uint32_t syntheticCounter_ = 0;
};

} /* namespace */

std::unique_ptr<SchemaModel> analyzeModule(const std::string &file,
                                           const ModuleAst &module,
                                           const std::string &rootName,
                                           Diagnostics &diagnostics)
{
    std::unique_ptr<SchemaModel> model = std::make_unique<SchemaModel>();
    Analyzer analyzer(file, module, diagnostics, model.get());
    analyzer.run(rootName);
    return model;
}

} /* namespace asn1c */
