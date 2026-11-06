/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

#include "parser.h"

#include "lexer.h"

#include <memory>
#include <vector>

namespace asn1c {
namespace {

class Parser {
public:
    Parser(const std::string &file, const std::vector<Token> &tokens,
           Diagnostics &diagnostics)
        : file_(file), tokens_(tokens), diagnostics_(diagnostics)
    {
    }

    bool run(ModuleAst &out)
    {
        if (peek().kind != TokenKind::Identifier) {
            syntaxError(peek().pos, "expected module name");
            return false;
        }
        out.name = peek().text;
        advance();

        /* 可选的模块 OID `{ ... }`，本轮不进入描述表。 */
        if (peek().kind == TokenKind::LBrace) {
            if (!skipBalancedBraces()) {
                return false;
            }
        }

        if (!expectKeyword("DEFINITIONS", "expected DEFINITIONS")) {
            return false;
        }
        if (keywordEquals(peek(), "EXPLICIT")) {
            advance();
            out.tagMode = 1;
            if (!expectKeyword("TAGS", "expected TAGS")) {
                return false;
            }
        } else if (keywordEquals(peek(), "IMPLICIT")) {
            advance();
            out.tagMode = 2;
            if (!expectKeyword("TAGS", "expected TAGS")) {
                return false;
            }
        } else if (keywordEquals(peek(), "AUTOMATIC")) {
            advance();
            out.tagMode = 0;
            if (!expectKeyword("TAGS", "expected TAGS")) {
                return false;
            }
        } else {
            out.tagMode = 3;
        }

        if (!expectToken(TokenKind::Assign, "expected '::='")) {
            return false;
        }
        if (!expectKeyword("BEGIN", "expected BEGIN")) {
            return false;
        }

        while (true) {
            if (peek().kind == TokenKind::End) {
                syntaxError(peek().pos, "missing END");
                return false;
            }
            if (keywordEquals(peek(), "END")) {
                advance();
                break;
            }
            if (keywordEquals(peek(), "IMPORTS")) {
                diagnostics_.add(file_, peek().pos.line, peek().pos.column,
                                 Severity::Error, DiagCode::ImportUnresolved,
                                 "IMPORTS is not supported: multi-module "
                                 "imports are not implemented");
                skipToSync();
                continue;
            }
            if (!parseDeclaration(out)) {
                if (peek().kind == TokenKind::End) {
                    syntaxError(peek().pos, "missing END");
                    return false;
                }
                skipToSync();
            }
        }

        if (peek().kind != TokenKind::End) {
            syntaxError(peek().pos, "unexpected token after END");
            return false;
        }
        return !diagnostics_.hasError();
    }

private:
    const Token &peek(size_t offset = 0) const
    {
        const size_t at = index_ + offset;
        return at < tokens_.size() ? tokens_[at] : tokens_.back();
    }

    void advance()
    {
        if (index_ + 1 < tokens_.size()) {
            ++index_;
        }
    }

    void syntaxError(const Pos &pos, const std::string &message)
    {
        diagnostics_.add(file_, pos.line, pos.column, Severity::Error,
                         DiagCode::Syntax, message);
    }

    void unsupported(const Pos &pos, const std::string &message)
    {
        diagnostics_.add(file_, pos.line, pos.column, Severity::Error,
                         DiagCode::UnsupportedConstruct, message);
    }

    bool expectKeyword(const char *keyword, const std::string &message)
    {
        if (!keywordEquals(peek(), keyword)) {
            syntaxError(peek().pos, message);
            return false;
        }
        advance();
        return true;
    }

    bool expectToken(TokenKind kind, const std::string &message)
    {
        if (peek().kind != kind) {
            syntaxError(peek().pos, message);
            return false;
        }
        advance();
        return true;
    }

    bool skipBalancedBraces()
    {
        if (peek().kind != TokenKind::LBrace) {
            syntaxError(peek().pos, "expected '{'");
            return false;
        }
        uint32_t depth = 0;
        while (peek().kind != TokenKind::End) {
            if (peek().kind == TokenKind::LBrace) {
                ++depth;
            } else if (peek().kind == TokenKind::RBrace) {
                --depth;
                if (depth == 0) {
                    advance();
                    return true;
                }
            }
            advance();
        }
        syntaxError(peek().pos, "unterminated '{'");
        return false;
    }

    /* 顶层错误恢复：跳过到分号或 END，括号深度归零。 */
    void skipToSync()
    {
        uint32_t depth = 0;
        while (peek().kind != TokenKind::End) {
            if (depth == 0 && keywordEquals(peek(), "END")) {
                return;
            }
            if (peek().kind == TokenKind::LBrace) {
                ++depth;
            } else if (peek().kind == TokenKind::RBrace) {
                if (depth > 0) {
                    --depth;
                }
            } else if (peek().kind == TokenKind::Semicolon && depth == 0) {
                advance();
                return;
            }
            advance();
        }
    }

    bool parseDeclaration(ModuleAst &out)
    {
        if (peek().kind != TokenKind::Identifier) {
            syntaxError(peek().pos, "expected type or value name");
            return false;
        }
        const Token nameToken = peek();
        advance();

        if (peek().kind == TokenKind::LBrace) {
            unsupported(peek().pos,
                        "parameterized type definitions are not supported");
            return false;
        }

        if (peek().kind == TokenKind::Assign) {
            advance();
            std::unique_ptr<TypeAst> type = std::make_unique<TypeAst>();
            if (!parseTypeExpr(*type)) {
                return false;
            }
            TypeAssignment assignment;
            assignment.name = nameToken.text;
            assignment.pos = nameToken.pos;
            assignment.type = std::move(type);
            out.types.push_back(std::move(assignment));
            return true;
        }

        std::unique_ptr<TypeAst> type = std::make_unique<TypeAst>();
        if (!parseTypeExpr(*type)) {
            return false;
        }
        if (!expectToken(TokenKind::Assign, "expected '::='")) {
            return false;
        }
        std::unique_ptr<ValueAst> value = std::make_unique<ValueAst>();
        if (!parseValue(*value)) {
            return false;
        }
        ValueAssignment assignment;
        assignment.name = nameToken.text;
        assignment.pos = nameToken.pos;
        assignment.type = std::move(type);
        assignment.value = std::move(value);
        out.values.push_back(std::move(assignment));
        return true;
    }

    bool parseTypeExpr(TypeAst &out)
    {
        out.pos = peek().pos;
        if (peek().kind == TokenKind::LBracket) {
            if (!parseTag(out.tag)) {
                return false;
            }
        }
        if (!parseBase(out)) {
            return false;
        }
        if (!parseConstraintList(out.constraints)) {
            return false;
        }
        if (keywordEquals(peek(), "CONTAINING")) {
            unsupported(peek().pos, "CONTAINING is not supported");
            return false;
        }
        if (keywordEquals(peek(), "CONSTRAINED")) {
            unsupported(peek().pos, "CONSTRAINED BY is not supported");
            return false;
        }
        if (keywordEquals(peek(), "WITH")) {
            unsupported(peek().pos, "WITH COMPONENTS is not supported");
            return false;
        }
        if (keywordEquals(peek(), "PATTERN")) {
            unsupported(peek().pos, "PATTERN constraints are not supported");
            return false;
        }
        return true;
    }

    bool parseTag(TagSpec &out)
    {
        out.pos = peek().pos;
        if (!expectToken(TokenKind::LBracket, "expected '['")) {
            return false;
        }
        if (peek().kind == TokenKind::LBracket) {
            unsupported(peek().pos,
                        "extension marker groups '[[...]]' are not supported");
            return false;
        }
        if (keywordEquals(peek(), "APPLICATION") ||
            keywordEquals(peek(), "PRIVATE") ||
            keywordEquals(peek(), "UNIVERSAL")) {
            unsupported(peek().pos,
                        "APPLICATION/PRIVATE/UNIVERSAL tag classes are not "
                        "supported");
            return false;
        }
        if (peek().kind != TokenKind::Number) {
            syntaxError(peek().pos, "expected tag number");
            return false;
        }
        uint64_t number = 0;
        if (!parseUnsigned(peek(), number) || number > UINT32_MAX) {
            syntaxError(peek().pos, "tag number out of range");
            return false;
        }
        out.number = static_cast<uint32_t>(number);
        advance();
        if (!expectToken(TokenKind::RBracket, "expected ']'")) {
            return false;
        }
        if (keywordEquals(peek(), "EXPLICIT")) {
            out.mode = TagModeSpec::Explicit;
            advance();
        } else if (keywordEquals(peek(), "IMPLICIT")) {
            out.mode = TagModeSpec::Implicit;
            advance();
        } else {
            out.mode = TagModeSpec::Bare;
        }
        out.present = true;
        return true;
    }

    bool parseBase(TypeAst &out)
    {
        const Token token = peek();
        if (token.kind != TokenKind::Identifier) {
            syntaxError(token.pos, "expected type expression");
            return false;
        }

        if (keywordEquals(token, "BOOLEAN")) {
            out.cls = TypeAst::Class::Boolean;
            advance();
        } else if (keywordEquals(token, "INTEGER")) {
            out.cls = TypeAst::Class::Integer;
            advance();
            if (peek().kind == TokenKind::LBrace) {
                if (!parseNamedNumbers(out, false)) {
                    return false;
                }
            }
        } else if (keywordEquals(token, "ENUMERATED")) {
            out.cls = TypeAst::Class::Enumerated;
            advance();
            if (peek().kind != TokenKind::LBrace) {
                syntaxError(peek().pos, "expected '{' after ENUMERATED");
                return false;
            }
            if (!parseNamedNumbers(out, true)) {
                return false;
            }
        } else if (keywordEquals(token, "BIT")) {
            out.cls = TypeAst::Class::BitString;
            advance();
            if (!expectKeyword("STRING", "expected STRING after BIT")) {
                return false;
            }
            if (peek().kind == TokenKind::LBrace) {
                if (!parseNamedNumbers(out, false)) {
                    return false;
                }
            }
        } else if (keywordEquals(token, "OCTET")) {
            out.cls = TypeAst::Class::OctetString;
            advance();
            if (!expectKeyword("STRING", "expected STRING after OCTET")) {
                return false;
            }
        } else if (keywordEquals(token, "OBJECT")) {
            out.cls = TypeAst::Class::ObjectIdentifier;
            advance();
            if (!expectKeyword("IDENTIFIER",
                                "expected IDENTIFIER after OBJECT")) {
                return false;
            }
        } else if (keywordEquals(token, "NULL")) {
            out.cls = TypeAst::Class::Null;
            advance();
        } else if (keywordEquals(token, "UTF8String")) {
            out.cls = TypeAst::Class::Utf8String;
            advance();
        } else if (keywordEquals(token, "PrintableString")) {
            out.cls = TypeAst::Class::PrintableString;
            advance();
        } else if (keywordEquals(token, "IA5String")) {
            out.cls = TypeAst::Class::Ia5String;
            advance();
        } else if (keywordEquals(token, "VisibleString")) {
            out.cls = TypeAst::Class::VisibleString;
            advance();
        } else if (keywordEquals(token, "NumericString")) {
            out.cls = TypeAst::Class::NumericString;
            advance();
        } else if (keywordEquals(token, "TeletexString") ||
                   keywordEquals(token, "T61String")) {
            out.cls = TypeAst::Class::TeletexString;
            advance();
        } else if (keywordEquals(token, "BMPString")) {
            out.cls = TypeAst::Class::BmpString;
            advance();
        } else if (keywordEquals(token, "UniversalString")) {
            out.cls = TypeAst::Class::UniversalString;
            advance();
        } else if (keywordEquals(token, "UTCTime")) {
            out.cls = TypeAst::Class::UtcTime;
            advance();
        } else if (keywordEquals(token, "GeneralizedTime")) {
            out.cls = TypeAst::Class::GeneralizedTime;
            advance();
        } else if (keywordEquals(token, "ANY")) {
            out.cls = TypeAst::Class::Any;
            advance();
            if (keywordEquals(peek(), "DEFINED")) {
                unsupported(peek().pos, "ANY DEFINED BY is not supported");
                return false;
            }
        } else if (keywordEquals(token, "SEQUENCE")) {
            out.cls = TypeAst::Class::Sequence;
            advance();
            if (!parseConstraintList(out.constraints)) {
                return false;
            }
            if (keywordEquals(peek(), "OF")) {
                out.cls = TypeAst::Class::SequenceOf;
                advance();
                out.element = std::make_unique<TypeAst>();
                if (!parseTypeExpr(*out.element)) {
                    return false;
                }
            } else if (peek().kind == TokenKind::LBrace) {
                if (!parseFieldList(out)) {
                    return false;
                }
            } else {
                syntaxError(peek().pos, "expected OF or '{' after SEQUENCE");
                return false;
            }
        } else if (keywordEquals(token, "SET")) {
            out.cls = TypeAst::Class::Set;
            advance();
            if (!parseConstraintList(out.constraints)) {
                return false;
            }
            if (keywordEquals(peek(), "OF")) {
                out.cls = TypeAst::Class::SetOf;
                advance();
                out.element = std::make_unique<TypeAst>();
                if (!parseTypeExpr(*out.element)) {
                    return false;
                }
            } else if (peek().kind == TokenKind::LBrace) {
                if (!parseFieldList(out)) {
                    return false;
                }
            } else {
                syntaxError(peek().pos, "expected OF or '{' after SET");
                return false;
            }
        } else if (keywordEquals(token, "CHOICE")) {
            out.cls = TypeAst::Class::Choice;
            advance();
            if (peek().kind != TokenKind::LBrace) {
                syntaxError(peek().pos, "expected '{' after CHOICE");
                return false;
            }
            if (!parseFieldList(out)) {
                return false;
            }
        } else if (keywordEquals(token, "CLASS")) {
            unsupported(token.pos, "CLASS definitions are not supported");
            return false;
        } else if (keywordEquals(token, "INSTANCE")) {
            unsupported(token.pos, "INSTANCE OF is not supported");
            return false;
        } else if (keywordEquals(token, "COMPONENTS")) {
            unsupported(token.pos, "COMPONENTS OF is not supported");
            return false;
        } else if (keywordEquals(token, "WITH")) {
            unsupported(token.pos, "WITH SYNTAX is not supported");
            return false;
        } else {
            out.cls = TypeAst::Class::Reference;
            out.refName = token.text;
            advance();
            if (peek().kind == TokenKind::LBrace) {
                unsupported(peek().pos,
                            "parameterized type instantiation is not "
                            "supported");
                return false;
            }
        }

        if (keywordEquals(peek(), "COMPONENTS")) {
            unsupported(peek().pos, "COMPONENTS OF is not supported");
            return false;
        }
        return true;
    }

    bool parseFieldList(TypeAst &out)
    {
        if (!expectToken(TokenKind::LBrace, "expected '{'")) {
            return false;
        }
        bool inExtension = false;
        while (true) {
            if (peek().kind == TokenKind::RBrace) {
                advance();
                break;
            }
            if (peek().kind == TokenKind::End) {
                syntaxError(peek().pos, "missing '}'");
                return false;
            }
            if (peek().kind == TokenKind::Ellipsis) {
                out.extensible = true;
                inExtension = true;
                advance();
                if (peek().kind == TokenKind::Comma) {
                    advance();
                }
                continue;
            }
            if (peek().kind == TokenKind::LBracket &&
                peek(1).kind == TokenKind::LBracket) {
                unsupported(peek().pos,
                            "extension marker groups '[[...]]' are not "
                            "supported");
                return false;
            }
            if (keywordEquals(peek(), "COMPONENTS")) {
                unsupported(peek().pos, "COMPONENTS OF is not supported");
                return false;
            }
            if (peek().kind != TokenKind::Identifier) {
                syntaxError(peek().pos, "expected field name");
                return false;
            }
            FieldAst field;
            field.name = peek().text;
            field.pos = peek().pos;
            advance();

            field.type = std::make_unique<TypeAst>();
            if (!parseTypeExpr(*field.type)) {
                return false;
            }
            if (keywordEquals(peek(), "OPTIONAL")) {
                field.optional = true;
                advance();
            } else if (keywordEquals(peek(), "DEFAULT")) {
                advance();
                field.defaultValue = std::make_unique<ValueAst>();
                if (!parseValue(*field.defaultValue)) {
                    return false;
                }
            }
            field.extension = inExtension;
            out.fields.push_back(std::move(field));

            if (peek().kind == TokenKind::Comma) {
                advance();
                continue;
            }
            if (peek().kind == TokenKind::RBrace) {
                advance();
                break;
            }
            syntaxError(peek().pos, "expected ',' or '}'");
            return false;
        }

        if (out.cls == TypeAst::Class::Choice) {
            for (const FieldAst &field : out.fields) {
                if (field.optional || field.defaultValue != nullptr) {
                    syntaxError(field.pos,
                                "CHOICE alternatives cannot be OPTIONAL or "
                                "have DEFAULT");
                    return false;
                }
            }
        }
        return true;
    }

    bool parseNamedNumbers(TypeAst &out, bool allowEllipsis)
    {
        if (!expectToken(TokenKind::LBrace, "expected '{'")) {
            return false;
        }
        while (true) {
            if (peek().kind == TokenKind::RBrace) {
                advance();
                break;
            }
            if (peek().kind == TokenKind::End) {
                syntaxError(peek().pos, "missing '}'");
                return false;
            }
            if (peek().kind == TokenKind::Ellipsis) {
                if (!allowEllipsis) {
                    unsupported(peek().pos,
                                "extension marker is not supported here");
                    return false;
                }
                out.extensible = true;
                advance();
                if (peek().kind == TokenKind::Comma) {
                    advance();
                }
                continue;
            }
            if (peek().kind != TokenKind::Identifier) {
                syntaxError(peek().pos, "expected named number");
                return false;
            }
            NamedNumberAst named;
            named.name = peek().text;
            named.pos = peek().pos;
            advance();
            if (!expectToken(TokenKind::LParen, "expected '('")) {
                return false;
            }
            bool valueNegated = false;
            if (peek().kind == TokenKind::Minus) {
                valueNegated = true;
                advance();
            }
            if (peek().kind != TokenKind::Number) {
                syntaxError(peek().pos, "expected number");
                return false;
            }
            if (!parseSigned(peek(), valueNegated, named.value)) {
                syntaxError(peek().pos, "named number value out of range");
                return false;
            }
            advance();
            if (!expectToken(TokenKind::RParen, "expected ')'")) {
                return false;
            }
            if (!out.extensible) {
                ++out.rootNamedCount;
            }
            out.namedNumbers.push_back(named);

            if (peek().kind == TokenKind::Comma) {
                advance();
            } else if (peek().kind != TokenKind::RBrace) {
                syntaxError(peek().pos, "expected ',' or '}'");
                return false;
            }
        }
        return true;
    }

    bool parseConstraintList(std::vector<ConstraintAst> &out)
    {
        while (true) {
            if (peek().kind == TokenKind::LParen) {
                ConstraintAst constraint;
                constraint.pos = peek().pos;
                advance();
                if (keywordEquals(peek(), "SIZE")) {
                    constraint.kind = ConstraintAst::Kind::Size;
                    advance();
                    if (!expectToken(TokenKind::LParen,
                                     "expected '(' after SIZE")) {
                        return false;
                    }
                    if (!parseBounds(constraint)) {
                        return false;
                    }
                    if (!expectToken(TokenKind::RParen, "expected ')'")) {
                        return false;
                    }
                } else {
                    constraint.kind = ConstraintAst::Kind::Range;
                    if (!parseBounds(constraint)) {
                        return false;
                    }
                }
                if (!expectToken(TokenKind::RParen, "expected ')'")) {
                    return false;
                }
                out.push_back(constraint);
                continue;
            }
            if (keywordEquals(peek(), "SIZE")) {
                ConstraintAst constraint;
                constraint.pos = peek().pos;
                constraint.kind = ConstraintAst::Kind::Size;
                advance();
                if (!expectToken(TokenKind::LParen,
                                 "expected '(' after SIZE")) {
                    return false;
                }
                if (!parseBounds(constraint)) {
                    return false;
                }
                if (!expectToken(TokenKind::RParen, "expected ')'")) {
                    return false;
                }
                out.push_back(constraint);
                continue;
            }
            if (keywordEquals(peek(), "PATTERN")) {
                unsupported(peek().pos, "PATTERN constraints are not supported");
                return false;
            }
            break;
        }
        return true;
    }

    bool parseBounds(ConstraintAst &constraint)
    {
        if (!parseBound(constraint.lower)) {
            return false;
        }
        if (peek().kind == TokenKind::DotDot) {
            advance();
            if (!parseBound(constraint.upper)) {
                return false;
            }
        } else {
            constraint.single = true;
            constraint.upper = constraint.lower;
        }
        return true;
    }

    bool parseBound(ConstraintBoundAst &bound)
    {
        bound.pos = peek().pos;
        if (keywordEquals(peek(), "MAX")) {
            bound.isMax = true;
            advance();
            return true;
        }
        if (keywordEquals(peek(), "MIN")) {
            bound.isMin = true;
            advance();
            return true;
        }
        bool negated = false;
        if (peek().kind == TokenKind::Minus) {
            negated = true;
            advance();
        }
        if (peek().kind == TokenKind::Number) {
            bound.hasValue = true;
            if (!parseSigned(peek(), negated, bound.value)) {
                syntaxError(peek().pos, "constraint value out of range");
                return false;
            }
            advance();
            return true;
        }
        if (peek().kind == TokenKind::Identifier) {
            if (negated) {
                syntaxError(peek().pos, "expected number");
                return false;
            }
            bound.refName = peek().text;
            advance();
            return true;
        }
        syntaxError(peek().pos, "expected constraint bound");
        return false;
    }

    bool parseValue(ValueAst &out)
    {
        out.pos = peek().pos;
        if (peek().kind == TokenKind::LBrace) {
            out.kind = ValueAst::Kind::Oid;
            return parseBraceParts(out.parts);
        }
        if (keywordEquals(peek(), "TRUE") ||
            keywordEquals(peek(), "FALSE")) {
            out.kind = ValueAst::Kind::Boolean;
            out.boolValue = keywordEquals(peek(), "TRUE");
            advance();
            return true;
        }
        if (keywordEquals(peek(), "NULL")) {
            out.kind = ValueAst::Kind::Null;
            advance();
            return true;
        }
        if (peek().kind == TokenKind::String) {
            out.kind = ValueAst::Kind::String;
            out.text = peek().text;
            advance();
            return true;
        }
        bool negated = false;
        if (peek().kind == TokenKind::Minus) {
            negated = true;
            advance();
        }
        if (peek().kind == TokenKind::Number) {
            out.kind = ValueAst::Kind::Integer;
            if (!parseSigned(peek(), negated, out.intValue)) {
                syntaxError(peek().pos, "integer value out of range");
                return false;
            }
            advance();
            return true;
        }
        if (peek().kind == TokenKind::Identifier && !negated) {
            out.kind = ValueAst::Kind::Reference;
            out.text = peek().text;
            advance();
            return true;
        }
        syntaxError(peek().pos, "expected value");
        return false;
    }

    bool parseBraceParts(std::vector<BracePartAst> &out)
    {
        if (!expectToken(TokenKind::LBrace, "expected '{'")) {
            return false;
        }
        while (true) {
            if (peek().kind == TokenKind::RBrace) {
                advance();
                return true;
            }
            if (peek().kind == TokenKind::End) {
                syntaxError(peek().pos, "missing '}'");
                return false;
            }
            BracePartAst part;
            part.pos = peek().pos;
            if (peek().kind == TokenKind::Number) {
                part.hasNumber = true;
                uint64_t number = 0;
                if (!parseUnsigned(peek(), number)) {
                    syntaxError(peek().pos, "arc value out of range");
                    return false;
                }
                part.number = number;
                advance();
            } else if (peek().kind == TokenKind::Identifier) {
                part.hasName = true;
                part.name = peek().text;
                advance();
                if (peek().kind == TokenKind::LParen) {
                    advance();
                    if (peek().kind != TokenKind::Number) {
                        syntaxError(peek().pos, "expected number");
                        return false;
                    }
                    uint64_t number = 0;
                    if (!parseUnsigned(peek(), number)) {
                        syntaxError(peek().pos, "arc value out of range");
                        return false;
                    }
                    part.hasNumber = true;
                    part.number = number;
                    advance();
                    if (!expectToken(TokenKind::RParen, "expected ')'")) {
                        return false;
                    }
                }
            } else {
                syntaxError(peek().pos, "expected value component");
                return false;
            }
            out.push_back(part);
            if (peek().kind == TokenKind::Comma) {
                advance();
            }
        }
    }

    bool parseUnsigned(const Token &token, uint64_t &out) const
    {
        uint64_t value = 0;
        for (char c : token.text) {
            if (c < '0' || c > '9') {
                return false;
            }
            const uint64_t digit = static_cast<uint64_t>(c - '0');
            if (value > (UINT64_MAX - digit) / 10u) {
                return false;
            }
            value = value * 10u + digit;
        }
        out = value;
        return true;
    }

    bool parseSigned(const Token &token, bool negated, int64_t &out) const
    {
        uint64_t magnitude = 0;
        if (!parseUnsigned(token, magnitude)) {
            return false;
        }
        if (negated) {
            if (magnitude > static_cast<uint64_t>(INT64_MAX) + 1u) {
                return false;
            }
            if (magnitude == static_cast<uint64_t>(INT64_MAX) + 1u) {
                out = INT64_MIN;
            } else {
                out = -static_cast<int64_t>(magnitude);
            }
        } else {
            if (magnitude > static_cast<uint64_t>(INT64_MAX)) {
                return false;
            }
            out = static_cast<int64_t>(magnitude);
        }
        return true;
    }

    const std::string &file_;
    const std::vector<Token> &tokens_;
    Diagnostics &diagnostics_;
    size_t index_ = 0;
};

} /* namespace */

bool parseModule(const std::string &file, const std::string &source,
                 ModuleAst &out, Diagnostics &diagnostics)
{
    std::vector<Token> tokens;
    if (!tokenize(file, source, tokens, diagnostics)) {
        return false;
    }
    Parser parser(file, tokens, diagnostics);
    return parser.run(out);
}

} /* namespace asn1c */
