/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 上下文与错误状态 C API 边界。
 *
 * 职责：校验调用方参数、把 C 句柄转换为内部 Context，并填充错误详情。
 * 依赖：core/asn1_context.h。
 * 约束：不新增公共符号；所有失败通过 asn1_err_t 返回。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include <asn1/asn1.h>

#include "core/asn1_context.h"

#include <cstdlib>
#include <cstring>

namespace {

asn1::Context *contextOf(asn1_ctx_t *handle) noexcept
{
    return static_cast<asn1::Context *>(static_cast<void *>(handle));
}

const asn1::Context *contextOf(const asn1_ctx_t *handle) noexcept
{
    return static_cast<const asn1::Context *>(static_cast<const void *>(handle));
}

void *defaultAlloc(void *user, size_t size) noexcept
{
    (void)user;
    return std::malloc(size);
}

void *defaultRealloc(void *user, void *ptr, size_t size) noexcept
{
    (void)user;
    return std::realloc(ptr, size);
}

void defaultFree(void *user, void *ptr) noexcept
{
    (void)user;
    std::free(ptr);
}

const asn1_allocator_t &defaultAllocator() noexcept
{
    static const asn1_allocator_t allocator = {
        sizeof(asn1_allocator_t), nullptr, defaultAlloc, defaultRealloc,
        defaultFree};
    return allocator;
}

} /* namespace */

// ============================================================================
// 类型定义
// ============================================================================

// 内部类型位于 core/asn1_context.h。

// ============================================================================
// 静态常量 / 内部辅助类型
// ============================================================================

// 默认分配器为函数内静态常量，避免运行期构造顺序依赖。

// ============================================================================
// 构造与析构
// ============================================================================

// 上下文构造在下方公共接口中完成。

// ============================================================================
// 公共接口
// ============================================================================

extern "C" void asn1_ctx_config_init(asn1_ctx_config_t *config)
{
    if (config == nullptr) {
        return;
    }
    std::memset(config, 0, sizeof(asn1_ctx_config_t));
    config->struct_size = sizeof(asn1_ctx_config_t);
}

extern "C" asn1_err_t asn1_ctx_size_for_config(const asn1_ctx_config_t *config,
                                               size_t *out_size)
{
    if (out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_size = 0;

    asn1_err_t error = ASN1_OK;
    if (asn1::validateConfig(config, &error) != ASN1_OK) {
        return error;
    }

    const size_t required =
        asn1::alignUp(sizeof(asn1::Context), alignof(std::max_align_t));
    *out_size = required;
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_ctx_create(const asn1_ctx_config_t *config,
                                      asn1_ctx_t **out_ctx)
{
    if (out_ctx == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_ctx = nullptr;
    if (config == nullptr) {
        return ASN1_E_INVALID_ARG;
    }

    asn1_err_t error = ASN1_OK;
    if (asn1::validateConfig(config, &error) != ASN1_OK) {
        return error;
    }

    const size_t required =
        asn1::alignUp(sizeof(asn1::Context), alignof(std::max_align_t));

    void *memory = nullptr;
    const asn1_allocator_t *allocator = config->allocator;

    if (config->static_pool != nullptr) {
        if (config->static_pool_size < required) {
            return ASN1_E_INVALID_CONFIG;
        }
        memory = config->static_pool;
    } else {
        const asn1_allocator_t &effective =
            allocator != nullptr ? *allocator : defaultAllocator();
        memory = effective.alloc(effective.user, sizeof(asn1::Context));
        if (memory == nullptr) {
            return ASN1_E_NOMEM;
        }
    }

    std::memset(memory, 0, sizeof(asn1::Context));
    asn1::Context *ctx = static_cast<asn1::Context *>(memory);
    const asn1_err_t rc = asn1::contextInit(ctx, config);
    if (rc != ASN1_OK) {
        if (config->static_pool == nullptr) {
            const asn1_allocator_t &effective =
                allocator != nullptr ? *allocator : defaultAllocator();
            effective.free(effective.user, memory);
        }
        return rc;
    }

    *out_ctx = reinterpret_cast<asn1_ctx_t *>(ctx);
    return ASN1_OK;
}

extern "C" void asn1_ctx_destroy(asn1_ctx_t *handle)
{
    if (handle == nullptr) {
        return;
    }
    asn1::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asn1::kContextMagic) {
        return;
    }

    const bool usesPool = ctx->m_usesStaticPool;
    const asn1_allocator_t allocator = ctx->m_allocator;

    asn1::contextDestroy(ctx);
    if (!usesPool) {
        allocator.free(allocator.user, ctx);
    }
}

extern "C" asn1_err_t asn1_ctx_get_error(const asn1_ctx_t *handle,
                                         asn1_error_info_t *out_info)
{
    if (handle == nullptr || out_info == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (out_info->struct_size != sizeof(asn1_error_info_t)) {
        return ASN1_E_INVALID_CONFIG;
    }

    const asn1::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asn1::kContextMagic) {
        return ASN1_E_INVALID_ARG;
    }

    out_info->code = ctx->m_errorCode;
    out_info->callback_code =
        (ctx->m_errorCode == ASN1_E_IO_READ ||
         ctx->m_errorCode == ASN1_E_IO_WRITE)
            ? ctx->m_callbackCode
            : 0;
    out_info->message = asn1::errorMessage(ctx->m_errorCode);
    out_info->offset = ctx->m_errorCode == ASN1_OK ? SIZE_MAX
                                                   : ctx->m_errorOffset;
    out_info->depth = ctx->m_errorCode == ASN1_OK ? 0 : ctx->m_errorDepth;
    out_info->reserved = 0;
    out_info->path = (ctx->m_errorCode != ASN1_OK && ctx->m_hasErrorPath)
                         ? ctx->m_errorPath
                         : nullptr;
    return ASN1_OK;
}

extern "C" void asn1_ctx_clear_error(asn1_ctx_t *handle)
{
    if (handle == nullptr) {
        return;
    }
    asn1::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asn1::kContextMagic) {
        return;
    }
    asn1::contextClearError(ctx);
}

// ============================================================================
// 告警接口（本轮解码不产生告警，记录数恒为 0）
// ============================================================================

extern "C" asn1_err_t asn1_ctx_set_warning_handler(asn1_ctx_t *handle,
                                                   asn1_warning_fn handler,
                                                   void *user)
{
    if (handle == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asn1::kContextMagic) {
        return ASN1_E_INVALID_ARG;
    }
    ctx->m_warningHandler = handler;
    ctx->m_warningUser = user;
    return ASN1_OK;
}

extern "C" size_t asn1_ctx_warning_count(const asn1_ctx_t *handle)
{
    if (handle == nullptr) {
        return 0;
    }
    const asn1::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asn1::kContextMagic) {
        return 0;
    }
    return static_cast<size_t>(ctx->m_warningCount);
}

extern "C" asn1_err_t asn1_ctx_get_warning(const asn1_ctx_t *handle,
                                           size_t index,
                                           asn1_warning_t *out_warning)
{
    if (handle == nullptr || out_warning == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (out_warning->struct_size != sizeof(asn1_warning_t)) {
        return ASN1_E_INVALID_CONFIG;
    }
    const asn1::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asn1::kContextMagic) {
        return ASN1_E_INVALID_ARG;
    }
    if (index >= static_cast<size_t>(ctx->m_warningCount)) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1::WarningRecord *record = asn1::contextWarningAt(ctx, index);
    if (record == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    out_warning->code = record->code;
    out_warning->offset = record->offset;
    out_warning->depth = record->depth;
    out_warning->field_name = record->fieldName;
    out_warning->message = record->message;
    return ASN1_OK;
}

extern "C" void asn1_ctx_clear_warnings(asn1_ctx_t *handle)
{
    if (handle == nullptr) {
        return;
    }
    asn1::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asn1::kContextMagic) {
        return;
    }
    asn1::contextClearWarnings(ctx);
}