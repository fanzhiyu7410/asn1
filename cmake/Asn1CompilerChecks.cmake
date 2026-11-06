# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 编译选项与告警分层。
# 公共头文件只暴露 C ABI，因此 C++ 标准要求对消费者保持 PRIVATE。
include_guard(GLOBAL)

# 核心与模块共享的方言、告警、可见性与 sanitizer 设置。
# 调用方负责补充各自的 include 目录与构建期定义。
function(asn1_apply_common_settings target)
  target_compile_features(${target} PRIVATE cxx_std_${ASN1_CXX_STANDARD})

  set_target_properties(
    ${target}
    PROPERTIES
      CXX_EXTENSIONS OFF
      CXX_VISIBILITY_PRESET hidden
      VISIBILITY_INLINES_HIDDEN ON
  )

  if(ASN1_FREESTANDING)
    target_compile_definitions(${target} PRIVATE ASN1_FREESTANDING=1)
  endif()

  if(MSVC)
    target_compile_options(${target} PRIVATE /EHs-c- /GR-)
    target_compile_definitions(${target} PRIVATE _HAS_EXCEPTIONS=0)
  else()
    target_compile_options(${target} PRIVATE -fno-exceptions -fno-rtti)
  endif()

  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
  else()
    target_compile_options(
      ${target}
      PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
    )
  endif()

  if(ASN1_WARNINGS_AS_ERRORS)
    if(MSVC)
      target_compile_options(${target} PRIVATE /WX)
    else()
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()

  if(ASN1_ENABLE_SANITIZERS)
    if(MSVC)
      message(WARNING "ASN1_ENABLE_SANITIZERS 在 MSVC 下未接入，请改用 clang-cl 或宿主平台工具链")
    else()
      target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
  endif()
endfunction()

# 核心库目标设置：核心 include 目录、生成版本头目录、内部 src 目录与核心构建期定义。
function(asn1_apply_library_settings target)
  set(generated_include_dirs)
  if(ASN1_GENERATED_INCLUDE_DIR)
    list(APPEND generated_include_dirs
      $<BUILD_INTERFACE:${ASN1_GENERATED_INCLUDE_DIR}>)
  endif()

  target_include_directories(
    ${target}
    PUBLIC
      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
      ${generated_include_dirs}
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
      ${PROJECT_SOURCE_DIR}/src
  )

  target_compile_definitions(${target} PRIVATE ASN1_BUILDING_LIBRARY)

  asn1_apply_common_settings(${target})
endfunction()
