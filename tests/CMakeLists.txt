# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT
# 测试骨架。当前用无第三方依赖的最小 C 用例覆盖已落地的版本查询契约；
# doctest 与 libFuzzer 在登记后接入，规划见 docs/07-测试与验证.md。

if(NOT ASN1_BUILD_TESTS)
  return()
endif()

# 统一注册 C 测试：优先静态库（避免 Windows 运行期 DLL 路径问题），
# 仅共享库构建时把 DLL 复制到测试可执行文件目录。
function(asn1_add_test name source)
  add_executable(${name} ${source})
  if(TARGET asn1::static)
    target_link_libraries(${name} PRIVATE asn1::static)
  else()
    target_link_libraries(${name} PRIVATE asn1::shared)
    if(WIN32)
      add_custom_command(
        TARGET ${name} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:asn1::shared> $<TARGET_FILE_DIR:${name}>
      )
    endif()
  endif()
  set_target_properties(
    ${name}
    PROPERTIES
      LINKER_LANGUAGE CXX
      C_STANDARD 99
      C_STANDARD_REQUIRED ON
  )
  if(MSVC)
    target_compile_options(${name} PRIVATE /utf-8)
  endif()
  add_test(NAME ${name} COMMAND ${name})
endfunction()

add_subdirectory(support)
add_subdirectory(embedded)
add_subdirectory(unit)
add_subdirectory(c_api)
add_subdirectory(headers)

# 模块用例依赖模块目标；模块未构建时跳过。
if(TARGET asn1::pkix::static OR TARGET asn1::pkix::shared)
  add_subdirectory(pkix)
endif()
if(TARGET asn1::pkcs::static OR TARGET asn1::pkcs::shared)
  add_subdirectory(pkcs)
endif()
if(TARGET asn1::cms::static OR TARGET asn1::cms::shared)
  add_subdirectory(cms)
endif()

add_subdirectory(conformance)
add_subdirectory(fuzz)

# asn1c 端到端测试依赖工具目标，仅在构建 asn1c 时接入。
if(TARGET asn1c)
  add_subdirectory(asn1c)
endif()
