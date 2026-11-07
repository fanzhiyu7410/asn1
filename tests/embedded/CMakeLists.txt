# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 嵌入式最小用例：静态池 / 无堆 / 无标准 IO。
# 宿主构建时注册为 CTest；交叉编译时只构建与链接，不做运行验证。

add_executable(test_embedded_pool embedded_pool.c)
set_target_properties(test_embedded_pool PROPERTIES C_STANDARD 99
                                                     C_STANDARD_REQUIRED ON)

if(TARGET asn1::static)
  target_link_libraries(test_embedded_pool PRIVATE asn1::static)
else()
  target_link_libraries(test_embedded_pool PRIVATE asn1::shared)
  if(WIN32)
    add_custom_command(
      TARGET test_embedded_pool POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:asn1::shared> $<TARGET_FILE_DIR:test_embedded_pool>
    )
  endif()
endif()

if(NOT CMAKE_CROSSCOMPILING)
  add_test(NAME test_embedded_pool COMMAND test_embedded_pool)

  # 宿主测量：静态池 + PKIX 描述表 + 真实证书解码 的最小池尺寸。
  add_executable(test_pkix_pool test_pkix_pool.c)
  set_target_properties(test_pkix_pool PROPERTIES C_STANDARD 99
                                                   C_STANDARD_REQUIRED ON)
  target_include_directories(
    test_pkix_pool PRIVATE
      ${PROJECT_SOURCE_DIR}/modules/pkix/generated
      ${PROJECT_SOURCE_DIR}/tests/data
  )
  if(TARGET asn1::static)
    target_link_libraries(test_pkix_pool PRIVATE asn1::static)
  else()
    target_link_libraries(test_pkix_pool PRIVATE asn1::shared)
  endif()
  add_test(NAME test_pkix_pool COMMAND test_pkix_pool)

  # 宿主测量：静态池 + 模块真实 open 的最小池，并验证池耗尽错误码。
  foreach(_module IN ITEMS pkcs cms)
    if(TARGET asn1::${_module}::static OR TARGET asn1::${_module}::shared)
      add_executable(test_${_module}_pool test_${_module}_pool.c)
      set_target_properties(test_${_module}_pool PROPERTIES C_STANDARD 99
                                                            C_STANDARD_REQUIRED ON)
      target_include_directories(
        test_${_module}_pool PRIVATE
          ${PROJECT_SOURCE_DIR}/tests/data
      )
      if(TARGET asn1::${_module}::static)
        target_link_libraries(test_${_module}_pool PRIVATE
                              asn1::${_module}::static)
      else()
        target_link_libraries(test_${_module}_pool PRIVATE
                              asn1::${_module}::shared)
        if(WIN32)
          add_custom_command(
            TARGET test_${_module}_pool POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
              $<TARGET_FILE:asn1::${_module}::shared>
              $<TARGET_FILE:asn1::shared>
              $<TARGET_FILE_DIR:test_${_module}_pool>
          )
        endif()
      endif()
      add_test(NAME test_${_module}_pool COMMAND test_${_module}_pool)
    endif()
  endforeach()
endif()
