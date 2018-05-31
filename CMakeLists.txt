cmake_minimum_required (VERSION 3.11)

project(kcron)

set(VERSION "1.0")

option (USE_CAPABILITIES 
        "Use capabilities to reduce privileges" TRUE)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

include(doc/CMakeLists.txt)
include(src/C/CMakeLists.txt)
include(src/shell/CMakeLists.txt)
