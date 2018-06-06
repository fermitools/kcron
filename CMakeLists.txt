cmake_minimum_required (VERSION 3.11)

project(kcron)

set(VERSION "1.0")

MACRO(MACRO_ENSURE_OUT_OF_SOURCE_BUILD MSG)
    STRING(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}" insource)
    GET_FILENAME_COMPONENT(PARENTDIR ${CMAKE_SOURCE_DIR} PATH)
    STRING(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${PARENTDIR}" insourcesubdir)
    IF(insource OR insourcesubdir)
        MESSAGE(FATAL_ERROR "${MSG}")
    ENDIF(insource OR insourcesubdir)
ENDMACRO(MACRO_ENSURE_OUT_OF_SOURCE_BUILD)

macro_ensure_out_of_source_build("Must build from sub directory: mkdir build ; cd build; cmake ../")

option (USE_CAPABILITIES 
        "Use capabilities to reduce privileges" TRUE)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

include(doc/CMakeLists.txt)
include(src/C/CMakeLists.txt)
include(src/shell/CMakeLists.txt)
