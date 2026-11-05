# SPDX-License-Identifier: MIT
cmake_minimum_required (VERSION 3.11)

project(kcron C)

set(LANGUAGES "C")

include(FeatureSummary)

set_package_properties(kcron PROPERTIES
 URL "https://github.com/fermitools/kcron"
 DESCRIPTION "A utility for getting Kerberos credentials in scheduled jobs")

execute_process(COMMAND git describe --abbrev=0 OUTPUT_VARIABLE VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)

####
set(CPACK_PACKAGE_NAME "fermilab-util_${CMAKE_PROJECT_NAME}")
set(CPACK_PACKAGE_CONTACT "fermilab <servicedesk@fnal.gov>")
set(CPACK_PACKAGE_DESCRIPTION "A utility for getting Kerberos credentials in scheduled jobs")
set(CPACK_PACKAGE_VERSION ${VERSION})

set(CPACK_RESOURCE_FILE_LICENSE ${PROJECT_SOURCE_DIR}/LICENSE)
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")

include(CPack)

####
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
        "Build type (Debug, Release, RelWithDebInfo, MinSizeRel)" FORCE
    )
    message(STATUS "Build type not specified, defaulting to RelWithDebInfo")
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

### Require out-of-source builds
file(TO_CMAKE_PATH "${PROJECT_BINARY_DIR}/CMakeLists.txt" LOC_PATH)
if(EXISTS "${LOC_PATH}")
    message(FATAL_ERROR "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please make a build subdirectory and run cmake from there.")
endif(EXISTS "${LOC_PATH}")


####
# My CMake files
include(doc/CMakeLists.txt)
include(src/C/CMakeLists.txt)
include(src/shell/CMakeLists.txt)

# Testing (CTest)
enable_testing()
include(CTest)
add_subdirectory(test)

####
# Print out feature summary
message("${CMAKE_PROJECT_NAME} - ${VERSION}")
feature_summary(WHAT ALL)
feature_summary(FILENAME ${CMAKE_CURRENT_BINARY_DIR}/features.log WHAT ALL)
