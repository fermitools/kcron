cmake_minimum_required (VERSION 3.14)

#############################
# Load CMake provided modules
include(CheckIncludeFile)
include(CheckIPOSupported)
include(CheckCCompilerFlag)
include(CheckPIESupported)
include(CMakePrintHelpers)
include(FeatureSummary)
include(GNUInstallDirs)

#############################
# Configuration Variables
# These can be overridden by builders, but defaults are provided.

if (NOT CLIENT_KEYTAB_DIR)
  set(CLIENT_KEYTAB_DIR /var/kerberos/krb5/user)
  cmake_print_variables(CLIENT_KEYTAB_DIR)
endif(NOT CLIENT_KEYTAB_DIR)

if (NOT FILE_PATH_MAX_LENGTH)
  set(FILE_PATH_MAX_LENGTH 4096)
  cmake_print_variables(FILE_PATH_MAX_LENGTH)
endif(NOT FILE_PATH_MAX_LENGTH)

#############################
# C Language Configuration
enable_language(C)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

#############################
# Compiler Sanity Test
CHECK_C_SOURCE_COMPILES("int main(void) { return 0; } " CAN_COMPILE)
if (NOT CAN_COMPILE)
  message(FATAL_ERROR "C compiler is non-functional")
endif(NOT CAN_COMPILE)

message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C Standard: C${CMAKE_C_STANDARD}")
message(STATUS "Supported C features: ${CMAKE_C_COMPILE_FEATURES}")

#############################
# Required Security Features

CHECK_INCLUDE_FILE(sys/capability.h HAVE_CAPABILITIES_H)
if (NOT HAVE_CAPABILITIES_H)
  message(FATAL_ERROR "sys/capability.h is REQUIRED - install libcap-dev or libcap-devel")
endif(NOT HAVE_CAPABILITIES_H)

#############################
# Optional Security Features

option (USE_LANDLOCK "Use landlock to reduce privilege exposure" TRUE)
if (USE_LANDLOCK)
  CHECK_INCLUDE_FILE(linux/landlock.h HAVE_LANDLOCK_H)
  if (NOT HAVE_LANDLOCK_H)
    message(FATAL_ERROR "linux/landlock.h not found - landlock support requested")
    set(USE_LANDLOCK FALSE)
  endif(NOT HAVE_LANDLOCK_H)
endif(USE_LANDLOCK)
add_feature_info(WITH_LANDLOCK USE_LANDLOCK "Use landlock to reduce privilege exposure")

option (USE_SECCOMP "Add seccomp filters for binaries" TRUE)
if (USE_SECCOMP)
  CHECK_INCLUDE_FILE(seccomp.h HAVE_SECCOMP_H)
  if (NOT HAVE_SECCOMP_H)
    message(FATAL_ERROR "seccomp.h not found - seccomp support requested")
    set(USE_SECCOMP FALSE)
  endif(NOT HAVE_SECCOMP_H)
endif(USE_SECCOMP)
add_feature_info(WITH_SECCOMP USE_SECCOMP "Add seccomp filters for binaries")

#############################
# Position Independent Code (PIE)
check_pie_supported(OUTPUT_VARIABLE output LANGUAGES C)
if(CMAKE_C_LINK_PIE_SUPPORTED)
  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
  message(STATUS "PIE support: enabled")
else()
  message(WARNING "PIE is not supported at link time: ${output}")
  message(WARNING "PIE link options will not be passed to linker")
endif(CMAKE_C_LINK_PIE_SUPPORTED)

#############################
# Interprocedural Optimization (LTO)
check_ipo_supported(RESULT IPO_RESULT)
if(IPO_RESULT)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
  message(STATUS "LTO/IPO support: enabled")
else()
  message(WARNING "Interprocedural Optimization is not supported: ${output}")
  message(WARNING "LTO will not be enabled")
endif(IPO_RESULT)

#############################
# Required Compiler Warnings
# These warnings help catch common security issues and bugs
add_compile_options(
  -Wall                                  # Enable most warnings
  -Wextra                                # Enable extra warnings
  -Wpedantic                             # ISO C conformance warnings
  -Wconversion                           # Implicit conversion warnings
  -Wsign-conversion                      # Sign conversion warnings
  -Wformat=2                             # Enhanced format string warnings
  -Wformat-security                      # Format security issues
  -Wstrict-prototypes                    # Require function prototypes
  -Wstrict-overflow=2                    # Overflow detection (level 2)
  -Wvla                                  # Variable length arrays discouraged
  -Wshadow                               # Warn on shadowed variables
  -Walloca                               # Warn on suspicious alloca usage
  -Wcast-qual                            # Warn on cast removing const/volatile
  -Wcast-align                           # Warn on alignment-affecting casts
  -Wwrite-strings                        # String literals are const
  -Wundef                                # Undefined macro in #if
  -Wmissing-prototypes                   # Missing function prototypes
  -Wmissing-declarations                 # Missing declarations
  -Wredundant-decls                      # Redundant declarations
  -Wnested-externs                       # Nested extern declarations
  -Winline                               # Inline function can't be inlined
  -Wdisabled-optimization                # Optimization disabled
  -Werror=implicit-function-declaration  # Error on implicit declarations
  -Werror                                # Treat all warnings as errors
)

# Additional hardening for formats
add_compile_options(-D_GLIBCXX_ASSERTIONS)

# Additional GCC features (not supported by all compilers)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(
        -Wlogical-op                       # Suspicious logical operations
        -Wduplicated-cond                  # Duplicated conditions
        -Wduplicated-branches              # Duplicated branches
        -Wnull-dereference                 # Potential NULL dereferences
        -Wjump-misses-init                 # Jump skips variable initialization
    )

  check_c_compiler_flag(-fplugin=annobin SET_ANNOBIN)
  if(SET_ANNOBIN)
    add_compile_options(-fplugin=annobin)
    message(STATUS "GCC Annobin plugin: enabled")
  else()
    message(WARNING "GCC Annobin plugin not available")
  endif(SET_ANNOBIN)

  check_c_compiler_flag(-grecord-gcc-switches SET_GCC_SWITCHES)
  if(SET_GCC_SWITCHES)
    add_compile_options(-grecord-gcc-switches)
    message(STATUS "Recording GCC switches: enabled")
  else()
    message(WARNING "Cannot record GCC switches in binary")
  endif(SET_GCC_SWITCHES)
endif(CMAKE_C_COMPILER_ID STREQUAL "GNU")

#############################
# Stack Unwinding Support (required for debugging)
CHECK_C_COMPILER_FLAG(-fasynchronous-unwind-tables UNWIND_TABLES)
if (UNWIND_TABLES)
  add_compile_options(-fasynchronous-unwind-tables)
  message(STATUS "Unwind tables: enabled")
else ()
  message(WARNING "Compiler does not support -fasynchronous-unwind-tables")
endif(UNWIND_TABLES)

#############################
# Stack Frame Pointer Support (required for debugging)
CHECK_C_COMPILER_FLAG(-fno-omit-frame-pointer FRAME_POINTER)
if (FRAME_POINTER)
  add_compile_options(-fno-omit-frame-pointer)
  message(STATUS "Frame pointer: enabled")
else()
  message(WARNING "Compiler does not support -fno-omit-frame-pointer")
endif(FRAME_POINTER)

#############################
# Function Inlining Optimization
CHECK_C_COMPILER_FLAG(-finline-functions INLINE_FUNCTIONS)
if (INLINE_FUNCTIONS)
  add_compile_options(-finline-functions)
  message(STATUS "Aggressive inline functions: enabled")
else ()
  message(WARNING "Compiler does not support -finline-functions")
endif(INLINE_FUNCTIONS)

#############################
# Linker Hardening Flags
# These flags prevent various exploit techniques
# -Wl,-z,defs  -- doesn't work with modern RHEL
add_link_options(
  -Wl,--as-needed       # Only link used symbols
  -Wl,-z,noexecstack    # Mark stack as non-executable
  -Wl,-z,nodump         # Prevent dumping
  -Wl,-z,relro          # Read-only relocations
  -Wl,-z,now            # Resolve all symbols at load time
  -Wl,-z,combreloc      # Combine relocation sections
  -Wl,-z,ibt            # Fail at runtime if ibt fails
  -Wl,-z,shstk          # Fail at runtime if no shadow stack
)

#############################
# Compiler Hardening Flags

# Stack protector: ALL
check_c_compiler_flag(-fstack-protector-all HAVE_SSP_ALL)
if (HAVE_SSP_ALL)
  add_compile_options(-fstack-protector-all)
else()
  message(FATAL_ERROR "Required flag -fstack-protector-all not supported")
endif(HAVE_SSP_ALL)

# Stack clash protection
CHECK_C_COMPILER_FLAG(-fstack-clash-protection STACK_CLASH)
if (STACK_CLASH)
  add_compile_options(-fstack-clash-protection)
  message(STATUS "Stack clash protection: enabled")
else ()
  message(WARNING "Stack clash protection not supported by compiler")
endif(STACK_CLASH)

# Disable stack slot reuse
CHECK_C_COMPILER_FLAG(-fstack-reuse=none STACK_REUSE)
if (STACK_REUSE)
  add_compile_options(-fstack-reuse=none)
else ()
  message(FATAL_ERROR "Required compiler flag '-fstack-reuse=none' not supported")
endif(STACK_REUSE)

# Zero call-used registers on return
check_c_compiler_flag(-fzero-call-used-regs=all HAVE_ZERO_CALL_REGS)
if (HAVE_ZERO_CALL_REGS)
  add_compile_options(-fzero-call-used-regs=all)
endif(HAVE_ZERO_CALL_REGS)

# Control-flow enforcement
if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
  # x86_64
  check_c_compiler_flag(-fcf-protection=full HAVE_CET)
  if (HAVE_CET)
    add_compile_options(-fcf-protection=full)
  else()
    message(FATAL_ERROR "Intel CET (-fcf-protection=full) required on x86_64")
  endif(HAVE_CET)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
  # ARM
  check_c_compiler_flag(-mbranch-protection=standard HAVE_BTI)
  if (HAVE_BTI)
    add_compile_options(-mbranch-protection=standard)
  else()
    message(FATAL_ERROR "Branch Protection (-mbranch-protection=standard) required on aarch64")
  endif(HAVE_BTI)
endif()

#############################
# Build Targets

add_executable(init-kcron-keytab)
add_executable(client-keytab-name)

#############################
# Installation Configuration

install(TARGETS init-kcron-keytab DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/kcron
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
install(TARGETS client-keytab-name DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/kcron
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Install libexec: ${CMAKE_INSTALL_LIBEXECDIR}")

#############################
# init-kcron-keytab Target Configuration

target_compile_features(init-kcron-keytab PRIVATE
  c_std_17
  c_restrict
  c_function_prototypes
  c_static_assert
)

target_sources(init-kcron-keytab PRIVATE
  ${PROJECT_SOURCE_DIR}/src/C/init-kcron-keytab.c
)

# Link required libraries
target_link_libraries(init-kcron-keytab PRIVATE cap)

if (USE_SECCOMP)
  target_link_libraries(init-kcron-keytab PRIVATE seccomp)
endif(USE_SECCOMP)

#############################
# client-keytab-name Target Configuration

target_compile_features(client-keytab-name PRIVATE
  c_std_17
  c_restrict
  c_function_prototypes
  c_static_assert
)

target_sources(client-keytab-name PRIVATE
  ${PROJECT_SOURCE_DIR}/src/C/client-keytab-name.c
)

# This tool doesn't need any special libraries (no caps, no seccomp)

#############################
# Generate Configuration Header

configure_file(
  "${PROJECT_SOURCE_DIR}/src/C/autoconf.h.in"
  "${PROJECT_BINARY_DIR}/src/C/autoconf.h"
  @ONLY
)

# Add include directories
include_directories(${PROJECT_BINARY_DIR}/src/C/)
include_directories(${PROJECT_SOURCE_DIR}/src/C/)

#############################
# Security Warnings

message(STATUS "")
message(STATUS "=== SECURITY NOTICE ===")
message(STATUS "init-kcron-keytab MUST be installed with file capabilities:")
message(STATUS "  capabilities: setcap cap_chown,cap_dac_override=ep ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBEXECDIR}/kcron/init-kcron-keytab")
message(STATUS "")
message(STATUS "The program will drop privileges immediately after creating the keytab file.")
message(STATUS "======================")
message(STATUS "")

#############################
# Static Analysis Targets

# cppcheck static analysis
add_custom_target(cppcheck
  COMMAND cppcheck
    --xml
    --xml-version=2
    --enable=all
    --std=c17
    --suppress=missingIncludeSystem
    ${PROJECT_SOURCE_DIR}/src/
    2>${PROJECT_BINARY_DIR}/cppcheck.xml
  COMMAND mkdir -p ${PROJECT_BINARY_DIR}/cppcheck
  COMMAND cppcheck-htmlreport
    --source-dir=${PROJECT_SOURCE_DIR}/src/
    --title=kcron
    --file=${PROJECT_BINARY_DIR}/cppcheck.xml
    --report-dir=${PROJECT_BINARY_DIR}/cppcheck
  COMMENT "Running cppcheck static analysis"
)

#############################
# Suppress Unused Variable Warnings
# These are used in trace commands but otherwise unused
set(IgnoreMe "${BUILD_SHARED_LIBS}${CMAKE_CXX_FLAGS_RELEASE}${CMAKE_C_FLAGS_RELEASE}${CMAKE_Fortran_FLAGS_RELEASE}${INCLUDE_INSTALL_DIR}${LIB_INSTALL_DIR}${LIB_SUFFIX}${SHARE_INSTALL_PREFIX}")

#############################
# Feature Summary
feature_summary(WHAT ALL)

#############################
## CMake Debugging Cheat Sheet
## Uncomment these for troubleshooting:
# cmake_print_variables(MY_VARIABLE)
# cmake_print_properties(TARGETS my_target PROPERTIES POSITION_INDEPENDENT_CODE)
# cmake -S . -B build --trace-expand --trace-source=CMakeLists.txt
#############################
