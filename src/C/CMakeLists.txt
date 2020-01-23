cmake_minimum_required (VERSION 3.14)

#############################
# Set C standards
enable_language(C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

#############################
# Load CMake provided modules
include(CheckIncludeFile)
include(CheckIPOSupported)
include(CheckCCompilerFlag)
include(CheckPIESupported)
include(CMakePrintHelpers)
include(FeatureSummary)
include(GNUInstallDirs)

CHECK_C_SOURCE_COMPILES("int main(void) { return 0; } " CAN_COMPILE)
if (NOT CAN_COMPILE)
  message(FATAL_ERROR "Compiler non functional")
endif (NOT CAN_COMPILE)

message(STATUS "C Compiler ${CMAKE_C_COMPILER}")
message(STATUS " Supported C features = ${CMAKE_C_COMPILE_FEATURES}")

#############################
# Add our feature options
option (USE_CAPABILITIES "Use capabilities to reduce privileges" TRUE)
if (USE_CAPABILITIES)
  CHECK_INCLUDE_FILE(sys/capability.h HAVE_CAPABILITIES_H)
  if (NOT HAVE_CAPABILITIES_H)
    message(FATAL_ERROR "sys/capability.h requested, but not found")
  endif (NOT HAVE_CAPABILITIES_H)

  add_link_options(-lcap)
endif (USE_CAPABILITIES)
add_feature_info(WITH_CAPABILITIES USE_CAPABILITIES "Use capabilities to reduce privileges")

option (USE_SYSTEMTAP "Add systemtap tracepoints for capabilities" TRUE)
if (USE_SYSTEMTAP)
  CHECK_INCLUDE_FILE(sys/sdt.h HAVE_SDT_H)
  if (NOT HAVE_SDT_H)
    message(FATAL_ERROR "sys/sdt.h requested, but not found")
  endif (NOT HAVE_SDT_H)
endif (USE_SYSTEMTAP)
add_feature_info(WITH_SYSTEMTAP USE_SYSTEMTAP "Add systemtap tracepoints for capabilities")

option (USE_SECCOMP "Add seccomp filters for binaries" FALSE)
if (USE_SECCOMP)
  CHECK_INCLUDE_FILE(linux/seccomp.h HAVE_SECCOMP_H)
  if (NOT HAVE_SECCOMP_H)
    message(FATAL_ERROR "linux/seccomp.h requested, but not found")
  endif (NOT HAVE_SECCOMP_H)
  message(FATAL_ERROR "SecComp not yet implemented")
endif (USE_SECCOMP)
add_feature_info(WITH_SECCOMP USE_SECCOMP "Add seccomp filters for binaries")


#############################
# Set Code position
check_pie_supported(OUTPUT_VARIABLE output LANGUAGES C)
if(CMAKE_C_LINK_PIE_SUPPORTED)
  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
else()
  message(WARNING "PIE is not supported at link time: ${output}.\n"
                  "PIE link options will not be passed to linker.")
endif(CMAKE_C_LINK_PIE_SUPPORTED)

check_ipo_supported(RESULT IPO_RESULT)
if(IPO_RESULT)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
  message(WARNING "Interprocedural Optimizationis not supported at link time: ${output}.\n"
                  "Interprocedural Optimization will not be passed to linker.")
endif(IPO_RESULT)

#############################
# Add required warnings level
add_compile_options(-Wall -Wpedantic -Wconversion -Wformat -Wformat-security -Wstrict-prototypes -Wstrict-overflow -Wextra -Werror)

#############################
# Ensure the linker is hardened
add_link_options(-Wl,-z,defs -Wl,-z,noexecstack -Wl,-z,nodump -Wl,-z,relro -Wl,-z,now -Wl,-pie -Wl,-z,combreloc)

#############################
# Permit sound debugging tables
CHECK_C_COMPILER_FLAG(-fasynchronous-unwind-tables UNWIND_TABLES)
if (UNWIND_TABLES)
  add_compile_options(-fasynchronous-unwind-tables)
else ()
  message(WARNING "compile flag '-fasynchronous-unwind-tables' not found")
endif (UNWIND_TABLES)

#############################
# Most of our internal functions can be inlined
CHECK_C_COMPILER_FLAG(-finline-functions INLINE_FUNCTIONS)
if (INLINE_FUNCTIONS)
  add_compile_options(-finline-functions)
else ()
  message(WARNING "Required compile flag '-finline-functions' not found")
endif (INLINE_FUNCTIONS)

#############################
# Harden the compiler

# Add -D_FORTIFY_SOURCE=2 hardening flags
# ssp-buffer-size has a minor performance hit, but eh
add_compile_options(-O2 -D_FORTIFY_SOURCE=2 --param=ssp-buffer-size=4)

CHECK_C_COMPILER_FLAG(-fexceptions C_EXCEPTIONS)
if (C_EXCEPTIONS)
  add_compile_options(-fexceptions)
else ()
  message(FATAL_ERROR "Required compile flag '-fexceptions' not found")
endif (C_EXCEPTIONS)

CHECK_C_COMPILER_FLAG(-fstack-clash-protection STACK_CLASH)
if (STACK_CLASH)
  add_compile_options(-fstack-clash-protection)
else ()
  message(FATAL_ERROR "Required compile flag '-fstack-clash-protection' not found")
endif (STACK_CLASH)

CHECK_C_COMPILER_FLAG(-fstack-reuse=none STACK_REUSE)
if (STACK_REUSE)
  add_compile_options(-fstack-reuse=none)
else ()
  message(FATAL_ERROR "Required compile flag '-fstack-reuse=none' not found")
endif (STACK_REUSE)

CHECK_C_COMPILER_FLAG(-fstack-protector-all STACK_PROTECT)
if (STACK_PROTECT)
  add_compile_options(-fstack-protector-all)
else ()
  message(FATAL_ERROR "Required compile flag '-fstack-protector-all' not found")
endif (STACK_PROTECT)

CHECK_C_COMPILER_FLAG(-mcet MCET)
if (MCET)
  add_compile_options(-mcet)
else ()
  message(WARNING "compile flag '-mcet' not found")
endif (MCET)

CHECK_C_COMPILER_FLAG(-fcf-protection FCF_PROTECT)
if (FCF_PROTECT)
  add_compile_options(-fcf-protection)
else ()
  message(WARNING "compile flag '-fcf-protection' not found")
endif (FCF_PROTECT)

#############################
#############################
#############################
# cmake_print_variables(MY_VARIABLE)
# cmake_print_properties( TARGETS my_target PROPERTIES POSITION_INDEPENDENT_CODE)
# cmake -S . -B build --trace-expand --trace-source=CMakeLists.txt
#############################
#############################
#############################

#############################
# Our build targets
add_executable(init-kcron-keytab)
add_executable(remove-kcron-keytab)

#############################
# Setup install target
install(TARGETS init-kcron-keytab remove-kcron-keytab DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/kcron)

#############################
# Our build targets specific options
target_compile_features(init-kcron-keytab PRIVATE c_std_11)
target_compile_features(init-kcron-keytab PRIVATE c_restrict)
target_compile_features(init-kcron-keytab PRIVATE c_function_prototypes)
target_compile_features(init-kcron-keytab PRIVATE c_static_assert)
target_sources(init-kcron-keytab PRIVATE ${PROJECT_SOURCE_DIR}/src/C/init-kcron-keytab.c)

target_compile_features(remove-kcron-keytab PRIVATE c_std_11)
target_compile_features(remove-kcron-keytab PRIVATE c_restrict)
target_compile_features(remove-kcron-keytab PRIVATE c_function_prototypes)
target_compile_features(remove-kcron-keytab PRIVATE c_static_assert)
target_sources(remove-kcron-keytab PRIVATE ${PROJECT_SOURCE_DIR}/src/C/remove-kcron-keytab.c)


########################################
########################################
########################################
########################################
########################################

execute_process(COMMAND bash "-c" "getent group users | cut -d ':' -f3 | tr -d '\\012'" OUTPUT_VARIABLE USER_GID)
cmake_print_variables(USER_GID)

set(KCRON_KEYTAB_DIR /var/adm/krb5)
set(CLIENT_KEYTAB /var/kerberos/krb5/user)
set(FILE_PATH_MAX_LENGTH 4096)

#############################
# Build config file
configure_file("${PROJECT_SOURCE_DIR}/src/C/autoconf.h.in" "${PROJECT_BINARY_DIR}/src/C/autoconf.h" @ONLY)
include_directories(${PROJECT_BINARY_DIR}/src/C/)
include_directories(${PROJECT_SOURCE_DIR}/src/C/)


set(IgnoreMe "${BUILD_SHARED_LIBS}${CMAKE_CXX_FLAGS_RELEASE}${CMAKE_C_FLAGS_RELEASE}${CMAKE_Fortran_FLAGS_RELEASE}${INCLUDE_INSTALL_DIR}${LIB_INSTALL_DIR}${LIB_SUFFIX}${SHARE_INSTALL_PREFIX}")
