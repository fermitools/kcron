cmake_minimum_required (VERSION 3.11)

include(CheckSymbolExists) 
include(CheckIncludeFile)
include(CheckCCompilerFlag)
include(GNUInstallDirs)

option (USE_SYSTEMTAP 
        "Add systemtap tracepoints for capabilities" TRUE)
option (USE_SECCOMP 
        "Add seccomp filters for binaries" FALSE)
option (USE_SANITIZE 
        "Add gcc sanitizers" TRUE)
option (USE_SANITIZE_AS_STATIC 
        "Add statically link gcc sanitizers" FALSE)

if (USE_CAPABILITIES)
  CHECK_INCLUDE_FILE(sys/capability.h HAVE_CAPABILITIES_H)
  if (NOT HAVE_CAPABILITIES_H)
    message(FATAL_ERROR "sys/capability.h requested, but not found")
  endif (NOT HAVE_CAPABILITIES_H)

  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lcap")
endif (USE_CAPABILITIES)

if (USE_SYSTEMTAP)
  CHECK_INCLUDE_FILE(sys/sdt.h HAVE_SDT_H)
  if (NOT HAVE_SDT_H)
    message(FATAL_ERROR "sys/sdt.h requested, but not found")
  endif (NOT HAVE_SDT_H)
endif (USE_SYSTEMTAP)

if (USE_SECCOMP)
  CHECK_INCLUDE_FILE(linux/seccomp.h HAVE_SECCOMP_H)
  if (NOT HAVE_SECCOMP_H)
    message(FATAL_ERROR "linux/seccomp.h requested, but not found")
  endif (NOT HAVE_SECCOMP_H)
endif (USE_SECCOMP)

execute_process(COMMAND bash "-c" "getent group users | cut -d ':' -f3" OUTPUT_VARIABLE USER_GID)

set(KCRON_KEYTAB_DIR /var/adm/krb5)
set(CLIENT_KEYTAB /var/kerberos/krb5/user)
set(HOSTNAME_MAX_LENGTH 300)
set(USERNAME_MAX_LENGTH 200)
set(FILE_PATH_MAX_LENGTH 2000)

set(INTERFACE_POSITION_INDEPENDENT_CODE TRUE)
set(POSITION_INDEPENDENT_CODE TRUE)

message(STATUS "C Compiler ${CMAKE_C_COMPILER}")

CHECK_C_SOURCE_COMPILES("int main(void) { return 0; } " CAN_COMPILE)
if (NOT CAN_COMPILE)
  message(FATAL_ERROR "Compiler non functional")
endif (NOT CAN_COMPILE)

# Add required warnings level
foreach(MYFLAG -Wall -Wpedantic -Wconversion -Wformat-security -Wstrict-prototypes -Wstrict-overflow -Wextra -Werror)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${MYFLAG}")
  string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  unset (MYFLAG)
endforeach(MYFLAG)

# Add -D_FORTIFY_SOURCE=2 hardening flags
# ssp-buffer-size has a performance hit, but eh
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -D_FORTIFY_SOURCE=2 --param=ssp-buffer-size=1")
string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

# Add linker hardening flags
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -z noexecstack -z relro -z now -pie")
foreach(MYFLAG -Wl,-z,defs -Wl,-z,noexecstack -Wl,-z,nodump -Wl,-z,relro -Wl,-z,now)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${MYFLAG}")
  string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  unset (MYFLAG)
endforeach(MYFLAG)

# Add performance optimizations
CHECK_C_COMPILER_FLAG(-finline-functions INLINE_FUNCTIONS)
if (INLINE_FUNCTIONS)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -finline-functions")
  string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
else ()
  message(FATAL_ERROR "Required compile flag '-finline-functions' not found")
endif (INLINE_FUNCTIONS)

# Permit sound debugging tables
CHECK_C_COMPILER_FLAG(-fasynchronous-unwind-tables UNWIND_TABLES)
if (UNWIND_TABLES)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fasynchronous-unwind-tables")
  string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
else ()
  message(WARNING "compile flag '-fasynchronous-unwind-tables' not found")
endif (UNWIND_TABLES)

# Add sanitizer options
if (USE_SANITIZE)
  CHECK_C_COMPILER_FLAG(-fsanitize=address LIBASAN)
  if (LIBASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
    string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  else ()
    message(FATAL_ERROR "Required compile flag '-fsanitize=address' not found")
  endif (LIBASAN)

  CHECK_C_COMPILER_FLAG(-fsanitize=undefined LIBUBSAN)
  if (LIBUBSAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined")
    string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  else ()
    message(FATAL_ERROR "Required compile flag '-fsanitize=undefined' not found")
  endif (LIBUBSAN)

  CHECK_C_COMPILER_FLAG(-fno-sanitize-recover=all NOSANRECOVER)
  if (NOSANRECOVER)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-sanitize-recover=all")
    string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  else ()
    message(FATAL_ERROR "Required compile flag '-fno-sanitize-recover=all' not found")
  endif (NOSANRECOVER)

  if (USE_SANITIZE_AS_STATIC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static-libasan -static-libubsan")
    string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  endif (USE_SANITIZE_AS_STATIC)
endif (USE_SANITIZE)

# Add basic security bits
CHECK_C_COMPILER_FLAG(-fPIC FPIC_CHECK)
if (FPIC_CHECK)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
  string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
else ()
  message(FATAL_ERROR "Required compile flag '-fPIC' not found")
endif (FPIC_CHECK)

CHECK_C_COMPILER_FLAG(-fstack-clash-protection STACK_CLASH)
if (STACK_CLASH)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-clash-protection")
  string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
else ()
  message(FATAL_ERROR "Required compile flag '-fstack-clash-protection' not found")
endif (STACK_CLASH)

CHECK_C_COMPILER_FLAG(-fstack-reuse=none STACK_REUSE)
if (STACK_REUSE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-reuse=none")
  string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
else ()
  message(FATAL_ERROR "Required compile flag '-fstack-reuse=none' not found")
endif (STACK_REUSE)

CHECK_C_COMPILER_FLAG(-fstack-protector-all STACK_PROTECT)
if (STACK_PROTECT)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all")
  string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
else ()
  message(FATAL_ERROR "Required compile flag '-fstack-protector-all' not found")
endif (STACK_PROTECT)

# Add Specter/Meltdown mitigations
CHECK_C_COMPILER_FLAG(-mindirect-branch=thunk-extern INDIRECT_BRANCH)
if (INDIRECT_BRANCH)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mindirect-branch=thunk-extern")
  string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
else ()
  message(FATAL_ERROR "Required compile flag '-mindirect-branch=thunk-extern' not found")
endif (INDIRECT_BRANCH)

CHECK_C_COMPILER_FLAG(-mindirect-branch-register INDIRECT_BRANCH_REGISTER)
if (INDIRECT_BRANCH_REGISTER)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mindirect-branch-register")
  string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
else ()
  message(FATAL_ERROR "Required compile flag '-mindirect-branch-register' not found")
endif (INDIRECT_BRANCH_REGISTER)

CHECK_C_COMPILER_FLAG(-mfunction-return FUNCTION_RETURN)
if (FUNCTION_RETURN)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfunction-return")
  string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
else ()
  message(WARNING "compile flag '-mfunction-return' not found")
endif (FUNCTION_RETURN)

# Drop any weird ';' that snuck in
string (REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

# Build config file
configure_file ("src/C/autoconf.h.in" "src/C/autoconf.h" @ONLY)

add_executable(init-kcron-keytab src/C/init-kcron-keytab.c src/C/kcron_ulimit.c)
add_executable(remove-kcron-keytab src/C/remove-kcron-keytab.c src/C/kcron_ulimit.c)

install(TARGETS init-kcron-keytab remove-kcron-keytab DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/kcron)

