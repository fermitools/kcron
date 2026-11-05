# SPDX-License-Identifier: MIT
cmake_minimum_required (VERSION 3.11)

include(GNUInstallDirs)

install(FILES ${PROJECT_SOURCE_DIR}/src/shell/kcron.sysconfig DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/sysconfig RENAME kcron
        PERMISSIONS OWNER_READ OWNER_WRITE
                    GROUP_READ
                    WORLD_READ)
install(PROGRAMS ${PROJECT_SOURCE_DIR}/src/shell/kcrondestroy ${PROJECT_SOURCE_DIR}/src/shell/kcroninit DESTINATION ${CMAKE_INSTALL_BINDIR})

#
# All CTest registrations for the shell utilities (syntax checks, sourcing,
# hardening, shellcheck) live in the test tree: ${PROJECT_SOURCE_DIR}/test/.
# This file therefore owns only build and install directives, matching the
# separation used across the rest of the project.
#
