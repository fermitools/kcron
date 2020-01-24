cmake_minimum_required (VERSION 3.11)

include(GNUInstallDirs)

install(FILES ${PROJECT_SOURCE_DIR}/src/shell/kcron.sysconfig DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/sysconfig RENAME kcron)
install(FILES ${PROJECT_SOURCE_DIR}/src/shell/kcrondestroy ${PROJECT_SOURCE_DIR}/src/shell/kcroninit DESTINATION ${CMAKE_INSTALL_BINDIR})

enable_testing()

add_test(NAME Syntax:Config COMMAND bash -n ${PROJECT_SOURCE_DIR}/src/shell/kcron.sysconfig)
add_test(NAME Syntax:Init COMMAND bash -n ${PROJECT_SOURCE_DIR}/src/shell/kcroninit)
add_test(NAME Syntax:Destroy COMMAND bash -n ${PROJECT_SOURCE_DIR}/src/shell/kcrondestroy)
