cmake_minimum_required (VERSION 3.11)

include(GNUInstallDirs)

install(FILES src/shell/kcron.sysconfig DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/sysconfig RENAME kcron)
install(FILES src/shell/kcron src/shell/kcrondestroy src/shell/kcroninit DESTINATION ${CMAKE_INSTALL_BINDIR})

