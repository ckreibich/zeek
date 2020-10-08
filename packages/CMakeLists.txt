# Run zkg to install our toplevel package. To locate zkg, we rely on
# the system path, but we add our installation tree's bin so we also
# find a zkg we just installed.
install(CODE "execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/install.sh ${CMAKE_INSTALL_PREFIX}/bin )")
