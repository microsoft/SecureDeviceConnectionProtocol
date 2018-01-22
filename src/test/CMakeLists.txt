add_executable(sdcptest test.c testkeys.c helpers.c)
target_link_libraries(sdcptest sdcpcli)
