add_executable(sdcptest test.c testkeys.c helpers.c)
add_executable(sdcpvirt virt_device.c testkeys.c helpers.c)
target_link_libraries(sdcptest sdcpcli)
target_link_libraries(sdcpvirt sdcpcli)
