SET(CMAKE_SYSTEM_NAME           Linux)
SET(CMAKE_SYSTEM_VERSION        1)
SET(CMAKE_SYSTEM_PROCESSOR      aarch64)

SET(CMAKE_C_COMPILER            "/usr/bin/aarch64-linux-gnu-gcc")
SET(CMAKE_CXX_COMPILER          "/usr/bin/aarch64-linux-gnu-g++")

SET(CMAKE_FIND_ROOT_PATH "/usr/aarch64-linux-gnu/usr" "/usr/aarch64-linux-gnu" "/usr")
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# NOS Engine 경로 명시적 지정
SET(ITC_DEV_ROOT "/usr/aarch64-linux-gnu/usr")
SET(ENV{ITC_DEV_ROOT} "/usr/aarch64-linux-gnu/usr")
SET(CMAKE_PREFIX_PATH "/usr/aarch64-linux-gnu/usr" "/usr/aarch64-linux-gnu")

# noslink 직접 지정
SET(NOSENGINE_client_LIBRARY "/usr/aarch64-linux-gnu/usr/lib/libnos_engine_client.so")
SET(NOSENGINE_uart_LIBRARY "/usr/aarch64-linux-gnu/usr/lib/libnos_engine_uart.so")
SET(NOSENGINE_i2c_LIBRARY "/usr/aarch64-linux-gnu/usr/lib/libnos_engine_i2c.so")
SET(NOSENGINE_spi_LIBRARY "/usr/aarch64-linux-gnu/usr/lib/libnos_engine_spi.so")
SET(NOSENGINE_can_LIBRARY "/usr/aarch64-linux-gnu/usr/lib/libnos_engine_can.so")

SET(CFE_SYSTEM_PSPNAME      "nos-linux")
SET(OSAL_SYSTEM_OSTYPE      "nos")

add_definitions(-DBYTE_ORDER_LE)
add_definitions(-D_LINUX_OS_)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CI_TRANSPORT udp_tf)
set(TO_TRANSPORT udp)