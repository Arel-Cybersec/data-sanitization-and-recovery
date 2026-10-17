cmake_minimum_required(VERSION 3.16)
project(erasecure VERSION 2.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(OpenSSL 1.1 REQUIRED COMPONENTS Crypto)

add_compile_options(-Wall -Wextra -Werror -Wformat=2 -Wno-format-truncation -Wshadow
                    -fstack-protector-strong -D_FORTIFY_SOURCE=2)
option(SANITIZE "Build with AddressSanitizer + UBSan" OFF)
if(SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

add_library(ec STATIC src/wipe.c src/shred.c src/devices.c src/audit.c src/carve.c)
target_link_libraries(ec PUBLIC OpenSSL::Crypto)

add_executable(erasecure src/main.c)
target_link_libraries(erasecure PRIVATE ec)

enable_testing()
add_executable(ec_tests tests/test_main.c)
target_link_libraries(ec_tests PRIVATE ec)
add_test(NAME ec_tests COMMAND ec_tests)

install(TARGETS erasecure RUNTIME DESTINATION bin)
