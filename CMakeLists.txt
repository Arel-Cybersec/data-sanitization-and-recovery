cmake_minimum_required(VERSION 3.16)
project(erasecure VERSION 2.2.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()


add_compile_options(-Wall -Wextra -Werror -Wformat=2 -Wno-format-truncation -Wshadow
                    -fstack-protector-strong -D_FORTIFY_SOURCE=2)
option(SANITIZE "Build with AddressSanitizer + UBSan" OFF)
if(SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

add_library(ec STATIC src/wipe.c src/audit.c src/carve.c src/image.c)
if(WIN32)
  # Windows: OS-provided CNG crypto, no extra DLLs; static runtime for a single .exe
  target_sources(ec PRIVATE src/os_windows.c src/crypto_windows.c)
  target_link_libraries(ec PUBLIC bcrypt shell32)
  target_compile_definitions(ec PUBLIC WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00 __USE_MINGW_ANSI_STDIO=1)
  add_link_options(-static)
else()
  find_package(OpenSSL 1.1 REQUIRED COMPONENTS Crypto)
  target_sources(ec PRIVATE src/os_linux.c src/crypto_openssl.c)
  target_link_libraries(ec PUBLIC OpenSSL::Crypto)
endif()

if(WIN32)
  # gui_windows.c: desktop window; the .rc embeds a manifest for modern
  # controls and sharp text on high-DPI screens.
  add_executable(erasecure src/main.c src/gui_windows.c src/windows/erasecure.rc)
  target_link_libraries(erasecure PRIVATE comdlg32 ole32 user32 gdi32 advapi32)
else()
  add_executable(erasecure src/main.c)
endif()
target_link_libraries(erasecure PRIVATE ec)

enable_testing()
add_executable(ec_tests tests/test_main.c)
target_link_libraries(ec_tests PRIVATE ec)
add_test(NAME ec_tests COMMAND ec_tests)

install(TARGETS erasecure RUNTIME DESTINATION bin)
