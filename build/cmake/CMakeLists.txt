cmake_minimum_required(VERSION 3.30)
project(steve_h C)
set(CMAKE_C_STANDARD 17)

add_executable(test_steve ../../test_steve.c)
target_compile_options(test_steve PRIVATE -Wall -Wextra -Wconversion -Werror)

# note(steve): On MacOS need MallocNanoZone=0 or you'll get a warning with asan in stdlib code.
# target_compile_options(test_steve PUBLIC -fsanitize=address -fno-omit-frame-pointer)
# target_link_options(test_steve PUBLIC -fsanitize=address -fno-omit-frame-pointer)

