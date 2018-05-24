cmake_minimum_required(VERSION 3.9)
project(nih-sftp-server C)

add_executable(nih-sftp-server nih-sftp-server.c)

target_compile_options(nih-sftp-server PRIVATE -Wall -Wextra -Werror -pedantic-errors -std=iso9899:1999)

install(TARGETS nih-sftp-server RUNTIME DESTINATION .)
