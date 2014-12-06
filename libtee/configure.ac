#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libtee], [0.0.0], [https://github.com/Open-TEE/libtee/issues],
	[libtee], [https://github.com/Open-TEE])
AM_INIT_AUTOMAKE([dist-bzip2 foreign subdir-objects])
AC_CONFIG_SRCDIR([src/utils.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
LT_INIT

# Checks for libraries.
AC_CHECK_LIB([uuid], [uuid_generate])
AC_CHECK_LIB([crypt], [crypt])
AC_CHECK_LIB([pthread], [pthread_mutex_init])
AC_CHECK_LIB([z], [crc32])

# Created configuration files
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
