#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([opentee-tests], [0.0.0], [https://github.com/Open-TEE/tests/issues],
	[opentee-tests], [https://github.com/Open-TEE])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_SRCDIR([internal_api/crypto_test.c])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
LT_INIT

# Checks for libraries.
AC_CHECK_LIB([crypt], [crypt])

# Created confiuration files.
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
