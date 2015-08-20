# Makefile.am -- Process this file with automake to produce Makefile.in

# Include libtool macros
ACLOCAL_AMFLAGS = -I m4

# Additional C compiler flags
AM_CFLAGS = -Wall -Wextra -Werror

# Test executables
check_PROGRAMS =

# Shared libraries
lib_LTLIBRARIES  =

# Tests run during 'make check'
TESTS = $(check_PROGRAMS)

# Include module-specific Makefiles
include internal_api/Makemodule.am
include pkcs11/Makemodule.am
