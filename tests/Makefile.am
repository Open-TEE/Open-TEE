# Makefile.am -- Process this file with automake to produce Makefile.in

# Include libtool macros
ACLOCAL_AMFLAGS = -I m4

# Additional C compiler flags
AM_CFLAGS = -Wall -Wextra -Werror

# Test executables
check_PROGRAMS =

# Tests run during 'make check'
TESTS = $(check_PROGRAMS)

# Include module-specific Makefiles
include internal_api/Makemodule.am
