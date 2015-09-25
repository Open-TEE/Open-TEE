## Makefile.am -- Process this file with automake to produce Makefile.in

# Include libtool macros
ACLOCAL_AMFLAGS = -I m4

# Additional C compiler flags
AM_CFLAGS = -Wall -Wextra -D _GNU_SOURCE

# Executables
bin_PROGRAMS =

# Shared libraries
lib_LTLIBRARIES  =

# Include module-specific Makefiles
include conn_test_app/Makemodule.am
include example_sha1_ca/Makemodule.am
include storage_test_ca/Makemodule.am
include test_session/Makemodule.am
include usr_study_ca/Makemodule.am
