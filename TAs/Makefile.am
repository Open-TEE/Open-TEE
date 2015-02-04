## Makefile.am -- Process this file with automake to produce Makefile.in

# Include libtool macros
ACLOCAL_AMFLAGS = -I m4

# Additional C compiler flags
AM_CFLAGS = -Wall -Wextra -D _GNU_SOURCE -DTA_PLUGIN

# Executables
bin_PROGRAMS =

# Shared libraries
lib_LTLIBRARIES  =

# Include module-specific Makefiles
include example_digest_ta/Makemodule.am
include example_ta/Makemodule.am
include storage_test_ta/Makemodule.am
#include smoke_test_TAs/Makemodule.am
include ta_conn_test_app/Makemodule.am
include usr_study_ta/Makemodule.am
