## Makefile.am -- Process this file with automake to produce Makefile.in

# Trusted Application destination directory
tadir = $(libdir)/TAs

# Include libtool macros
ACLOCAL_AMFLAGS = -I m4

# Additional C compiler flags
AM_CFLAGS = -Wall -Wextra -D_GNU_SOURCE -DTA_PLUGIN -D_FORTIFY_SOURCE=2

# Additional libtool linking flags
AM_LDFLAGS = -avoid-version

# Executables
bin_PROGRAMS =

# Shared libraries
lib_LTLIBRARIES  =

# TAs
ta_LTLIBRARIES =

# Include module-specific Makefiles
include example_digest_ta/Makemodule.am
include example_ta/Makemodule.am
include ta_conn_test_app/Makemodule.am
include usr_study_ta/Makemodule.am

# Clean .la files from TA destination directory. The .la files contain
# portable encoding of static and shared library names and dependencies.
# These are usually safe to remove on ELF platforms (including Linux) where
# the runtime linker loads indirect library dependencies automatically On
# certain platforms, dependencies of the compile module are not encoded in
# the binary, so the .la file is needed so that lt_dlopen will find and
# load the correct dependencies. If porting Open-TEE to such platforms
# (e.g. MacOS) the .la files should be left intact.
install-data-hook:
	rm -f $(addprefix $(DESTDIR)$(tadir)/,$(ta_LTLIBRARIES))

# Make sure TA .so files are removed from the TA destination directory during
# uninstall. Since the .la files are removed by the install-data-hook, libtool
# does not to clean these up itself.
uninstall-local:
	rm -f $(addprefix $(DESTDIR)$(tadir)/,$(ta_LTLIBRARIES:.la=.so))
