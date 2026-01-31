import socket
import sys
import cffi
import os

from pycparser import parse_file, c_generator

ffi = cffi.FFI()

headerpath = "%s/libtee/include/com_protocol.h" % os.getcwd()
ast = parse_file(headerpath, use_cpp=True)
generator = c_generator.CGenerator()
cdef = generator.visit(ast)

# Needed for testing, Python CFFI can't "call" macros directly
cdef = "\n".join([cdef, 'size_t getBigIntSizeInU32(size_t n);'])
ffi.cdef(cdef)

#internal_api_lib_path = os.path.abspath("../../gcc-debug")
api = ffi.verify(open("libtee/src/com_protocol.c").read(),
                 #library_dirs = [internal_api_lib_path],
                 #libraries = ['InternalApi']
                 )

# Create a UDS socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = '/tmp/open_tee_tui_display'
#server_address = '/tmp/open_tee_sock'
print >>sys.stderr, 'connecting to %s' % server_address
try:
        sock.connect(server_address)
except socket.error, msg:
        print >>sys.stderr, msg
        sys.exit(1)

#sock.send('HAHAA TESTIDATAA')
