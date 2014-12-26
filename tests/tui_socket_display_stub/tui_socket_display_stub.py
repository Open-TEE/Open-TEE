#!/usr/bin/env python

import socket
import cffi
import msgpack

ffi = cffi.FFI()

cdef = """
int com_recv_msg(int sockfd, void **msg, int *msg_len);
int com_send_msg(int sockfd, void *msg, int msg_len);

int com_get_msg_name(void *msg, uint8_t *msg_name);
int com_get_msg_type(void *msg, uint8_t *msg_type);
int com_get_msg_sess_id(void *msg, uint64_t *sess_id);

size_t sizeof_com_msg_hdr();
void free_msg(void *msg);
void set_com_msg_hdr(void *buf,
                     uint64_t sess_id,
                     uint8_t msg_name,
                     uint8_t msg_type);
"""

ffi.cdef(cdef)

sizeof_com_msg_hdr = """
size_t sizeof_com_msg_hdr()
{
    return sizeof(struct com_msg_hdr);
}

void free_msg(void *msg)
{
    free(msg);
}

void set_com_msg_hdr(void *buf,
                     uint64_t sess_id,
                     uint8_t msg_name,
                     uint8_t msg_type)
{
    struct com_msg_hdr *hdr = buf;

    hdr->sess_id = sess_id;
    hdr->msg_name = msg_name;
    hdr->msg_type = msg_type;
}
"""

# internal_api_lib_path = os.path.abspath("../../gcc-debug")
api = ffi.verify("\n".join([open("libtee/src/com_protocol.c").read(),
                            sizeof_com_msg_hdr]),
                 include_dirs=['libtee/include'],
                 library_dirs=['qt-5-4-0-debug/'],
                 libraries=['tee', 'z']
                 )

TUI_SOCKET_NAME = "/tmp/open_tee_tui_display"


class Com_Proto_Socket:
    def __init__(self, sock=None):
        if sock is None:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            self.socket = sock

    def connect(self, socket_name):
        self.socket.connect(socket_name)

    def recv_msg(self):
        # Create cdata objects for message pointer and length
        recv_msg = ffi.new("void **")
        msglen = ffi.new("int[1]")

        # Create cdata objects for retrieving message header info
        session_id = ffi.new("uint64_t[1]")
        msg_name = ffi.new("uint8_t[1]")
        msg_type = ffi.new("uint8_t[1]")

        # Receive message with "com_protocol" library.
        # This call allocates memory for receive message.
        ret = api.com_recv_msg(tui_socket.socket.fileno(), recv_msg, msglen)
        if ret != 0:
            raise Exception('Socket failure')

        # Get
        api.com_get_msg_sess_id(recv_msg[0], session_id)
        api.com_get_msg_name(recv_msg[0], msg_name)
        api.com_get_msg_type(recv_msg[0], msg_type)

        msg_hdr = {"session_id": session_id[0],
                   "msg_name": msg_name[0],
                   "msg_type": msg_type[0]}

        # Cast void pointer to char so that it is readable through
        # CFFI interface
        msg = ffi.cast("char **", recv_msg)

        # Convert message from C-array to Python string
        msg_str = ''.join([(msg[0])[i] for i in
                           range(api.sizeof_com_msg_hdr(), msglen[0])])

        # Free memory allocated for message
        api.free_msg(msg[0])

        return (msg_hdr, msg_str, msglen[0])

    def send_msg(self, msg_hdr, msg):
        # Calculate message length
        msg_len = api.sizeof_com_msg_hdr() + len(msg)

        # Allocate buffer for message
        msg_buf = ffi.new("uint8_t[]", msg_len)

        api.set_com_msg_hdr(msg_buf,
                            msg_hdr["session_id"],
                            msg_hdr["msg_name"],
                            msg_hdr["msg_type"])

        for i in range(0, len(msg)):
            msg_buf[api.sizeof_com_msg_hdr() + i] = ord(msg[i])

        ret = api.com_send_msg(tui_socket.socket.fileno(), msg_buf, msg_len)
        if ret != msg_len:
            raise Exception('Socket failure')


class TUI_Socket(Com_Proto_Socket):
    def __init__(self, sock=None):
        if sock is None:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            self.socket = sock

    def connect(self, socket_name=None):
        self.socket.connect(
            TUI_SOCKET_NAME if socket_name is None else socket_name)

    def recv_msg(self):
        msg_hdr, msg, msg_len = Com_Proto_Socket.recv_msg(self)
        unpacked = [] if msg_len - api.sizeof_com_msg_hdr() <= 0 \
            else msgpack.unpackb(msg)

        return msg_hdr, unpacked, msg_len


tui_socket = TUI_Socket()
tui_socket.connect()

TUI_CHECK_TEXT_FORMAT = 0x10
TUI_GET_SCREEN_INFO = 0x11
TUI_INIT_SESSION = 0x12
TUI_CLOSE_SESSION = 0x13
TUI_DISPLAY_SCREEN = 0x14

while True:
    print("Waiting for message")

    msg_hdr, msg, msg_len = tui_socket.recv_msg()
    msg_name = msg_hdr["msg_name"]
    response = []

    print("Received: " + str(msg))

    if msg_name == TUI_CHECK_TEXT_FORMAT:
        print("TUI_CHECK_TEXT_FORMAT")
        response = [0, 420, 240, 666]
    elif msg_name == TUI_GET_SCREEN_INFO:
        print("TUI_GET_SCREEN_INFO")
        response = [0,
                    8, 8, 8, 8,
                    50, 50,
                    3,
                    300,
                    50,
                    256,
                    0, 0, 0,
                    300,
                    100,
                    [
                        ['Text1', 100, 50, True, True],
                        ['Text2', 100, 50, True, True],
                        ['Text3', 100, 50, True, True],
                        ['Text4', 100, 50, True, True],
                        ['Text5', 100, 50, True, True],
                        ['Text6', 100, 50, True, True]
                    ]]
    elif msg_name == TUI_INIT_SESSION:
        print("TUI_INIT_SESSION")
        response = 0
    elif msg_name == TUI_CLOSE_SESSION:
        print("TUI_CLOSE_SESSION")
        response = 0
    elif msg_name == TUI_DISPLAY_SCREEN:
        print("TUI_DISPLAY_SCREEN")
        #entryfields_in = msg[2]
        #entryfields = map(lambda x: str(x[0]) + " Answer", entryfields_in)
        entryfields = ['kayttaja', 'salasana', '1234']
        response = [0, entryfields, 0]

    # Response
    msg_hdr["msg_type"] = 0

    print("Sending response: %s" % str(response))

    tui_socket.send_msg(msg_hdr, msgpack.packb(response))
