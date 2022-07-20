import socket


class NetSocket():
    def __init__(self, sock_type=None):
        if sock_type == None:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.socket = socket.socket(socket.AF_INET, sock_type)

        self.is_connected = False


    def connect_test(self, host, port):
        self.socket.connect((host, port))
        self.is_connected = True
        self.socket.sendall(b"Hello World\n")

        data = self.client.recv(1024)

        print(f"Received {data!r}")


if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 4242

    client = NetSocket()

    while not client.is_connected:
        try:
            client.connect_test(HOST, PORT)
        except:
            continue
    # client.socket.close()