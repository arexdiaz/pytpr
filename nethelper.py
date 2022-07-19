import logging
import select
import socket
import queue
import re

logging.basicConfig(level=logging.INFO)

EXIT_CMD = " && echo _EXIT_STATUS=$? || echo _EXIT_STATUS=$?\n"

def strip_status(s):
    return re.sub(r"_EXIT_STATUS=\w+", "", s.decode().strip())

class SocketServer():
    def __init__(self, sock_type=None):
        if sock_type == None:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.server = socket.socket(socket.AF_INET, sock_type)

        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.inputs = [self.server]
        self.outputs = []
        self.message_queues = {}
        self.connection = None
        self.client_address = None

    def listen(self):

        self.server.listen()

        readable, _, _ = select.select(self.inputs, self.outputs, self.inputs)

        for s in readable:
            if s is self.server:
                self.connection, self.client_address = self.server.accept()
                logging.info(f"Connection established on {self.client_address}")

                self.connection.setblocking(0)

                self.inputs.append(self.connection)
                self.message_queues[self.connection] = queue.Queue()

    def is_shell(self):
        self.connection.sendall(f"/bin/bash 2>&1\n".encode())
        self.connection.sendall(f"echo hello{EXIT_CMD}".encode())
        check = self.send_command("echo test")
        if not check:
            return False

    # TODO: Figure out what I wrote a year ago
    def send_command(self, command=None, wt_output=True):
        """Gets data from client with proper monitoring using select() and queue for sending data.
        """
        output = b""

        while True:
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs, 10)

            for s in readable:
                try:
                    data = s.recv(1024)
                except(OSError):
                    break

                if data:
                    logging.debug(f"Recieved data {data} from {s.getpeername()}")
                    output = output + data
                    if s not in self.outputs:
                        self.outputs.append(s)
                    if not wt_output:
                        print(strip_status(data))

                    if b"_EXIT_STATUS=" in data:
                        if wt_output:
                            return output
                        else:
                            return None
                else:
                    logging.error(f"Closing connection from {self.client_address} after reading no data")
                    if s in self.outputs:
                        self.outputs.remove(s)
                    self.inputs.remove(s)
                    s.close()

                    del self.message_queues[s]
                    return

            if command and writable:
                for s in writable:
                    self.message_queues[s].put((command + EXIT_CMD).encode())
                    try:
                        next_msg = self.message_queues[s].get_nowait()
                    except(queue.Empty):
                        logging.debug(f"Output queue for {s.getpeername()} is empty")
                        self.outputs.remove(s)
                    else:
                        logging.debug(f"Sending {next_msg} to {s.getpeername()}")
                        s.sendall(next_msg)
                        command = None

            for s in exceptional:
                logging.warning(f"Handling exceptional condition for {s.getpeername()}")
                self.inputs.remove(s)
                for s in self.outputs:
                    self.outputs.remove(s)
                s.close()

                del self.message_queues[s]

            if not readable and not writable and not exceptional:
                return False
