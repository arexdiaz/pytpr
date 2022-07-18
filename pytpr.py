import logging
import socket
import select
import queue
import sys
import cmd
import re


logging.basicConfig(level=logging.INFO)

class Sock():
    def __init__(self, host, port, sock_type=None):
        if sock_type == None:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.server = socket.socket(socket.AF_INET, sock_type)

        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server.bind((host, port))
        except(OSError):
            raise socket.error()

        self.inputs = [self.server]
        self.outputs = []
        self.message_queues = {}
        self.connection = None
        self.client_address = None

        logging.info(f"Started listener on {host, port}")

        self.server.listen()
        select.select(self.inputs, self.outputs, self.inputs)


    def send_command(self, command=None, wt_output=True):
        """Gets data from client with proper monitoring using select() and queue for sending data.
        """
        exit_stat = " && echo _EXIT_STATUS=$? || echo _EXIT_STATUS=$?\n"
        output = b""

        #TODO: Starting from here this can be written in to a function
        while True:
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs, 1)

            for s in readable:
                if s is self.server:
                    self.connection, self.client_address = self.server.accept()
                    logging.info(f"Connection established on {self.client_address}")

                    self.connection.setblocking(0)
                    self.connection.sendall(f"/bin/bash 2>&1\n".encode())
                    self.connection.sendall(f"echo hello{exit_stat}".encode())

                    self.inputs.append(self.connection)
                    self.message_queues[self.connection] = queue.Queue()
        #TODO: To here
                else:
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
                            print(re.sub(r"_EXIT_STATUS=\w+", "", data.decode().strip()))

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
                    self.message_queues[s].put((command + exit_stat).encode())
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


class NetShell(cmd.Cmd):
    def __init__(self, host, port):
        super(NetShell, self).__init__()
        self.prompt = "net_shell > "
        self.sock = Sock(host, int(port))
        self.id = None
        self.output = None

    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished."""
        if self.output:
            print(re.sub(r"_EXIT_STATUS=\w+", "", self.output.decode().strip()))

        return stop

    def default(self, line):
        """Called on an input line when the command prefix is not recognized.
        
            Sends input line to the remote session.
        """
        self.output = self.sock.send_command(line, wt_output=False)

    def do_test(self, line):
        """Used to test commands with multiple packets
        """
        self.output = self.sock.send_command("ping 8.8.8.8 -c 4")

    def do_exit(self, line):
        logging.info(f"Closing connection from {self.sock.client_address}") # TODO: client_address should be replaced with a session ID in the future
        self.sock.connection.close()
        self.sock.server.close()
        return True

class LocalShell(cmd.Cmd):

    def __init__(self):
        super(LocalShell, self).__init__()
        self.prompt = "local_shell > "
        self.sessions = []
        self.currentSession = None

    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished.
        """
        # Forgot what this does
        if self.currentSession and self.currentSession.sock.connection.fileno() == -1:
            self.sessions[self.currentSession.id] = None
            logging.debug(f"Removed session {self.currentSession.id + 1} from array")
            self.currentSession = None

        return stop

    def do_listen(self, line="localhost 4242"):
        if not line:
            host, port = ("localhost", 4242)
        else:
            host, port = line.strip().split(" ")

        try:
            self.currentSession = NetShell(host, port)
        except(socket.error):
            logging.error("Address already in use")
            return
        
        try:
            self.currentSession.sock.send_command("echo hello")
        except(KeyboardInterrupt):
            self.currentSession.sock.server.close()
            self.currentSession = None
            print("")
            return
        
        self.sessions.append(self.currentSession)
        self.currentSession.id = (len(self.sessions) - 1)
        logging.info(f"Session {self.currentSession.id + 1} created")
        intrp(self.currentSession)
    
    def do_exit(self, line):
        logging.info("Exiting...")
        sys.exit()


def intrp(shellObj):
    try:
        shellObj.cmdloop()
    except(KeyboardInterrupt):
        print("")
        intrp(shellObj)

if __name__ == "__main__":
    intrp(LocalShell())
