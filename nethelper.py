import logging
import select
import signal
import socket
import queue
import time
import re


logging.basicConfig(level=logging.INFO)

ORIGINAL_SIGTSTP = signal.getsignal(signal.SIGTSTP)
EXIT_CMD = " && echo _3X1T_5TATUS=$? || echo _3X1T_5TATUS=$?\n"

def strip_status(s):
    return re.sub(r"_3X1T_5TATUS=\w+", "", s.decode().strip())

def sig_handler(signum, frame):
    raise KeyboardBgInterrupt

def _sigtspt_check():
    try:
        msg = input("Put session in background? (y/n) > ")
    except (KeyboardInterrupt, KeyboardBgInterrupt):
        print("")
        _sigtspt_check()
    if msg.lower() == "y":
        return True
    elif msg.lower() == "n":
        return False
    else:
        _sigtspt_check()

def netshell_loop(shellObj):
    signal.signal(signal.SIGTSTP, sig_handler)

    if shellObj.is_closed:
        signal.signal(signal.SIGTSTP, ORIGINAL_SIGTSTP)
        return
    
    try:
        shellObj.cmdloop()
    except KeyboardInterrupt:
        print("")
        netshell_loop(shellObj)
    except KeyboardBgInterrupt:
        print("")
        msg =_sigtspt_check()
        if msg:
            signal.signal(signal.SIGTSTP, ORIGINAL_SIGTSTP)
            return
        else:
            netshell_loop(shellObj)
    except BrokenPipeError:
        signal.signal(signal.SIGTSTP, ORIGINAL_SIGTSTP)
        return

class KeyboardBgInterrupt(Exception):
    pass

class NetSock():
    def __init__(self, sock_type=None):
        if sock_type == None:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.server_socket = socket.socket(socket.AF_INET, sock_type)

        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.inputs = [self.server_socket]
        self.outputs = []
        self.message_queues = {}
        self.client_socket = None
        self.client_address = None

    def _close_socket(self, s):
        logging.error(f"Closing connection from {self.client_address} after reading no data")
        if s in self.outputs:
            self.outputs.remove(s)
        self.inputs.remove(s)
        s.close()

        del self.message_queues[s]
        return

    def listen(self):

        self.server_socket.listen()

        readable, _, _ = select.select(self.inputs, self.outputs, self.inputs)

        for s in readable:
            if s is self.server_socket:
                self.client_socket, self.client_address = self.server_socket.accept()
                logging.info(f"Connection established on {self.client_address}")

                self.client_socket.setblocking(0)

                self.inputs.append(self.client_socket)
                self.message_queues[self.client_socket] = queue.Queue()
                

    def is_shell(self):
        self.client_socket.sendall(f"/bin/bash 2>&1\n".encode())
        self.client_socket.sendall(f"echo hello{EXIT_CMD}".encode())
        logging.info(f"Validating if connection has shell..")
        time.sleep(0.1)
        check = self.send_command("echo THIS_IS_A_TEST_STRING_IGNORE_PLS")
        logging.info(f"Success!")
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

                    if b"_3X1T_5TATUS=" in data:
                        if wt_output:
                            return output
                        else:
                            return None
                else:
                    self._close_socket(s)

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
                try:
                    self.server_socket.sendall(b"")
                except(BrokenPipeError):
                    for s in readable:
                        self._close_socket(s)
                return False 
