#!/usr/bin/python
from nethelper import ServerSocket, prettify_output, netshell_loop
from threading import Thread
import logging
import socket
import time
import sys
import cmd


logging.basicConfig(level=logging.INFO)

class NetShell(cmd.Cmd):
    def __init__(self, server):
        super(NetShell, self).__init__()
        self.prompt = "net_shell > "
        self.server = server
        self.id = None
        self.output = None
        self.is_closed = False

        Thread(target=self._is_alive).start()

    def precmd(self, line):
        """Hook method executed just before the command line is
        interpreted, but after the input prompt is generated and issued.
        """
        if self.is_closed:
            raise BrokenPipeError
        return line
    
    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished."""

        return stop

    """
        <--CMD library ends here-->
    """

    def _is_alive(self):
        """ Checks if socket is alive
            https://stackoverflow.com/questions/48024720/python-how-to-check-if-socket-is-still-connected
        """
        while True:
            try:
                data = self.server.client_socket.recv(16, socket.MSG_DONTWAIT | socket.MSG_PEEK)
                if len(data) == 0:
                    raise OSError
            except (BlockingIOError, ConnectionResetError):
                continue
            except OSError:
                self.is_closed = True
                self.onecmd("exit")
                break
            except Exception as e:
                logging.error("unexpected exception when checking if a socket is closed")
                break

            time.sleep(1)

    """
        <--Commands start here-->
    """

    def do_ls(self, line):
        if not line:
            pwd = prettify_output(self.server.send_command("pwd"))
            ls = prettify_output(self.server.send_command("ls -lA"))
        else:
            old_path = prettify_output(self.server.send_command("pwd"))
            cd = prettify_output(self.server.send_command(f"cd {line}"))
            # TODO: Fix bash crashing after using this command twice without this if statement
            # if "no such file or directory" in cd.lower():
            #     logging.error("No such file or directory")
            #     return
            pwd = prettify_output(self.server.send_command("pwd"))
            ls = prettify_output(self.server.send_command(f"ls -lA"))
            self.server.send_command(f"cd {old_path}")

        sys.stdout.write(f"{pwd}{'=' * (len(pwd))}\n\n{ls}\n")

    def do_run(self, line):
        self.output = self.server.send_command(line, wt_output=False)
        if self.output:
            sys.stdout.write(f"prettify_output(self.output)\n")

    def do_exit(self, line):
        logging.info(f"Closing connection from {self.server.client_address}") # TODO: client_address should be replaced with a session ID in the future

        self.server.client_socket.close()
        self.server.server_socket.close()
        return True

class LocalShell(cmd.Cmd):
    def __init__(self):
        super(LocalShell, self).__init__()
        self.prompt = "local_shell > "
        self.sessions = []
        self.currentSession = None
        if len(sys.argv) > 1 and sys.argv[1] == "-l": self.do_listen(None)
        
    def emptyline(self):
        """Called when an empty line is entered in response to the prompt.

        If this method is not overridden, it repeats the last nonempty
        command entered.
        """
        return None


    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished.
        """
        # TODO: Dont remove shell object instead use shellObj.is_closed variable

        return stop

    """
        <--Commands start here-->
    """

    def do_listen(self, line):
        if not line:
            host, port = ("localhost", 4242)
        else:
            host, port = line.strip().split(" ")

        sock = ServerSocket()

        try:
            sock.server_socket.bind((host, int(port)))
        except socket.error:
            logging.error("Address already in use")
            return
        
        logging.info(f"Started listener on {host, port}")

        try:
            sock.listen()
            if sock.is_shell():
                logging.error("No shell found")
                return
        except KeyboardInterrupt:
            sock.server_socket.close()
            print("")
            return
        except BrokenPipeError:
            sock.server_socket.close()
            logging.error("BrokenPipeError")
            return

        self.currentSession = NetShell(sock)

        self.sessions.append(self.currentSession)
        self.currentSession.id = (len(self.sessions) - 1)
        logging.info(f"Session {self.currentSession.id + 1} created")
        netshell_loop(self.currentSession)
    
    def do_exit(self, line):
        logging.info("Exiting...")

        for shellObj in self.sessions:
            if shellObj.is_closed:
                shellObj.server.client_socket.close()
                shellObj.server.server_socket.close()

        sys.exit()


def _local_loop(shellObj):
    try:
        shellObj.cmdloop()
    except KeyboardInterrupt:
        print("")
        _local_loop(shellObj)

def main():
    _local_loop(LocalShell())


if __name__ == "__main__":
    main()