#!/usr/bin/python
from nethelper import NetSock, strip_status, netshell_loop
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
        if self.output:
            print(strip_status(self.output))

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
                    self.is_closed = True
                    self.onecmd("exit")
                    break
            except (BlockingIOError, ConnectionResetError):
                continue
            except OSError:
                break
            except Exception as e:
                logging.error("unexpected exception when checking if a socket is closed")
                break

            time.sleep(1)

    """
        <--Commands start here-->
    """

    def do_run(self, line):
        self.output = self.server.send_command(line, wt_output=False)

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
        if self.currentSession and self.currentSession.is_closed:
            self.sessions[self.currentSession.id] = None
            logging.debug(f"Removed session {self.currentSession.id + 1} from array")
            self.currentSession = None

        return stop

    """
        <--Commands start here-->
    """

    def do_listen(self, line):
        if not line:
            host, port = ("localhost", 4242)
        else:
            host, port = line.strip().split(" ")

        sock = NetSock()

        try:
            sock.server_socket.bind((host, int(port)))
        except socket.error:
            logging.error("Address already in use")
            return
        
        logging.info(f"Started listener on {host, port}")

        try:
            sock.listen()
        except KeyboardInterrupt:
            sock.server_socket.close()
            print("")
            return

        try:
            if sock.is_shell():
                logging.error("No shell found")
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
            if shellObj:
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