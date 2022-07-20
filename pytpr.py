from nethelper import NetSock, strip_status
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

    def default(self, line):
        """ Called on an input line when the command prefix is not recognized.
        
            Sends input line to the remote session.
        """
        self.output = self.server.send_command(line, wt_output=False)

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
            except BlockingIOError:
                continue
            except ConnectionResetError:
                continue
            except OSError:
                break
            except Exception as e:
                logging.error("unexpected exception when checking if a socket is closed")
                break
            time.sleep(1)

    def do_test(self, line):
        """Used to test commands with multiple packets"""
        self.output = self.server.send_command("ping 8.8.8.8 -c 4")

    def do_test_conn(self, line):
        self.output = self.server.server_socket.sendall(b"")

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
        if self.lastcmd:
            return self.onecmd(self.lastcmd)

    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished.
        """
        # Checks if the sockets file descriptor is closed
        if self.currentSession and self.currentSession.server.client_socket.fileno() == -1:
            self.sessions[self.currentSession.id] = None
            logging.debug(f"Removed session {self.currentSession.id + 1} from array")
            self.currentSession = None

        return stop

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
        signal_catch(self.currentSession)
    
    def do_exit(self, line):
        logging.info("Exiting...")
        sys.exit()


def signal_catch(shellObj):
    try:
        if shellObj.is_closed:
            return
    except AttributeError:
        pass

    try:
        shellObj.cmdloop()
    except KeyboardInterrupt:
        print("")
        signal_catch(shellObj)
    except BrokenPipeError:
        return

if __name__ == "__main__":
    signal_catch(LocalShell())
