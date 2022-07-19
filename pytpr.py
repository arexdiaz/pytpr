from nethelper import SocketServer, strip_status
import logging
import socket
import sys
import cmd


logging.basicConfig(level=logging.INFO)

class NetShell(cmd.Cmd):
    def __init__(self, sock):
        super(NetShell, self).__init__()
        self.prompt = "net_shell > "
        self.sock = sock
        self.id = None
        self.output = None

    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished."""
        if self.output:
            print(strip_status(self.output))

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
        if len(sys.argv) > 1 and sys.argv[1] == "-l": self.do_listen(None)
        
    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished.
        """
        # Forgot what this does
        if self.currentSession and self.currentSession.sock.connection.fileno() == -1:
            self.sessions[self.currentSession.id] = None
            logging.debug(f"Removed session {self.currentSession.id + 1} from array")
            self.currentSession = None

        return stop

    def do_listen(self, line):
        if not line:
            host, port = ("localhost", 4242)
        else:
            host, port = line.strip().split(" ")

        sock = SocketServer()

        try:
            sock.server.bind((host, int(port)))
        except(socket.error):
            logging.error("Address already in use")
            return
        
        logging.info(f"Started listener on {host, port}")

        try:
            sock.listen()
        except(KeyboardInterrupt):
            sock.server.close()
            print("")
            return

        try:
            if sock.is_shell():
                logging.error("No shell found")
                return
        except(BrokenPipeError):
            sock.server.close()
            logging.error("BrokenPipeError")
            return
        

        self.currentSession = NetShell(sock)

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
