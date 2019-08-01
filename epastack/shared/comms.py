import socket
from socket import error as socketerror
import select
import threading
import traceback
import logging
import Queue

import check

'''
TODO: PROTOCOLS
    specify what types of messages / payloads the various components would want to pass to one another
'''

PROTOCOLS = {
    'D2B New Check': 0x1,
    'D2B Remove Check': 0x2,
    'D2B Change Check': 0x3,
    'D2B Add Node': 0x4,
    'D2B Remove Node': 0x5,
    'D2B Request Node List': 0x6,
    'Heartbeat': 0xDEAD,
    'B2D Results': 0x10,
    'B2D Node List': 0x11,
    'D2B Update Control Value': 0x20
}

class Server:
    '''
    This class provides a simple interface for running a TCP connection server. Its run() function handles
    concurrent connections via use of the POSIX 'select' functionality.

    If you want to start a socket server that listens on a port for incoming connections from anywhere, this
    class is for you.

    All efforts have been made to ensure that this class will shutdown gracefully without hanging. Best results
    are had if the Client class (below) is used on the client side. There may still be some issues with this.
    '''

    def __init__(self, parent, port, handler):
        '''
        Constructor

        :param parent: the class object of the caller. required in order to handle the case that the handler function
                        is a class method
        :param port: int - the port to listen on
        :param handler: a function that takes three arguments: (classObj, socket, string). This will be the function
                        that gets called when a message is received, so it should be some kind of parser
        '''

        self.parent = parent            # The parent class, for passing back to the handler
        self.logger = parent.logger     # The logger to use for logging
        self.port = port                # The port to listen on
        self.handler = handler          # The function to pass incoming messages to

        # SET UP SOCKET
        self.serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serversock.bind(('', self.port))
        self.logger.info("Server bound socket to port " + str(self.port))
        self.serversock.listen(5)

        # SET UP QUEUES
        self.inputs = [self.serversock]
        self.outputs = []

        self.message_queues = dict()

        # FOR HELPING GRACEFUL SHUTDOWN
        self.halted = False

    def run(self):
        '''
        This is the function that handles asynchronous incoming messages and serializes their responses.

        :return: None
        '''
        self.logger.info("Server.run() started.")
        while self.inputs:
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)

            self.logger.debug("Value of self.halted: " + str(self.halted))

            if self.halted:
                for sock in readable:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                for sock in writable:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                for sock in exceptional:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                self.logger.info("Server.run() returning because of halt.")
                return

            for sock in readable:
                if sock is self.serversock:
                    clientsock, client_addr = sock.accept()
                    self.logger.info("Serversock accepted connection from: " + str(client_addr))
                    clientsock.setblocking(0)   # TODO: Not sure why this has to be done
                    self.inputs.append(clientsock)
                    self.message_queues[clientsock] = Queue.Queue()

                else:
                    data = sock.recv(4096)
                    if data:
                        self.logger.debug("Server received data  on socket " + str(sock.getpeername()))
                        self.message_queues[sock].put(data)
                        if sock not in self.outputs:
                            self.logger.debug("Server adding socket " + str(sock.getpeername()) + "to self.outputs")
                            self.outputs.append(sock)

                    else:
                        self.logger.debug("Server call to sock.recv() returned no data. Removing and closing socket")
                        if sock in self.outputs:
                            self.outputs.remove(sock)
                        self.inputs.remove(sock)
                        if not self.message_queues[sock] or self.message_queues[sock].empty():
                            del self.message_queues[sock]
                        sock.shutdown(socket.SHUT_RDWR)
                        sock.close()
                        #del self.message_queues[sock]

            for sock in writable:
                try:
                    sock.fileno()
                except:
                    continue
                if not self.message_queues.get(sock):
                    continue
                try:
                    next_msg = self.message_queues[sock].get_nowait()
                    self.logger.debug("Server getting msg from message_queues")
                except Queue.Empty:
                    self.logger.error("Server writable loop encountered Empty Queue. Removing socket from outputs.")
                    self.outputs.remove(sock)
                    #del self.message_queues[sock]
                except Exception as e:
                    self.logger.error("Exception occurred in Server: ", e)
                else:
                    self.logger.debug("Server starting handler in thread.")
                    if next_msg == "ping":
                        sock.sendall("pong")
                    else:
                        sock.sendall("ack")
                        threading.Thread(target=self.handler, args=(self.parent, next_msg)).run()

            for sock in exceptional:
                self.inputs.remove(sock)
                if sock in self.outputs:
                    self.outputs.remove(sock)
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                del self.message_queues[sock]

        self.logger.error("Server.run() finishing (out of while loop).")

    def halt(self):
        '''
        Function for gracefully halting the server. It creates a new socket to connect to itself to "flush" any
        blocking call to socket.accept().

        :return: None
        '''

        self.halted = True
        cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cs.connect(('', self.port))
        cs.sendall("shutdown")
        cs.close()

class Client:
    '''
    This class provides a simple interface for client TCP connections. If you want to connect
    to some listening server, this class is for you. Its purpose is to abstract out some of
    the tedium of socket programming and allow for modularity and reusability.

    This class is intended for use by at least the Diagnosis Manager and the Backend Manager;
    the Frontend Manager uses it too.
    '''

    def __init__(self, logger, default_servername='', default_serverport=9158):
        '''
        Note that this function initializes self.shutdown to True. This is present in order to allow the
        listener socket to shutdown gracefully without hanging. The default_listen function sets this value
        to False to avoid shutdown behavior, and so should any custom listener function passed to this object.

        :param logger: logging.Logger object - this is required to log to parent's log
        :param default_servername: string - the remote hostname to which this class will connect
        :param default_serverport: int - the remote port on which this class will connect
        '''

        self.logger = logger

        self.servername = default_servername                        # hostname for server socket binding
        self.serverport = default_serverport                        # port bound to server socket
        self.thrd = []                                              # server thread of control
        self.listen = None                                          # server response handler

        self.shutdown = True        # flag to let thread know to shut down

    @staticmethod
    def get_hostname():
        return socket.gethostname()

    def sendmsg_cont(self, msg, first=True, last=False, sockt=None):
        '''
        Sends arbitrary text to the host/port of this class, without closing socket in between

        :param msg: string - arbitrary plaintext
        :param first: boolean - whether this is the first message in the session
        :param last: boolean - whether this is the last message in the session
        :param sockt: socket - only if first == False
        :return: socket created on first send, or socket passed in on subsequent calls
        '''
        self.logger.info("Client.sendmsg_cont() started")

        if first:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     # allow reuse of address to prevent Error 98: address already in use
            sock.connect((self.servername, self.serverport))
            self.logger.debug("Client.sendmsg_cont() connected to " + self.servername + ":" + str(self.serverport))

        else:
            sock = sockt

        sock.sendall(msg)

        if last:
            #data = sock.recv(1024)
            sock.close()
            self.logger.debug("Client.sendmsg_cont() closed socket")

        #self.logger.debug("Client.sendmsg() recieved" + str(data))

        self.logger.info("Client.sendmsg_cont() done")

        return sock

    def sendmsg(self, msg):
        '''
        Sends arbitrary text to the host/port of this class.

        :param msg: string - arbitrary text
        :return: None
        '''
        self.logger.info("Client.sendmsg() started")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     # allow reuse of address to prevent Error 98: address already in use

        sock.connect((self.servername, self.serverport))
        self.logger.debug("Client.sendmsg() connected to " + self.servername + ":" + str(self.serverport))

        sock.sendall(msg)
        data = sock.recv(1024)

        self.logger.debug("Client.sendmsg() recieved" + str(data))

        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

        self.logger.info("Client.sendmsg() closed socket & done")

    def halt(self):
        '''
        Sets the Client.shutdown field to True, and sends throwaway text to the listening port in order to
        trigger the listen() shutdown protocol.

        NOTE: This function may be deprecated.

        :return: None
        '''
        self.logger.info("Client.halt() started.")

        if not self.shutdown:
            self.shutdown = True
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            sock.connect((self.servername,self.serverport))
            self.logger.debug("Client.halt() connected to " + self.servername + ':' + str(self.serverpo))

            sock.sendall('shutdown signal')
            data = sock.recv(1024)

            self.logger.debug("Client.halt(): sent halt signal, recieved reply: " + data)

            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

            self.logger.debug("Client.halt() finished.")
        else:
            self.logger.error('Client.halt() called when self.shutdown set to True. Server already halted.')

    def ping(self):
        '''
        Sends 'ping' in plaintext to the configured address, waits for a response and prints it out.

        :return: None
        '''
        self.logger.info("Client.ping() started")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     # allow reuse of address to prevent Error 98: address already in use

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.servername, self.serverport))
        self.logger.debug("Client.ping(): connected to " + self.servername + ':' + str(self.serverport))

        sock.sendall('ping')
        data = sock.recv(1024)
        self.logger.info("Client.ping(): received " + data)

        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

        self.logger.debug("Client.ping() finished.")

