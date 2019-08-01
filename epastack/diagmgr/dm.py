import os
import json
import socket
import traceback
import pickle
import threading
import logging
from Crypto import Hash
import uuid
import copy

import epastack.shared.check as check
import epastack.shared.policies as policies
import epastack.shared.comms as comms
import results
from dmConfig import *
import epastack.oracle.oracle as oracle
import collections
"""
TODO: DOCUMENTATION
    provide some examples in the comments of how checks look as dicts.
"""

class DiagMgr:

    io_fields = {
        'checks': 0,
    }

    # Parsing symbols for the saved check definition files
    io_symbols = {
        'fields': ';',
        'checks': '::',
        'types': '===',
        'c_type': '_c_',
    }

    PROTOCOL_HANDLERS = {
        0x10: lambda x, y: DiagMgr.handle_results(x, y),
        0x11: lambda x, y: DiagMgr.handle_node_list(x, y)
    }

    def __init__(self, sched_p=0, fin='chs.pickle', fout='chs.pickle', listen_hosts_path='listen_hosts.json', send_hosts_path='send_hosts.json'):
        self.logger = logging.getLogger(__name__)

        self.hostname = comms.Client.get_hostname()

        self.sched_p = sched_p  # scheduling policy for BEM

        self.filein = fin       # filename to import
        self.fileout = fout     # filename to export
        self.checks = {}        # dict of checks
        self.results = {}       # id: [results] dict to store results (until we get a DB)
        self.bemnodes = {}      # string: [int] dict to store BEMs and the node ids they each monitor
        self.node_costs = {}    # int: int dict to store usec/byte hashing capabilities of nodes

        self.listen_hosts_path = listen_hosts_path
        self.listen_hosts = {}  # a dict identical in type to the global LISTEN_HOSTS dict
        self.listen_servers = {}# a dict of string : Comms.Server   values

        self.send_hosts_path = send_hosts_path
        self.send_hosts = {}    # a dict of string : (string, int) values identical to the global SEND_HOSTS dict
        self.send_servers = {}  # a dict of string : Comms.Client   values 

        self.serverthreads = {} # dict for holding listening server threads

        self.checkmap = {}      # dictionary for mapping check instances to check definitions.



        # SET UP ORACLE
        self.oracle = oracle.Oracle()

        self.kernel_functions = collections.OrderedDict()  # dictionary to store kernel symbols returned by the oracle

        # Load hosts from config file, or else set default hosts

        if os.path.isfile(self.listen_hosts_path):
            with open(self.listen_hosts_path,'r') as fname:
                self.listen_hosts = pickle.load(fname)
        else:
            self.listen_hosts = LISTEN_HOSTS.copy()
            with open(self.listen_hosts_path, 'w') as fname:
                pickle.dump(self.listen_hosts, fname)

        # Load send hosts from config file, or else set default hosts

        if os.path.isfile(self.send_hosts_path):
            with open(self.send_hosts_path,'r') as fname:
                self.send_hosts = pickle.load(fname)
        else:
            self.send_hosts = SEND_HOSTS.copy()
            with open(self.send_hosts_path, 'w') as fname:
                pickle.dump(self.send_hosts, fname)

        # Initialize listen servers from hosts

        for host in self.listen_hosts.keys():
            servername, serverport = self.listen_hosts[host]
            self.listen_servers[host]  = comms.Server(self, serverport, handler=DiagMgr.handle_messages)

        # Initialize send servers from hosts

        for host in self.send_hosts.keys():
            servername, serverport = self.send_hosts[host]
            self.send_servers[host]  = comms.Client(self.logger, servername, serverport)

        # Load any checks from file

        try:
            with open(self.filein, 'r') as fh:
                self.checks = pickle.load(fh)

        except IOError:
            print "No saved Checks file to load."


    def __str__(self):
        dgmgr = ''
        if self.checks:
            for item in self.checks:
                dgmgr += str(item) + '\n'
            dgmgr += '\n'
        return dgmgr

    def addhost(self, args):
        assert(len(args) == 3)
        assert(args[0] in ['-l', '-s'])
        type = args[0]
        name = args[1]
        port = int(args[2])

        if type == '-l':
            self.listen_hosts[name] = (name, port)
            self.listen_servers[name] = comms.Server(self, port, handler=DiagMgr.handle_messages)
            with open(self.listen_hosts_path, 'w') as fname:
                pickle.dump(self.listen_hosts, fname)
        else:
            self.send_hosts[name] = (name, port)
            self.send_servers[name] = comms.Client(self.logger, name, port)
            with open(self.send_hosts_path, 'w') as fname:
                pickle.dump(self.send_hosts, fname)

        print "Host added."

    @staticmethod
    def get_from_server(parent, sock, address):
        """
        Returns data received from socket, after printing it.

        This function should eventually parse the data based on the communication protocols,
        before doing some specified action based on the message code.

        For our one use-case so far, the BEM would be sending back Check results. So this function could call
        another function that dropped the parsed data into a results dict, which would then feed into the web
        frontend, etc.

        :param sock: a live socket (post sock.accept())
        :param address: a (host, port) tuple
        """

        data = sock.recv(1024)
        if not data:
            print "get_from_server: nothing received."
            return None
        print "get_from_server: received ", data
        if data == 'shutdown signal':
            parent.shutdown = True
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        return data

    def ping_server(self, args):
        """
        Pings one or more known hosts by calling the Client.ping() function on that server.

        :param args: a list of strings of known hosts
        """

        def check_args(args):
            if len(args) < 1:
                print "Usage: ping [HOSTNAME] (more than one hostname allowed)"
                return False
            else:
                return True

        if not check_args(args):
            return

        for host in args:
            if host in self.send_hosts.keys():
                server = self.send_servers.get(host)
                if not server:
                    print "Server not found in dm.DiagMgr servers dict. ", host, " not pinged."
                    print ' '.join(self.send_hosts.keys())
                    self.logger.error("ping_server() error: server not found")
                    return
                server.ping()
            else:
                print "Hostname ", host, " not found in dm.DiagMgr hosts dict. ", host, " not pinged."
                print ' '.join(self.send_hosts.keys())
                self.logger.error("ping_server() error: server not found")

    def server_stop_all(self):
        """
        Halts all known servers.
        """

        for host in self.listen_hosts.keys():
            server = self.listen_servers.get(host)
            if server:
                print "Halting ", host
                try:
                    threading.Thread(target=server.halt).run()
                    print host + " halted."
                except Exception:
                    traceback.print_exc()
            else:
                print "Hmm...a host not found in servers during DiagMgr.server_stop_all()."

    def server_stop(self, args):
        """
        Halts one or more known servers.

        :param args: a list of strings of known hostnames
        """

        def check_args(args):
            if not args:
                print "usage: serverstop [HOST NAME] (more than one hostname allowed)"
                return False
            return True

        if not check_args(args):
            return

        for host in args:
            server = self.listen_servers.get(host)
            if server:
                print "Halting ", host
                try:
                    server.halt()
                except Exception:
                    traceback.print_exc()
            else:
                print host, " not a known server; no halt."

    def server_start_all(self):
        """
        Starts listeners for all known hosts.
        """

        for host in self.listen_hosts.keys():
            server = self.listen_servers.get(host)
            if server:
                print "Starting ", host
                self.serverthreads[host] = threading.Thread(target=server.run).start()
            else:
                print "Hmm...a host not found in servers during DiagMgr.server_start_all()."

    def server_start(self, args):
        """
        Starts listeners for one or more known hosts.

        :param args: a list of strings of known hostnames
        """

        def check_args(args):
            if not args:
                print "usage: serverstart [HOST NAME] (more than one hostname allowed)"
                return False
            return True

        if not check_args(args):
            return

        for host in args:
            server = self.listen_servers.get(host)
            if server:
                print "Starting ", host
                server.shutdown = False
                self.serverthreads[host] = threading.Thread(target=server.run).start()
            else:
                print host, " not a known server; no start."

    def server_restart(self, args):
        """
        Restarts one or more known hosts

        :param args: a list of strings of known hostnames
        """

        def check_args(args):
            if not args:
                print "usage: serverstop [HOST NAME] (more than one hostname allowed)"
                return False
            return True

        if not check_args(args):
            return

        for host in args:
            server = self.listen_servers.get(host)
            if server:
                print "Restarting ", host
                server.halt()
                self.serverthreads[host] = threading.Thread(target=server.run).start()
            else:
                print host, " not a known server; no restart."

    def print_hosts(self):
        """
        Prints all known hosts.
        """

        print "Listen Hosts:"
        for host in self.listen_hosts.keys():
            hs, prt = self.listen_hosts[host]
            print hs, " : ", prt

        print "Send Hosts:"
        for host in self.send_hosts.keys():
            hs, prt = self.send_hosts[host]
            print hs, " : ", prt

    def close(self):
        """
        Writes out checks to file
        """
        self.logger.info("close() started.")
        # loads("[{},{}]".format(dumps(a), dumps(b)))
        with open(self.fileout, 'w+') as fh:
            pickle.dump(self.checks, fh, -1)

    def get_checks(self):
        """
        Returns all installed checks as a dict.
        """

        return self.checks

    def add_check(self, chk):
        """
        Add a check to the class checks dict.

        :param chk: a correctly-formatted dict representing the check.
        """
        self.logger.info("add_check() started.")

        numchecks = len(self.checks.keys()) # TODO Make this a monotonic counter

        checkname = chk.get('name')

        if checkname in self.checks.keys() and "provision" not in checkname:
            self.logger.error("dm.add_check() given a checkname that is already in use")
            raise KeyError("That check name is already in use.")

        node = chk['node_id']
        cost = self.node_costs.get(node, 1) # should be a usec/byte rate
        self.logger.debug("computed cost: {}".format(str(cost)))
        size = chk.get('len', 1)            # length of measurement in bytes
        self.logger.debug("computed size: {}".format(str(size)))

        chk['cost'] = cost*size
        self.logger.debug("Total computed check cost: {}".format(str(chk['cost'])))


        c = check.Check(chk, numchecks)
        self.logger.debug("adding check: {}".format(str(c)))
        self.checks[checkname] = c

    def send_all(self,args):
        if len(args) < 2:
            self.logger.error("dm.send_all() argslist too short")
            raise Exception("Arg list to send_all to short")
        self.logger.info("send_all started")
        host = args[0]
        nodename = args[1]
        i = 0
        for chk in self.checks.keys():
            i += 1
            print "Sending check " + str(i)
            self.send_check([host,chk,nodename])

    def send_check(self, args):
        if len(args) < 3:
            self.logger.error("dm.send_check() argslist too short")
            raise Exception("Arg list to send_check too short.")

        self.logger.info("send_check started")

        host = args[0]
        chkname = args[1]
        nodename = args[2]

        if host not in self.send_servers.keys():
            self.logger.error("No comms object set up for named host.")
            raise KeyError("Host '{}' not found.".format(host))
        
        if len(self.serverthreads.keys()) < 1:
            self.logger.error("send_check() attempted without listen server started")
            raise Exception(("Listen server not started\n" +
                            "Please start the server with `serverstart {}`\n" +
                            "Or restart the DM Terminal with `python dmterm.py -s`").format(self.listen_hosts.keys()[0]))

        chk = self.checks.get(chkname)
        if not chk:
            self.logger.error("argument to send_check not in checks dict")
            raise KeyError("Check '{}' not found.".format(chkname))

        def_id = chk.id
        chk = copy.copy(chk)

        # chk.id = uuid.uuid1().int>>64     # TODO: differentiate between check ID and instance ID lower down in the stack (particularly the oracle)
        inst_id = chk.id

        self.checkmap[inst_id] = def_id

        msg = dict()
        msg['opnum'] = comms.PROTOCOLS['D2B New Check']
        msg['source'] = self.hostname
        msg['node_id'] = nodename
        msg['payload'] = chk.__dict__
        self.logger.debug("sending: " + DiagMgr.msg_to_string(msg))
        msg = pickle.dumps(msg)

        self.logger.info("send_check() calling comms.sendmsg()")
        self.send_servers[host].sendmsg(msg)

    def update_control_value(self, args):
        if len(args) != 4:
            self.logger.error("dm.update_control_value arglist wrong length")
            # this should already have been checked by the check_args function
            raise Exception("update_control_value expected 4 arguments and recieved {}".format(len(args)))

        host = args[0]
        node = args[1]
        cv = args[2]
        val = args[3]

        if host not in self.send_servers.keys():
            self.logger.error("No comms object set up for named host.")
            raise KeyError("Host '{}' not found.".format(host))

        msg = dict()
        msg['opnum'] = comms.PROTOCOLS['D2B Update Control Value']
        msg['source'] = self.hostname
        msg['payload'] = {"target": cv, "value": val, "node_id": node}

        self.logger.debug("Sending CV Update request to {} for node {} with cv: {} val: {}".format(host, node, cv, val))
        self.send_servers[host].sendmsg(pickle.dumps(msg))

    @staticmethod
    def handle_messages(parent, data):
        """
        This function identifies incoming messages by their opnum and dispatches
        the correct handler.

        :param parent: an instance of this class
        :param data: a pickled data string
        :return: None
        """
        parent.logger.info("handle_messages() started")

        if not data:
            parent.logger.error("handle_messages(): nothing received.")
            return None

        msg = pickle.loads(data)
        opnum = msg['opnum']

        if opnum not in parent.PROTOCOL_HANDLERS.keys():
            parent.logger.error("Received message with unknown opnum: " + str(opnum))
            return

        parent.PROTOCOL_HANDLERS[opnum](parent, data)

    def handle_node_list(self, data):
        """
        This function captures the NodeList objects as they come back from the
        BEM.

        :param data: a pickled data string
        :return: None
        """
        self.logger.info("handle_node_list() started")

        if not data:
            self.logger.error("handle_node_list(): nothing received.")
            return None

        msg = pickle.loads(data)
        source = msg.get('source')
        nodelist = msg.get('payload')

        if source is None:
            self.logger.error("No source in the message provided to handle_node_list()!")
            return

        if nodelist is None:
            self.logger.error("No nodelist in the message provided to handle_node_list()!")
            return

        self.bemnodes[source] = nodelist


    def handle_results(self, data):
        """
        This function captures the Results objects as they come back from the 
        BEM.

        :param data: a pickled data string
        :return: None
        """
        self.logger.info("handle_results() started")

        if not data:
            self.logger.error("handle_results(): nothing received.")
            return

        msg = pickle.loads(data)
        result = msg['payload']
        inst_id = result.get('id')  # the id of the check instance

        if inst_id is None:
            self.logger.error("handle_results(): no result id provided.")
            return
        def_id = self.checkmap.get(inst_id)  # the id of the check definition

        if def_id is None:
            self.logger.error("handle_results(): unexpected result - no mapping to definition")
            return

        check = None;
        for chk in self.checks.values():
            if chk.id == def_id:
                check = chk
        if check is None:
            self.logger.error("handle_results(): could not find check for id.")
            return
        node = check.node_id
        cost = result['cost'] # This cost is a sum of the task costs, in usec

        check.cost = cost
        self.node_costs[node] = cost // result['size'] # TODO: We may want to come up with some criteria by which the node cost gets updated

        results_list = self.results.get(def_id)
        if results_list is None:
            self.results[def_id] = [result]
        else:
            self.results[def_id].append(result)

        self.update_check(result, def_id)
        self.update_costs(node)

    def update_check(self, result, def_id):
        """
        Update checks as results come in
        """
        check = None
        for chk in self.checks.values():
            if chk.id == def_id:
                check = chk

        if check is None:
            self.logger.error("update_check(): could not find check for id %s".format(check_id))
            return

        size = result.get('size')
        if size is None:
            self.logger.error("No size found for result")
            return
        if getattr(check, 'hashes') is None:
            self.logger.error("check.hashes attribute not found; creating")
            self.logger.error("{}".format(check.__dict__))
            check.hashes = {}
        granularity = result['granularity']
        check.hashes[granularity] = result['hashes']
        check.last_insp = result['time']

    def update_costs(self, node_id):
        """
        Updates check costs for the given node.
        
        :param node_id: the node_id for which to update Check costs
        :return: None
        """

        cost = self.node_costs[node_id]

        for checkname in self.checks.keys():
            check = self.checks[checkname]
            if check.node_id == node_id:
                check.cost = cost * check.len

    @staticmethod
    def msg_to_string(msg):
        """
        Converts a dict to a string
        """
        st = ""
        for key in msg.keys():
            st += str(key) + ": " + str(msg.get(key)) + "\n"
        return st

    def request_node_list(self, bems):
        """
        This function sends a message to one or more BEMs requesting a list
        of all the nodes they monitor.

        If the SEND_HOSTS global dict ever includes non-BEM objects, such
        as Oracles or other DMs, the logic in this function will need to be
        changed to differentiate BEM socket info from the others.

        :param bems: a list of hostname strings; should be empty if requesting 
                     node lists from all BEMs is desired
        :return: None
        """
        self.logger.info("request_node_list() started")
        self.logger.info("bems argument: " + str(bems))

        msg = dict()
        msg['opnum'] = comms.PROTOCOLS['D2B Request Node List']
        msg['node_id'] = None
        msg['payload'] = None
        self.logger.debug("sending: " + DiagMgr.msg_to_string(msg))
        msg = pickle.dumps(msg)

        self.logger.info("request_node_list() calling comms.sendmsg()")
        
        if len(bems) == 0:
            for host in self.send_servers.keys():
                self.logger.info("request_node_list() sending to " + str(host))
                self.send_servers[host].sendmsg(msg)
        else:
            for host in bems:
                self.logger.info("request_node_list() sending to " + str(host))
                self.send_servers[host].sendmsg(msg)
