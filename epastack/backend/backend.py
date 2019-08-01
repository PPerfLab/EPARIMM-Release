import logging
import Queue
import traceback
import os
import pickle
import sys
sys.path.insert(0, '../..')
from epastack.shared.scheduling.fifo import *
from epastack.shared.task import Task
import epastack.shared.policies as policies
import epastack.shared.comms as comms
import epastack.shared.check as check
import epastack.oracle.oracle as oracle
import decomp
import argparse
import datetime
import time
import struct
import threading
import signal
import uuid

from Crypto import Random
from Crypto.Hash import HMAC, SHA256
# AES
from Crypto.Cipher import AES
from binascii import a2b_hex
from backendConfig import *

class Backend_Manager:
    """
    This class is meant to sit between the DM and the FEM/HCM. It's job is to listen for Checks sent by
    the DM, decompose each Check into one or more Tasks, put those Tasks into one or more bins, and
    send the bins on to the FEM/HCM. It should also listen for results coming from the FEM/HCM,
    recompose those results into Check Results, and send the Check Results back up to the DM.

    The BEM remembers messages it has seen/sent by maintaining Queues. The Queue objects are dicts
    formatted in the following way:

    id:             'id'
    check:          'check'
    time received:  't_recv'
    time sent:      't_snd'
    time returned:  't_ret'
    hash size:      'size'
    result hash:    'res_hash'
    """

    # TODO Get these from shared.comms

    PROTOCOL_HANDLERS = {
        0x1: lambda x, y: Backend_Manager.newcheck(x, y),
        0x2: lambda x, y: Backend_Manager.updatecheck(x, y),
        0x6: lambda x, y: Backend_Manager.return_node_list(x, y),
        0x10: lambda x, y: Backend_Manager.handle_fem_results(x, y),
        0x20: lambda x, y: Backend_Manager.update_control_value(x, y),
        0xDEAD: lambda x, y: Backend_Manager.heartbeat_reply(x, y)
    }

    CONTROL_PARAMATERS = {
            "bin_size": lambda x, y: Backend_Manager.update_bin_size(x, y),
            "delay": lambda x, y: Backend_Manager.update_delay(x, y)
    }

    def __init__(self, bin_size, node_q_maxsize=100, listen_hosts_path='bem_listen_hosts.json',
                 send_hosts_path='bem_send_hosts.json', listen_port=BACKEND_PORT, dm_port=DM_PORT, dm_host=DM_HOST,
                 node_addresses=None, debug=True, encrypt = False, hmac=False):
        '''
        Constructor

        :param bin_size: int - the initial size for bins (this could be adjusted at runtime by a terminal)
        :param node_q_maxsize: int - the max size for the queue maintained for each monitored node
        :param listen_hosts_path: str - the file/path indicating a correctly-formatted JSON file storing server configuration information
        :param send_hosts_path: str - same as above, except for client configuration
        :param listen_port: int - port to listen on for incoming connections
        :param dm_port: int - the port on which to connect to the DM
        :param dm_host: str - the hostname of the DM
        :param node_addresses: dict - a dict of [hostname: port] mappings for monitored nodes
        :param debug: bool - whether or not to enable printing of some debugging info to stdout
        :param encrypt: bool - whether or not to enable encrypted traffic
        :param hmac: bool - whether or not to enable HMAC authentication on messages
        '''

        # SET UP LOGGING
        self.logger = logging.getLogger(LOG_NAME)

        # SET UP ORACLE
        self.oracle = oracle.Oracle()

        # SELF IDENTIFICATION
        self.hostname = comms.Client.get_hostname()

        # SET BIN SIZE
        self.bin_size = bin_size

        # SET UP HALTER FLAG
        # True indicates that server is stopped
        self.halted = False

        # DEBUGGING
        self.debug = debug

        # HMAC Signing
        self.HMAC = hmac

        # ENCRYPTION
        # TODO - should these actually be settable seperately?
        self.ENCRYPT = encrypt
        self.DECRYPT = encrypt

        # DM NAME
        self.dm_hostname = dm_host

        # SET UP PER NODE DATA STRUCTURES
        self.recvd_checks = dict()      # nodeID: [check] Queue-per-node for tracking received checks
        self.recvd_lists = dict()       # nodeID: {taskID => task}  List-per-node for tracking received task results
        self.sent_lists = dict()        # nodeID: {taskID => task}  List-per-node for tracking sent tasks
        self.wait_queues = dict()       # nodeID: [task]  List-per-node for tasks to be scheduled.
        self.check_tasks = dict()       # nodeID: {chk_id => [task_id]} Track tasks for each check for each node.
        self.schedulers = dict()        # nodeID: instance of Scheduler
        self.delays = dict()            # nodeID: scheduling delay

        self.nodelist = node_addresses
        if not self.nodelist:
            self.nodelist = DEFAULT_NODELIST

        for item in self.nodelist.keys():
            self.recvd_checks[item] = []
            self.recvd_lists[item] = dict()
            self.sent_lists[item] = dict()
            self.wait_queues[item] = FifoQueue()
            self.check_tasks[item] = dict()
            self.schedulers[item] = FifoScheduler()
            self.delays[item] = 1      # Default Scheduling Delay

        # SET UP DONE QUEUE
        self.done = Queue.Queue()

        # SET UP COMMUNICATIONS
        self.listen_hosts_path = listen_hosts_path
        self.listen_hosts = {}
        self.listen_servers = {}

        self.send_hosts_path = send_hosts_path
        self.send_hosts = {}
        self.send_servers = {}

        self.serverthreads = {} # dict for holding listening server threads
        self.schedulerthreads = {}

        # Load server configs from config file, or else set default hosts

        if os.path.isfile(self.listen_hosts_path):
            with open(self.listen_hosts_path,'r') as fname:
                self.listen_hosts = pickle.load(fname)
        else:
            self.listen_hosts = dict()
            self.listen_hosts['bem_local'] = ('',listen_port)
            with open(self.listen_hosts_path, 'w') as fname:
                pickle.dump(self.listen_hosts, fname)

        # Load client configs from config file, or else set default hosts

        if os.path.isfile(self.send_hosts_path):
            with open(self.send_hosts_path,'r') as fname:
                self.send_hosts = pickle.load(fname)
        else:
            self.send_hosts = dict()
            self.send_hosts[dm_host] = (dm_host, dm_port)           # Communication with DM
            for node_num in self.nodelist.keys():
                self.send_hosts[str(node_num)] = self.nodelist[node_num] # Communication with each node
            with open(self.send_hosts_path, 'w') as fname:
                pickle.dump(self.send_hosts, fname)

        # Initialize servers from hosts

        for host in self.listen_hosts.keys():
            servername, serverport = self.listen_hosts[host]
            self.listen_servers[host] = comms.Server(self, serverport, handler=self.dm_handle)

        # Initialize clients from hosts

        for host in self.send_hosts.keys():
            servername, serverport = self.send_hosts[host]
            self.send_servers[host] = comms.Client(self.logger, servername, serverport)

        # SET UP NODE COST TABLE
        self.node_costs = dict()        # node_id (int) : usec/byte (int)

    def print_queues(self):
        '''
        Prints the "received list" queue for each monitored node to log
        :return:
        '''
        self.logger.info("print_queues() started")
        for node_id in self.nodelist.keys():
            self.logger.info("Node id: " + str(node_id))
            l = self.recvd_checks.get(node_id)
            if l is None:
                self.logger.info("\nStrange... No checks list found for node " + str(node_id))
            else:
                self.logger.info("Received checks: ")
                self.logger.info('\n'.join([str(x) for x in l]))
            q = self.recvd_lists.get(node_id)
            if q is None:
                self.logger.info("\nStrange... No tasks queue found for node " + str(node_id))
            else:
                self.logger.info("Received tasks: ")
                self.logger.info('\n'.join([str(x) for x in q]))

    def start(self):
        '''
        Starts the socket servers for each host in self.listen_hosts

        :return: None
        '''
        self.logger.info("start() started")
        signal.signal(signal.SIGINT, self.interrupt_handler)

        for host in self.listen_hosts.keys():
            self.logger.debug("Current host: " + host)
            server = self.listen_servers.get(host)
            if server:
                self.logger.info("Starting server: " + str(host))
                self.serverthreads[host] = threading.Thread(target=server.run).start()
            else:
                self.logger.error(str(host) + " not a known server; no start.")

        for node in self.nodelist.keys():
            self.schedulerthreads[node] = threading.Thread(target=self.dispatch_loop, args=(node,)).start()

    def halt(self):
        '''
        Provides graceful halting of socket servers.

        :return:
        '''
        self.logger.info("bem.halt() started")
        self.halted = True
        self.server_halt()
        sys.exit(0)

    def server_halt(self):
        '''
        Halts socket servers.

        :return:
        '''
        self.logger.info("bem.server_halt() started")
        for host in self.listen_hosts.keys():
            server = self.listen_servers.get(host)
            if server:
                print "Halting ", host
                self.logger.info("Halting " + host)
                try:
                    threading.Thread(target=server.halt).run()
                    print host + " halted."
                    self.logger.info(host + " halted.")
                except Exception:
                    self.logger.error("Halting " + host + " failed.")
                    traceback.print_exc()
            else:
                print "Hmm...a host not found in servers during bem.server_halt()."
                self.logger.error("Strange. There was a key in bem.listen_servers that didn't map to a server.")

    def heartbeat_reply(self, sender):
        '''
        NOT IMPLEMENTED; eventually might be a periodic ping
        :param sender:
        :return:
        '''
        self.logger.info("heartbeat_reply started")

    def handle_fem_results(self, results):
        '''
        This function is called as a result of the FEM/HCM sending results back (opcode 0x10).

        In theory it should decrypt/authenticate (if enabled), unpack the struct, reconsitute the results
        as Task objects, recompose the Tasks into a Check, and send the Check (result) back up to the DM.


        Note that this function expects the FEM/HCM to send task results one at a time.

        :param results: dict - an unpickled dict from the FEM, with message header (node_id, etc) still intact

        :return: None
        '''
        self.logger.info("handle_fem_results started")

        node_id = results['node_id']
        resultsString = results['payload']

        if (self.DECRYPT==1):
            self.logger.info("Going to decrypt...")
            # Decrypt encrypted results from Monitored Node
            Ivec = resultsString[:16] # This comes from the struct format
            st = []
            for ch in resultsString:
                st.append(ch.encode('hex'))
            key = INSPECTOR_KEY
            key = a2b_hex(key)
            encobj = AES.new(key, AES.MODE_CBC, Ivec)
            plaintext = bytes(Ivec) + bytes((encobj.decrypt(resultsString[16:]))) 
            hmacInput = plaintext[:240]  # Ivec + plaintext 
            ReceivedHmac = (plaintext[240:].encode('hex'))
            binstruct = struct.unpack(''.join(['<', 'Q'*12, 'I'*18, 'Q'*11]), plaintext[16:]) 
            # binstruct now has the decrypted results from the Inspector

        else: # No decryption on data coming in, BUGBUG haven't dealt with IVEC
            self.logger.info("No need to decrypt...")
            binstruct = struct.unpack(''.join(['<', 'Q'*12, 'I'*18, 'Q'*11]), resultsString[16:]) 
            ReceivedHmac = resultsString[240:].encode('hex')  # bin is not encrypted in this case 
            hmacInput = resultsString[:240] 

        # Generate a new HMAC to compare with Inspector-provided HMAC
        if (self.HMAC):
            HmacKey = ''.join(chr(x) for x in HMAC_KEY)  # HMAC Key
            st = []
            for ch in hmacInput:
                st.append(ch.encode('hex'))
            hash_obj = HMAC.new(key=HmacKey, msg=bytes(hmacInput), digestmod=SHA256)
            CalculatedHmac = hash_obj.hexdigest()
            if CalculatedHmac == ReceivedHmac:  # Fixme: Use CompareDigest?
                self.logger.info("\nHMAC match - result contents ok.")

            else:
                self.logger.error("\nWARNING - No HMAC match! Results potentially tampered with!")  # fixme, report this up to Web GUI server

            self.logger.info("Inspector generated Hmac " + str(ReceivedHmac))
            self.logger.info("BEM generated HMAC:\t " + CalculatedHmac)
        else:
            self.logger.info("HMAC Check disabled in BEM!")

        argsdict = {}
        order = list(Task.unpack_order)
        for i in range(len(order)):
            arg = order[i]
            argsdict[arg] = binstruct[i]

        self.logger.debug("unpacked task from fem: \n{}".format(argsdict))

        if argsdict.get('command') == policies.MEMORY_COMMANDS['HASH_MEM_VIRT']:
            argsdict['address'] = argsdict.get('virtaddr')
        elif argsdict.get('command') == policies.MEMORY_COMMANDS['HASH_MEM_PHYS']:
            argsdict['address'] = argsdict.get('physaddr')

#        newtask = Task(argsdict)

        uuid = argsdict.get('task_uuid')
        newtask = self.sent_lists[node_id][uuid]

        newtask.received = time.time()

        self.logger.info("Task {} created {}, queued {}, packed {}, received {}.".format(newtask.task_uuid, newtask.created, newtask.queued, newtask.packed, newtask.received))

        for arg, value in argsdict.iteritems():
            setattr(newtask, arg, value)

        if newtask.command != 0:
            self.recvd_lists[node_id][newtask.task_uuid] = newtask

            #find associated check id
            checks = self.check_tasks[node_id]
            chk_id = None
            for check in checks.keys():
                if newtask.task_uuid in checks[check]:
                    chk_id = check
                    break
            if chk_id is None:
                #Got task results for unknown task
                self.logger.error("Received task results for task with no associated check")
                return
            newtask.check_id = chk_id
            newtask.node_id = node_id
            
            if self.oracle.store_results(newtask) == -1:
                print('RESULT STORE FAILED!')

            #determine if check is complete
            check_done = True
            for t in checks[chk_id]:
                if not (t in self.recvd_lists[node_id].keys()):
                    check_done = False
                    break

            if check_done:
                tasks = []
                for t in checks.pop(chk_id):
                    t = self.recvd_lists[node_id].pop(t)
                    tasks.append(t)
                result = decomp.Recomp.recomp_1(tasks, chk_id)
                self.dm_send_results(result.export())
            else:
                self.logger.info("Received a task result")

        else:
            print "received a zeroed result."

    def newcheck(self, msg):
        """
        This function "installs" a new check on the BEM queue for the appropriate node. This amounts to putting
        the check on an in-memory list, and then sending it off to be decomposed and sent to FEM/HCM.

        :param msg: a message dict

        :return: None
        """
        self.logger.info("newcheck started")
        self.logger.info("newcheck 'msg' arg: ")
        self.logger.info(msg)
        node_id = int(msg['node_id'])
        if node_id not in self.nodelist.keys():
            self.logger.error("Received nonexistent node_id from DM: " + str(node_id))
            return

        payload = msg['payload']

        check_id = payload['id']

        self.logger.info("newcheck payload: ")
        self.logger.info(payload)

        chk = check.Check(payload, check_id)

        obj = dict()
        obj['id'] = chk.id
        obj['t_recv'] = datetime.datetime.now()
        obj['check'] = chk

        checks = self.recvd_checks.get(node_id)
        if checks is None:
            self.logger.error("Strange...no checks list found in bem for node " + str(node_id))
            self.recvd_checks[node_id] = [obj]
        else:
            checks.append(obj)

        if self.debug:
            self.print_queues()

        self.decomp(chk, node_id)

    def updatecheck(self, check):
        '''
        NOT IMPLEMENTED

        The purpose of this function will be to update the (scheduling) particulars of a given check that's
        already in the BEM system.

        This will require a bit more management of stored Checks.

        :param check:
        :return:
        '''
        self.logger.info("updatecheck started")

    @staticmethod
    def dm_handle(self, data):
        '''
        This is the function that parses incoming messages. It reads off the 'opnum' field from the
        message and dispatches another handler function accordingly.

        :param self: class - the class object that wants a message handled
        :param sock: socket - the socket on which the message was received
        :param data: string - the message

        :return: None
        '''
        self.logger.info("dm_handle started")

        if not data:
            self.logger.error("dm_handle: no data received.")
            return

        msg = pickle.loads(data)
        self.logger.debug("dm_handle() loaded from pickle: ")
        self.logger.debug(msg)
        print msg

        msg_type = msg.get('opnum')

        self.logger.debug("dm_handle(): dispatching handler " + str(msg_type))
        # TODO - Check opnum validity
        Backend_Manager.PROTOCOL_HANDLERS[msg_type](self, msg)

    def dm_send_results(self, results):
        '''
        Package and send one (or more?) check results to the DM.

        :param results: a dict formed by bem.results_send()

        :return: None
        '''
        self.logger.info("dm_send_results() started")

        msg = dict()
        msg['opnum'] = comms.PROTOCOLS['B2D Results']
        msg['source'] = self.hostname
        msg['payload'] = results

        msg = pickle.dumps(msg)
        self.logger.debug("dm_send_results() pickling complete")

        commo = self.send_servers[self.dm_hostname]
        commo.sendmsg(msg)
        self.logger.debug("dm_send_results() message send complete")

    def results_send(self, obj):
        '''
        Wraps a Check object in some extra information to conform to CheckResult spec

        :param obj: a Check (result) object
        :return:
        '''
        self.logger.info("results_send() started")

        res = dict()
        res['id'] = obj['id']
        res['complete'] = True
        res['result'] = True
        res['size'] = obj['size']
        res['hash'] = ["somehash"]
        res['time'] = obj['t_ret']
        res['cost'] = obj['cost']

        self.dm_send_results(res)

    def assign_id(self, task, node_id):
        """
        Assigns the given task a unique (per node) task id.

        TODO is there a better way of doing this?
        Perhaps incorporating a check id and a task id in a way that allows for
        faster lookups?

        :param task: the task to be assigned an ID
        :param node_id: the node the task will be assigned to.
        :return: None
        """
        task.task_uuid = uuid.uuid1().int>>64

    def decomp(self, chk, node_id):
        """
        Decomposes a check into one or more tasks and adds it to a node's task queue.
        :param chk: a Check object
        :param node_id: the destination node_id for the check.
        :return:
        """
        self.logger.info("decomp() started")

        tasks = decomp.Decomp.decomp_1(chk)
        task_ids = []
        for task in tasks:
            self.assign_id(task, node_id)
            task_ids.append(task.task_uuid)
            self.wait_queues[node_id].enqueue(task)
            task.queued=time.time()
        self.check_tasks[node_id][chk.id] = task_ids

    def error_task(self, node_id, newtask):
        """
        Sets a given tasks result to error.
        """
        self.logger.error("Forcing task result to error for task id {}".format(newtask.task_uuid))
        newtask.result = policies.ERROR
        self.recvd_lists[node_id][newtask.task_uuid] = newtask

        #find associated check id
        checks = self.check_tasks[node_id]
        chk_id = None
        for check in checks.keys():
            if newtask.task_uuid in checks[check]:
                chk_id = check
                break
        if chk_id is None:
            #Got task results for unknown task
            return
        newtask.check_id = chk_id
        newtask.node_id = node_id
        
        if self.oracle.store_results(newtask) == -1:
            print('RESULT STORE FAILED!')

        #determine if check is complete
        check_done = True
        for t in checks[chk_id]:
            if not (t in self.recvd_lists[node_id].keys()):
                check_done = False
                break

        if check_done:
            tasks = []
            for t in checks.pop(chk_id):
                t = self.recvd_lists[node_id].pop(t)
                tasks.append(t)
            result = decomp.Recomp.recomp_1(tasks, chk_id)
            self.dm_send_results(result.export())

    def schedule_node(self, node_id):
        """
        Builds bins from the specified node's wait list and sends them to the node.

        :param node_id: the ID of the node to schedule bins to.
        :return:
        """
        self.logger.debug("schedule_node started for node " + str(node_id))
        done = False
        bin =None
        while not done:
            try:
                bin = self.schedulers[node_id].plan_bin(self.wait_queues[node_id], self.bin_size)
                done = True
            except UnschedulableTaskException as e:
                # Planner encountered an unschedulable task.
                self.logger.error("schedule_node encountered a task that could not be scheduled")
                t = e.task
                self.error_task(node_id, t)

        if not bin:
            # Nothing to send
            self.logger.error("schedule_node ended up with no binds to send!")
            return
        self.send_bin_to_fem(bin, node_id)

    def send_bin_to_fem(self, bin, node_id):
        '''
        Does the work to send a bin to the FEM/HCM

        :param bin: a bin made by bem.plan_bin()
        :param node_id: int - the id of the node where the bin should be sent

        :return:
        '''
        self.logger.info("send_bin_to_fem() started")

        # NOTE: This code is this way to maintain backward compatability with v1.0 FEM code

        commo = self.send_servers.get(str(node_id))
        if not commo:
            self.logger.error("send_bin_to_fem() could not find Client by that node_number")
            raise KeyError

        self.logger.debug("send_bin_to_fem() sending to " + commo.servername + ':' + str(commo.serverport))

        first = False
        last = False
        sockt = None

        self.logger.debug("bin to be sent: " + ','.join([str(t) for t in bin]))

        for i, task in enumerate(bin):

            # Get Golden Values From Oracle

            task.packed = time.time()
            gv = self.oracle.get_golden_values(task)
            
            if not gv:
                task.hash1, task.hash2, task.hash3, task.hash4, task.hash5, task.hash6, task.hash7, task.hash8 = [0] * 8 
            else:
                task.hash1, task.hash2, task.hash3, task.hash4, task.hash5, task.hash6, task.hash7, task.hash8 = [int(v) for v in gv]

            self.sent_lists[node_id][task.task_uuid] = task

            if i == 0:
                first = True
            else:
                first = False
            if i == len(bin)-1:
                last = True
            else:
                last = False

            self.logger.debug("send_bin_to_fem() sending " + str(task))

            for key in dir(task):
                if not getattr(task, key):
                    setattr(task, key, 0)

            Ivec = Random.new().read(16)

            if (self.HMAC):
                self.logger.info("BEM HMAC'ing task contents...")
                # Sign the task
                task.manager_sig1 = SIGNATURE[0]
                task.manager_sig2 = SIGNATURE[1]
                task.manager_sig3 = SIGNATURE[2]
                task.manager_sig4 = SIGNATURE[3]
                task.manager_sig5 = SIGNATURE[4]
                # Make the input to be Hmac'd: Ivec + task data (not including HMAC fields at end)
                HmacBinstruct = struct.pack(''.join(['<', 'Q'*12, 'I'*18, 'Q'*7]), task.command, task.operand,
                                            task.virtaddr, task.physaddr, task.len, task.result, task.nonce, task.cost,
                                            task.priority, task.lastchecked, task.task_uuid, task.reserved1, task.hash1, task.hash2, task.hash3,
                                            task.hash4, task.hash5, task.hash6, task.hash7, task.hash8,
                                            task.manager_sig1, task.manager_sig2, task.manager_sig3, task.manager_sig4,
                                            task.manager_sig5, task.inspector_sig1, task.inspector_sig2,
                                            task.inspector_sig3, task.inspector_sig4, task.inspector_sig5,
                                            task.bigStat0, task.bigStat1, task.bigStat2, task.bigStat3,
                                            task.bigStat4, task.bigStat5, task.bigStat6)
                HmacInput = Ivec + HmacBinstruct
                
                # Make HMAC over Ivec + task data
                HmacKey = ''.join(chr(x) for x in HMAC_KEY)  # HMAC Key
                hash_obj = HMAC.new(key=HmacKey, msg=bytes(HmacInput), digestmod=SHA256)
                CalculatedHmac = hash_obj.digest()
                self.logger.info("\nHere is the outgoing hmac " + str(CalculatedHmac.encode('hex')))

                # Store generated HMAC in task hmac and finalize the binstruct
                task.Hmac1 = CalculatedHmac[0:8]
                task.Hmac2 = CalculatedHmac[8:16]
                task.Hmac3 = CalculatedHmac[16:24]
                task.Hmac4 = CalculatedHmac[24:32]
                binstruct = HmacInput + task.Hmac1 + task.Hmac2 + task.Hmac3 + task.Hmac4

            else:  # No HMAC
                task.Hmac1 = 0
                task.Hmac2 = 0
                task.Hmac3 = 0
                task.Hmac4 = 0
                # Sign the task
                task.manager_sig1 = SIGNATURE[0]
                task.manager_sig2 = SIGNATURE[1]
                task.manager_sig3 = SIGNATURE[2]
                task.manager_sig4 = SIGNATURE[3]
                task.manager_sig5 = SIGNATURE[4]
                binstruct = struct.pack(''.join(['<', 'Q'*12, 'I'*18, 'Q'*11]), task.command, task.operand,
                                        task.virtaddr, task.physaddr, task.len, task.result, task.nonce, task.cost,
                                        task.priority, task.lastchecked, task.task_uuid, task.reserved1, task.hash1, task.hash2, task.hash3, task.hash4,
                                        task.hash5, task.hash6, task.hash7, task.hash8, task.manager_sig1,
                                        task.manager_sig2, task.manager_sig3, task.manager_sig4, task.manager_sig5,
                                        task.inspector_sig1, task.inspector_sig2, task.inspector_sig3,
                                        task.inspector_sig4, task.inspector_sig5, task.bigStat0,
                                        task.bigStat1, task.bigStat2, task.bigStat3, task.bigStat4, task.bigStat5,
                                        task.bigStat6, task.Hmac1, task.Hmac2, task.Hmac3, task.Hmac4)
                binstruct = Ivec + binstruct

            if (self.ENCRYPT):
                self.logger.info("Putting plaintext Ivec in front of encrypted binstruct...")
                # AES
                key = INSPECTOR_KEY
                key = a2b_hex(key)
                self.logger.info("sendBinToFrontend IV = " + str(Ivec).encode('Hex'))
                encobj = AES.new(key, AES.MODE_CBC, Ivec)
                st = []
                for ch in Ivec:
                    st.append(ch.encode('hex'))
                self.logger.info("Used Ivec = " + str(st))
                ciphertext = encobj.encrypt(binstruct[16:])
                msg = pickle.dumps(Ivec + ciphertext, pickle.HIGHEST_PROTOCOL)
                sockt = commo.sendmsg_cont(msg, first=first, last=last, sockt=sockt)
            else:
                self.logger.info("Sending unencrypted....") # But including IV to keep data structures consistent when encryption enabled/disabled
                self.logger.info("sendBinToFrontend IV = " + str(Ivec).encode('Hex'))
                msg = pickle.dumps(binstruct, pickle.HIGHEST_PROTOCOL)
                sockt = commo.sendmsg_cont(msg, first=first, last=last, sockt=sockt)

            self.logger.debug("send_bin_to_fem() done.")
    
    def interrupt_handler(self, sig, frame):
        """
        SIGINT entry point
        """
        self.halt()

    def dispatch_loop(self, node):
        """
        Schedules the given node with available tasks on an interval.
        """
        while(True):
            if self.halted:
                return
            self.schedule_node(node)
            self.logger.debug("Sleeping for {}".format(self.delays[node]))
            time.sleep(self.delays[node])

    
    def return_node_list(self, msg):
        """
        Sends the list of monitored nodes (a list of ints) to the DM.

        :param msg: the original opnum 0x6 message sent by the DM. This is unused in the function,
                    it is present in order to make all the functions in the dispatch table for 
                    this class have the same type signature.
        :returns: None
        """
        
        self.logger.info("return_node_list() started")

        response = dict()
        response['opnum'] = comms.PROTOCOLS['B2D Node List']
        response['source'] = self.hostname
        response['payload'] = self.nodelist.keys()

        response = pickle.dumps(response)
        self.logger.debug("return_node_list() pickling complete")

        commo = self.send_servers[self.dm_hostname]
        commo.sendmsg(response)
        self.logger.debug("return_node_list() message send complete")

    def update_control_value(self, msg):
        '''
        Called when we recieve a message for a control paramater update.
        '''
        payload = msg['payload']
        target = payload['target']
        self.logger.debug("Recieved cv request with tgt: {} val: {}".format(target, payload['value']))
        if target in Backend_Manager.CONTROL_PARAMATERS.keys():
            Backend_Manager.CONTROL_PARAMATERS[target](self,payload)

    def update_bin_size(self, payload):
        '''
        Updates the bin packing size limit.
        TODO Does this need to redecompose queued tasks?
        '''
        self.bin_size = int(payload['value'])

    def update_delay(self, payload):
        '''
        Updates the scheduling delay for a node.
        '''
        node = int(payload['node_id'])
        self.logger.info("Setting Delay for node {} to {}".format(node, int(payload['value'])))
        self.delays[node] = int(payload['value'])


#if __name__ == "__main__":
def bem_main():
    parser = argparse.ArgumentParser(description="Initialize BEM instance.")
    parser.add_argument('-d', '--dmhost', help='Specify the default hostname of the remote DM "hostname:port".')
    parser.add_argument('-b', '--binsize', help='Specify the default bin size for the BEM', default='50000')
    nspace = vars(parser.parse_args())
    DEFAULT_BIN_SIZE = int(nspace.get('binsize'))


    dmhost = nspace.get('dmhost')

    check.Check.initialize('epastack/db/schemas/check.json')

    if dmhost:
        dmhost = dmhost.split(':')
        print dmhost
        hostname = dmhost[0]
        port = dmhost[1]
        bem = Backend_Manager(dm_host=hostname, dm_port=int(port), bin_size=DEFAULT_BIN_SIZE)
    else:
        bem = Backend_Manager(DEFAULT_BIN_SIZE, hmac=True, encrypt=True)
    bem.start()
    print "Press RETURN to quit BEM..."
    try:
        raw_input()
    except KeyboardInterrupt:
        pass
    bem.halt()
    print "bem.halt() finished."
    sys.exit(0)

