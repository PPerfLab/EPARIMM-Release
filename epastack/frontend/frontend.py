#
# Brian Delgado
# August 25, 2018
#

import socket
import pickle
import struct 
import logging
from frontendConfig import *   # Network configuration
import os
import logging
import logging.config
import epastack.shared.comms as comms

from epastack.shared.task import Task
from Crypto import Random

###########################################################################
# Non-configurable parameters
#
# Ring 0 Manager Command 
TRIGGER_COMMAND = 0x33 # Command to tell Ring0 Manager to trigger an SMI 
#
#
#
# Backend Manager command
#
RETURN_BIN_CMD  = 0x10
#
#
# Constants (update this if you change task size)
TASK_SIZE = 272
###########################################################################

if not os.path.exists(LOG_DIR):
	os.makedirs(LOG_DIR)
logging.config.fileConfig('epastack/frontend/frontendLogging.ini')
logger = logging.getLogger("frontend")

#
#
# This is the Task class that holds the various data needed for a given task
# Note: Keep this in sync with the BEM!
#
class Task():
        def __init__(self, funcname, virtaddr, operand, len, cost, command, priority,lastchecked, hash1, hash2, hash3, hash4, hash5, hash6, hash7, hash8, nonce, result, node_id, physaddr, manager_sig1, manager_sig2, manager_sig3, manager_sig4, manager_sig5, inspector_sig1, inspector_sig2, inspector_sig3, inspector_sig4, inspector_sig5, BigStat0,  BigStat1, BigStat2, BigStat3, BigStat4, BigStat5, BigStat6, Hmac1, Hmac2, Hmac3, Hmac4, task_uuid, reserved1):
		                self.funcname = funcname #0
				self.virtaddr = virtaddr #1
				self.operand = operand   #2
				self.len        = len    #3
				self.cost = cost         #4
				self.command = command   #5
				self.physaddr = physaddr #6
				self.priority = priority #7
				self.lastchecked = lastchecked #8
				self.hash1 = hash1 #9
				self.hash2 = hash2 #10
				self.hash3 = hash3 #11
				self.hash4 = hash4 #12
				self.hash5 = hash5 #13
				self.hash6 = hash6 #14
				self.hash7 = hash7 #15
				self.hash8 = hash8 #16
				self.nonce = nonce #17
				self.result = result #18
				self.node_id = node_id #19
				self.physaddr = physaddr #20
				self.manager_sig1 = manager_sig1 #21
				self.manager_sig2 = manager_sig2 #22
				self.manager_sig3 = manager_sig3 #23
				self.manager_sig4 = manager_sig4 #24
				self.manager_sig5 = manager_sig5 #25
				self.inspector_sig1 = inspector_sig1 #26
				self.inspector_sig2 = inspector_sig2 #27
				self.inspector_sig3 = inspector_sig3 #28
				self.inspector_sig4 = inspector_sig4 #29
				self.inspector_sig5 = inspector_sig5 #30
                                self.BigStat0 = BigStat0 #31
				self.BigStat1 = BigStat1 #32
				self.BigStat2 = BigStat2 #33
				self.BigStat3 = BigStat3 #34
				self.BigStat4 = BigStat4 #35
				self.BigStat5 = BigStat5 #36
				self.BigStat6 = BigStat6 #37
				self.Hmac1 = Hmac1 #38
				self.Hmac2 = Hmac2 #39
				self.Hmac3 = Hmac3 #40
				self.Hmac4 = Hmac4 #41
                                self.task_uuid = task_uuid #42
                                self.reserved1 = reserved1 #43

LOG_NAME = "frontend_manager.log"
#logger = logging.getLogger(LOG_NAME)
logger = None
#BEM_CLIENT = comms.Client(logger, BACKEND_SERVER, BACKEND_PORT)
BEM_CLIENT = None

#
#
# EPA Frontend -> EPA Backend (send results back)
#
#
def sendResultsToBackend(resultsList, port):
    logger.info("sendResultsToBackend() started")

    for results in resultsList:
        try:
            res = dict()
            res['opnum'] = RETURN_BIN_CMD
            res['node_id'] = 0              #TODO: This should not be hard coded. We need a way for the FEM to know its node_id
            res['payload'] = results
            msg = pickle.dumps(res, pickle.HIGHEST_PROTOCOL)
            BEM_CLIENT.sendmsg(msg)
        except Exception as e:
            logger.error("EXCEPTION: " + str(e))
            print "Exception encountered in sendResultsToBackend: " + str(e)
#
#
# EPA Frontend -> EPA Legacy Backend
#
#
def sendResultsToLegacyBackend(resultsList, port):
    import socket
    import cPickle as pickle
    results = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((BACKEND_SERVER, port))
    cmdFile = sock.makefile("wb")
 
    # Add header
    results.insert(0, RETURN_BIN_CMD)
  
    for results in resultsList:
        pickle.dump(results, cmdFile, pickle.HIGHEST_PROTOCOL)
    cmdFile.close()
    sock.close()
#
#
# EPA FrontEnd -> Ring 0 Manager (get results)
#
#
def readBinResults(tasklist):
    readLen = 1
    resultslist = []
    procfile = open(PROCFILE_NAME, "rb")

    while (readLen >0):
            readstring = procfile.read(TASK_SIZE)
            readLen = len(readstring)
            if (readLen == TASK_SIZE):
                    logger.info("Read back from proc file " + str(readLen))
                    resultslist.append(readstring)
            #else: # note, this will return 0 when reading is done
                    #print "DID NOT GET TASK_SIZE, GOT " + str(readLen)
    procfile.close()
    if (len(resultslist) != len(tasklist)):
        logger.info("The number of received results " + str(len(resultslist)) + " does not match the number of sent results! " + str(len(tasklist))) # Some problem occurred

    logger.info("Returning results")
    return resultslist

#	
#
# frontend -> Ring 0 Manager
# Tell the driver to send a bin to the Inspector using TRIGGER_COMMAND
#
#
def triggerBin():
	task = Task("TRIGGER",0, 0, 0, 0, TRIGGER_COMMAND, 0,0,0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,0,0,0,0,0,0,  0,0,0,0,  0,0)
        procfile = open(PROCFILE_NAME, "wb")

	# Convert to C struct
                                  #2  #12          #8        #5    #5    #7     #4   
	binstruct = struct.pack("<QQ QQQQQQQQQQQQ IIIIIIII  IIIII IIIII QQQQQQQ QQQQ", 
                                0,0, #2 (ivec1 and ivec2)
                                TRIGGER_COMMAND, task.operand, task.virtaddr, task.physaddr, task.len, task.result, task.nonce, task.cost, task.priority, task.lastchecked, task.task_uuid, task.reserved1 , #12 
                                task.hash1, task.hash2, task.hash3, task.hash4, task.hash5, task.hash6, task.hash7, task.hash8, #8
                                task.manager_sig1, task.manager_sig2, task.manager_sig3, task.manager_sig4, task.manager_sig5,  #5
                                task.inspector_sig1, task.inspector_sig2, task.inspector_sig3, task.inspector_sig4, task.inspector_sig5, #5
                                0,0,0,0,0,0,0, #7  
                                0,0,0,0)       #4

	# Trigger Ring 0 Manager to send the bin
	logger.info("Tell Ring0 Manager to send bin")
	procfile.write((binstruct) + '\n')
	procfile.close()
#
#
# frontend -> Ring 0 Manager
# Transfer all tasks in bin to Ring 0 Manager, but don't have Ring 0 Manager send it yet
#
#
def sendBinTo_Ring_0_Manager(binstruct):
	#print "Sending a task:"
	
	for task in binstruct :
		procfile = open(PROCFILE_NAME, "wb")
		logger.info("After packing...")

		procfile.write(task)
		procfile.write("\n")
		logger.info("Length of task going to Ring 0 manager = " + str(len(task)))
		procfile.close()
#
#
# Print details about the task
#
#
def printTask(task):
        logger.info("")
        logger.info(" Command: " + str(task.command) + " VA:" + str(hex((task.virtaddr))) + " PA:" + str(hex((task.physaddr))) + " Len:"+ str(hex((task.len))) + " Operand: " + str(task.operand))
        logger.info(" Hash:" + str(task.hash1) + " " + str(task.hash2) + " " + str(task.hash3) + " " + str(task.hash4) + " " + str(task.hash5) + " " + str(task.hash6) + " " + str(task.hash7) + " " + str(task.hash8))
        logger.info(" Manager_SIG:" + str(task.manager_sig1) + " " + str(task.manager_sig2) + " " + str(task.manager_sig3) + " " + str(task.manager_sig4) + " " + str(task.manager_sig5))
        logger.info(" Inspector_SIG:" + str(task.inspector_sig1) + " " + str(task.inspector_sig2) + " " + str(task.inspector_sig3) + " " + str(task.inspector_sig4) + " " + str(task.inspector_sig5))
        logger.info(" Last checked: " + str(task.lastchecked) + " Result:" + str(task.result) + " Nonce: " + str(task.nonce) + " Cost:" + str(task.cost) + " Priority: " + str(task.priority))


#
#
# Main Function loop
#
#
#if __name__ == '__main__':
def fem_main():
    global logger, BEM_CLIENT
    logger = logging.getLogger(LOG_NAME)
    BEM_CLIENT = comms.Client(logger, BACKEND_SERVER, BACKEND_PORT)
    tasklist = []
    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    BUFSIZE = 100000
    bincount = 0
    binstruct = []

    # Set up EPA Frontend to listen to EPA Backend
    host = ''
    serversock.bind((host, FRONTEND_PORT))
    serversock.listen(20)

    # EPA Backend -> EPA Frontend
    while True:
        logger.info("Waiting for measurement command on port " + str(FRONTEND_PORT))
        clientsock,address = serversock.accept()
        clientFile = clientsock.makefile('rb', BUFSIZE)
        logger.info("Connection from %s" % str(address))

        # Got connection from EPA Backend, now get the data
        try:
                while True: # Receive all bin data
                        recvtask = pickle.load(clientFile) # Receive encrypted string
                        logger.info("Length of receive = " + str(len(recvtask)))
                        c = ''
                        for ch in recvtask[:16]:
                                c += ch.encode('hex')
                        logger.info("IV = " + str(c))
                        logger.info(recvtask.encode('hex'))
                        tasklist.append(recvtask)
                        
        except:
                # Done reading all data
                bincount +=1
                
        logger.info("Length of tasklist = " + str(len(tasklist)))
        # Form encrypted C structs and send to Ring0 Manager
        sendBinTo_Ring_0_Manager(tasklist)
        
        # Trigger Ring0 Manager to send bin to SMM Inspector
        triggerBin()		
        clientFile.close()

        # Read results from SMM Inspector
        resultslist = readBinResults(tasklist)

        logger.debug("Results list:")
        for item in resultslist:
            logger.debug(str(item))

        # Send results to server
        if LEGACY_BACKEND:
            sendResultsToLegacyBackend(resultslist, BACKEND_PORT)
        else:
            sendResultsToBackend(resultslist, BACKEND_PORT)
        tasklist = []

