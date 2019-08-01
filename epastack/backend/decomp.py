import epastack.shared.task as task
import epastack.shared.check as check
import epastack.shared.policies as policies
import sys
import logging
import time
import pprint

class Decomp:
    '''
    The class that performs Check -> Task decomposition.

    Goal: decomposition algorithm extensible
    '''

    logger = logging.getLogger("Decomp")
    granularity = 2 **check.HASH_LOWER_EXP                  # Max number of bytes per task
    max_cost_per_byte = 1 # TODO Get this somewhere (provisioning?)

    '''
    NOTE: The above figure should eventually be set based on guidance from a DM informed by 
    hashing speed and SMM time/bin size gathered either during provisioning on a monitored node,
    or memoized/kept in a DB by the DM based on node system type/ID. 
    '''

    def __init__(self, granularity=None):
        '''

        :param granularity: this would be a tunable parameter for number of bytes to be measured per task? Presumably this would apply only to memory checks.
        '''
        if granularity:
            Decomp.granularity = granularity

    @staticmethod
    def set_gran(val):
        Decomp.granularity = val

    @staticmethod
    def decomp_all_sizes(chk, cost):
        '''
        the BEM uses this in the case that the 'hashes' dict of the Check is empty/unknown. So this decomp
        function generates Tasks for all given hash sizes.

        :param chk:
        :param cost:
        :return:
        '''
        logger = Decomp.logger
        logger.info("decomp_all_sizes() started")

        command = chk.command
        tasks = []

        if command in policies.REGISTER_COMMANDS:
            logger.debug("Register command: " + str(command))
            argsdict = {}
            for arg in task.Task.param_names.keys():
                argsdict[arg] = chk.__dict__[arg] if chk.__dict__.get(arg) else None
            tasks = [task.Task(argsdict)]
            logger.debug("decomp_all_sizes() returning " + str(tasks))
            return tasks

        else:
            logger.debug("Some other command: " + str(command))
            tasklens = []
            for size in chk.sizes:
                tasklens.append([size for i in range(chk.len // size)])

            for sublist in tasklens:
                for i, task_len in enumerate(sublist):
                    argsdict = {}

                    for arg in task.Task.param_names.keys():
                        if arg == 'address':
                            argsdict[arg] = chk.address + (task_len*i)
                        elif arg == 'len':
                            argsdict[arg] = task_len
                        elif arg == 'cmp_hash':
                            argsdict[arg] = None
                        elif arg == 'cost':
                            argsdict[arg] = cost*task_len
                        else:
                            argsdict[arg] = chk.__dict__.get(arg)

                    tasks.append(task.Task(argsdict))

            logger.debug("decomp_all_sizes() returning " + str(tasks))
            return tasks

    @staticmethod
    def decomp_hashes(hashstring, arg):
        '''
        Turns a colon-separated hashstring into a series of integer values that
        can be passed to the HCM for packing into a Task class/struct.

        Returns a list of (hashfield, hash-chunk) pairs for adding to the
        argsdict that goes is passed to the Task constructor.

        :param hashstring: a string representing hash-chunks, colon-separated
        :param arg: the name of the Check dict argument where sets of hashes
                    are kept, probably "cmp_hash"
        :return: List[(string, int)]
        '''
        logger = Decomp.logger
        lst = []
        if hashstring is None:
            lst.append((arg, None))
        else:
            logger.debug("hashstring: {}".format(hashstring))
            lst.append((arg, hashstring))

            hash_chunks = hashstring.split(':')
            for i in range(1,9):
                hashfield = "hash{}".format(i)
                hash_chunk = hash_chunks[i-1]
                lst.append((hashfield, int(hash_chunk)))

        return lst

    @staticmethod
    def decomp_1(chk):
        '''
        Converts a check into one or more tasks.

        :param chk: a diagmgr.check.Check object
        :return: a list of epastack.backend.task.Task objects
        '''
        logger = Decomp.logger
        logger.info("decomp_1() started")

        logger.info("check dict: ")
        logger.info(chk.__dict__)
        inspector_hash_places= 10
        command = chk.command
        if chk.cost is None:
            base_cost = Decomp.max_cost_per_byte
        else:
            base_cost = chk.cost // chk.len
        tasks = []

        if command in policies.REGISTER_COMMANDS.values():
            argsdict = {}
            for arg in task.Task.param_names.keys():
                if arg == 'cmp_hash':
                    if chk.hashes is not None:
                        hashstring = chk.hashes.get(min(chk.len, Decomp.granularity))[0]
                        if hashstring is None:
                            argsdict[arg] = None
                        else:
                            entries = Decomp.decomp_hashes(hashstring, arg)
                            for entry in entries:
                                key = entry[0]
                                value = entry[1]
                                argsdict[key] = value
                    else:
                        argsdict[arg] = None
                elif arg == "check_id":
                    argsdict[arg] = chk.id
                else:
                    argsdict[arg] = chk.__dict__.get(arg, None)
            t = task.Task(argsdict)
            t.created = time.time()
            tasks = [t]
            logger.debug("decomp_1() returning " + str(["{}".format(t.__dict__) for t in tasks]))
            return tasks

        elif command in policies.MEMORY_COMMANDS.values():
            numtasks = chk.len // (Decomp.granularity)
            logger.debug("numtasks: {}".format(numtasks))
            logger.debug("check hashes: \n{}".format(chk.hashes))
            if numtasks == 0:
                task_len = chk.len

                argsdict = {}
                for arg in task.Task.param_names.keys():
                    if arg == 'address':
                        argsdict[arg] = chk.address
                    elif arg == 'len':
                        argsdict[arg] = task_len
                    elif arg == 'cmp_hash':
                        if chk.hashes is not None:
                            hashstring = chk.hashes.get(min(chk.len, Decomp.granularity))[0]
                            if hashstring is None:
                                argsdict[arg] = None
                            else:
                                entries = Decomp.decomp_hashes(hashstring, arg)
                                for entry in entries:
                                    key = entry[0]
                                    value = entry[1]
                                    argsdict[key] = value
                        else:
                            argsdict[arg] = None
                    elif arg == 'cost':
                        argsdict[arg] = int(base_cost*task_len)
                    elif arg == 'check_id':
                        argsdict[arg] = chk.id
                    else:
                        argsdict[arg] = chk.__dict__.get(arg)

                t = task.Task(argsdict)
                t.created = time.time()
                tasks.append(t)

            else:

                task_len = Decomp.granularity
                last_len = chk.len % Decomp.granularity
                
                task_counter = 0
                for i in xrange(numtasks):
                    argsdict = {}
                    for arg in task.Task.param_names.keys():
                        if arg == 'address':
                            argsdict[arg] = chk.address + (task_len*i)
                        elif arg == 'len':
                            argsdict[arg] = task_len
                        elif arg == 'cmp_hash':
                            if chk.hashes is not None:
                                hashstring = chk.hashes.get(min(chk.len, Decomp.granularity))[i]
                                entries = Decomp.decomp_hashes(hashstring, arg)
                                for entry in entries:
                                    key = entry[0]
                                    value = entry[1]
                                    argsdict[key] = value
                            else:
                                argsdict[arg] = None
                        elif arg == 'cost':
                            argsdict[arg] = int(base_cost*task_len)
                        elif arg == 'check_id':
                            argsdict[arg] = chk.id
                        else:
                            argsdict[arg] = chk.__dict__.get(arg)

                    t = task.Task(argsdict)
                    t.created = time.time()
                    tasks.append(t)
                    task_counter += 1

                if last_len > 0:
                    argsdict = {}
                    for arg in task.Task.param_names.keys():
                        if arg == 'address':
                            argsdict[arg] = chk.address + (task_len*numtasks)
                        elif arg == 'len':
                            argsdict[arg] = last_len
                        elif arg == 'cmp_hash':
                            if chk.hashes is not None:
                                argsdict[arg] = chk.hashes.get(min(chk.len, Decomp.granularity))[task_counter]
                            else:
                                argsdict[arg] = None
                        elif arg == 'cost':
                            argsdict[arg] = int(base_cost*last_len)
                        elif arg == 'check_id':
                            argsdict[arg] = chk.id
                        else:
                            argsdict[arg] = chk.__dict__.get(arg)

                    t = task.Task(argsdict)
                    t.created = time.time()
                    tasks.append(t)
                    task_counter += 1


            logger.debug("decomp_1() returning " + pprint.pformat(["{}".format(t.__dict__) for t in tasks]))
            return tasks
        else:
            raise Exception("Unknown inspector command passed to Decomp.") #TODO: handle other commands possibly

class Recomp:

    default_cost_per_byte = 1   # usec/byte rate

    logger = logging.getLogger("Recomp")
    def __init__(self):
        pass

    @staticmethod
    def recomp_1(tasklist, c_id):
        """
        Recomposes tasks from tasklist into a Check Results object

        :param tasklist: a list of one or more task objects
        :param c_id: the check ID of the tasks
        :return: a ResultsDesc dict
        """


        logger = Recomp.logger
        logger.info("recomp_1() started")
        logger.debug("recomp_1 passed tasklist: " + '\n'.join([str(t) for t in tasklist]))

        command = tasklist[0].command
        if not all([t.command == command for t in tasklist]):
            logger.error("Commands in tasklist not all the same!")
            return None

        result = tasklist[0].result
        if not all([t.result == result for t in tasklist]):
            logger.error("Results in tasklist not all the same!")
            return None

        task_len = tasklist[0].len
        if not all([t.len == task_len for t in tasklist]):
            logger.error("Lengths in tasklist not all the same!")
            return None

        total_length = 0
        time = sys.maxint
        cost = 0
        hashes = []
        if command in policies.MEMORY_COMMANDS.values():
            tasks = sorted(tasklist, key=lambda t: t.address)
            addr = tasks[0].address
            total_length = 0
            for task in tasks:
                logger.debug("current task: {}".format(task))
                time = min(time, task.lastchecked)
                total_length += task.len
                cost += task.cost
                total_hash = ''
                for i in range(1,9):
                    hashfield = "hash" + str(i)
                    logger.debug("hashfield: {}".format(hashfield))
                    partial_hash = str(getattr(task, hashfield))
                    logger.debug("partial_hash: {}".format(partial_hash))
                    if partial_hash is not None and total_hash is not None:
                        total_hash += partial_hash + ':'
                    else:
                        logger.error("None type hash encountered. setting entire hash to None")
                        total_hash = None
                logger.debug("total_hash: {}".format(total_hash))
                if total_hash is not None:
                    logger.debug("task hash: {}".format(total_hash))
                    hashes.append(total_hash)
                    logger.debug("Hashes so far: {}".format(hashes))
            Decomp.max_cost_per_byte = max(Decomp.max_cost_per_byte, cost/total_length)

        else:
            assert(len(tasklist)==1)
            task = tasklist[0]
            result = task.result
            cost = task.cost
            total_hash = ''
            for i in range(1,9):
                hashfield = "hash" + str(i)
                logger.debug("hashfield: {}".format(hashfield))
                partial_hash = str(getattr(task, hashfield))
                logger.debug("partial_hash: {}".format(partial_hash))
                if partial_hash is not None and total_hash is not None:
                    total_hash += partial_hash + ':'
                else:
                    logger.error("None type hash encountered. setting entire hash to None")
                    total_hash = None
            logger.debug("total_hash: {}".format(total_hash))
            if total_hash is not None:
                hashes.append(total_hash)
            time = task.lastchecked
            total_length = 8 #TODO MOVEME

        args = dict()
        args['id'] = c_id
        args['complete'] = True     #TODO:
        args['result'] = result
        args['size'] = total_length
        args['time'] = time
        args['cost'] = cost
        args['hashes'] = hashes
        args['granularity'] = task_len
        res = check.CheckResult(args)
        logger.debug("recomp_1 returning: " + str(res.export()))
        return res
