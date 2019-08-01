import collections
import json
import epastack.shared.policies as policies

class Task():
    param_names = collections.OrderedDict([
        ('id', int),
        ('check_id', int),
        ('node_id', int),
        #('vm_id', int),
        ('command', int),
        ('operand', int),
        ('address', int),
        ('len', int),
        ('priority', int),
        ('cmp_hash', str),
        ('cost', int)   # The need for this field is in question
        #('lastchecked', int),

    ])

    unpack_order = collections.OrderedDict([
        ('command', 0), 
        ('operand', 1), 
        ('virtaddr', 2), 
        ('physaddr', 3),
        ('len', 4), 
        ('result', 5), 
        ('nonce', 6), 
        ('cost', 7), 
        ('priority', 8), 
        ('lastchecked', 9),
        ('task_uuid', 10),
        ('reserved1', 11),
        ('hash1', 12),
        ('hash2', 13),
        ('hash3', 14),
        ('hash4', 15),
        ('hash5', 16),
        ('hash6', 17),
        ('hash7', 18),
        ('hash8', 19),
        ('manager_sig1', 20),
        ('manager_sig2', 21),
        ('manager_sig3', 22),
        ('manager_sig4', 23),
        ('manager_sig5', 24),
        ('inspector_sig1', 25),
        ('inspector_sig2', 26),
        ('inspector_sig3', 27),
        ('inspector_sig4', 28),
        ('inspector_sig5', 29),
        ('bigStat0', 30),
        ('bigStat1', 31),
        ('bigStat2', 32),
        ('bigStat3', 33),
        ('bigStat4', 34),
        ('bigStat5', 35),
        ('bigStat6', 36),
        ('hmac1', 37),
        ('hmac2', 38),
        ('hmac3', 39),
        ('hmac4', 40)
    ])

    #def __init__(self, funcname, virtaddr, operand, len, cost, command, priority,lastchecked, hash1, hash2, hash3, hash4, hash5, hash6, hash7, hash8, nonce, result, node_id, physaddr, manager_sig1, manager_sig2, manager_sig3, manager_sig4, manager_sig5, inspector_sig1, inspector_sig2, inspector_sig3, inspector_sig4, inspector_sig5, reserved1, reserved2,  BigStat1, BigStat2, BigStat3, SmallStat1, SmallStat2, SmallStat3, SmallStat4, SmallStat5, SmallStat6):
    def __init__(self, argsdict):
        self.id = argsdict.get('id') # if argsdict.get('funcname') else None
        self.check_id = argsdict.get('check_id')
        self.node_id = argsdict.get('node_id')
        #self.vm_id = argsdict.get('vm_id')
        self.command = argsdict.get('command')
        self.operand = argsdict.get('operand')
        self.address = argsdict.get('address')
        self.len = argsdict.get('len')
        self.priority = argsdict.get('priority')
        self.cmp_hash = argsdict.get('cmp_hash')
        self.cost = argsdict.get('cost')
        self.lastchecked = argsdict.get('lastchecked')

        self.task_uuid = argsdict.get('task_uuid')
        self.reserved1 = argsdict.get('reserved1')

        self.hash1 = argsdict.get('hash1')
        self.hash2 = argsdict.get('hash2')
        self.hash3 = argsdict.get('hash3')
        self.hash4 = argsdict.get('hash4')
        self.hash5 = argsdict.get('hash5')
        self.hash6 = argsdict.get('hash6')
        self.hash7 = argsdict.get('hash7')
        self.hash8 = argsdict.get('hash8')
        self.manager_sig1 = argsdict.get('manager_sig1')
        self.manager_sig2 = argsdict.get('manager_sig2')
        self.manager_sig3 = argsdict.get('manager_sig3')
        self.manager_sig4 = argsdict.get('manager_sig4')
        self.manager_sig5 = argsdict.get('manager_sig5')

        self.inspector_sig1 = argsdict.get('inspector_sig1')
        self.inspector_sig2 = argsdict.get('inspector_sig2')
        self.inspector_sig3 = argsdict.get('inspector_sig3')
        self.inspector_sig4 = argsdict.get('inspector_sig4')
        self.inspector_sig5 = argsdict.get('inspector_sig5')



        self.virtaddr = self.physaddr = self.address
        self.result = argsdict.get('result')
        self.nonce = argsdict.get('nonce')
        self.lastchecked = argsdict.get('lastchecked')

        self.bigStat0 = argsdict.get('bigStat0')
        self.bigStat1 = argsdict.get('bigStat1')
        self.bigStat2 = argsdict.get('bigStat2')
        self.bigStat3 = argsdict.get('bigStat3')
        self.bigStat4 = argsdict.get('bigStat4')
        self.bigStat5 = argsdict.get('bigStat5')
        self.bigStat6 = argsdict.get('bigStat6')
        self.hmac1 = argsdict.get('hmac1')
        self.hmac2 = argsdict.get('hmac2')
        self.hmac3 = argsdict.get('hmac3')
        self.hmac4 = argsdict.get('hmac4')


        # self.lastchecked = 0
        #self.bigStat0 = self.bigStat1 = self.bigStat2 = self.bigStat3 = self.bigStat4 = self.bigStat5 = self.bigStat6 = 0
        #self.hmac1 = self.hmac2 = self.hmac3 = self.hmac4 = 0
        #self.manager_sig1 = 0x414e414d
        #self.manager_sig2 = 0x31524547
        #self.manager_sig3 = 0x35343332
        #self.manager_sig4 = 0x39383736
        #self.manager_sig5 = 0x33323130
        #self.inspector_sig1 = 0
        #self.inspector_sig2 = 0
        #self.inspector_sig3 = 0
        #self.inspector_sig4 = 0
        #self.inspector_sig5 = 0
        #self.virtaddr = self.physaddr = self.address
        #self.result = 0
        #self.nonce = 0
        #self.lastchecked = 0
        #self.hash = [0]

        

    def __str__(self):
        string = ''
        #for key in Task.unpack_order.keys():
        task_dict = vars(self)
        task_fields = task_dict.keys()
        for key in task_fields:
            string += key + ": " + str(task_dict[key]) + '\n'

        return string

    @staticmethod
    def load_tasks_from_dicts(dictsarg):
        '''
        Generates one or more task objects from a dict of dicts.

        :param dictsarg: a dict of dicts, where each entry key represents a dict that
                            can be passed to the Task constructor
        :return: a dict of Task objects, stored by variable name (not ID#)
        '''
        tasks = {}

        for t_name in dictsarg.keys():
            t_dict = dictsarg[t_name]

            t = Task(t_dict)
            tasks[t_name] = t

        return tasks

    @staticmethod
    def gen_task_to_json():
        modes = ['a', 'w']
        types = {'i': int, 'f':float, 's':str}
        answers = ['y', 'yes', 'n', 'no']

        def add_or_replace(dict, field):
            answer = False
            val = 0xDEADBEEF
            while not answer:
                print "Field: ", field
                tp = 'x'
                while tp not in types.keys():
                    tp = raw_input("What type (i, f, s)? ")
                typ = types[tp]
                val = typ(raw_input('Enter new value: '))

                print "Your new value is: ", val
                ans = 'x'
                while ans not in answers:
                    ans = raw_input('Is this correct (y/n)? ')

                if ans == 'y' or ans == 'yes':
                    answer = True
                else:
                    answer = False

            dict[field] = val

            return dict

        dicts = {}
        done = False
        while not done:
            argsdict = {}

            name = 'None'
            answer = False
            while not answer:
                name = raw_input("Task name: ")

                ans = 'x'
                while ans not in answers:
                    print name
                    ans = raw_input("Is this correct? ")

                if ans == 'y' or ans == 'yes':
                    answer = True

            # All user-input values will be interpreted as ints unless prepended with 's ' or 'f '
            for item in Task.param_names.keys():
                print "Field: ", item
                vals = raw_input("Desired Value: ").split(' ')
                if len(vals) == 1:
                    arg = int(vals[0])
                    argsdict[item] = arg
                elif vals[0] == 's':
                    arg = vals[1]
                    argsdict[item] = arg
                elif vals[0] == 'f':
                    arg = float(vals[1])
                    argsdict[item] = arg

            answer = False
            while not answer:
                for k, v in argsdict.items():
                    print k, ": ", v
                ans = 'x'
                while ans not in answers:
                    ans = raw_input("Is this correct? ")
                if ans == 'n' or ans == 'no':
                    field = 'x'
                    while field not in argsdict.keys():
                        field = raw_input("What field needs corrected? ")
                    argsdict = add_or_replace(argsdict, field)
                else:
                    answer = True

            dicts[name] = argsdict

        filename = 'x'
        done = False
        while not done:
            filename = raw_input("Enter file name: ")
            print filename

            ans = 'x'
            while ans not in answers:
                ans = raw_input("Is this correct? ")
            if ans == 'y' or ans == 'yes':
                done = True
            else:
                done = False

        md = 'x'
        while md not in modes:
            md = raw_input("Overwrite or append (w/a)? ")

        with open(filename + ".json", md) as fname:
            json.dump(dicts, fname)

    @staticmethod
    def load_tasksdict_from_json(filename):

        with open(filename, 'r') as fhandle:
            contents = json.load(fhandle)

        assert(type(contents) == dict)
        return contents
