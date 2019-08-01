from Crypto import Random
import collections
import policies
import re
import json
import sys
# TODO: check or constrain expected values
#       e.g. Resource should be one of several register values, or a range of 32/64-bit addresses
#       Update: this is now done, to an extent, in the Terminal.

#HASH_SIZES = [1, 2, 4, 16, 32]
HASH_LOWER_EXP = 9
HASH_UPPER_EXP = 13

class Check:
    '''
    The Check is essentially a wrapper for the _dict member (a dict), but including some constraints
    and argument parsing.
    '''

    # Static Members

    '''
    :attributes:
    This is a list of 3-tuples, constructed from a check.json file during a call to
        Check.initialize().
    Each tuple follows the format: (name, type, validation)
    'name' is a string naming the class field
    'type' is a Python version of a JSON-compatible data type 
        (see https://docs.python.org/2/library/json.html for more info)
    'validation' is a string containing Python code such as "policies.INSPECTOR_OPERANDS[x]", 
    i.e. a dictionary access command to be used in converting an epa-rimm command string such 
    as "HASH_MEM_VIRT" or "CR0_REG" into its corresponding numeric value. 

    These values are used by the terminal and the Check constructor for handling user input
    and instantiation Check class objects.
    '''    
    attributes = []

    '''
    :user_fields:
    This is a dict of string : int mappings that stores the position at which the user should 
    provide the given value when inputting a new check. This dict gets constructed from information
    in the 'check.json' file whenever Check.initialize() is called (which should be only once at 
    the start of each module that uses this class). Its purpose is to assist with parsing and
    validating user input of Checks.
    '''
    user_fields = dict()

    check_id = 0

    # Class Methods

    def __init__(self, argsdict, id):

        for field in Check.attributes:
            name = field[0]
            tp = field[1]
            item = argsdict.get(name)
            if item is not None:
                setattr(self, name, tp(item))
            else:
                setattr(self, name, None)

        self.id = id

    def __str__(self):
        '''
        Concatenates the key, value pairs as newline-separated lines, with key and value separated by a colon and space

        :return: string
        '''
        #return pprint.pformat(self._dict)
        st = ''
        for k in self.__dict__.keys():
            if k == "address":
                st += k + ': ' + hex(self.__dict__[k]) + '\n'
            else:
                st += k + ': ' + str(self.__dict__[k]) + '\n'
        return st

    @staticmethod
    def initialize(filename):
        """
        This function should be run when the eparimm stack (the DM in particular) is started. Its purpose
        is to open the given filename, which needs to be a .json file, and ingest the json schema in order
        to initialize the class attributes of the Check class. 

        This is a programmatic way of 1: deriving the Check specification and documentation from a single 
        file, and 2: ensuring the DM and DB are always in sync regarding Check structure. 3: to follow 
        DRY principles.

        :param filename: string - path to a filename ending in .json (note this must actually be a json 
                         schema for the Check class)
        :return: None
        """
        
        if not re.match(r'.*\.json$', filename):
            raise Exception("Check.initialize() requires a filename ending in .json.")

        # ingest the schema
        with open(filename, 'r') as fh:
            schema = json.load(fh)
    
        for field in schema['fields']:
            name = field['field']       # the field name
            tp = eval(field['type'])    # the field type
            val = field['validate']     # the validator function for this field
            Check.attributes.append((name,tp, val))

            # get the argument position, if the arg is user-specified
            user = eval(field['user specified'])
            if user:
                # decrement the argument position by 1 to make it an index
                Check.user_fields[name] = user - 1

        #print Check.attributes
        #print Check.user_fields

class CheckResult:

    '''
    fields = collections.OrderedDict([
        ('id', int),
        ('complete', bool),
        ('result', bool),
        ('size', int),
        ('hashes', [str]),
        ('time', int)
    ])
    '''

    def __init__(self, argsdict):

        '''
        self.id = argsdict.get('id')
        self.complete = argsdict.get('id')
        self.result = argsdict.get('result')
        self.size = argsdict.get('size')
        self.hashes = argsdict.get('hashes')
        self.time = argsdict.get('time')
        '''
        self.fields = list()
        for k in argsdict.keys():
            setattr(self, k, argsdict[k])
            self.fields.append(k)

    def export(self):
        """
        exports self as a clean dict for pickling
        :return: self as dict
        """
        exp = dict()
        for key in self.fields:
            exp[key] = self.__dict__.get(key)
        return exp
