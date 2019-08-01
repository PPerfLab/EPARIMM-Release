# BSD 3-Clause License
# 
# Copyright (c) 2016-2019, Portland State University
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import argparse
import time
import re
import collections
from cmd import Cmd
from epastack.diagmgr.dm import *

#from epastack.backend.old_backend import *
from epastack.backend.decomp import *
import epastack.shared.policies as policies
import epastack.shared.check as check

'''
TODO: Commands
    loadcheck - load check from a file

TODO: Style
    Most or all of these functions fail silently. Probably not a good thing.
'''


class Terminal(Cmd):
    '''
    Exposes an interactive menu to user for using the Diagnosis Manager.
    '''
    def __init__(self, dm=None):
        '''
        Establishes menu option dicts and instantiates the DiagMgr object 'owned' by this Terminal.

        :param dm: the DiagMgr object that this Terminal will manage.
        '''
        Cmd.__init__(self)
        # commands the terminal knows
#        self.commands = collections.OrderedDict([
#            ('ls', lambda x: self.prnt(x)),
#            ('add', lambda x: self.add(x)),
#            ('enqueue', lambda x: self.send_check(x)),
#            ('help', lambda x: self.prnt_cmds(x)),
#            ('nodelists', lambda x: self.request_node_list(x)),
#            ('serverstart', lambda x: self.dm.server_start(x)),
#            ('serverstop', lambda x: self.dm.server_stop(x)),
#            ('serverstartall', lambda x: self.dm.server_start_all()),
#            ('serverstopall', lambda x: self.dm.server_stop_all()),
#            ('ping', lambda x: self.dm.ping_server(x)),
#            ('addhost', lambda x: self.addhost(x)),
#            ('delhost', lambda: 1+1),                # TODO
#            ('edithost', lambda: 1+1),                # TODO
#            ('schedp', lambda: 1+1),                  # TODO
#            ('exit', lambda x: self.close(x))
#        ])

        self.descriptions = collections.OrderedDict([ 
            ('ls', 'list all checks. [-c] list known hosts'),
            ('add', 'add a check'),
            ('enqueue', 'send a check to a backend manager'),
            ('enqueueall', 'send ALL checks to a backend manager'),
            ('help', 'list available commands'),
            ('nodelists', 'request node lists from one or more BEMs'),
            ('serverstart', 'start a configured listening server'),
            ('serverstop', 'stop a configured listening server'),
            ('serverstartall', 'start listening servers for all defined backends'),
            ('serverstopall', 'stop all active listening servers'),
            ('ping', 'check for reply from a known backend. ping [HOSTNAME]'),
            ('addhost', 'add a known backend. addhost [HOSTNAME] [PORT]'),
            ('decomp', 'Show what a check looks like when decomposed into a Task'),
            ('updatecv', 'Send a request to update a BEM Control Value'),
            ('exit', 'exit the program')
        ])

        if not dm:
            self.dm = DiagMgr()            # The diagnosis manager object
        else:
            self.dm = dm

        # SET UP LOGGING
        self.logger = logging.getLogger(__name__)

    def do_serverstart(self,args):
        self.dm.server_start(args.split())

    def do_serverstartall(self, args):
        self.dm.server_start_all()

    def do_serverstopall(self, args):
        self.dm.server_stop_all()

    def do_serverstop(self, args):
        self.dm.server_stop(args.split())
        
    def do_ping(self, args):
        self.dm.ping_server(args.split()) # ping expects a host list not a string
                 
    def addhost(self, args):
        def check_args(args):
            if len(args) != 3 or args[0] not in ['-l', '-s']:
                print "Usage: addhost -{l,s} [hostname] [port]"
                self.logger.error("addhost() args error: malformed input")
                return False
            try:
                int(args[2])
            except Exception:
                traceback.print_exception()
                self.logger.error("addhost() args error: malformed port")
                return False
            return True

        if not check_args(args):
            return

        self.dm.addhost(args)

    def print_decomp(self, args): 

        def check_args(args):
            if len(args) < 1:
                print "Usage: decomp [check name]"
                self.logger.error("print_decomp() args error: malformed input")
                return False

            for i in xrange(len(args)):
                if args[i] not in self.dm.checks.keys():
                    print "No check by the name " + args[i] + " is installed."
                    self.logger.error("print_decomp() args error: check not found")
                    return False

            return True

        if not check_args(args):
            return

        for arg in args:
            try:
                tasks = Decomp.decomp_1(self.dm.checks[arg])
                for task in tasks:
                    print str(task)
            except KeyError:
                print "Could not decompose ", arg
                self.logger.error("print_decomp() decomp error")
                return

        return

    def ls(self, args):
        '''
        Pretty-prints installed Checks and their results

        Can also pretty print other state based on the passed-in switch.

        :param args: [string] - zero or more switches, defined in this function's 'switches' dict. If None, this function
        will default to pretty-print Checks

        :return: None
        '''

        switches = {                        # known switches
            '-c': lambda: prnt_hosts()
        }

        def prnt_hosts():
            '''
            Behavior of -c switch

            :return: None
            '''
            self.dm.print_hosts()

        if not args:
            print '=================='
            print '      Checks      '
            print '=================='
            self.print_checks()
        elif len(args) > 1 or args[0] not in switches.keys():
            print "ls options available: ", switches.keys()
        else:
            switches[args[0]]()

    def do_help(self, args):
        '''
        Prints all available 'commands,' or menu options.

        :param args: Not used

        :return: None
        '''

        print "Available commands:"
        for item in self.descriptions.items():
            print item[0], ": ", item[1]

    def add(self, args):
        '''
        Delegator function for adding Checks (and potentially later, hosts). Checks for given switch
        and dispatches appropriate sub-function from 'calls' dict.

        :param args: [string] - the first string in the list should be one of the switches listed in this function's
        'calls' dict; the remainder of the list should be either a filename (for -p switch), or the parameters required
        for a Check object: name, type, resource, priority, enabled. See Check object for more detail.

        :return: None
        '''

        switch_char = '-'
        types = ['c']   # the `types` and `calls` variables are meant to
        calls = {       # facilitate ease of exending this interface to different abstractions (e.g. profiles)
            "c": lambda x: self.add_check(x),
        }

        def check_args(args):
            '''
            Returns None if arguments are malformed, and a type from 'types' list if they are well-formed.

            Checks for: no arguments, too few arguments (fewer than 2), non-switch first argument, switches not known.

            :param args: [string] - same as parent function
            :return: Option(string) - one of 'types' list
            '''

            if len(args) < 1:
                print "No arguments passed to add."
                self.logger.error("add() args error: no arguments passed")
                return None
            if (len(args[0]) < 2) or (not args[0][0] == switch_char):
                print args
                print "Command 'add' requires -p or -c argument to specify check."
                self.logger.error("add() args error: no -c switch")
                return None
            t = args[0][1]
            if t not in types:
                print "Command 'add' requires -c argument to specify check."
                self.logger.error("add() args error: no -c switch #2")
                return None
            return t

        type = check_args(args)
        if not type:
            return

        try:
            calls[type](args[1:])
        except KeyError:
            print "The name '{}' is already taken".format(args[1])

    def do_add(self, args):
        self.add(args.split())

    def do_ls(self, args):
        self.ls(args.split())

    def do_decomp(self, args):
        self.print_decomp(args.split())

    def do_nodelists(self, args):
        self.nodelists(args.split())

    def do_addhost(self, args):
        self.addhost(args.split())

    def do_enqueue(self, args):
        self.enqueue(args.split())

    def do_enqueueall(self, args):
        self.enqueue_all(args.split())

    def do_updatecv(self, args):
        self.updatecv(args.split())

    def print_checks(self):
        '''
        Asks DiagMgr object to pretty-print all installed checks.

        :param args: Not used at this time
        :return: None
        '''

        def check_args(args):
            '''
            Does nothing at this time.

            :param args: Not used
            :return: None
            '''
            pass

        checks = self.dm.get_checks()
        results = self.dm.results

        print
        if not checks:
            print "No Checks installed."
            return

        for i in checks.keys():
            chk = checks[i]
            print chk
            c_id = chk.id
            c_res = results.get(c_id)
            if c_res is None:
                print "No results for check " + str(c_id) + '\n'
            else:
                st = ''
                for res in c_res:
                    for k in res.keys():
                        if k == "address":
                            st += k + ': ' + hex(res[k]) + '\n'
                        if k == "result":
                            st += k + ': '
                            if res[k] == policies.INIT:
                                st += 'INIT'
                            elif res[k] == policies.UNCHANGED:
                                st += 'UNCHANGED'
                            elif res[k] == policies.CHANGED:
                                st += 'CHANGED'
                            elif res[k] == policies.ERROR:
                                st += 'ERROR'
                            st += '\n'
                        else:
                            st += k + ': ' + str(res[k]) + '\n'
                    st += '\n'
                print st
                if self.dm.kernel_functions:
                    i = 1
                    print '====================='
                    print '      Functions      '
                    print '====================='
                    print '\n'
                    for key, value in self.dm.kernel_functions.iteritems():
                        for item in value:
                            print str(i) +'] '
                            print 'Symbol Name:  ' + item[1]
                            print 'Symbol Address: ' + str(key)
                            print 'Symbol Type: '+ item[0]
                            print '\n'
                            i+=1


    def add_check(self, args):
        '''
        Calls DiagMgr add_check() on well-formed arguments. Returns without doing anything otherwise.

        :param args: [string] - list of parameters necessary to create a Check object.
        :return: None
        '''
        self.logger.info("add_check() started")

        def check_args(args, argsdict):
            '''
            Returns False if arguments aren't well-formed, True if they are.

            User input is first checked for the appropriate length. Then, each value in the
            input is checked against the corresponding field in the Checks class static member
            `attributes`, which includes information about the value name (e.g. "command"
            or "operand"), its expected type, and snippets of python code required for
            narrower evaluation (to constrain a value within, say, Policies.INSPECTOR_COMMANDS).

            :param args: [string] - a list of parameters matching expected order for Check
            :return: Boolean
            '''

            NAME_ATTRIBUTE_INDEX = 0
            TYPE_ATTRIBUTE_INDEX = 1
            VALIDATOR_ATTRIBUTE_INDEX = 2

            self.logger.info("check_args started\n" + str(args))

            fields = check.Check.user_fields.keys()

            if not len(args) == len(fields):
                # print "Usage: add -c [name] [node] [enabled] [priority] [expected value] [cmd] [operand] ((for registers))"
                # print "Or:    add -c [name] [node] [enabled] [priority] [expected value] [cmd] [addr] [virt/phys] [len] ((for memory addresses))"
                print "Usage: add -c " + ' '.join(['[' + item + ']' for item in sorted(check.Check.user_fields.keys(), cmp=lambda x,y: cmp(check.Check.user_fields[x], check.Check.user_fields[y]))]) # TODO: Eventually add vm_id
                self.logger.error("add_check() args error: malformed input - arg length")
                return False

            first_item = 0
            command_str = list(filter(lambda x: x[NAME_ATTRIBUTE_INDEX] == 'command', check.Check.attributes))[first_item][NAME_ATTRIBUTE_INDEX]
            command_ind = check.Check.user_fields.get(command_str)

            # loop through and validate all of the Check attributes defined by the check schema
            for field in check.Check.attributes:
                name = field[NAME_ATTRIBUTE_INDEX]
                # get the index for this positional argument
                ind = check.Check.user_fields.get(name)
                if ind is None: # if it doesn't exist, that's because it's not a user-defined attribute
                    continue
                field_value = args[ind]
                typ = field[TYPE_ATTRIBUTE_INDEX]
                validator = field[VALIDATOR_ATTRIBUTE_INDEX]
                
                try:
                    #print "arg: ", args[ind]
                    # some attributes are just type-validated
                    if validator == "None":
                        test = typ(field_value)
                        argsdict[name] = test
                        continue

                    #print "CP1 - field[2]: ", field[2]
                    # turn the validator into a python function by evaluating the text and putting it into a lambda
                    fn = lambda x, y: eval(validator)

                    #print "CP2 - fn: ", fn
                    # If the validator fails it will throw a KeyError
                    # If it is successful, it will spit out a legitimate value for this attribute
                    val = fn(field_value, args[command_ind])

                    #print "CP3 -- val: ", val
                    argsdict[name] = val

                except KeyError as e:
                    print field_value + " is not within the correct range"
                    return False

                except ValueError as e:
                    print field_value + " should have been a different type"
                    return False

                except Exception as e:
                    print "some other exception has occurred"
                    print e
                    return False
            
            # enforce zero address argument for register commands
            if argsdict['command'] in policies.REGISTER_COMMANDS.values() and argsdict['address'] != 0:
                print("Address argument for register commands must be 0x0")
                return False


            return True

        argsdict = {}

        if not check_args(args, argsdict):
            return

        #print "contents of argsdict: ", argsdict
        self.logger.info("check_args() checkpoint 4")
        self.dm.add_check(argsdict)

    def enqueue(self, args):

        def check_args(args):

            if not args or len(args) < 3:
                print 'Usage: enqueue [Backend name] [check name] [monitored node id#]'
                return False
            return True

        if not check_args(args):
            return

        try:
            self.dm.send_check(args)
        except Exception as e:
            print '{}'.format(e)
    
    def enqueue_all(self,args):

        def check_args(args):
            if not args or len(args)<2:
                print 'Usage: enqueueall [host] [node id]'
                return False
            return True

        if not check_args(args):
            return

        try:
            self.dm.send_all(args)
        except Exception as e:
            print e.message

    def updatecv(self, args):

        def check_args(args):
            if not args or len(args) != 4:
                print 'Usage: updatecv [host] [node id] [control value name] [new value]'
                return False
            return True
        
        if not check_args(args):
            return

        try:
            self.dm.update_control_value(args)
        except KeyError as e:
            print e.message

        
    def nodelists(self, args):
        """
        Checks input for valid hostnames and then kickstarts DM function of same name.

        :param args: [string] - a list of hostnames to send requests to. This can be None
        :return: None
        """

        self.logger.info("request_node_list() started")

        def check_args(args):
            """
            Returns false if the user has provided a host unknown to the DM

            :param args: [string] - a list of hostnames to send requests to
                         this list should be None in order to request from all BEMs
            :return: Boolean
            """
            self.logger.info("request_node_list().check_args() started")
            if not args:
                return True

            for host in args:
                if host not in self.dm.send_hosts.keys():
                    print host + " is an unknown host."
                    self.logger.error("request_node_list() args errorj: " + host + " is unknown.")
                    return False

            return True

        if not check_args(args):
            return

        self.dm.request_node_list(args)

    def do_exit(self, args):
        '''
        Performs a sys-level exit of the program after trying to perform a graceful
        shutdown by calling DiagMgr.close()

        :return: None
        '''

        try:
            self.dm.server_stop_all()
            self.dm.close()
        except Exception as e:
            self.logger.error("close() error: dm.close() threw exception")
            print e
        sys.exit(0)

    @staticmethod
    def not_a_cmd():
        '''
        prints a message to the terminal
        :return: None
        '''
        print "That is not a recognized command."

    def get(self):
        '''
        Gets input from the user.
        Listens for Ctrl-C (keyboard interrupt) and stops DiagMgr servers before exiting to
        prevent them from hanging.

        :return: string - whatever user input before newline
        '''

        try:
            return str(raw_input('> '))
        except KeyboardInterrupt:
            self.logger.error("get() error: keyboard interrupt")
            self.dm.server_stop_all()
            sys.exit()

    def listen(self):
        '''
        The "runtime loop" of the Terminal.

        Gets input from user, dispatches command based on the first word in user input, passing the rest
        of the input as arguments. Depends on commands to check arguments for well-formed-ness.

        Calls half-second sleep() to keep the "prompt" icon (>) from getting jumbled in with any error messages.

        :return: None
        '''

        while 1:
            args = []
            command = ''
            incoming = self.get()
            try:
                words = str.strip(incoming).split(' ')
                command = words[0]
                args = words[1:]
            except Exception:
                pass
            try:
                self.commands[command](args)
            except KeyError:
                self.not_a_cmd()
            except Exception:
                self.logger.error("listen() error: Exception thrown")
                traceback.print_exc()
            time.sleep(0.5)


    def command_file(self, f):
        try:
            with open(f, 'r') as cmdfile:
                for line in cmdfile.readlines():
                    self.onecmd(line)
                
        except Exception as e:
            print "Caught exception in command file:" + str(e)

    def do_loadfile(self, args):
        args = args.split(' ')
        if len(args) != 1:
            print "Usage: loadfile <file>"
        self.command_file(f=args[0])

    # Don't repeat commands on empty line
    def emptyline(self):
        pass

    # Handle EOFs
    def do_EOF(self, s):
        pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Initialize DM instance.")
    parser.add_argument('-f', '--file', help='Specify the initialization file for the DM.')
    parser.add_argument('-s', '--start', action='store_true', help='Automatically start DM servers on startup.')
    parser.add_argument('-c', '--commandfile', help='Specify a command file to be run.')
    nspace = vars(parser.parse_args())
    check.Check.initialize('epastack/db/schemas/check.json')
    logfile = LOG_NAME  # TODO: get this from cmdline
    loglevel = logging.DEBUG # TODO: get this from cmdline
    if logfile == None:
        logging.basicConfig(level=loglevel, stream=StandardError)
    else:
        if os.path.isfile(logfile):
            os.remove(logfile)
        logging.basicConfig(filename=logfile, level=loglevel)

    t = None
    if not nspace.get('file'):
        t = Terminal()
        t.prompt ='>'
        startall = nspace['start']
        if startall:
            t.dm.server_start_all()
        if nspace.get('commandfile'):
            t.command_file(f=nspace['commandfile'])
        t.cmdloop("Starting prompt...")
    else:
        d = DiagMgr(fin=nspace['file'])
        t = Terminal(dm=d)

    
