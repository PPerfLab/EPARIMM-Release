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


import epastack.backend.backend
import epastack.backend.backendConfig
import json


'''
This file was written to test the feasibility of writing and loading Tasks to and from
JSON. 

The Task object itself is not serializable; saving the argsdict instead appears to be 
the better option.
'''



def load_tasks_from_file(filename):

    tasksdict = epastack.backend.backend.Task.load_tasks_from_text(filename)

    for taskname in tasksdict.keys():
        t = epastack.backend.backend.Task(tasksdict[taskname])
        print "Task: "
        print t
        raw_input("ENTER for again...")



def task_dump():
    argsdict = {}

    # All user-input values will be interpreted as ints unless prepended with 's ' or 'f '
    for item in epastack.backend.backend.Task.param_names.keys():
        print item
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

    #t = epastack.backend.backend.Task(argsdict)    # Runtime error

    print "dumping Task..."

    with open("testfile.json", 'w+') as fname:
        json.dump(argsdict, fname)

def task_load():
    print "loading..."

    with open("testfile.json", 'r') as fname:
        contents = json.load(fname)

    print "contents:"
    print contents

    t = epastack.backend.backend.Task(contents)

    print "task: "
    print t


#task_dump()
#task_load()
load_tasks_from_file('epastack/backend/tasks.txt')
print "Done."
