'''
Cody Shepherd
results.py
'''
import collections

RESULT_OUTCOMES = {
    'unchanged': 0x80,
    'changed': 0x81,
}

FIELDS = collections.OrderedDict([
    ('id', int),            # Check ID
    ('complete', bool),     # Whether or not the Check is finished on the inspector side
    ('result', int),       # Did the Check come back good or not
    ('size', int),          # The Hash size chosen by the BEM
    ('hash', [str]),          # The measured hash
    ('time', int)           # Inspection time
])
