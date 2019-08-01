import yaml

###########################################################################################################
# Non-configurable parameters
#
# Inspector Commands:
#
INSPECTOR_COMMANDS = {          # Cody added; for ease of reference in DM
    'CHECK_REG'       : 0x10,
    'HASH_MEM_VIRT'   : 0x13,
    'HASH_MEM_PHYS'   : 0x14,
    'SEND_BIN'        : 0x33,
    'CHANGE_MEM'      : 0x40,
    'PRINT_MEM_PHYS'  : 0x41,
    'CHECK_MSR'       : 0x42,
    'CHECK_IDTR_IDT'  : 0x43, # Combined IDTR and IDT measurement
    'PRINT_MEM_VIRT'  : 0x44,
    'PRINT_MEM_VSTR'  : 0x45,
    'PRINT_MEM_PSTR'  : 0x46,
    'BENCH_SMI'       : 0x99
}

REGISTER_COMMANDS = {           # Cody added for convenience in Check -> Task decomp. Though this techincally violates DRY
    'CHECK_REG'     : INSPECTOR_COMMANDS['CHECK_REG'],
    'CHECK_MSR'     : INSPECTOR_COMMANDS['CHECK_MSR']
}

MEMORY_COMMANDS = {             # Cody added for convenience in Check -> Task decomp.
    'HASH_MEM_VIRT'     : INSPECTOR_COMMANDS['HASH_MEM_VIRT'],
    'HASH_MEM_PHYS'     : INSPECTOR_COMMANDS['HASH_MEM_PHYS']
}

#
# Inspector Operands:
#
INSPECTOR_OPERANDS = {          # Cody added; for ease of reference in DM
    'NONE'            : 0x00,
    'IDTR_REG'        : 0x20,
    'CR0_REG'         : 0x21,
    'CR3_REG'         : 0x22,
    'CR4_REG'         : 0x23,
    'LDT_REG'         : 0x24,
    'GDT_REG'         : 0x25
}

#
# Constants
#
UNCHANGED       = 0x80
CHANGED         = 0x81
INIT            = 0x100
ERROR           = 0x200

NOT_DONE        = 0
DONE            = 1

MAX_PRIORITY = 25

MAX_TASKS = 20     # If you change # this, you also need to change Ring 0 Manager and SMM inspector! (Fixme: put a header so this isn't needed)

SCHED_TYPES = {
    'once': 0,
    'always': 1,
    'count': 2
}

#
# VALIDATORS
#

msr_file = "epastack/shared/msr.yaml"


def msr_operands():
    with open(msr_file, 'r') as fh:
        msr = yaml.load(fh)
    return msr.get('MSR_OPERANDS')


def validate_address(address, command):
    """
    :param address: str - the address (base 10 or 16) argument to be validated
    :param command: str - the command for which address is an operand
    :return: int - a valid address value for the given command
    """
    null_args = ["none", "0x0", "0"]
    if command in REGISTER_COMMANDS.keys() or command in REGISTER_COMMANDS.values():
        if address not in null_args:
            raise Exception("Non-null address arguments are not valid for register commands.")
        else:
            return 0x0

    if address[:2] == '0x':
        address_int = int(address, 16)
    else:
        address_int = int(address)

    return address_int


def validate_length(length, command):
    """
    :param length: str - the length (in bytes) argument to be validated
    :param command: str - the command for which length is an operand
    :return: int - a valid natural number for length
    """
    length_int = int(length)
    if length_int < 1:
        raise Exception("Non-positive length arguments are not valid.")

    if command == "CHECK_MSR" or command == "0x42" or command == "66":
        if length_int != 4 and length_int != 8:
            raise Exception("4 and 8 are the only acceptable "
                            "length arguments for MSR commands.")

    return length_int


def validate_operand(operand, command):
    """
    :param operand: str - the operand to be validated.
    :return: int - a hex value integer
    """

    null_args = ["none", "0x0", "0"]
    if command in MEMORY_COMMANDS.keys() or command in MEMORY_COMMANDS.values():
        if operand.lower() not in null_args:
            raise Exception("Non-null operand arguments are invalid for memory commands.")
        else:
            return 0x0

    if operand[:2] == '0x' and (
            int(operand, 16) in INSPECTOR_OPERANDS.values() or
            int(operand, 16) in msr_operands()):
        return int(operand, 16)
    elif operand in INSPECTOR_OPERANDS.keys():
        return INSPECTOR_OPERANDS[operand]
    else:
        raise KeyError("{} not a valid operand".format(operand))
