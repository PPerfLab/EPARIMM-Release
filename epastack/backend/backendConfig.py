import os

# Configurable parameters
HOST_LIST = ["localhost"]
DEFAULT_NODELIST = {    # This is the map for communications with monitored nodes.
    0: ('epa-vm', 10005) 
}
DM_HOST = 'epa-vm'
DM_PORT = 10002

#DM_LISTEN_PORT = 10001 # CODY -- network port to listen on for Checks from DM
DM_OUT_PORT    = 9158  # CODY -- network port to send Check results back on
BACKEND_PORT  = 10001 # Network port to listen on for client responses
FRONTEND_PORT  = 10005 # Network port to send bins to

# Encryption key
INSPECTOR_KEY = '0000000000000000000000000000000000000000000000000000000000000000'
# HMAC key
HMAC_KEY =  [0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                               0x0b, 0x0b, 0x0b, 0x0b, 0x0b]
# Manager signature
SIGNATURE = [0x414e414d,
		     0x31524547,
		     0x35343332,
		     0x39383736,
		     0x33323130]

LOG_NAME = "backend.log"
