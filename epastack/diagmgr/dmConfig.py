# LISTEN_HOSTS lists the port(s) on which the DM will
# listen for incoming traffic
LISTEN_HOSTS = {
    'dm_local': ('', 10002)
}

# SEND_HOSTS is, for now, the list of Backend Managers
# that this DM will talk to. In the future it may include
# an Oracle, and/or other DMs

# Note that once this dict no longer represents only BEMs,
# the DiagMgr class will need some way to differentiate 
# BEMs from other types of hosts to which it can send data
SEND_HOSTS = {
    #'deepthought': ('deepthought', 11001)
    'epa-vm': ('epa-vm', 10001)
}

LOG_NAME = 'diag_mgr.log'
