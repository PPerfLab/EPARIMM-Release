import os

# Frontend config parameters for this node
FRONTEND_PORT   = 10005 # frontend listens on this port
BACKEND_PORT    = 10001 # backend listens on this port

PROCFILE_NAME = "/proc/ring0manager"  # SMM-based inspector

BACKEND_SERVER = "epa-vm"
THIS_HOST      = "epa-vm"
LOG_DIR = os.getenv("HOME") + "/logs/epa_frontend/"
LOG_NAME = "frontend.log"
LEGACY_BACKEND = False               # Use legacy backend
