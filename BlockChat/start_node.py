import os
import signal
import time
import socket
from node import node

port = int(os.getenv('NODE_PORT', 5001))
is_bootstrap = os.getenv('NODE_TYPE') == "bootstrap"
suffix = port - 5001

if not is_bootstrap:
    time.sleep(2)
# Get the container's hostname (which is also the container's name within the Docker network)
hostname = socket.gethostname()
# Resolve the hostname to an IP address
ip_address = socket.gethostbyname(hostname)

node_instance = node(ip_address, port, 3, 3, is_bootstrap)

signal.signal(signal.SIGINT, node_instance.signal_handler)
