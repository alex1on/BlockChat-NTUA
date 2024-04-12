import os
import signal
import time
import sys
import socket
from node import node

if len(sys.argv) < 3:
    print("Usage: python start_node.py [port] [bootstrap/node]")
    sys.exit(1)

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

# if not is_bootstrap:
#     time.sleep(2)
#     node_instance.create_transaction("coins", 10, "", 0)
# time.sleep(2)
# node_instance.create_transaction("coins", 11, "", 0)
# time.sleep(2)
# node_instance.create_transaction("coins", 12, "", 0)
# time.sleep(2)
# node_instance.create_transaction("coins", 13, "", 0)
# time.sleep(2)
# node_instance.create_transaction("coins", 14, "", 0)
# time.sleep(2)
# #node_instance.broadcast_block()