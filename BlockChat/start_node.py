import signal
import time
import sys
import socket
from node_v2 import node

if len(sys.argv) < 2:
    print("Usage: python start_node.py [port]")
    sys.exit(1)

port = int(sys.argv[1])
suffix = port - 5001

# Get the container's hostname (which is also the container's name within the Docker network)
hostname = socket.gethostname()
# Resolve the hostname to an IP address
ip_address = socket.gethostbyname(hostname)
print(ip_address)

# node_instance = node(f"simple_node{suffix}", port, 3)
node_instance = node(ip_address, port, 3)

signal.signal(signal.SIGINT, node_instance.signal_handler)
time.sleep(2)
node_instance.create_transaction("coins", 10, "", 0)
time.sleep(2)
node_instance.create_transaction("coins", 11, "", 0)
time.sleep(2)
node_instance.create_transaction("coins", 12, "", 0)
time.sleep(2)
node_instance.create_transaction("coins", 13, "", 0)
time.sleep(2)
node_instance.create_transaction("coins", 14, "", 0)
time.sleep(2)
#node_instance.broadcast_block()
