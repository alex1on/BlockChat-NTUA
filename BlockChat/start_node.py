import signal
import time
import sys
from node_v2 import node

if len(sys.argv) < 2:
    print("Usage: python start_node.py [port]")
    sys.exit(1)

port = int(sys.argv[1])
suffix = port - 5001
node_instance = node(f"simple_node{suffix}", port, 3)
signal.signal(signal.SIGINT, node_instance.signal_handler)
time.sleep(2)
node_instance.create_transaction("coins", 10, "", 0)
time.sleep(2)
node_instance.broadcast_block()
