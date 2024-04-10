import signal
import sys
from node_v2 import node

if len(sys.argv) < 2:
    print("Usage: python start_node.py [port]")
    sys.exit(1)

port = int(sys.argv[1])
suffix = port - 5001
node_instance = node(f"simple_node{suffix}", port, 3)
signal.signal(signal.SIGINT, node_instance.signal_handler)
