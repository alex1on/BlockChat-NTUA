import signal
from node_v2 import node

node1 = node("localhost", 50001, 3)
signal.signal(signal.SIGINT, node1.signal_handler)
