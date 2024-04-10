import signal
import time
from node_v2 import node

node1 = node("localhost", 50001, 3)
signal.signal(signal.SIGINT, node1.signal_handler)
time.sleep(2)
node1.create_transaction("coins", 10, "", 0)
time.sleep(2)
node1.broadcast_block()