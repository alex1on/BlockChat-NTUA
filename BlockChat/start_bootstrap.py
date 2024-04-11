import signal
from node_v2 import node

bootstrap = node("bootstrap_node", 5001, 3, 3, True)
signal.signal(signal.SIGINT, bootstrap.signal_handler)