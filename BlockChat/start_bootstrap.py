import signal
from node_v2 import node

bootstrap = node("localhost", 5000, 3, True)
signal.signal(signal.SIGINT, bootstrap.signal_handler)