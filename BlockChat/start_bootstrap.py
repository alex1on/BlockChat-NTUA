import signal
import socket
from node import node

# Get the container's hostname (which is also the container's name within the Docker network)
hostname = socket.gethostname()
# Resolve the hostname to an IP address
ip_address = socket.gethostbyname(hostname)
print(ip_address)

bootstrap = node(ip_address, 5001, 3, 3, True)
signal.signal(signal.SIGINT, bootstrap.signal_handler)