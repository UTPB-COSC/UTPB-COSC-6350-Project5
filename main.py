import sys
from Client import BluetoothClient
from Server import BluetoothServer

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "server":
        server = BluetoothServer()
        server.start()
    else:
        client = BluetoothClient()
        client.connect()