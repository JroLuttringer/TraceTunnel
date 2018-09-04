import sys  # sys.stdout
import telnetlib  # telnet connection to gns3 routers
import time  # time.sleep
import json  # read .gns3
import socket               # Import socket module
import _thread as thread
import signal

# global variables
dict_name_port = {}
tn_connections = {}
all_routers = {}
current_topology_state = 0

# Server running gns3
routeurs_addr = "127.0.0.1"
EXIT_MSG = "end"
s         = None #socket
SERVER_IP = "130.79.90.202"
PORT      = 30000

# gns3 configuration files
confs_file_path = "/home/jro/Documents/Projets/TER/topologies/OpaqueRealiste/IMC17"
gns_file        = "/home/jro/Documents/Projets/TER/topologies/OpaqueRealiste/IMC17/OpaqueRealiste.gns3"

# command for each configuration
PHP_CMD    = "\r\n no mpls ldp explicit-null \r\n"
UHP_CMD    = "\r\n mpls ldp explicit-null \r\n"
PROP_CMD   = "\r\n mpls ip propagate-ttl \r\n"
NOPROP_CMD = "\r\n no mpls ip propagate-ttl \r\n"
BRPR_CMD   = "\r\n mpls ldp label \r\n" + "\r\n no allocate global host-routes \r\n"
DPR_CMD    = "\r\n mpls ldp label \r\n" + "\r\n allocate global host-routes \r\n"

def signal_handler(sig, frame):
    print("CTRL-C pressed: Exiting")
    if s is not None:
        s.close()
        for tn in tn_connections:
            tn.close()
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)
signal.pause()

def init_server():
    global s
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((SERVER_IP, PORT))        # Bind to the port
    s.listen(5)                 # Now wait for client connection.
    print('Server-conf started!')
    print('Waiting for clients...')

def flush(tn):
    tn.write("\r\nend\r\nq\r\n\r\nterminal length 0\r\n\r\n")
    time.sleep(15)
    tn.read_very_eager()

def send_command(names, cmd):
    for name in names:
        tn = tn_connections[name]
        flush(tn)
        tn.write("\r\n conf t \r\n")
        tn.write(cmd)
        tn.write("\r\n end \r\n")
        tn.close()

def name_port():
    with open(gns_file) as gns_fd:
        gns_json = json.load(gns_fd)
        for nodes in gns_json['topology']['nodes']:
            if nodes['console'] is not None and nodes['console'] != "null":
                dict_name_port[nodes['name']] = int(nodes['console'])
                tn_connections[nodes['name']] = telnetlib.Telnet(routeurs_addr, dict_name_port[nodes['name']])
                if nodes['name'] not in all_routers:
                    all_routers.add(nodes['names'])

def parse_msg(msg):
    num_msg = int(msg)
    if num_msg < 0 or num_msg > 3:
        return "Unknown configuration"

    if num_msg != 3 and current_topology_state == 3:
        send_command(all_routers, BRPR_CMD)

    if num_msg == 0 and current_topology_state != 0: #INV PHP
        send_command(["PE2"], PHP_CMD)
        send_command(["PE1"], NOPROP_CMD)

    if num_msg == 1 and current_topology_state != 1: #EXP PHP
        send_command(["PE2"], PHP_CMD)
        send_command(["PE1"], PROP_CMD)

    if num_msg == 2 and current_topology_state != 2: # INV UHP
        send_command(["PE1"], NOPROP_CMD)
        send_command(["PE2"], UHP_CMD)

    if num_msg == 3 and current_topology_state != 3:
        send_command(all_routers, DPR_CMD)
        if current_topology_state != 0:
            send_command(["PE2"], PHP_CMD)
            send_command(["PE1"], NOPROP_CMD)

    current_topology_state = num_msg
    return "Configuration %s done" % msg

def on_new_client(clientsocket,addr):
    print('Got connection from', addr)
    while True:
        msg = str.decode(clientsocket.recv(256))
        if msg == EXIT_MSG:
            clientsocket.close()
            return
        answer = parse_msg(msg)
        msg = str.encode(answer)
        clientsocket.send(msg)
        return

def main():
    init_server()
    #name_port()
    while True:
       c, addr = s.accept()
       thread.start_new_thread(on_new_client,(c,addr))

if __name__ == "__main__":
    main()
