import threading
import time

import RNS
from RNS.Interfaces.Interface import Interface
from websockets.sync.server import Server
from websockets.sync.server import serve
from websockets.sync.server import ServerConnection

from src.backend.interfaces.WebsocketClientInterface import WebsocketClientInterface


class WebsocketServerInterface(Interface):

    # TODO: required?
    DEFAULT_IFAC_SIZE = 16

    RESTART_DELAY_SECONDS = 5

    def __str__(self):
        return f"WebsocketServerInterface[{self.name}/{self.listen_ip}:{self.listen_port}]"

    def __init__(self, owner, configuration):

        super().__init__()

        self.owner = owner

        self.IN = True
        self.OUT = False
        self.HW_MTU = 262144 # 256KiB
        self.bitrate = 1_000_000_000 # 1Gbps
        self.mode = RNS.Interfaces.Interface.Interface.MODE_FULL

        self.server: Server | None = None
        self.spawned_interfaces: [WebsocketClientInterface] = []

        # parse config
        ifconf = Interface.get_config_obj(configuration)
        self.name = ifconf.get("name")
        self.listen_ip = ifconf.get("listen_ip", None)
        self.listen_port = ifconf.get("listen_port", None)

        # ensure listen ip is provided
        if self.listen_ip is None:
            raise SystemError(f"listen_ip is required for interface '{self.name}'")

        # ensure listen port is provided
        if self.listen_port is None:
            raise SystemError(f"listen_port is required for interface '{self.name}'")

        # convert listen port to int
        self.listen_port = int(self.listen_port)

        # run websocket server
        thread = threading.Thread(target=self.serve)
        thread.daemon = True
        thread.start()

    @property
    def clients(self):
        return len(self.spawned_interfaces)

    # todo docs
    def received_announce(self, from_spawned=False):
        if from_spawned:
            self.ia_freq_deque.append(time.time())

    # todo docs
    def sent_announce(self, from_spawned=False):
        if from_spawned:
            self.oa_freq_deque.append(time.time())

    # do nothing as the spawned child interface will take care of rx/tx
    def process_incoming(self, data):
        pass

    # do nothing as the spawned child interface will take care of rx/tx
    def process_outgoing(self, data):
        pass

    def serve(self):

        # handle new websocket client connections
        def on_websocket_client_connected(websocket: ServerConnection):

            # create new child interface
            RNS.log("Accepting incoming WebSocket connection", RNS.LOG_VERBOSE)
            spawned_interface = WebsocketClientInterface(self.owner, {
                "name": f"Client on {self.name}",
                "target_host": websocket.remote_address[0],
                "target_port": str(websocket.remote_address[1]),
            }, websocket=websocket)

            # configure child interface
            spawned_interface.IN = self.IN
            spawned_interface.OUT = self.OUT
            spawned_interface.HW_MTU = self.HW_MTU
            spawned_interface.bitrate = self.bitrate
            spawned_interface.mode = self.mode
            spawned_interface.parent_interface = self
            spawned_interface.online = True

            # todo implement?
            spawned_interface.announce_rate_target = None
            spawned_interface.announce_rate_grace = None
            spawned_interface.announce_rate_penalty = None

            # todo ifac?
            # todo announce rates?

            # activate child interface
            RNS.log(f"Spawned new WebsocketClientInterface: {spawned_interface}", RNS.LOG_VERBOSE)
            RNS.Transport.interfaces.append(spawned_interface)

            # associate child interface with this interface
            while spawned_interface in self.spawned_interfaces:
                self.spawned_interfaces.remove(spawned_interface)
            self.spawned_interfaces.append(spawned_interface)

            # run read loop
            spawned_interface.read_loop()

            # client must have disconnected as the read loop finished, so forget the spawned interface
            self.spawned_interfaces.remove(spawned_interface)

        # run websocket server
        try:
            RNS.log(f"Starting Websocket server for {str(self)}...", RNS.LOG_DEBUG)
            with serve(on_websocket_client_connected, self.listen_ip, self.listen_port, compression=None) as server:
                self.online = True
                self.server = server
                server.serve_forever()
        except Exception as e:
            RNS.log(f"{self} failed with error: {e}", RNS.LOG_ERROR)

        # websocket server is no longer running, let's restart it
        self.online = False
        RNS.log(f"Websocket server stopped for {str(self)}...", RNS.LOG_DEBUG)
        time.sleep(self.RESTART_DELAY_SECONDS)
        self.serve()

    def detach(self):

        # mark as offline
        self.online = False

        # stop websocket server
        if self.server is not None:
            self.server.shutdown()

        # mark as detached
        self.detached = True

# set interface class RNS should use when importing this external interface
interface_class = WebsocketServerInterface
