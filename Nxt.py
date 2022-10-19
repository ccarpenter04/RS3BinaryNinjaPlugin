"""
Copyright 2022 AridTag
This file is part of BinjaNxt.
BinjaNxt is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

BinjaNxt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with BinjaNxt.
If not, see <https://www.gnu.org/licenses/>.
"""
from BinjaNxt.Client import Client
from BinjaNxt.ClientTcpMessage import ClientTcpMessage
from BinjaNxt.Isaac import Isaac
from BinjaNxt.JagTypes import *
from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandler import PacketHandlers
from binaryninja import *
from binaryninja.log import log_error
from binaryninja.plugin import BackgroundTaskThread

from BinjaNxt.ConnectionManager import ConnectionManager
from BinjaNxt.TimeTools import TimeTools
from BinjaNxt.Console import Console


# from NxtAnalysisData import NxtAnalysisData
# from PacketHandler import PacketHandlers
# from NxtUtils import *


class Nxt(BackgroundTaskThread):
    bv: BinaryView

    found_data: NxtAnalysisData

    packet_handlers: PacketHandlers
    client_tcp_message: ClientTcpMessage
    isaac_cipher: Isaac
    connection_manager: ConnectionManager
    console: Console
    time_tools: TimeTools
    client: Client

    def __init__(self, binv: BinaryView):
        BackgroundTaskThread.__init__(self, 'Beginning pattern recognition for NXT structures', True)
        self.bv = binv
        self.found_data = NxtAnalysisData()
        self.packet_handlers = PacketHandlers(self.found_data)
        self.client_tcp_message = ClientTcpMessage(self.found_data)
        self.isaac_cipher = Isaac(self.found_data)
        self.connection_manager = ConnectionManager(self.found_data)
        self.time_tools = TimeTools(self.found_data)
        self.console = Console(self.found_data)
        self.client = Client(self.found_data)

    def run(self) -> bool:
        if self.bv is None:
            return False
        # Run this first until the refactor is complete. Right now, client has to be defined in self.client.run()
        if not self.client.run(self.bv):
            # TODO define MainState enum
            log_error("Failed to refactor jag::Client.")
        if not self.time_tools.run(self.bv):
            log_error("Failed to refactor jag::game::TimeTools")
        self.found_data.types.create_types(self.bv)
        if not self.console.run(self.bv):
            log_error("Failed to refactor jag::game::Console")
        if not self.connection_manager.run(self.bv):
            log_error("Failed to refactor connection manager")
        if not self.packet_handlers.run(self.bv):
            log_error('Failed to refactor packets')
        if not self.client_tcp_message.run(self.bv):
            log_error("Failed to refactor client tcp message")
        if not self.isaac_cipher.run(self.bv):
            log_error("Failed to refactor the jag::Isaac")

        self.found_data.print_info()
        show_message_box("BinjaNxt", 'Done!', MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)
        return True
