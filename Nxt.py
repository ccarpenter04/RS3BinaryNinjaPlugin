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
from BinjaNxt.ConnectionManager import ConnectionManager
from BinjaNxt.Console import Console
from BinjaNxt.Isaac import Isaac
from BinjaNxt.JagTypes import *
from BinjaNxt.MiniMenu import MiniMenu
from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandler import PacketHandlers
from BinjaNxt.SystemPaths import SystemPaths
from BinjaNxt.TimeTools import TimeTools
from BinjaNxt.LocType import LocType
from BinjaNxt.HeightMapAndLinkMap import HeightMapAndLinkMap
from BinjaNxt.NPCList import NPCList
from BinjaNxt.IdentifiableConstants import IdentifiableConstants
from binaryninja import *
from binaryninja.log import log_error
from binaryninja.plugin import BackgroundTaskThread


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
    system_paths: SystemPaths
    minimenu: MiniMenu
    client: Client
    height_and_link_map: HeightMapAndLinkMap
    loc_type: LocType
    npc_list: NPCList
    constants: IdentifiableConstants

    def __init__(self, binv: BinaryView):
        BackgroundTaskThread.__init__(self, 'Beginning pattern recognition for NXT structures', True)
        self.bv = binv
        self.found_data = NxtAnalysisData(binv)
        self.packet_handlers = PacketHandlers(self.found_data)
        self.client_tcp_message = ClientTcpMessage(self.found_data)
        self.isaac_cipher = Isaac(self.found_data)
        self.connection_manager = ConnectionManager(self.found_data)
        self.time_tools = TimeTools(self.found_data)
        self.system_paths = SystemPaths(self.found_data)
        self.console = Console(self.found_data)
        self.minimenu = MiniMenu(self.found_data)
        self.client = Client(self.found_data)
        self.height_and_link_map = HeightMapAndLinkMap(self.found_data)
        self.loc_type = LocType(self.found_data)
        self.npc_list = NPCList(self.found_data)
        self.constants = IdentifiableConstants(self.found_data)

    def run(self) -> bool:
        if self.bv is None:
            return False

        self.found_data.types.create_enums(self.bv)
        if not self.constants.run(self.bv):
            log_error("Failed to refactor known constants")

        # Run this first until the refactor is complete. Right now, client has to be defined in self.client.run()
        if not self.client.run(self.bv):
            log_error("Failed to refactor jag::Client")
        if not self.time_tools.run(self.bv):
            log_error("Failed to refactor jag::game::TimeTools")
        if not self.system_paths.run(self.bv):
            log_error("Failed to refactor jag::SystemPaths")
        self.found_data.types.create_structs(self.bv)
        if not self.npc_list.run(self.bv):
            log_error("Failed to refactor jag::NPCList")
        if not self.minimenu.run(self.bv):
            log_error("Failed to refactor jag::MiniMenu")
        if not self.height_and_link_map.run(self.bv):
            log_error("Failed to refactor jag::game::HeightMap and jag::game::LinkMap")
        if not self.loc_type.run(self.bv):
            log_error("Failed to refactor jag::game::LocType")
        if not self.isaac_cipher.run(self.bv):
            log_error("Failed to refactor the jag::Isaac")
        if not self.console.run(self.bv):
            log_error("Failed to refactor jag::game::Console")
        if not self.connection_manager.run(self.bv):
            log_error("Failed to refactor jag::ConnectionManager")
        if not self.packet_handlers.run(self.bv):
            log_error('Failed to refactor packets')
        if not self.client_tcp_message.run(self.bv):
            log_error("Failed to refactor client tcp message")
        self.bv.update_analysis_and_wait()
        show_message_box("BinjaNxt", 'Done!', MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)
        return True
