from typing import Optional

from BinjaNxt.ClientProtInfo import ClientProtInfo
from BinjaNxt.JagTypes import JagTypes
from BinjaNxt.PacketHandlerInfo import PacketHandlerInfo
from binaryninja import Function


class NxtAnalysisData:
    types: JagTypes = JagTypes()
    static_client_ptrs: list[int] = []
    current_time_ms_addr: Optional[int] = None
    checked_alloc_addr: Optional[int] = None
    connection_manager_ctor_addr: Optional[int] = None
    client_ctor_addr: Optional[int] = None
    register_packet_handler_addr: Optional[int] = None
    packet_handlers: list[PacketHandlerInfo] = []
    make_client_message_addr: Optional[int] = None
    register_clientprot_addr: Optional[int] = None
    eastl_basic_string_range_intialize: Optional[int] = None
    isaac_init_addr: Optional[int] = None
    isaac_generate_addr: Optional[int] = None
    clientprots: list[ClientProtInfo] = []
    get_ground_intersection_func: Function = None
    height_map_get_fine_height_func: Function = None
    link_map_get_tile_link_func: Function = None

    def print_info(self):
        self.packet_handlers.sort(key=lambda x: x.opcode)
        print('Handlers: [')
        print(*self.packet_handlers, sep=',\n    ')
        print(']')

        self.clientprots.sort(key=lambda x: x.opcode)
        print('ClientProts: [')
        print(*self.clientprots, sep=',\n')
        print(']')

        self.print_cpp()

    def print_cpp(self):
        print('ServerProtNames')
        for handler in self.packet_handlers:
            print('{' + '{}, L"{}"'.format(handler.opcode, handler.name) + '},\n')

        print('\n\n')

        print('ServerProtSizes')
        for handler in self.packet_handlers:
            print('{' + '{}, {}'.format(handler.opcode, handler.size) + '},\n')

        print('ClientProtSizes')
        for prot in self.clientprots:
            print('{' + '{}, {}'.format(prot.opcode, prot.size) + '},\n')
