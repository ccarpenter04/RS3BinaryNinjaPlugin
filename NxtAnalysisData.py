from typing import Optional

from BinjaNxt.ClientProtInfo import ClientProtInfo
from BinjaNxt.JagTypes import JagTypes
from BinjaNxt.PacketHandlerInfo import PacketHandlerInfo
from binaryninja import Function, BinaryView


class NxtAnalysisData:
    types: JagTypes
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
    eastl_gPrimeNumberArray_address: Optional[int] = None

    def __init__(self, bv: BinaryView):
        self.types = JagTypes(bv)
