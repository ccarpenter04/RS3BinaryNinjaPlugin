from BinjaNxt.JagTypes import *
from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandlerInfo import *
from binaryninja import *


class LocType:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        if not self.find_decode_type(bv):
            return False
        return True

    def find_decode_type(self, bv: BinaryView) -> bool:
        # for func in bv.functions:
        # if len(func.parameter_vars) == 3:
        # arg list: 0: ObjType, 1: Packet, 2: opcode
        # if(func.)

        return True

    def fine_get_max_remove_roof_level(self, bv: BinaryView) -> bool:
        for func in bv.functions:
            if len(func.parameter_vars) != 6:
                continue
        return True
