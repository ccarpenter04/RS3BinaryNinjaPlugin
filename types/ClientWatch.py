from BinjaNxt.JagTypes import *
from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandlerInfo import *
from binaryninja import *


class ClientWatch:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        if not self.find_change_main_state(bv):
            log_warn("Unable to locate jag::ClientWatch::ChangeMainState(jag::MainState, jag::MainState)")
        return True

    def find_change_main_state(self, bv: BinaryView) -> bool:
        for address, line in bv.find_all_constant(bv.start, bv.end, 0x1e):
            for func in bv.get_functions_containing(address):
                if not ensure_func_analyzed(func):
                    continue
                llil = func.llil
                if 4 >= len(func.parameter_vars) >= 2 and 2 <= len(llil.basic_blocks) <= 5:
                    log_info("Found jag::ClientWatch::ChangeMainState @ {}".format(hex(func.start)))
                    change_func_name(func, 'jag::ClientWatch::ChangeMainState')
                    change_ret_type(func, Type.void())
                    change_var(func.parameter_vars[0], 'this',
                               Type.pointer(bv.arch, self.found_data.types.client_watch))
                    change_var(func.parameter_vars[1], "previousState", self.found_data.types.main_state)
                    change_var(func.parameter_vars[2], "newState", self.found_data.types.main_state)
                    return True
        return False
