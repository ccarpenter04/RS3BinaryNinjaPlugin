from BinjaNxt.JagTypes import *
from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandlerInfo import *
from binaryninja import *


class MainLogicManager:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        if not self.find_change_main_state(bv):
            log_warn("Unable to locate jag::MainLogicManager::ChangeMainState(jag::MainState, jag::MainState)")
        return True

    def find_change_main_state(self, bv: BinaryView) -> bool:
        # Funcs that contain both account_creation_state and logged in state constants
        for func in get_all_functions_containing_all_constants(bv, bv.start, bv.end, 0x1e, 0x17):
            if not ensure_func_analyzed(func):
                continue
            llil = func.llil
            log_info("Considering {} as a possibility for MainLogicManager::ChangeState".format(hex(func.start)))
            log_info("--> Details: parameters: {}".format(len(func.parameter_vars)) + " basic blocks: {}".format(
                len(llil.basic_blocks)))
            if 4 >= len(func.parameter_vars) >= 3 and 25 <= len(llil.basic_blocks) <= 45:
                log_info("Found jag::MainLogicManager::ChangeMainState @ {}".format(hex(func.start)))
                change_func_name(func, 'jag::MainLogicManager::ChangeMainState')
                change_ret_type(func, Type.void())
                change_var(func.parameter_vars[0], 'this',
                           Type.pointer(bv.arch, self.found_data.types.main_logic_manager))
                change_var(func.parameter_vars[1], "previousState", self.found_data.types.main_state)
                change_var(func.parameter_vars[2], "newState", self.found_data.types.main_state)
                return True
        return False
