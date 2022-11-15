from BinjaNxt.JagTypes import *
from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandlerInfo import *
from binaryninja import *


class NPCList:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        if not self.find_constructor(bv):
            log_warn("Unable to locate jag::NPCList::NPCList")
        return True

    def find_constructor(self, bv: BinaryView) -> bool:
        xrefs = bv.get_code_refs(self.found_data.eastl_gPrimeNumberArray_address)
        for xref in xrefs:
            func: Function = xref.function
            parameter_vars: ParameterVariables = func.parameter_vars
            if len(parameter_vars) == 2:
                address_of_constant = bv.find_next_constant(func.start, 0x401)
                for block in func.basic_blocks:
                    if block.start <= address_of_constant <= block.end:
                        log_info("Found jag::NPCList::NPCList @ {}".format(hex(func.start)))
                        change_func_name(func, '{}::NPCList'.format(self.found_data.types.npc_list_name))
                        change_ret_type(func, Type.pointer(bv.arch, self.found_data.types.npc_list))
                        change_var(func.parameter_vars[0], 'this',
                                   Type.pointer(bv.arch, self.found_data.types.npc_list))
                        change_var(func.parameter_vars[1], 'pClient',
                                   Type.pointer(bv.arch, self.found_data.types.client))
                        return True

        return False
