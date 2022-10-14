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
from BinjaNxt.JagTypes import *
from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandlerInfo import *
from binaryninja import *


class Client:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        set_main_state_func = None
        size_of_smallest = 250  # It should always be around ~25
        for func in bv.functions:
            if not ensure_func_analyzed(func):
                continue
            ref_count = len(list(bv.get_code_refs(func.start)))
            if ref_count == 24:
                unresolved_call_count = 0
                total_call_count = 0
                for insn in func.llil.instructions:
                    if not isinstance(insn, LowLevelILCall):
                        continue
                    call_insn: LowLevelILCall = insn
                    called = get_called_func(bv, call_insn)
                    if called is None:
                        unresolved_call_count += 1
                    total_call_count += 1
                if unresolved_call_count == 1 and total_call_count == 1:
                    instruction_count = len(list(func.llil.instructions))
                    if instruction_count < size_of_smallest:
                        set_main_state_func = func
                        size_of_smallest = instruction_count
        if set_main_state_func is None:
            log_info("Couldn't find jag::Client::SetMainState")
            return False
        log_info("jag::Client::SetMainState is {}".format(hex(set_main_state_func.start)))
        change_func_name(set_main_state_func, 'jag::Client::SetMainState')
        change_var(set_main_state_func.parameter_vars[0], "pClient",
                   Type.pointer(bv.arch, self.found_data.types.client))
        return True
