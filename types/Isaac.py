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


class Isaac:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        isaac_init_addr = None
        max_isaac_constants = 0
        for func in bv.functions:
            if not ensure_func_analyzed(func):
                continue
            if len(func.parameter_vars) != 2:
                continue
            isaac_cipher_key = 0
            isaac_constants_found = 0
            for insn in func.llil.instructions:
                isaac_cipher_key += insn.prefix_operands.count(0x9e3779b9)
                quantity_of_constant = insn.prefix_operands.count(0x404)
                isaac_constants_found += quantity_of_constant
            if isaac_constants_found >= 1 and isaac_cipher_key == 1:
                if isaac_constants_found > max_isaac_constants:
                    max_isaac_constants = isaac_constants_found
                    isaac_init_addr = func.start
        if isaac_init_addr is None:
            log_info('Unable to find jag::Isaac::Init')
            return False
        self.found_data.isaac_init_addr = isaac_init_addr
        log_info('Found jag::Isaac::Init @ ' + hex(self.found_data.isaac_init_addr))
        isaac_init_func = bv.get_function_at(self.found_data.isaac_init_addr)
        change_func_name(isaac_init_func, 'jag::Isaac::Init')
        # change_var(isaac_init_func.parameter_vars[0], 'pIsaac', Type.pointer(bv.arch, self.found_data.types.isaac))

        isaac_generate_addr = None
        isaac_init_instructions = list(isaac_init_func.llil.instructions)
        isaac_init_instructions.reverse()
        for insn in isaac_init_instructions:
            if not isinstance(insn, LowLevelILCall):
                continue
            call_insn: LowLevelILCall = insn
            called = get_called_func(bv, call_insn)
            if called is None:
                continue
            isaac_generate_addr = called.start
            break
        if isaac_generate_addr is None:
            log_info('Unable to find jag::Isaac::Generate')
            return False
        self.found_data.isaac_generate_addr = isaac_generate_addr
        log_info('Found jag::Isaac::Generate @ ' + hex(self.found_data.isaac_generate_addr))
        isaac_generate_func = bv.get_function_at(self.found_data.isaac_generate_addr)
        change_func_name(isaac_generate_func, 'jag::Isaac::Generate')
        #change_var(isaac_generate_func.parameter_vars[0], 'pIsaac', Type.pointer(bv.arch, self.found_data.types.isaac))
        return True
