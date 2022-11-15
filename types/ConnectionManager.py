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


class ConnectionManager:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        if not self.find_ctor(bv):
            Logger.log_warn("Failed to locate jag::ConnectionManager::ctor")
        return True

    def find_ctor(self, bv: BinaryView) -> bool:
        """
        Finds jag::ConnectionManager ctor by looking for instances of reg = reg + 20000.
        There are only a few functions that use this value
        """

        log_info('Searching for jag::ConnectionManager::ctor this will take awhile...')
        candidates: Dict[LowLevelILInstruction, Function] = {}
        for func in bv.functions:
            candidate_ins: Optional[LowLevelILInstruction] = None
            is_candidate = False
            is_super_candidate = False

            if not ensure_func_analyzed(func):
                continue

            for insn in func.llil.instructions:
                if not is_candidate:
                    if insn.operation != LowLevelILOperation.LLIL_SET_REG:
                        continue

                    set_reg: LowLevelILSetReg = insn
                    value_expr = set_reg.operands[1]
                    if value_expr.operation != LowLevelILOperation.LLIL_ADD:
                        continue

                    for op in value_expr.operands:
                        if isinstance(op, LowLevelILConst):
                            const: LowLevelILConst = op
                            if const.constant == 20000:
                                candidate_ins = insn
                                is_candidate = True
                                # print(str(candidate_ins) + " @ " + hex(candidate_ins.address))
                                break
                else:
                    distance = insn.address - candidate_ins.address
                    if distance > 25:
                        # print('    discard at ' + str(distance))
                        break

                    if insn.operation != LowLevelILOperation.LLIL_RET:
                        continue

                    # print('    ' + str(distance))
                    is_super_candidate = True
                    break

            if is_super_candidate:
                candidates[candidate_ins] = func
                break

        if len(candidates) != 1:
            log_error(
                'Failed to isolate jag::ConnectionManager::ctor.\n    Remaining candidates: {}'.format(candidates))
            return False

        insn_using_current_time: Optional[LowLevelILInstruction]
        ctor: Optional[Function]
        insn_using_current_time, ctor = list(candidates.items())[0]
        ctor_instructions = list(ctor.llil.instructions)

        current_time_addr = self.find_current_time_addr(insn_using_current_time, ctor_instructions)
        if current_time_addr is None:
            log_debug('Failed to find address of jag::FrameTime::m_CurrentTimeMS')
        else:
            self.found_data.current_time_ms_addr = current_time_addr
            bv.define_user_data_var(self.found_data.current_time_ms_addr, Type.int(8, False),
                                    self.found_data.types.current_time_ms_name)
        ctor_refs = list(bv.get_code_refs(ctor.start))
        if len(ctor_refs) != 1:
            log_debug('Expected 1 xref to jag::ConnectionManager::ctor but got {}'.format(len(ctor_refs)))
            return False

        allocation = find_allocation_from_ctor_call(bv,
                                                    list(
                                                        ctor_refs[0].function.llil_instructions),
                                                    ctor_refs[0].function.get_llil_at(ctor_refs[0].address),
                                                    self.found_data.checked_alloc_addr)
        if allocation is None:
            log_debug('Failed to determine size of jag::ConnectionManager')
            return False

        with StructureBuilder.builder(bv, QualifiedName(self.found_data.types.conn_mgr_name)) as builder:
            builder.packed = True
            builder.width = allocation.size
            builder.alignment = allocation.alignment

        self.found_data.types.conn_mgr = bv.get_type_by_name(self.found_data.types.conn_mgr_name)

        self.found_data.connection_manager_ctor_addr = ctor.start
        log_info('Found jag::ConnectionManager::ConnectionManager @ {:#x}'.format(
            self.found_data.connection_manager_ctor_addr))

        change_func_name(ctor, '{}::ConnectionManager'.format(self.found_data.types.conn_mgr_name))
        change_ret_type(ctor, Type.pointer(bv.arch, self.found_data.types.conn_mgr))
        change_var(ctor.parameter_vars[0], "this", Type.pointer(bv.arch, self.found_data.types.conn_mgr))
        change_var(ctor.parameter_vars[1], "pClient", Type.pointer(bv.arch, self.found_data.types.client))
        return True

    def find_current_time_addr(self,
                               insn_using_current_time: LowLevelILInstruction,
                               ctor_instructions: list[LowLevelILInstruction]) -> Optional[int]:
        """
        In order to get the data address for jag::FrameTime::m_CurrentTimeMS we need to figure out the register that the current time
        value is stored in then we need to move backwards from insn_using_current_time to find the assignment to that
        register
        @param insn_using_current_time:
        @param ctor_instructions:
        @return: The address of jag::FrameTime::m_CurrentTimeMS or None
        """
        reg_name: Optional[RegisterName] = None
        value_expr = insn_using_current_time.operands[1]
        for op in value_expr.operands:
            if isinstance(op, LowLevelILReg):
                reg: LowLevelILReg = op
                reg_name = reg.src.name

        if reg_name is None:
            log_error(
                'jag::FrameTime::m_CurrentTimeMS doesn\'t appear to be coming from a register. Script needs updating!')
            return None

        idx = find_instruction_index(ctor_instructions, insn_using_current_time)
        while idx > 0:
            idx -= 1  # decrementing at the start because we are starting at insn_using_current_time
            insn = ctor_instructions[idx]
            if insn.operation != LowLevelILOperation.LLIL_SET_REG:
                continue

            set_reg: LowLevelILSetReg = insn
            if set_reg.dest.name != reg_name:
                continue

            src = set_reg.src
            if isinstance(src, LowLevelILLoad):
                load: LowLevelILLoad = src
                operand = load.operands[0]
                if isinstance(operand, LowLevelILConstPtr):
                    ptr: LowLevelILConstPtr = operand
                    return ptr.constant
            log_error(
                'jag::FrameTime::m_CurrentTimeMS doesn\'t appear to be coming from a static address. Script needs updating!')
            break
        return None
