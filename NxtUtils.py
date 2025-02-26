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
from typing import Optional, Set

from binaryninja import Function, Type, Undetermined, Variable, BinaryView, RegisterName, log_debug
from binaryninja import LowLevelILInstruction, LowLevelILCall

RCX = RegisterName('rcx')
RDX = RegisterName('rdx')
RSI = RegisterName('rsi')
RBP = RegisterName('rbp')
R8 = RegisterName('r8')
R8D = RegisterName('r8d')


class AllocationDetails:
    size: int = 0
    alignment: int = 0

    def __init__(self, size, alignment):
        self.size = size
        self.alignment = alignment


def int32(x: int):
    if x > 0xFFFFFFFF:
        raise OverflowError
    if x > 0x7FFFFFFF:
        x = int(0x100000000 - x)
        if x < 2147483648:
            return -x
        else:
            return -2147483648
    return x


def ensure_func_analyzed(func: Function) -> bool:
    if func.analysis_skipped:
        log_debug('Function {} was not analyzed. Reason {}'.format(func.name, func.analysis_skip_reason))
        return False
    return True


def is_valid_function_call(bv: BinaryView, llil: LowLevelILInstruction) -> (bool, Optional[int]):
    if not isinstance(llil, LowLevelILCall) or len(llil.operands) != 1:
        return False, None

    call_insn: LowLevelILCall = llil
    call_dest = call_insn.dest.value
    if isinstance(call_dest, Undetermined):
        return False, None

    dest_func = bv.get_function_at(call_dest.value)
    if dest_func is None:
        return False, None

    return True, dest_func.start


def get_called_func(bv: BinaryView, llil: LowLevelILCall) -> Optional[Function]:
    """
    Gets the function that is being called by the given the instruction.
    If the call cannot be resolved or is a virtual function call, this function will return None
    """
    target = llil.dest.value
    if isinstance(target, Undetermined):
        return None

    return bv.get_function_at(target.value)


def change_comment(bv: BinaryView, addr: int, desired_comment: str):
    comment = bv.get_comment_at(addr)
    if comment != desired_comment:
        bv.set_comment_at(addr, desired_comment)


def change_var(var: Variable, name: str, var_type: Type):
    set_name = var.name != name
    set_type = var.type != var_type
    if set_name and set_type:
        var.set_name_and_type_async(name, var_type)
    elif set_type:
        var.set_type_async(var_type)
    elif set_name:
        var.set_name_async(name)


def change_var_name(var: Variable, name: str):
    if var.name != name:
        var.set_name_async(name)


def change_var_type(var: Variable, var_type: Type):
    if var.type != var_type:
        var.set_type_async(var_type)


def change_func_name(func: Function, name: str):
    if func.name != name:
        func.name = name


def change_ret_type(func: Function, ret_type: Type):
    if func.return_type != ret_type:
        func.return_type = ret_type


def get_all_functions_containing_all_constants(bv: BinaryView, start_address: int, end_address: int, *constants) -> \
        Set[Function]:
    funcs: Set[Function] = set()
    # First pass - Build a list to use as a base
    constant = constants[0]
    result_queue = bv.find_all_constant(start_address, end_address, constant)
    for address, line in result_queue:
        for func in bv.get_functions_containing(address):
            funcs.add(func)
    # Second pass - build a list of functions for each constant, then check which of the existing funcs aren't in the
    #               new constants List[Function]
    first_constant = True
    for constant in constants:
        if first_constant:
            first_constant = False
            continue
        result_queue = bv.find_all_constant(start_address, end_address, constant)
        funcs_for_constant: Set[Function] = set()
        for address, line in result_queue:
            for func in bv.get_functions_containing(address):
                funcs_for_constant.add(func)
        funcs_to_remove = set()
        for func in funcs:
            if not funcs_for_constant.__contains__(func):
                funcs_to_remove.add(func)
        for func in funcs_to_remove:
            funcs.remove(func)
    return funcs


def find_instruction_index(instructions: list[LowLevelILInstruction], insn: LowLevelILInstruction) -> int:
    """
    Finds the index of the given instruction in the list of instructions by its address.
    @param instructions:
    @param insn:
    @return: The index of the instruction or -1 if not found
    """
    return next((i for i, item in enumerate(instructions) if item.address == insn.address), -1)


def find_allocation_from_ctor_call(bv: BinaryView,
                                   calling_function_instructions: list[LowLevelILInstruction],
                                   calling_instruction: LowLevelILInstruction,
                                   alloc_addr: int) -> Optional[AllocationDetails]:
    """
    Determines the size and alignment of the allocation for the object being constructed.
    The value of num_bytes (rcx) must be able to be determined.
    If the value of alignment (rdx) cannot be determined then a default alignment of 16 will be assumed

    @param bv:
    @param calling_function_instructions:
    @param calling_instruction:
    @param alloc_addr: the address of the alloc function. It is assumed the alloc signature is as follows: void* alloc(int32_t num_bytes, int32_t alignment)
    @return: The AllocationDetails passed to the invokation of jag::HeapInterface::CheckedAlloc to allocate the object
    whose constructor is being called by calling_instruction or None
    """
    idx = find_instruction_index(calling_function_instructions, calling_instruction)
    while idx > 0:
        idx -= 1
        insn = calling_function_instructions[idx]

        (is_valid, dest_addr) = is_valid_function_call(bv, insn)
        if not is_valid:
            continue

        # If we hit another function call then we can't guarantee the registeres will have the correct values
        if dest_addr != alloc_addr:
            return None

        size = insn.get_reg_value(RCX)  # num_bytes
        alignment = insn.get_reg_value(RDX)  # alignment
        if isinstance(size, Undetermined):
            print('Unable to determine size of allocation')
            return None

        return AllocationDetails(size.value, alignment.value if not isinstance(alignment, Undetermined) else 16)
    return None


def recursive_call_count(bv: BinaryView, func: Function) -> int:
    self_call_quantity = 0
    xrefs = bv.get_code_refs(func.start)
    for xref in xrefs:
        if xref.address != func.start and xref.function.start == func.start:
            self_call_quantity += 1
    return self_call_quantity
