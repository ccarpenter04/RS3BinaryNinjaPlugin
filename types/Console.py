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


class Console:
    found_data: NxtAnalysisData
    add_message_func: Function

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        if not self.find_add_message(bv):
            return False
        if not self.find_operator_delete(bv):
            return False
        if not self.find_register_commands_login(bv):
            return False
        return True

    def find_add_message(self, bv: BinaryView) -> bool:
        for string in bv.strings:
            if string.value == 'commands - This command':
                xrefs = list(bv.get_code_refs(string.start))
                if len(xrefs) != 1:
                    log_warn(
                        "Unable to identify jag::game::Console::AddMessage because of its xref count of {}".format(
                            len(xrefs)))
                    break
                for insn in xrefs[0].function.llil.instructions:
                    if isinstance(insn, LowLevelILCall):
                        self.add_message_func = get_called_func(bv, insn)
                        if self.add_message_func is not None:
                            log_info('Found jag::game::Console::AddMessage @ ' + hex(self.add_message_func.start))
                            break
                break
        if self.add_message_func is None:
            return False
        change_func_name(self.add_message_func, "jag::game::Console::AddMessage")
        return True

    def find_operator_delete(self, bv: BinaryView) -> bool:
        if self.add_message_func is None:
            return False
        operator_delete_func = None
        for insn in self.add_message_func.llil.instructions:
            if isinstance(insn, LowLevelILCall):
                function_called = get_called_func(bv, insn)
                if function_called is not None:
                    operator_delete_func = function_called
        if operator_delete_func is None:
            return False
        log_info('Found operator delete[] @ ' + hex(operator_delete_func.start))
        change_func_name(operator_delete_func, "operator delete[]")
        return True

    def find_register_commands_login(self, bv: BinaryView) -> bool:
        if self.add_message_func is None:
            return False
        register_commands_login_func = None
        for string in bv.strings:
            if string.value == 'Usage: setlobby <id> <server> (eg: setlobby 25 tws14)':
                xrefs = list(bv.get_code_refs(string.start))
                if len(xrefs) != 1:
                    log_warn(
                        "Unable to identify jag::RegisterCommandsLogin because of its xref count of {}".format(
                            len(xrefs)))
                    break
                register_commands_login_func = xrefs[0].function
                break
        if register_commands_login_func is None:
            return False
        log_info('Found jag::RegisterCommandsLogin @ ' + hex(register_commands_login_func.start))
        change_func_name(register_commands_login_func, "jag::RegisterCommandsLogin")
        return True
