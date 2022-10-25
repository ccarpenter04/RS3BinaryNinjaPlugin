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


class SystemPaths:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        check_launcher_cfg_func = None

        for string in bv.strings:
            if string.value == "preferences.cfg":
                xrefs = list(bv.get_code_refs(string.start))
                if len(xrefs) != 2:
                    log_warn(
                        "Unable to identify jag::SystemPaths::CheckLauncherCFG because of its xref count of {}".format(
                            len(xrefs)))
                    break
                if xrefs[0].function.start == xrefs[1].function.start:
                    check_launcher_cfg_func = xrefs[0].function
                    log_info(
                        'Found jag::SystemPaths::CheckLauncherCFG @ ' + hex(check_launcher_cfg_func.start))
                break
        if check_launcher_cfg_func is None:
            return False
        change_func_name(check_launcher_cfg_func, "jag::SystemPaths::CheckLauncherCFG")
        return True
