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


class TimeTools:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        format_real_time_seconds_func = None

        for string in bv.strings:
            if string.value == '%H:%M:%S':
                xrefs = list(bv.get_code_refs(string.start))
                if len(xrefs) != 2:
                    log_warn(
                        "Unable to identify jag::game::TimeTools::FormatRealTimeSeconds because of its xref count of {}".format(
                            len(xrefs)))
                    break
                if xrefs[0].function.start == xrefs[1].function.start:
                    format_real_time_seconds_func = xrefs[0].function
                    log_info(
                        'Found jag::game::TimeTools::FormatRealTimeSeconds @ ' + hex(
                            format_real_time_seconds_func.start))
                break
        if format_real_time_seconds_func is None:
            return False
        change_func_name(format_real_time_seconds_func, "jag::game::TimeTools::FormatRealTimeSeconds")

        eastl_basic_string_range_intialize_func = None
        for insn in format_real_time_seconds_func.llil.instructions:
            if isinstance(insn, LowLevelILCall):
                eastl_basic_string_range_intialize_func = get_called_func(bv, insn)
                if eastl_basic_string_range_intialize_func is not None:
                    log_info('Found eastl::basic_string<char, eastl::allocator>::RangeInitialize @ ' + hex(
                        eastl_basic_string_range_intialize_func.start))
                    self.found_data.eastl_basic_string_range_intialize = eastl_basic_string_range_intialize_func
                    break
        if eastl_basic_string_range_intialize_func is None:
            return False
        change_func_name(eastl_basic_string_range_intialize_func,
                         "eastl::basic_string<char, eastl::allocator>::RangeInitialize")
        return True
