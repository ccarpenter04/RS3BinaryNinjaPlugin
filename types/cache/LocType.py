from BinjaNxt.JagTypes import *
from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandlerInfo import *
from binaryninja import *


class LocType:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        if not self.get_location_height(bv):
            log_warn("Failed to locate jag::game::LocType::GetLocationHeight")
        if not self.find_get_max_remove_roof_level(bv):
            log_warn("Failed to locate jag::game::LocType::GetMaxRemoveRoofLevel")
        if not self.find_decode_type(bv):
            log_warn("Failed to locate jag::game::LocType::DecodeType")
        return True

    def find_decode_type(self, bv: BinaryView) -> bool:
        decode_type_func: [Function, None] = None
        make_location_sound_data_func: [Function, None] = None
        for func in bv.functions:
            if decode_type_func is not None and make_location_sound_data_func is not None:
                break
            if len(func.parameter_vars) == 3:
                # and func.parameter_vars[2].type.handle check for equality Type.int(4):
                # arg list: 0: ObjType, 1: Packet, 2: opcode
                for insn in func.llil.instructions:
                    if isinstance(insn, LowLevelILCall):
                        called_func = get_called_func(bv, insn)
                        if called_func is None:
                            continue
                        # There should be 12 calls to this function from the decode function
                        # Just in case there's inlining, we search a small range
                        # This is the only function where make_location_sound_data is called
                        if len(called_func.callers) == 12:
                            multiple_callers = False
                            for caller in called_func.callers:
                                if caller.start != func.start:
                                    multiple_callers = True
                                    break
                            if not multiple_callers:
                                decode_type_func = func
                                make_location_sound_data_func = called_func
                                log_info(
                                    "Found jag::game::LocType::DecodeType @ {}".format(hex(decode_type_func.start)))
                                log_info("Found jag::game::LocType::MakeLocationSoundData @ {}".format(
                                    hex(make_location_sound_data_func.start)))
                                break

        if decode_type_func is None:
            return False
        change_func_name(decode_type_func, "jag::game::LocType::DecodeType")
        change_var(decode_type_func.parameter_vars[0], "this", Type.pointer(bv.arch, self.found_data.types.loc_type))
        change_var(decode_type_func.parameter_vars[1], "packet", Type.pointer(bv.arch, self.found_data.types.packet))
        change_var_name(decode_type_func.parameter_vars[2], "opcode")
        if make_location_sound_data_func is None:
            return False
        change_func_name(make_location_sound_data_func, "jag::game::LocType::MakeLocationSoundData")
        change_var(make_location_sound_data_func.parameter_vars[0], "this",
                   Type.pointer(bv.arch, self.found_data.types.loc_type))
        return True

    def find_get_max_remove_roof_level(self, bv: BinaryView) -> bool:
        for func in bv.functions:
            if len(func.parameter_vars) != 6:
                continue
        return True

    def get_location_height(self, bv: BinaryView) -> bool:
        xrefs = list(bv.get_code_refs(self.found_data.height_map_get_fine_height_func.start))
        for xref in xrefs:
            xref_func = xref.function
            if xref_func is None:
                continue
            if len(list(xref_func.parameter_vars)) == 8:
                log_info("Found jag::game::LocType::GetLocationHeight @ {}".format(hex(xref_func.start)))
                change_func_name(xref_func, "jag::game::LocType::GetLocationHeight")
                return True

        return False
