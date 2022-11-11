from BinjaNxt.JagTypes import *
from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandlerInfo import *
from binaryninja import *


class MiniMenu:
    found_data: NxtAnalysisData
    colour_code_func = None

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        if not self.find_colour_code(bv):
            return False
        if not self.find_add_npc_entries(bv):
            return False
        if not self.find_add_player_entries(bv):
            return False
        if not self.find_get_ground_intersection(bv):
            return False
        if not self.find_add_entries_3d_view(bv):
            return False
        return True

    def find_colour_code(self, bv: BinaryView) -> bool:
        for string in bv.strings:
            if string.value == "<col=0xff3000>":
                xrefs = list(bv.get_code_refs(string.start))
                if len(xrefs) != 2:
                    log_warn(
                        "Unable to identify jag::MiniMenu::ColourCode because of its xref count of {}".format(
                            len(xrefs)))
                    break
                if xrefs[0].function.start == xrefs[1].function.start:
                    self.colour_code_func = xrefs[0].function
                    log_info(
                        'Found jag::MiniMenu::ColourCode @ ' + hex(
                            self.colour_code_func.start))
                break
        if self.colour_code_func is None:
            return False
        change_func_name(self.colour_code_func, "jag::MiniMenu::ColourCode")
        return True

    def find_add_npc_entries(self, bv: BinaryView) -> bool:
        if self.colour_code_func is None:
            return False
        add_npc_entries_func = None
        xrefs = list(bv.get_code_refs(self.colour_code_func.start))
        # Function start address, xref count to the specific function
        xrefs_by_function = {}
        for xref in xrefs:
            count = xrefs_by_function.get(xref.function, 0)
            xrefs_by_function.update({xref.function: count + 1})
        for func in xrefs_by_function.keys():
            if xrefs_by_function[func] == 1:
                add_npc_entries_func = bv.get_function_at(func.start)
                log_info('Found jag::MiniMenu::AddNPCEntries @ ' + hex(func.start))
                break
        if add_npc_entries_func is None:
            return False
        change_func_name(add_npc_entries_func, "jag::MiniMenu::AddNPCEntries")
        change_var_type(add_npc_entries_func.parameter_vars[0], Type.pointer(bv.arch, self.found_data.types.minimenu))
        return True

    def find_add_player_entries(self, bv: BinaryView) -> bool:
        if self.colour_code_func is None:
            return False
        add_player_entries_func = None
        xrefs = list(bv.get_code_refs(self.colour_code_func.start))
        # Function start address, xref count to the specific function
        xrefs_by_function = {}
        for xref in xrefs:
            count = xrefs_by_function.get(xref.function, 0)
            xrefs_by_function.update({xref.function: count + 1})
        for func in xrefs_by_function.keys():
            if xrefs_by_function[func] == 2:
                add_player_entries_func = bv.get_function_at(func.start)
                log_info('Found jag::MiniMenu::AddPlayerEntries @ ' + hex(func.start))
                break
        if add_player_entries_func is None:
            return False
        change_func_name(add_player_entries_func, "jag::MiniMenu::AddPlayerEntries")
        change_var_type(add_player_entries_func.parameter_vars[0],
                        Type.pointer(bv.arch, self.found_data.types.minimenu))
        return True

    def find_get_ground_intersection(self, bv: BinaryView) -> bool:
        for func in bv.functions:
            if len(func.parameter_vars) != 5:
                continue
            counter = recursive_call_count(bv, func)
            if counter == 1 and len(list(bv.get_code_refs(func.start))) == 2:
                for insn in func.llil.instructions:
                    if isinstance(insn, LowLevelILIf):
                        for operand in insn.condition.prefix_operands:
                            if operand == 2:
                                log_info("Found jag::MiniMenu::GetGroundIntersection @ {}".format(hex(func.start)))
                                self.found_data.get_ground_intersection_func = func
        if self.found_data.get_ground_intersection_func is None:
            log_warn("Unable to find jag::MiniMenu::GetGroundIntersection")
            return False
        change_func_name(self.found_data.get_ground_intersection_func, "jag::MiniMenu::GetGroundIntersection")
        change_var(self.found_data.get_ground_intersection_func.parameter_vars[0], "pMiniMenu",
                        Type.pointer(bv.arch, self.found_data.types.minimenu))
        change_var(self.found_data.get_ground_intersection_func.parameter_vars[1], "pWorld",
                        Type.pointer(bv.arch, self.found_data.types.world))
        return True

    def find_add_entries_3d_view(self, bv: BinaryView) -> bool:
        add_entries_3d_view = None
        for string in bv.strings:
            if string.value == " -> ":
                xrefs = list(bv.get_code_refs(string.start))
                for xref in xrefs:
                    if add_entries_3d_view is not None:
                        break
                    func = xref.function
                    if len(func.parameter_vars) != 5:
                        continue
                    for insn in func.llil.instructions:
                        if add_entries_3d_view is not None:
                            break
                        if isinstance(insn, LowLevelILIf):
                            for operand in insn.condition.prefix_operands:
                                if operand == 0x40:
                                    log_info("Found jag::MiniMenu::AddEntries3DView @ {}".format(hex(func.start)))
                                    add_entries_3d_view = func
                                    break

        if add_entries_3d_view is None:
            log_warn("Unable to find jag::MiniMenu::AddEntries3DView")
            return False
        change_func_name(add_entries_3d_view, "jag::MiniMenu::AddEntries3DView")
        change_var_type(add_entries_3d_view.parameter_vars[0],
                        Type.pointer(bv.arch, self.found_data.types.minimenu))
        return True
