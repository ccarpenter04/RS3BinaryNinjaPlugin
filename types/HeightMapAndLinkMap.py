from BinjaNxt.JagTypes import *
from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandlerInfo import *
from binaryninja import *


class HeightMapAndLinkMap:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        if not self.find_get_fine_height_and_get_tile_link(bv):
            log_warn("Unable to find jag::game::HeightMap::GetFineHeight")
        if not self.find_apply_hill_rotation(bv):
            log_warn("Unable to find jag::game::HeightMap::ApplyHillRotation")
        return True

    def find_get_fine_height_and_get_tile_link(self, bv: BinaryView) -> bool:
        for insn in self.found_data.get_ground_intersection_func.llil.instructions:
            if isinstance(insn, LowLevelILCall):
                resolved_func = get_called_func(bv, insn)
                if resolved_func is None:
                    continue
                parameter_vars = list(resolved_func.parameter_vars)
                if len(parameter_vars) == 6:
                    self.found_data.height_map_get_fine_height_func = resolved_func
                    log_info('Found jag::game::HeightMap::GetFineHeight @ ' + hex(
                        self.found_data.height_map_get_fine_height_func.start))
                elif len(parameter_vars) == 4:
                    self.found_data.link_map_get_tile_link_func = resolved_func
                    log_info('Found jag::game::LinkMap::GetTileLink @ ' + hex(
                        self.found_data.link_map_get_tile_link_func.start))

                if (self.found_data.height_map_get_fine_height_func is not None
                        and self.found_data.link_map_get_tile_link_func is not None):
                    break

        if self.found_data.height_map_get_fine_height_func is None:
            return False
        if self.found_data.link_map_get_tile_link_func is None:
            return False

        change_func_name(self.found_data.height_map_get_fine_height_func, "jag::game::HeightMap::GetFineHeight")
        change_var(self.found_data.height_map_get_fine_height_func.parameter_vars[0], "pHeightMap",
                   Type.pointer(bv.arch, self.found_data.types.height_map))

        change_func_name(self.found_data.link_map_get_tile_link_func, "jag::game::LinkMap::GetTileLink")
        change_var(self.found_data.link_map_get_tile_link_func.parameter_vars[0], "pLinkMap",
                   Type.pointer(bv.arch, self.found_data.types.link_map))
        return True

    def find_apply_hill_rotation(self, bv: BinaryView) -> bool:
        apply_hill_rotation_func = None
        for func in bv.functions:
            if not ensure_func_analyzed(func):
                continue
            parameter_vars = list(func.parameter_vars)
            if len(parameter_vars) == 5:
                total_calls = 0
                get_fine_height_calls = 0
                for insn in func.llil.instructions:
                    if isinstance(insn, LowLevelILCall):
                        resolved_func = get_called_func(bv, insn)
                        if resolved_func is None:
                            continue
                        total_calls += 1
                        if resolved_func.start == self.found_data.height_map_get_fine_height_func.start:
                            get_fine_height_calls += 1
                if get_fine_height_calls == 1 and total_calls == 1:
                    apply_hill_rotation_func = func
                    log_info('Found jag::game::HeightMap::ApplyHillRotation @ ' + hex(apply_hill_rotation_func.start))
                    break

        if apply_hill_rotation_func is None:
            return False

        change_func_name(apply_hill_rotation_func, "jag::game::HeightMap::ApplyHillRotation")
        change_var(apply_hill_rotation_func.parameter_vars[0], "pHeightMap",
                   Type.pointer(bv.arch, self.found_data.types.height_map))
        return True
