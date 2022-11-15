from BinjaNxt.JagTypes import *
from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandlerInfo import *
from binaryninja import *


class ClientWatch:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        if not self.find_change_main_state(bv):
            log_warn("Unable to locate jag::ClientWatch::ChangeMainState(jag::MainState, jag::MainState)")
        return True

    def find_change_main_state(self, bv: BinaryView) -> bool:
        return False
