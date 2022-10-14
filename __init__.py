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
from binaryninja import *

from BinjaNxt.Nxt import Nxt
#from Nxt import Nxt

def run(bv: BinaryView):
    nxt = Nxt(bv)
    nxt.start()


def __run(bv: BinaryView, addr):
    run(bv)


PluginCommand.register_for_address("BinjaNxt Refactor", "Refactors the Runescape Nxt client", __run)
