from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from binaryninja.log import log_error, log_info

from .parser import VTILParser
from .utils import find_block_address, find_instruction, get_filename

import tempfile
import json
import os

class VTILView(BinaryView):
    name = "VTIL"
    long_name = "VTIL"
    
    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture["VTIL"].standalone_platform
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        # TODO: Check headers
        return True
    
    def init(self):
        tmp = tempfile.gettempdir()
        tmp = os.path.join(tmp, "vtil_binja.txt")
        open(tmp, "w").write(self.raw.file.filename)
        vtil = VTILParser.from_file(self.raw.file.filename)
        
        max_instructions = 0
        for basic_block in vtil.explored_blocks.basic_blocks:
            max_instructions += len(basic_block.instructions)
        cache = {}
        for i in range(0, max_instructions):
            next_vip, sp_index, sp_reset, sp_offset, code = find_instruction(i, vtil, cached=False) # cache
            cache[i] = {
                "next_vip": next_vip,
                "sp_index": sp_index,
                "sp_reset": sp_reset,
                "sp_offset": sp_offset,
                "code": code
            }
        tmp = tempfile.gettempdir()
        tmp = os.path.join(tmp, "vtil_binja.json")
        json.dump(cache, open(tmp, "w"))

        self.add_auto_segment(
            0, max_instructions, 0, max_instructions,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable
        )
        self.add_auto_section(
            ".text", 0, max_instructions,
            SectionSemantics.ReadOnlyCodeSectionSemantics
        )

        entry_vip = vtil.entrypoint.entry_vip
        entry_addr = find_block_address(entry_vip, vtil)
        symbol = Symbol(SymbolType.FunctionSymbol, entry_addr, f"_vip_{hex(entry_vip)[2:]}")
        self.define_auto_symbol(symbol)

        #conditionals = []
        for basic_block in vtil.explored_blocks.basic_blocks:
            vip = basic_block.entry_vip

            if entry_vip == vip: continue

            addr = find_block_address(vip, vtil)
            symbol = Symbol(SymbolType.FunctionSymbol, addr, f"vip_{hex(vip)[2:]}")
            self.define_auto_symbol(symbol)
            self.set_comment_at(addr, f"vip_{hex(vip)[2:]}:")

            #self.add_function(addr)

        """
            if basic_block.instructions[-1].name == "js" or basic_block.instructions[-1].name == "jmp":
                conditionals.extend(basic_block.next_vip)

        for conditional in conditionals:
            if entry_vip == conditional: continue

            addr = find_block_address(conditional, vtil)
            func = self.get_function_at(addr)
            if func != None:
                self.remove_function(func)
        """

        self.add_entry_point(entry_addr)

        return True