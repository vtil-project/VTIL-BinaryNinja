from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.platform import Platform
from binaryninja.types import Symbol
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from binaryninja.log import log_error, log_info

from .parser import VTILParser
from .vtil import VTIL, register_vtil_view
from .utils import find_block_address, find_instruction

import tempfile
import json
import os

class VTILView(BinaryView):
    name = "VTIL"
    long_name = "VTIL"
    vtil = None
    _next_base_addr = 0x100000
    
    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture["VTIL"].standalone_platform
        self.vtil = VTILParser.from_file(data.file.filename)
        self.base_addr = VTILView._next_base_addr
        VTILView._next_base_addr += 0x1000000

    @classmethod
    def is_valid_for_data(self, data):
        return data[0:4] == b'VTIL'
    
    def init(self):
        max_instructions = 0
        for basic_block in self.vtil.explored_blocks.basic_blocks:
            max_instructions += len(basic_block.instructions)

        # Fill the cache
        for i in range(0, max_instructions):
            find_instruction(i, self.vtil)

        register_vtil_view(self.base_addr, max_instructions, self.vtil)

        self.add_auto_segment(
            self.base_addr, max_instructions, 0, max_instructions,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable
        )
        self.add_auto_section(
            ".text", self.base_addr, max_instructions,
            SectionSemantics.ReadOnlyCodeSectionSemantics
        )

        entry_vip = self.vtil.entrypoint.entry_vip
        entry_addr = self.base_addr + find_block_address(entry_vip, self.vtil)
        symbol = Symbol(SymbolType.FunctionSymbol, entry_addr, f"_vip_{hex(entry_vip)[2:]}")
        self.define_auto_symbol(symbol)

        for basic_block in self.vtil.explored_blocks.basic_blocks:
            vip = basic_block.entry_vip
            addr = self.base_addr + find_block_address(vip, self.vtil)

            # append a comment to help with indirect jumps :=)
            comment = ""
            branch_ins = basic_block.instructions[-1]
            if branch_ins.name == "jmp":
                if isinstance(branch_ins.operands[0].operand, VTILParser.RegisterDesc):
                    comment += "Indirect => { " + ', '.join('vip_{:x}'.format(trgt) for trgt in basic_block.next_vip) + " }"

            if basic_block.sp_offset != branch_ins.sp_offset:
                if comment != "": comment += " | "
                comment += f"SP Delta: {hex(basic_block.sp_offset)}"

            if comment != "":
                self.set_comment_at(addr + len(basic_block.instructions) - 1, comment)

            if entry_vip == vip: continue

            label_type = SymbolType.LocalLabelSymbol if hasattr(SymbolType, "LocalLabelSymbol") else SymbolType.DataSymbol
            symbol = Symbol(label_type, addr, f"vip_{hex(vip)[2:]}")
            self.define_auto_symbol(symbol)
            self.set_comment_at(addr, f"vip_{hex(vip)[2:]}:")


        self.add_entry_point(entry_addr)

        return True
