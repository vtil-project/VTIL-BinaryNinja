from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from binaryninja.log import log_error, log_info

from .parser import VTILParser
from .utils import find_block_address

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
        open("file.txt", "w").write(self.raw.file.filename)
        vtil = VTILParser.from_file(self.raw.file.filename)
        
        max_instructions = 0
        for basic_block in vtil.explored_blocks.basic_blocks:
            max_instructions += len(basic_block.instructions)

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
        symbol = Symbol(SymbolType.FunctionSymbol, entry_addr, f"_start_vip{entry_vip}")
        self.define_auto_symbol(symbol)
        
        conditionals = []
        for basic_block in vtil.explored_blocks.basic_blocks:
            vip = basic_block.entry_vip

            if entry_vip == vip: continue

            addr = find_block_address(vip, vtil)
            symbol = Symbol(SymbolType.FunctionSymbol, addr, f"vip{vip}")
            self.define_auto_symbol(symbol)
            self.add_function(addr)

            if basic_block.instructions[-1].name == "js":
                conditionals.append(basic_block.instructions[-1].operands[1].operand.imm)
                conditionals.append(basic_block.instructions[-1].operands[2].operand.imm)

        for conditional in conditionals:
            if entry_vip == conditional: continue

            addr = find_block_address(conditional, vtil)
            func = self.get_function_at(addr)
            if func != None:
                self.remove_function(func)

        self.add_entry_point(entry_addr)
        return True