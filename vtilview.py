from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from binaryninja.log import log_error, log_info

from .parser import VTILParser

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
        vip = vtil.entrypoint.entry_vip
        self.add_entry_point(vip)
        symbol = Symbol(SymbolType.FunctionSymbol, vip, f"_vip{vip}")
        self.define_auto_symbol(symbol)
        return True