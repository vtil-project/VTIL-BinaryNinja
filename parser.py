# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class VTILParser(KaitaiStruct):

    class ArchitectureIdentifier(Enum):
        amd64 = 0
        arm64 = 1
        virtual = 2
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = self._root.Header(self._io, self, self._root)
        self.entrypoint = self._root.Entrypoint(self._io, self, self._root)
        self.routine_convention = self._root.RoutineConvention(self._io, self, self._root)
        self.subroutine_convention = self._root.SubroutineConvention(self._io, self, self._root)
        self.spec_subroutine_conventions = self._root.SpecSubroutineConventions(self._io, self, self._root)
        self.explored_blocks = self._root.ExploredBlocks(self._io, self, self._root)

    class SubroutineConvention(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.volatile_registers_count = self._io.read_u4le()
            self.volatile_registers = [None] * (self.volatile_registers_count)
            for i in range(self.volatile_registers_count):
                self.volatile_registers[i] = self._root.RegisterDesc(self._io, self, self._root)

            self.param_registers_count = self._io.read_u4le()
            self.param_registers = [None] * (self.param_registers_count)
            for i in range(self.param_registers_count):
                self.param_registers[i] = self._root.RegisterDesc(self._io, self, self._root)

            self.retval_registers_count = self._io.read_u4le()
            self.retval_registers = [None] * (self.retval_registers_count)
            for i in range(self.retval_registers_count):
                self.retval_registers[i] = self._root.RegisterDesc(self._io, self, self._root)

            self.frame_register = self._root.RegisterDesc(self._io, self, self._root)
            self.shadow_space = self._io.read_u8le()
            self.purge_stack = self._io.read_u1()


    class Operand(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.sp_index = self._io.read_u4le()
            _on = self.sp_index
            if _on == 0:
                self.operand = self._root.ImmediateDesc(self._io, self, self._root)
            elif _on == 1:
                self.operand = self._root.RegisterDesc(self._io, self, self._root)


    class RegisterDesc(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flags = self._io.read_u8le()
            self.combined_id = self._io.read_u8le()
            self.bit_count = self._io.read_s4le()
            self.bit_offset = self._io.read_s4le()


    class RoutineConvention(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.volatile_registers_count = self._io.read_u4le()
            self.volatile_registers = [None] * (self.volatile_registers_count)
            for i in range(self.volatile_registers_count):
                self.volatile_registers[i] = self._root.RegisterDesc(self._io, self, self._root)

            self.param_registers_count = self._io.read_u4le()
            self.param_registers = [None] * (self.param_registers_count)
            for i in range(self.param_registers_count):
                self.param_registers[i] = self._root.RegisterDesc(self._io, self, self._root)

            self.retval_registers_count = self._io.read_u4le()
            self.retval_registers = [None] * (self.retval_registers_count)
            for i in range(self.retval_registers_count):
                self.retval_registers[i] = self._root.RegisterDesc(self._io, self, self._root)

            self.frame_register = self._root.RegisterDesc(self._io, self, self._root)
            self.shadow_space = self._io.read_u8le()
            self.purge_stack = self._io.read_u1()


    class Instruction(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.name_len = self._io.read_u4le()
            self.name = (self._io.read_bytes(self.name_len)).decode(u"UTF-8")
            self.operands_amount = self._io.read_u4le()
            self.operands = [None] * (self.operands_amount)
            for i in range(self.operands_amount):
                self.operands[i] = self._root.Operand(self._io, self, self._root)

            self.vip = self._io.read_u8le()
            self.sp_offset = self._io.read_s8le()
            self.sp_index = self._io.read_u4le()
            self.sp_reset = self._io.read_u1()


    class ImmediateDesc(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.imm = self._io.read_u8le()
            self.bitcount = self._io.read_u4le()


    class ExploredBlocks(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.basic_blocks_amount = self._io.read_u4le()
            self.basic_blocks = [None] * (self.basic_blocks_amount)
            for i in range(self.basic_blocks_amount):
                self.basic_blocks[i] = self._root.BasicBlock(self._io, self, self._root)



    class SpecSubroutineConventions(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.spec_subroutine_conventions_amount = self._io.read_u4le()
            self.spec_subroutine_convention = [None] * (self.spec_subroutine_conventions_amount)
            for i in range(self.spec_subroutine_conventions_amount):
                self.spec_subroutine_convention[i] = self._root.SubroutineConvention(self._io, self, self._root)



    class SpecSubroutineConvention(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.vip = self._io.read_u8le()
            self.volatile_registers_count = self._io.read_u4le()
            self.volatile_registers = [None] * (self.volatile_registers_count)
            for i in range(self.volatile_registers_count):
                self.volatile_registers[i] = self._root.RegisterDesc(self._io, self, self._root)

            self.param_registers_count = self._io.read_u4le()
            self.param_registers = [None] * (self.param_registers_count)
            for i in range(self.param_registers_count):
                self.param_registers[i] = self._root.RegisterDesc(self._io, self, self._root)

            self.retval_registers_count = self._io.read_u4le()
            self.retval_registers = [None] * (self.retval_registers_count)
            for i in range(self.retval_registers_count):
                self.retval_registers[i] = self._root.RegisterDesc(self._io, self, self._root)

            self.frame_register = self._root.RegisterDesc(self._io, self, self._root)
            self.shadow_space = self._io.read_u8le()
            self.purge_stack = self._io.read_u1()


    class Entrypoint(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.entry_vip = self._io.read_u8le()


    class BasicBlock(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.entry_vip = self._io.read_u8le()
            self.sp_offset = self._io.read_s8le()
            self.sp_index = self._io.read_u4le()
            self.last_temporary_index = self._io.read_u4le()
            self.instruction_amount = self._io.read_u4le()
            self.instructions = [None] * (self.instruction_amount)
            for i in range(self.instruction_amount):
                self.instructions[i] = self._root.Instruction(self._io, self, self._root)

            self.prev_vip_amount = self._io.read_u4le()
            self.prev_vip = [None] * (self.prev_vip_amount)
            for i in range(self.prev_vip_amount):
                self.prev_vip[i] = self._io.read_u8le()

            self.next_vip_amount = self._io.read_u4le()
            self.next_vip = [None] * (self.next_vip_amount)
            for i in range(self.next_vip_amount):
                self.next_vip[i] = self._io.read_u8le()



    class Header(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic1 = self._io.read_u4le()
            self.arch_id = self._root.ArchitectureIdentifier(self._io.read_u1())
            self.zero_pad = self._io.read_u1()
            self.magic2 = self._io.read_u2le()


