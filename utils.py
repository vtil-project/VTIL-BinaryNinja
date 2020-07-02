from binaryninjaui import DockHandler

from .parser import VTILParser

# from: https://github.com/vtil-project/VTIL-Core/blob/master/VTIL-Architecture/arch/register_desc.hpp#L40
register_virtual        = 0
register_physical       = 1 << 0
register_local          = 1 << 1
register_flags          = 1 << 2
register_stack_pointer  = 1 << 3
register_image_base     = 1 << 4
register_volatile       = 1 << 5
register_readonly       = 1 << 6
register_undefined      = 1 << 7
register_internal       = register_virtual | (1 << 8)
register_special        = register_flags | register_stack_pointer | register_image_base | register_undefined

# from: https://github.com/vtil-project/VTIL-Core/blob/master/VTIL-Architecture/arch/register_desc.hpp#L223
def is_internal(flags):
    return flags & register_internal == register_internal

# from: https://github.com/vtil-project/VTIL-Core/blob/master/VTIL-Architecture/arch/register_desc.hpp#L244
def to_string(flags, bit_offset, bit_count, local_id):
    prefix = ""
    suffix = ""

    if flags & register_volatile: prefix = "?"
    if flags & register_readonly: prefix += "&&"

    if bit_offset != 0: suffix = f"@{bit_offset}"
    if bit_count != 64: suffix += f":{bit_count}"

    if is_internal(flags):             return f"{prefix}sr{local_id}{suffix}"
    if flags & register_undefined:     return f"{prefix}UD{suffix}"
    if flags & register_flags:         return f"{prefix}$flags{suffix}"
    if flags & register_stack_pointer: return f"{prefix}$sp{suffix}"
    if flags & register_image_base:    return f"{prefix}base{suffix}"
    if flags & register_local:         return f"{prefix}t{local_id}{suffix}"

    if flags & register_physical:
            return f"{prefix}PHYS_REG_UNKN{suffix}"

    return f"{prefix}vr{local_id}{suffix}"

def find_instruction(addr, vtil):
    for basic_block in vtil.explored_blocks.basic_blocks:
        instructions = basic_block.instructions

        for instruction in instructions:
            code = ""
            code += instruction.name + " "

            for operand in instruction.operands:
                operand = operand.operand

                if isinstance(operand, VTILParser.RegisterDesc):
                    code += to_string(operand.flags, operand.bit_offset, operand.bit_count, operand.combined_id)
                    code += " "
                else:
                    code += hex(operand.imm) + " "

            if addr == 0:
                return code.strip()
            
            addr -= 1

def get_filename():
    """
    dock = DockHandler.getActiveDockHandler()
    frame = dock.getViewFrame()
    ctx = frame.getFileContext()
    return ctx.getFilename()
    """

    return open("file.txt", "r").read()

def find_block_address(vip, vtil):
    addr = 0

    for basic_block in vtil.explored_blocks.basic_blocks:
        if basic_block.entry_vip == vip: break

        addr += len(basic_block.instructions)
    
    return addr