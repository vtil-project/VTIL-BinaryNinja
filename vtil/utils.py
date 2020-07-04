from binaryninja.log import log_info, log_error
from binaryninjaui import DockHandler

from .parser import VTILParser

from capstone import *

import tempfile
import json
import os

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

def get_physical(reg, arch):
    cs = None
    if arch == 0:
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == 1:
        cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return cs.reg_name(reg)

# from: https://github.com/vtil-project/VTIL-Core/blob/master/VTIL-Architecture/arch/register_desc.hpp#L244
def to_string(flags, bit_offset, bit_count, local_id, architecture):
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
        reg = get_physical(local_id, architecture)
        return f"{prefix}{reg}{suffix}"

    return f"{prefix}vr{local_id}{suffix}"

def find_instruction(addr, vtil):
    # Initialize the cache if not done already.
    if not hasattr(vtil, "parser_cache"):
        setattr(vtil, "parser_cache", {})

    # If cached already, return the reslt.
    if addr in vtil.parser_cache:
        return vtil.parser_cache[addr]
    it = addr

    for basic_block in vtil.explored_blocks.basic_blocks:
        instructions = basic_block.instructions
        if it - len(instructions) > 0:
            it -= len(instructions)
            continue

        for instruction in instructions:
            if it == 0:
                code = ""
                code += instruction.name + " "

                for operand in instruction.operands:
                    operand = operand.operand

                    if isinstance(operand, VTILParser.RegisterDesc):
                        architecture = int(bin(operand.combined_id)[2:].zfill(64)[:56], 2) # lol?
                        local_id = int(bin(operand.combined_id)[2:].zfill(64)[56:], 2) # lol?
                        code += to_string(operand.flags, operand.bit_offset, operand.bit_count, local_id, architecture)
                        code += " "
                    else:
                        code += hex(operand.imm) + " "
                
                res = (basic_block.next_vip, instruction.sp_index, instruction.sp_reset, instruction.sp_offset, code.strip())
                vtil.parser_cache[addr] = res
                return res
            it -= 1
def find_block_address(vip, vtil):
    addr = 0

    for basic_block in vtil.explored_blocks.basic_blocks:
        if basic_block.entry_vip == vip: break

        addr += len(basic_block.instructions)
    
    return addr