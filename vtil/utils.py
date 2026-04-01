from .parser import VTILParser

from capstone import *

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


def decode_register_desc(operand):
    architecture = int(bin(operand.combined_id)[2:].zfill(64)[:56], 2)
    local_id = int(bin(operand.combined_id)[2:].zfill(64)[56:], 2)
    text = to_string(operand.flags, operand.bit_offset, operand.bit_count, local_id, architecture)
    return {
        "kind": "reg",
        "text": text,
        "flags": operand.flags,
        "bit_offset": operand.bit_offset,
        "bit_count": operand.bit_count,
        "local_id": local_id,
        "architecture": architecture,
    }


def decode_immediate_desc(operand):
    return {
        "kind": "imm",
        "text": hex(operand.imm),
        "value": operand.imm,
        "bit_count": operand.bitcount,
    }


def decode_instruction(addr, vtil):
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
                decoded_operands = []
                rendered = []

                for op in instruction.operands:
                    operand = op.operand
                    if isinstance(operand, VTILParser.RegisterDesc):
                        decoded = decode_register_desc(operand)
                    else:
                        decoded = decode_immediate_desc(operand)
                    decoded_operands.append(decoded)
                    rendered.append(decoded["text"])

                rendered_code = instruction.name
                if rendered:
                    rendered_code += " " + " ".join(rendered)

                res = {
                    "next_vip": basic_block.next_vip,
                    "sp_index": instruction.sp_index,
                    "sp_reset": instruction.sp_reset,
                    "sp_offset": instruction.sp_offset,
                    "mnemonic": instruction.name,
                    "operands": decoded_operands,
                    "code": rendered_code,
                }
                vtil.parser_cache[addr] = res
                return res
            it -= 1

def find_instruction(addr, vtil):
    decoded = decode_instruction(addr, vtil)
    if decoded is None:
        return None, 0, 0, 0, None
    return (
        decoded["next_vip"],
        decoded["sp_index"],
        decoded["sp_reset"],
        decoded["sp_offset"],
        decoded["code"],
    )

def find_block_address(vip, vtil):
    addr = 0

    for basic_block in vtil.explored_blocks.basic_blocks:
        if basic_block.entry_vip == vip: break

        addr += len(basic_block.instructions)
    
    return addr