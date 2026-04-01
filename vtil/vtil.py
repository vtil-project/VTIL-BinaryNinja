from binaryninja.log import log_info, log_error
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType
from binaryninja.filemetadata import FileMetadata
from binaryninja.lowlevelil import LowLevelILLabel
from .parser import VTILParser
from .utils import to_string, find_instruction, find_block_address, decode_instruction

registered_vtil_views = []

VTIL_CANONICAL_MNEMONICS = {
    "mov", "movsx", "str", "ldd", "ifs", "neg", "add", "sub", "mul", "imul",
    "mulhi", "imulhi", "div", "idiv", "rem", "irem", "popcnt", "bsf", "bsr",
    "not", "shr", "shl", "xor", "or", "and", "ror", "rol",
    "tg", "tge", "te", "tne", "tle", "tl", "tug", "tuge", "tule", "tul",
    "js", "jmp", "vexit", "vxcall", "nop", "sfence", "lfence", "vemit", "vpinr", "vpinw", "vpinrm", "vpinwm",
}

def register_vtil_view(base_addr, size, vtil_struct):
    registered_vtil_views.append((base_addr, size, vtil_struct))

def resolve_vtil_for_address(addr):
    for base_addr, size, vtil_struct in reversed(registered_vtil_views):
        if base_addr <= addr < (base_addr + size):
            return base_addr, vtil_struct
    return None, None

def make_goto_token(vip, base_addr, vtil_struct):
    target_addr = base_addr + find_block_address(vip, vtil_struct)
    return InstructionTextToken(
        InstructionTextTokenType.PossibleAddressToken,
        f"vip_{vip:x}",
        value=target_addr,
        size=8,
    )


def normalize_mnemonic(mnemonic):
    aliases = {
        "bnot": "not",
        "bshr": "shr",
        "bshl": "shl",
        "bxor": "xor",
        "bor": "or",
        "band": "and",
        "bror": "ror",
        "brol": "rol",
    }
    if mnemonic in aliases:
        return aliases[mnemonic]
    if mnemonic in VTIL_CANONICAL_MNEMONICS:
        return mnemonic

    # handle serialized forms with access-size suffixes (e.g. strd, movq).
    if len(mnemonic) > 1 and mnemonic[-1] in "bwdq":
        candidate = mnemonic[:-1]
        if candidate in VTIL_CANONICAL_MNEMONICS:
            return candidate
    return mnemonic


def _build_vtil_registers():
    regs = {
        "$sp": RegisterInfo("$sp", 8),
        "$flags": RegisterInfo("$flags", 8),
        "base": RegisterInfo("base", 8),
    }

    # common x64 physical registers encountered in vtil dumps
    for reg_name in [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "al", "bl", "cl", "dl",
    ]:
        regs[reg_name] = RegisterInfo(reg_name, 8)

    # virtual/local/internal vtil registers
    for i in range(0, 2048):
        regs[f"vr{i}"] = RegisterInfo(f"vr{i}", 8)
        regs[f"t{i}"] = RegisterInfo(f"t{i}", 8)
        regs[f"sr{i}"] = RegisterInfo(f"sr{i}", 8)
        regs[f"tmp{i}"] = RegisterInfo(f"tmp{i}", 8)

    return regs

class VTIL(Architecture):
    name = "VTIL"
    max_instr_length = 1
    stack_pointer = "$sp"

    regs = _build_vtil_registers()

    instructions = {
        "str": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "str"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "["),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, "+"),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, "]"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
            ],
            "operands": [3, 5, 8]
        },
        "ldd": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "ldd"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, ", ["),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, "+"),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, "]"),
            ],
            "operands": [2, 4, 6]
        },
        "te": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "te"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " := ("),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " == "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, ")")
            ],
            "operands": [2, 4, 6]
        },
        "tne": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "tne"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " := ("),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " != "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, ")")
            ],
            "operands": [2, 4, 6]
        },
        "tg": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "tg"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " := ("),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " > "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, ")")
            ],
            "operands": [2, 4, 6]
        },
        "tge": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "tge"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " := ("),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " >= "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, ")")
            ],
            "operands": [2, 4, 6]
        },
        "tl": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "tl"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " := ("),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " < "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, ")")
            ],
            "operands": [2, 4, 6]
        },
        "tle": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "tle"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " := ("),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " <= "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, ")")
            ],
            "operands": [2, 4, 6]
        },
        "tug": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "tug"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " := ("),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " u> "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, ")")
            ],
            "operands": [2, 4, 6]
        },
        "tuge": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "tuge"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " := ("),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " u>= "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, ")")
            ],
            "operands": [2, 4, 6]
        },
        "tul": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "tul"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " := ("),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " u< "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, ")")
            ],
            "operands": [2, 4, 6]
        },
        "tule": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "tule"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " := ("),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " u<= "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, ")")
            ],
            "operands": [2, 4, 6]
        },
        "ifs": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "ifs"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " := "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " ? "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " : "),
                InstructionTextToken(InstructionTextTokenType.IntegerToken, "0")
            ],
            "operands": [2, 4, 6]
        },
        "js": {
            "tokens": [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "js"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " ? "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, " : "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, "UNKNOWN")
            ],
            "operands": [2, 4, 6]
        }
    }

    def get_instruction_info(self, data, addr):
        result = InstructionInfo()
        result.length = 1

        base_addr, vtil_struct = resolve_vtil_for_address(addr)
        if vtil_struct is None:
            return result

        relative_addr = addr - base_addr

        next_vip, _, _, _, code = find_instruction(relative_addr, vtil_struct)
        block_vips = {bb.entry_vip for bb in vtil_struct.explored_blocks.basic_blocks}

        def _resolve_target(vip):
            if vip not in block_vips:
                return None
            return base_addr + find_block_address(vip, vtil_struct)

        if code != None and normalize_mnemonic(code.split(" ", 1)[0]) == "js":
            if len(next_vip) >= 2:
                true_target = _resolve_target(next_vip[0])
                false_target = _resolve_target(next_vip[1])
                if true_target is not None:
                    result.add_branch(BranchType.TrueBranch, true_target)
                if false_target is not None:
                    result.add_branch(BranchType.FalseBranch, false_target)
        elif code != None and normalize_mnemonic(code.split(" ", 1)[0]) == "vxcall":
            if len(next_vip) >= 1:
                target = _resolve_target(next_vip[0])
                if target is not None:
                    result.add_branch(BranchType.UnconditionalBranch, target)
        elif code != None and normalize_mnemonic(code.split(" ", 1)[0]) == "jmp":
            if len(next_vip) == 1:
                target = _resolve_target(next_vip[0])
                if target is not None:
                    result.add_branch(BranchType.UnconditionalBranch, target)
            else:
                resolved_targets = []
                for vip in next_vip:
                    target = _resolve_target(vip)
                    if target is not None:
                        resolved_targets.append(target)

                if len(resolved_targets) == 0:
                    result.add_branch(BranchType.IndirectBranch)
                else:
                    for target in resolved_targets:
                        result.add_branch(BranchType.UnconditionalBranch, target)
        elif code != None and normalize_mnemonic(code.split(" ", 1)[0]) == "vexit":
            result.add_branch(BranchType.FunctionReturn)

        return result

    def get_instruction_text(self, data, addr):
        tokens = []

        base_addr, vtil_struct = resolve_vtil_for_address(addr)
        if vtil_struct is None:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "UNMAPPED"))
            return tokens, 1

        relative_addr = addr - base_addr
        next_vip, sp_index, sp_reset, sp_offset, code = find_instruction(relative_addr, vtil_struct)
        if code == None:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "ERROR"))
            return tokens, 1

        if sp_index > 0:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "["))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"{int(sp_index):>2}", value=sp_index, size=64))
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "] "))
        else:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "     "))

        prefix = "-"
        if sp_offset >= 0: prefix = "+"
        sp_offset = abs(sp_offset)

        if sp_reset > 0:
            txt = f">{prefix}{hex(sp_offset)}"
            txt = f"{txt:<6}"
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, txt))
        else:
            txt = f" {prefix}{hex(sp_offset)}"
            txt = f"{txt:<6}"
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, txt))
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " "))

        
        if " " in code:
            instr, operands = code.split(" ", 1)
            instr = normalize_mnemonic(instr)

            if " " in operands:
                operands = operands.split(" ")
            else:
                operands = [operands]

            if instr in self.instructions.keys():
                token_set = list(self.instructions[instr]["tokens"])

                for index in self.instructions[instr]["operands"]:
                    operand = operands.pop(0)

                    if "0x" in operand:
                        if instr == "js":
                            token_set[index] = make_goto_token(int(operand, 16), base_addr, vtil_struct)
                        elif instr == "jmp":
                            token_set[index] = make_goto_token(next_vip[0], base_addr, vtil_struct)
                        else:
                            token_set[index] = InstructionTextToken(InstructionTextTokenType.IntegerToken, operand, value=int(operand, 16), size=64)
                    else:
                        token_set[index] = InstructionTextToken(InstructionTextTokenType.RegisterToken, operand)
                
                tokens.extend(token_set)
            else:
                # fallback
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, instr))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                
                for operand in operands:
                    if "0x" in operand:
                        if instr == "jmp":
                            tokens.append(make_goto_token(next_vip[0], base_addr, vtil_struct))
                        elif instr == "js":
                            tokens.append(make_goto_token(int(operand, 16), base_addr, vtil_struct))
                        else:
                            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, operand, value=int(operand, 16), size=64))
                    else:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, operand))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "))
                
                tokens.pop()
        else:
            tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, code))
        
        return tokens, 1
        
    
    def get_instruction_low_level_il(self, data, addr, il):
        base_addr, vtil_struct = resolve_vtil_for_address(addr)
        if vtil_struct is None:
            il.append(il.unimplemented())
            return 1

        relative_addr = addr - base_addr
        decoded = decode_instruction(relative_addr, vtil_struct)
        if decoded is None:
            il.append(il.unimplemented())
            return 1

        next_vip = decoded["next_vip"]
        code = decoded["code"]
        if code is None:
            il.append(il.unimplemented())
            return 1

        parts = code.split(" ")
        instr = normalize_mnemonic(parts[0])
        operands = parts[1:] if len(parts) > 1 else []
        decoded_operands = decoded.get("operands", [])

        def _normalize_reg(value):
            out = value
            while out.startswith("?"):
                out = out[1:]
            while out.startswith("&&"):
                out = out[2:]
            if "@" in out:
                out = out.split("@", 1)[0]
            if ":" in out:
                out = out.split(":", 1)[0]
            return out

        def _is_hex(value):
            return value.startswith("0x")

        def _const(value):
            return il.const(8, int(value, 16))

        def _reg_name(value):
            return _normalize_reg(value)

        def _reg(value):
            # vtil register space is dynamic only lift real BN registers
            reg_name = _reg_name(value)
            if reg_name in self.regs:
                return il.reg(8, reg_name)
            return None

        def _operand(value):
            if _is_hex(value):
                return _const(value)
            if _reg_name(value).upper() == "UD":
                return il.const(8, 0)
            return _reg(value)

        def _op_size(op):
            bits = int(op.get("bit_count", 64))
            return max(1, min(8, (bits + 7) // 8))

        def _op_reg_name(op):
            return _normalize_reg(op.get("text", ""))

        def _op_expr(op, expected_size=None):
            if op.get("kind") == "imm":
                size = expected_size if expected_size is not None else _op_size(op)
                return il.const(size, int(op.get("value", 0)))

            reg_name = _op_reg_name(op)
            if reg_name.upper() == "UD":
                size = expected_size if expected_size is not None else _op_size(op)
                return il.const(size, 0)
            if reg_name not in self.regs:
                return None
            size = expected_size if expected_size is not None else _op_size(op)
            return il.reg(size, reg_name)

        def _set_dst_from_op(dst_op, value_expr):
            dst_name = _op_reg_name(dst_op)
            dst_size = _op_size(dst_op)
            if dst_name not in self.regs:
                return False
            il.append(il.set_reg(dst_size, dst_name, value_expr))
            return True

        block_vips = {bb.entry_vip for bb in vtil_struct.explored_blocks.basic_blocks}

        def _resolve_target(vip):
            if vip not in block_vips:
                return None
            return base_addr + find_block_address(vip, vtil_struct)

        def _emit_branch_to_addr(target_addr):
            label = il.get_label_for_address(self, target_addr)
            if label is None and hasattr(il, "add_label_for_address"):
                try:
                    il.add_label_for_address(self, target_addr)
                    label = il.get_label_for_address(self, target_addr)
                except Exception:
                    label = None
            if label is not None:
                il.append(il.goto(label))
            else:
                il.append(il.jump(il.const_pointer(8, target_addr)))

        if instr == "vexit":
            il.append(il.ret(il.const_pointer(8, 0)))
            return 1

        if instr in {"nop", "sfence", "lfence", "vemit", "vpinr", "vpinw", "vpinrm", "vpinwm"}:
            il.append(il.nop())
            return 1

        if instr == "jmp":
            if len(next_vip) == 1:
                target = _resolve_target(next_vip[0])
                if target is not None:
                    _emit_branch_to_addr(target)
                else:
                    target_expr = _operand(operands[0]) if len(operands) > 0 else None
                    if target_expr is None:
                        il.append(il.unimplemented())
                    else:
                        il.append(il.jump(target_expr))
            else:
                target_expr = _operand(operands[0]) if len(operands) > 0 else None
                resolved = []
                for vip in next_vip:
                    target = _resolve_target(vip)
                    if target is not None:
                        resolved.append((vip, target))

                # build an explicit dispatch chain so LLIL/MLIL/HLIL can form CFG edges, hopefully
                if target_expr is not None and len(resolved) > 0:
                    for index, (vip, target_addr) in enumerate(resolved):
                        hit = LowLevelILLabel()
                        try_addr = LowLevelILLabel()
                        nxt = LowLevelILLabel()

                        # some traces carry vip values while others carry mapped linear addresses
                        il.append(il.if_expr(il.compare_equal(8, target_expr, il.const(8, vip)), hit, try_addr))
                        il.mark_label(try_addr)
                        il.append(il.if_expr(il.compare_equal(8, target_expr, il.const_pointer(8, target_addr)), hit, nxt))

                        il.mark_label(hit)
                        _emit_branch_to_addr(target_addr)
                        if index == (len(resolved) - 1):
                            il.mark_label(nxt)
                            _emit_branch_to_addr(resolved[0][1])
                        else:
                            il.mark_label(nxt)
                elif target_expr is not None:
                    il.append(il.jump(target_expr))
                else:
                    il.append(il.unimplemented())
            return 1

        if instr == "vxcall" and len(next_vip) == 1:
            target = _resolve_target(next_vip[0])
            if target is not None:
                _emit_branch_to_addr(target)
                return 1
            il.append(il.unimplemented())
            return 1

        if instr == "js" and len(next_vip) == 2:
            cond = _operand(operands[0]) if len(operands) > 0 else None
            if cond is None:
                il.append(il.unimplemented())
                return 1
            t = LowLevelILLabel()
            f = LowLevelILLabel()
            target_t = _resolve_target(next_vip[0])
            target_f = _resolve_target(next_vip[1])
            if target_t is None or target_f is None:
                il.append(il.unimplemented())
                return 1
            il.append(il.if_expr(cond, t, f))
            il.mark_label(t)
            _emit_branch_to_addr(target_t)
            il.mark_label(f)
            _emit_branch_to_addr(target_f)
            return 1

        if instr == "ldd" and len(operands) >= 3:
            dst_name = _reg_name(operands[0])
            dst = _reg(operands[0])
            base = _reg(operands[1])
            off = _operand(operands[2])
            if dst is None or base is None or off is None:
                il.append(il.unimplemented())
                return 1
            ptr = il.add(8, base, off)
            il.append(il.set_reg(8, dst_name, il.load(8, ptr)))
            return 1

        if instr == "str" and len(operands) >= 3:
            base = _reg(operands[0])
            off = _operand(operands[1])
            src = _operand(operands[2])
            if base is None or off is None or src is None:
                il.append(il.unimplemented())
                return 1
            ptr = il.add(8, base, off)
            il.append(il.store(8, ptr, src))
            return 1

        cmp_ops = {
            "te": il.compare_equal,
            "tne": il.compare_not_equal,
            "tg": il.compare_signed_greater_than,
            "tge": il.compare_signed_greater_equal,
            "tl": il.compare_signed_less_than,
            "tle": il.compare_signed_less_equal,
            "tug": il.compare_unsigned_greater_than,
            "tuge": il.compare_unsigned_greater_equal,
            "tul": il.compare_unsigned_less_than,
            "tule": il.compare_unsigned_less_equal,
        }

        binary_inplace_ops = {
            "add": il.add,
            "sub": il.sub,
            "mul": il.mult,
            "imul": il.mult,
            "and": il.and_expr,
            "or": il.or_expr,
            "xor": il.xor_expr,
            "shl": il.shift_left,
            "shr": il.logical_shift_right,
            "rol": il.rotate_left,
            "ror": il.rotate_right,
        }

        if instr == "mov" and len(operands) >= 2:
            if len(decoded_operands) >= 2:
                dst = decoded_operands[0]
                dst_name = _op_reg_name(dst)
                dst_size = _op_size(dst)
                src_expr = _op_expr(decoded_operands[1], dst_size)
                if dst_name not in self.regs or src_expr is None:
                    il.append(il.unimplemented())
                    return 1
                il.append(il.set_reg(dst_size, dst_name, src_expr))
                return 1

            dst_name = _reg_name(operands[0])
            src = _operand(operands[1])
            if dst_name not in self.regs or src is None:
                il.append(il.unimplemented())
                return 1
            il.append(il.set_reg(8, dst_name, src))
            return 1

        if instr == "movsx" and len(operands) >= 2:
            if len(decoded_operands) >= 2:
                dst = decoded_operands[0]
                src = decoded_operands[1]
                dst_name = _op_reg_name(dst)
                dst_size = _op_size(dst)
                src_size = _op_size(src)
                src_expr = _op_expr(src, src_size)
                if dst_name not in self.regs or src_expr is None:
                    il.append(il.unimplemented())
                    return 1
                il.append(il.set_reg(dst_size, dst_name, il.sign_extend(dst_size, src_expr)))
                return 1

            dst_name = _reg_name(operands[0])
            src = _operand(operands[1])
            if dst_name not in self.regs or src is None:
                il.append(il.unimplemented())
                return 1
            il.append(il.set_reg(8, dst_name, il.sign_extend(8, src)))
            return 1

        if instr == "neg" and len(operands) >= 1:
            dst_name = _reg_name(operands[0])
            src = _reg(operands[0])
            if dst_name not in self.regs or src is None:
                il.append(il.unimplemented())
                return 1
            il.append(il.set_reg(8, dst_name, il.neg_expr(8, src)))
            return 1

        if instr == "not" and len(operands) >= 1:
            dst_name = _reg_name(operands[0])
            src = _reg(operands[0])
            if dst_name not in self.regs or src is None:
                il.append(il.unimplemented())
                return 1
            il.append(il.set_reg(8, dst_name, il.not_expr(8, src)))
            return 1

        if instr in binary_inplace_ops and len(operands) >= 2:
            dst_name = _reg_name(operands[0])
            lhs = _reg(operands[0])
            rhs = _operand(operands[1])
            if dst_name not in self.regs or lhs is None or rhs is None:
                il.append(il.unimplemented())
                return 1
            il.append(il.set_reg(8, dst_name, binary_inplace_ops[instr](8, lhs, rhs)))
            return 1

        if instr in {"mulhi", "imulhi"}:
            if len(decoded_operands) >= 2:
                dst = decoded_operands[0]
                lhs = decoded_operands[0] if len(decoded_operands) == 2 else decoded_operands[1]
                rhs = decoded_operands[1] if len(decoded_operands) == 2 else decoded_operands[2]

                dst_size = _op_size(dst)
                lhs_expr = _op_expr(lhs, dst_size)
                rhs_expr = _op_expr(rhs, dst_size)
                if lhs_expr is None or rhs_expr is None:
                    il.append(il.unimplemented())
                    return 1

                if instr == "mulhi":
                    full = il.mult_double_prec_unsigned(dst_size, lhs_expr, rhs_expr)
                else:
                    full = il.mult_double_prec_signed(dst_size, lhs_expr, rhs_expr)

                shifted = il.logical_shift_right(dst_size * 2, full, il.const(1, dst_size * 8))
                hi = il.low_part(dst_size, shifted)
                if not _set_dst_from_op(dst, hi):
                    il.append(il.unimplemented())
                return 1

            il.append(il.unimplemented())
            return 1

        if instr in {"div", "idiv", "rem", "irem"}:
            if len(decoded_operands) >= 2:
                dst = decoded_operands[0]
                dst_size = _op_size(dst)
                rhs = decoded_operands[1] if len(decoded_operands) == 2 else decoded_operands[2]
                rhs_expr = _op_expr(rhs, dst_size)
                if rhs_expr is None:
                    il.append(il.unimplemented())
                    return 1

                if len(decoded_operands) == 2:
                    lhs = decoded_operands[0]
                    lhs_expr = _op_expr(lhs, dst_size)
                    if lhs_expr is None:
                        il.append(il.unimplemented())
                        return 1

                    if instr == "div":
                        result = il.div_unsigned(dst_size, lhs_expr, rhs_expr)
                    elif instr == "idiv":
                        result = il.div_signed(dst_size, lhs_expr, rhs_expr)
                    elif instr == "rem":
                        result = il.mod_unsigned(dst_size, lhs_expr, rhs_expr)
                    else:
                        result = il.mod_signed(dst_size, lhs_expr, rhs_expr)
                else:
                    high = decoded_operands[1]
                    low_expr = _op_expr(decoded_operands[0], dst_size)
                    high_expr = _op_expr(high, dst_size)
                    if low_expr is None or high_expr is None:
                        il.append(il.unimplemented())
                        return 1

                    wide_size = dst_size * 2
                    high_wide = il.zero_extend(wide_size, high_expr)
                    low_wide = il.zero_extend(wide_size, low_expr)
                    high_shifted = il.shift_left(wide_size, high_wide, il.const(1, dst_size * 8))
                    dividend = il.or_expr(wide_size, high_shifted, low_wide)

                    if instr == "div":
                        result = il.div_double_prec_unsigned(dst_size, dividend, rhs_expr)
                    elif instr == "idiv":
                        result = il.div_double_prec_signed(dst_size, dividend, rhs_expr)
                    elif instr == "rem":
                        result = il.mod_double_prec_unsigned(dst_size, dividend, rhs_expr)
                    else:
                        result = il.mod_double_prec_signed(dst_size, dividend, rhs_expr)

                if not _set_dst_from_op(dst, result):
                    il.append(il.unimplemented())
                return 1

            il.append(il.unimplemented())
            return 1

        if instr in {"popcnt", "bsf", "bsr"}:
            if len(decoded_operands) == 0:
                il.append(il.unimplemented())
                return 1

            dst = decoded_operands[0]
            dst_size = _op_size(dst)
            src = decoded_operands[0] if len(decoded_operands) == 1 else decoded_operands[1]
            src_expr = _op_expr(src, dst_size)
            if src_expr is None:
                il.append(il.unimplemented())
                return 1

            bit_count = dst_size * 8
            if instr == "popcnt":
                acc = il.const(dst_size, 0)
                for i in range(bit_count):
                    bit = il.test_bit(dst_size, src_expr, il.const(1, i))
                    acc = il.add(dst_size, acc, il.bool_to_int(dst_size, bit))
                if not _set_dst_from_op(dst, acc):
                    il.append(il.unimplemented())
                return 1

            # vtil defines BSF/BSR as returning one based bit index, or zero if src is zero
            result = il.const(dst_size, 0)
            indices = range(bit_count) if instr == "bsf" else range(bit_count - 1, -1, -1)
            for i in indices:
                bit = il.bool_to_int(dst_size, il.test_bit(dst_size, src_expr, il.const(1, i)))
                still_zero = il.bool_to_int(
                    dst_size,
                    il.compare_equal(dst_size, result, il.const(dst_size, 0)),
                )
                take = il.and_expr(dst_size, bit, still_zero)
                result = il.add(dst_size, result, il.mult(dst_size, take, il.const(dst_size, i + 1)))

            if not _set_dst_from_op(dst, result):
                il.append(il.unimplemented())
            return 1

        if instr in cmp_ops and len(operands) >= 3:
            dst = _reg_name(operands[0])
            lhs = _operand(operands[1])
            rhs = _operand(operands[2])
            if dst not in self.regs or lhs is None or rhs is None:
                il.append(il.unimplemented())
                return 1
            il.append(il.set_reg(8, dst, cmp_ops[instr](8, lhs, rhs)))
            return 1

        if instr == "ifs" and len(operands) >= 3:
            dst = _reg_name(operands[0])
            cond = _operand(operands[1])
            val = _operand(operands[2])
            if dst not in self.regs or cond is None or val is None:
                il.append(il.unimplemented())
                return 1
            t = LowLevelILLabel()
            f = LowLevelILLabel()
            done = LowLevelILLabel()
            il.append(il.if_expr(cond, t, f))
            il.mark_label(t)
            il.append(il.set_reg(8, dst, val))
            il.append(il.goto(done))
            il.mark_label(f)
            il.append(il.set_reg(8, dst, il.const(8, 0)))
            il.mark_label(done)
            return 1

        il.append(il.unimplemented())
        return 1
