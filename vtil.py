from binaryninja.log import log_info, log_error
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType
from binaryninja.filemetadata import FileMetadata

from .parser import VTILParser
from .utils import to_string, find_instruction, get_filename, find_block_address

class VTIL(Architecture):
    name = "VTIL"
    max_length = 1
    stack_pointer = "$sp"
    vtil = None

    regs = {
        "$sp" : RegisterInfo("$sp", 1)
    }

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
                InstructionTextToken(InstructionTextTokenType.TextToken, " == "),
                InstructionTextToken(InstructionTextTokenType.TextToken, "UNKNOWN"),
                InstructionTextToken(InstructionTextTokenType.TextToken, ")")
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

        if self.vtil == None:
            try:
                self.vtil = VTILParser.from_file(get_filename())
            except:
                return result

        code = find_instruction(addr, self.vtil)

        if code != None and code.startswith("js"):
            _, _, true, false = code.split(" ")
            true = find_block_address(int(true, 16), self.vtil)
            false = find_block_address(int(false, 16), self.vtil)
            result.add_branch(BranchType.TrueBranch, true)
            result.add_branch(BranchType.FalseBranch, false)

        return result

    def get_instruction_text(self, data, addr):
        tokens = []

        if self.vtil == None:
            try:
                self.vtil = VTILParser.from_file(get_filename())
            except:
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "ERROR"))
                return tokens, 1

        code = find_instruction(addr, self.vtil)
        if code == None:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "ERROR"))
            return tokens, 1
        
        if " " in code:
            instr, operands = code.split(" ", 1)
            if " " in operands:
                operands = operands.split(" ")
            else:
                operands = [operands]

            if instr in self.instructions.keys():
                token_set = self.instructions[instr]["tokens"]

                for index in self.instructions[instr]["operands"]:
                    operand = operands.pop(0)
                    if "0x" in operand:
                        if instr == "js":
                            cond_addr = find_block_address(int(operand, 16), self.vtil)
                            cond_addr = hex(cond_addr)
                            token_set[index] = InstructionTextToken(InstructionTextTokenType.GotoLabelToken, f"{cond_addr} (vip{int(operand, 16)})")
                        else:
                            token_set[index] = InstructionTextToken(InstructionTextTokenType.IntegerToken, operand)
                    else:
                        token_set[index] = InstructionTextToken(InstructionTextTokenType.RegisterToken, operand)
                
                tokens.extend(token_set)
            else:
                # fallback
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, instr))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                for operand in operands:
                    if "0x" in operand:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, operand))
                    else:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, operand))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "))
                tokens.pop()
        else:
            tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, code))
        
        return tokens, 1
        
    
    def get_instruction_low_level_il(self, data, addr, il):
        pass