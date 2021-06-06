# x86 to xvm transpiler
# uses clang
# clang -o test.s -masm=intel -S -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti -fverbose-asm -Wall -Wextra -O0 -m32 test.c

import sys

ignore_directives = [
    ".text",
    ".intel_syntax",
    ".file",
    ".globl",
    ".p2align",
    ".type",
    ".size",
    ".ident",
    ".addrsig",
    ".section",
]

starters = [
    ".Lfunc_end",
]

strings = [
    ".xcc_ident:\n"
    "    .asciz    \"xcc version 1.0.0\\nAuthor : X3eRo0\\nDate : 7th March, 2021\\n\""
]

def remove_directives(code):
    # remove useless directives
    global ignore_directives
    removes = []
    for line in range(len(code)):
        for directive in ignore_directives:
            if directive in code[line]:
                removes.append(line)

    for i in removes:
        code[i] = ""

    removes = []

    for line in range(len(code)):
        for starter in starters:
            if code[line].startswith(starter):
                removes.append(line)

    for i in removes:
        code[i] = ""

    return code

def escape(string):
    s = ""
    for i in string:
        s += "\\x%.2X" % ord(i)
    return s

def collect_data(code):
    global strings
    removes = []
    for i in range(len(code)):
        if (".L.str" in code[i] and code[i].endswith(":") and ".asciz" in code[i+1]):
            strings.append(code[i])
            strings.append(code[i+1])

            removes.append(code[i])
            removes.append(code[i+1])

        if (".L__const" in code[i] and code[i].endswith(":")):
            j = i + 1
            strings.append(code[i])
            removes.append(code[i])
            while(".asci" in code[j] or ".dd" in code[j] or ".dw" in code[j] or ".db" in code[j]):
                if ".asci" in code[j]:
                    bstr = ""
                    write = 0
                    temp = bytes(code[j].encode("utf-8").decode('unicode_escape'), 'latin1').decode('latin1')
                    for i in temp:
                        if write:
                            if i == "\"":
                                continue
                            bstr += i
                        if i == "\"":
                            write += 1
                            write %= 2
                    strings.append("    .asciz \"" + escape(bstr) + "\"")
                else:
                    strings.append(code[j])
                removes.append(code[j])
                j += 1

    for i in removes:
        code.remove(i)

    return code


def strclean(line):
    line = line.lstrip("\r\n")
    line = line.rstrip("\n")
    line = line.lstrip("\r")
    line = line.replace("\t", "    ")
    line = line.replace("#", ";")
    return line

def clean_code(code):
    for i in range(len(code)):
        if code[i] == "":
            code.remove(code[i])
            continue

        code[i] = strclean(code[i])
    return code

def transform_registers(code):
    x86reg_to_xvmreg = {
        "eax" : "$r0",
        "rax" : "$r0",
        "dil" : "$r1",
        "edi" : "$r1",
        "rdi" : "$r1",
        "sil" : "$r2",
        "esi" : "$r2",
        "rsi" : "$r2",
        "ebx" : "$r3",
        "rbx" : "$r3",
        "ecx" : "$r4",
        "rcx" : "$r4",
        "edx" : "$r5",
        "rdx" : "$r5",
        "ebp" : "$bp",
        "rbp" : "$bp",
        "esp" : "$sp",
        "rsp" : "$sp",
        "eip" : "$pc",
        "rip" : "$pc",
        "r9d" : "$r9",
        "r8d" : "$r8",
    }

    for i in range(len(code)):
        for a, b in enumerate(x86reg_to_xvmreg):
            code[i] = code[i].replace(b, x86reg_to_xvmreg[b])

    return code


def word_opc(opc):
    opcs = {
        "mov" : "movw",
        "add" : "addw",
        "sub" : "subw",
        "mul" : "mulw",
        "div" : "divw",
        "xor" : "xorw",
        "and" : "andw",
        "or"  : "orw",
    }
    if opc in list(opcs.keys()):
        return opcs[opc]
    else:
        return opc

def byte_opc(opc):
    opcs = {
        "mov" : "movb",
        "add" : "addb",
        "sub" : "subb",
        "mul" : "mulb",
        "div" : "divb",
        "xor" : "xorb",
        "and" : "andb",
        "or"  : "orb",
    }
    if opc in list(opcs.keys()):
        return opcs[opc]
    else:
        return opc

def change_access_mode_opcode(ia, opc):
    if ia == "word_ptr":
        opc = word_opc(opc)
    if ia == "byte_ptr":
        opc = byte_opc(opc)

    return opc

def transform_instructions(code):

    output = []

    for i in range(len(code)):
        instruction_access = ""

        temp1 = strclean(code[i]).strip()
        if temp1 == "" or temp1.startswith(";") or ":" in temp1 or temp1.startswith(".asci") or temp1.startswith(".long") or temp1.startswith(".short") or temp1.startswith(".quad"):
            code[i] = code[i].replace(".long", ".dd")
            code[i] = code[i].replace(".quad", ".dd")
            code[i] = code[i].replace(".short", ".dw")
            code[i] = code[i].replace(".byte", ".db")
            code[i] = code[i].replace(".ascii", ".asciz")
            output.append(code[i])
            continue

        if "dword ptr" in code[i]:
            code[i] = code[i].replace("dword ptr", "")

        if "qword ptr" in code[i]:
            code[i] = code[i].replace("qword ptr", "")
        
        if "word ptr" in code[i]:
            instruction_access = "word_ptr"
            code[i] = code[i].replace("word ptr", "")

        if "byte ptr" in code[i]:
            instruction_access = "byte_ptr"
            code[i] = code[i].replace("byte ptr", "")

        opcodem= code[i].split()[0]
        opcode = change_access_mode_opcode(instruction_access, opcodem)
        temp   = code[i].replace(opcodem, "").strip()
        temp   = temp.split(",")
        arg1,arg2   = "", ""

        if len(temp) > 0:
            arg1 = temp[0].strip()
        if len(temp) > 1:
            arg2 = temp[1].strip()

        if arg1 == "" or arg1 == None:
            output.append(code[i])
            continue
        if arg1 == 'al':
            arg1 = "$r0"
            opcode = change_access_mode_opcode("byte_ptr", opcode)

        if arg2 == 'al':
            arg2 = "$r0"
            opcode = change_access_mode_opcode("byte_ptr", opcode)

        if arg1 == 'dl':
            arg1 = "$r1"
            opcode = change_access_mode_opcode("byte_ptr", opcode)

        if arg2 == 'dl':
            arg2 = "$r1"
            opcode = change_access_mode_opcode("byte_ptr", opcode)

        if arg1 == 'cx':
            arg1 = '$r4'

        if arg2 == 'cx':
            arg2 = '$r4'

        if arg1 == 'cl':
            arg1 = '$r4'

        if arg2 == 'cl':
            arg2 = '$r4'

        if arg1 == "r8":
            arg1 = "$r8"

        if arg2 == "r8":
            arg2 = "$r8"

        if opcode == "movabs":
            arg2 = arg2.replace("offset ", "")
            output.append("    mov    %s, %s" % (arg1, arg2))
            continue

        if opcode == "movzx" or opcode == "movsx":
            opcode = change_access_mode_opcode(instruction_access, "mov")

        if opcode == "jg":
            opcode = "ja"

        if opcode == "je":
            opcode = "jz"

        if opcode == "jne":
            opcode = "jnz"

        if opcode == "shl":
            opcode = "lsu"

        if opcode == "shr":
            opcode = "rsu"

        if opcode == "sar":
            opcode = "rsu"


        if opcode == "imul":
            opcode = "mul"
            if (len(temp) == 3):
                try:
                    temp[2] = int(temp[2])
                    if temp[2] < 0:
                        temp[2] = 2 ** 32 - (-temp[2])
                    temp[2] = "#0x%x" % temp[2]
                except:
                    pass
                output.append("    %s %s, %s" % (opcode, temp[1], temp[2]))
                output.append("    mov %s, %s" % (temp[0], temp[1]))
                continue

        if opcode == "div":
            arg2 = arg1
            arg1 = "$r0"

        if opcode == "lea":
            arg2r = arg2.replace("[", "").replace("]", "").split(" ")[0]
            modif = arg2.replace("[", "").replace("]", "").split(" ")[1]
            arg2i = arg2.replace("[", "").replace("]", "").split(" ")[2]

            if modif == "+":
                output.append("    %s    %s, %s" % ("mov", arg1, arg2r))
                output.append("    add    %s, #0x%x" % (arg1, int(arg2i)))
                continue
            else:
                output.append("    %s    %s, %s" % ("mov", arg1, arg2r))
                output.append("    sub    %s, #0x%x" % (arg1, int(arg2i)))
                continue


        if arg1[0] == "[" and ("+" in arg1 or "-" in arg1):
            temp = arg1.replace("[", "").replace("]", "").split()
            if (len(temp) == 5):
                output.append("    push   %s" % (temp[2]))
                if (temp[1]) == "+":
                    output.append("    add    [$sp], %s" % (temp[0]))
                else:
                    output.append("    sub    [$sp], %s" % (temp[0]))

                if (temp[3] == "+"):
                    output.append("    add    [$sp], #0x%x" % (int(temp[0])))
                else:
                    output.append("    sub    [$sp], #0x%x" % (int(temp[4])))
                    try:
                        arg2 = int(arg2)
                        if arg2 < 0:
                            arg2 = 2 ** 32 - (-arg2)
                        arg2 = "#0x%x" % arg2
                    except:
                        pass
                    output.append("    pop $r9")
                    output.append("    %s  [$r9], %s"  % (opcode, arg2))

                continue

            if (len(temp) == 3):
                arg1r = temp[0]
                modif = temp[1]
                arg1i = temp[2]

                if arg1i[0] == "r":
                    arg1i = "$"+arg1i

                if (arg1i.startswith("$")):
                    # insert context independent instructions to accommodate for this instruction
                    output.append("    add     %s, %s" % (arg1r, arg1i))
                    arg1 = "[%s]" % arg1r

                else:
                    arg1i = "#0x%x" % int(arg1i)
                    arg1 = "[%s %s %s]" % (arg1r, modif, arg1i)

        if arg2 != "":

            if (arg2[0] == "["):

                temp = arg2.replace("[", "").replace("]", "").split()
                if len(temp) > 2 and "*" in temp[2]:
                    output.append("    push    %s" % temp[2].split("*")[1])
                    output.append("    mul    [$sp], #0x%x" % (int(temp[2].split("*")[0])))
                    output.append("    pop    $rc")
                    output.append("    add    $rc, %s" % temp[0])
                    output.append("    mov    %s, [$rc]" % arg1)
                    continue


                if (len(temp) == 5):
                    output.append("    push   %s" % (temp[2]))
                    if (temp[1]) == "+":
                        output.append("    add    [$sp], %s" % (temp[0]))
                    else:
                        output.append("    sub    [$sp], %s" % (temp[0]))

                    if (temp[3] == "+"):
                        output.append("    add    [$sp], #0x%x" % (int(temp[0])))
                    else:
                        output.append("    sub    [$sp], #0x%x" % (int(temp[4])))

                    output.append("    pop $r9")
                    output.append("    %s  %s, [$r9]"  % (opcode, arg1))

                    continue

                if (len(temp) == 3):
                    arg2r = temp[0]
                    if (len(temp) > 1):
                        modif = temp[1]
                        arg2i = temp[2]
                        if (arg2i.startswith("$") or arg2i.startswith("r")):
                            # insert context independent instructions to accommodate for this instruction
                            if arg2r == "r8":
                                arg2r = "$r8"
                            if arg2i == "r8":
                                arg2i = "$r8"
                            output.append("    add     %s, %s" % (arg2r, arg2i))
                            arg2 = "[%s]" % arg2r
                        else:
                            arg2 = "[%s %s #0x%x]" % (arg2r, modif, int(arg2i))
            else:
                try:
                    arg2i = int(arg2)
                    if arg2i < 0:
                        arg2i = 2 ** 32 - (-arg2i)
                    arg2 = "#0x%x" % arg2i
                except:
                    pass
            output.append("    %s    %s, %s" % (opcode, arg1, arg2))
        else:
            output.append("    %s    %s" % (opcode, arg1))



    return output

def add_strings(code):
    code.append("\n")
    code.append(".section .data")
    for line in strings:
        code.append(line)

    return code


if __name__ == "__main__":
    code = open(sys.argv[1], "r").readlines()
    code = clean_code(code)
    code = remove_directives(code)
    code = transform_registers(code)
    code = transform_instructions(code)
    code = collect_data(code)
    code = add_strings(code)
    outp = open(sys.argv[2], "w")
    outp.write('''
_start:
    call main
    hlt
''')

    for line in code:
        if (line != ""):
            outp.write(line+"\n")

    outp.close()