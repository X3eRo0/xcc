import random
import string
import os
from pwn import *
from main_asm import main_asm

random.seed("X3eRo0")

decrypt_fnc = '''
u32 decrypt_xor(char * bytes, char * key, u32 len, u32 keylen){
    for (u32 i = 0; i < len; i++){
        bytes[i] ^= key[i % keylen];
    }
}
'''

flag = "zh3r0{s0_m4ny_t34rS_wh1Le_P33l1ng_tH1s_On10n}"

def bitstream(string):
    bits = []
    for i in range(len(string)):
        b = ord(string[i])

        for j in range(8):
            bits.append((b >> j) & 1)

    return bits

def check_0(bit_pos, bit):
    check = '''
u32 check_bit_%d(char * input){
    u8 byte = input[%d];
    if (((byte >> %d) & 1) == %d){
        return 1;
    } else {
        return 0;
    }
}
''' % (bit_pos, bit_pos//8, bit_pos % 8, bit)
    return check


def check_1(bit_pos, bit):
    check = '''
u32 check_bit_%d(char * input){
    u8 byte = input[%d];
    if (((byte >> %d) & 1) != %d){
        return 0;
    } else {
        return 1;
    }
}
''' % (bit_pos, bit_pos//8, bit_pos%8, bit)
    return check

def check_2(bit_pos, bit):
    if (bit == 0):
        return check_0(bit_pos, bit)

    check = '''
u32 check_bit_%d(char * input){
    u8 byte = input[%d];
    if ((byte & (1 << %d))){
        return 1;
    } else {
        return 0;
    }
}
''' % (bit_pos, bit_pos//8, bit_pos%8)
    return check

bits = bitstream(flag)

fp = open("/tmp/chall2.c", "w")

fp.write("#include <stdio.h>\n")
fp.write("#include <stdint.h>\n")
fp.write("\n")
fp.write("typedef uint8_t u8;\n")
fp.write("typedef uint16_t u16;\n")
fp.write("typedef uint32_t u32;\n")

visited = []
funcs = [check_0, check_1, check_2]
while len(visited) != len(bits):
    r = random.randint(0, len(bits) - 1)
    if r not in visited:
        visited.append(r)
        fp.write(funcs[random.randint(0, 2)](r, bits[r])+"\n")

fp.write(decrypt_fnc+"\n")
fp.write("int main(){\n")
#fp.write("\tchar * flag = \"%s\";\n" % flag)
#for i in range(len(bits)):
#    fp.write("\tprintf(\"%.4d %%d\\n\", check_bit_%d(flag));\n" % (i, i))

fp.write("\treturn 0;\n")
fp.write("}\n")
fp.close()
os.system("cd ~/xvm/tools && ./xcc /tmp/chall2.c /tmp/test.xvm 2> /dev/null")

file = open("/tmp/xvm-clang.asm", "r").readlines()
current_function = []
check_functions = []
write = False 
for i in range(len(file)): 
    if "check_bit_" in file[i]: 
        write = True 
    if "ret" in file[i]: 
        write = False 
        current_function.append("    ret\n") 
        check_functions.append(current_function) 
        current_function = [] 
    if write: 
        current_function.append(file[i])

check_functions = check_functions[:-1]
map_addr = 0x31337000
fname = "checks/check_%d.asm" 
change = False

keys = []

for i in range(len(check_functions)//32 + 1):
    keys.append(''.join(random.choices(string.ascii_lowercase + string.digits, k = 32)))

for i in range(len(check_functions)): 
    if (i and (i % 32 == 0)): 
        map_addr += 0x1000 
        change = True 
     
    f = open(fname % (i // 32), "a") 
    if (i % 32 == 0): 
        f.write("\n.section .chk%d 0x%x 0x%x rwx\n\n" % (i // 32, map_addr, 0x1000)) 
         
    for j in check_functions[i]: 
        f.write(j) 
    
    if (i % 32 == 31):
        f.write('\nkey_%d:\n\t.asciz "' % (i//32 + 1) + keys[i//32 + 1] + '"')

    f.write("\n")     
    f.close()

for i in range(len(check_functions)//32 + 1):
    os.system("~/xvm/cmake-build-debug/xasm -s -i ./checks/check_%d.asm -o ./bins/bin_%d.xvm | sed \"s,\x1B\\[[0-9;]*[a-zA-Z],,g\" > ./bins/bin_%d.symbols" % (i, i, i))

symbols = []
funcs = []

for i in range(len(check_functions)//32 + 1):
    f = open("./bins/bin_%d.xvm" % i, "rb").read()
    #print("[+] Encrypting bin_%d.xvm with key : %s" % (i, keys[i]))
    f = xor(f, keys[i])
    fp = open("./bins/bin_%d.asm" % i, "w")
    fp.write(".section .chk%d #0x%x #0x1000 rwx\n" % (i, 0x31337000 + (i * 0x1000)))
    fp.write(".db\t")

    for j in range(len(f)):
        if (j != 0 and j % 16 == 0):
            fp.write("\n.db\t#0x%.2X," % f[j])
        else:
            fp.write("#0x%.2X," % f[j])

    fp.write("\n")
    fp.close()

    s = open("./bins/bin_%d.symbols" % i, "r").readlines()

    bin_syms = {}
    bin_func = []
    for line in s:
        line = line.strip()
        if ("check_bit_" in line or "key_" in line):
            line = line.split()
            addr = int(line[0][1:], 16)
            symb = line[1]
            if ("key_" not in symb):
                bin_func.append(symb)
            bin_syms[symb] = addr

    funcs.append(bin_func)
    symbols.append(bin_syms)

main_asm = main_asm % keys[0]

for i in range(len(symbols)):
    syms = symbols[i]
    func = funcs[i]
    for f in func:
        main_asm += "\t.dd #0x%x\n" % syms[f]

main_asm += "\nkeys:\n"
main_asm += "\t.dd #0x%x\n" % (0x1337f16b)
for i in range(len(symbols)-1):
    main_asm += "\t.dd #0x%x\n" % symbols[i]["key_%d" % (i+1)]

print(main_asm)
