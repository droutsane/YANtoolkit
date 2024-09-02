from pwn import *

def describe_register(val): #val is 2nd opcode
    if val == 0x40:
        return 'a'
    elif val == 0x1:
        return 'b'
    elif val == 0x10:
        return 'c'
    elif val == 0x20:
        return 'd'
    elif val == 0x4:
        return 's'
    elif val == 0x2:
        return 'i'
    elif val == 0x8:
        return 'f'
    elif val == 0x0:
        return "NONE"
    else:
        return '?'

def describe_flag(inp):
    fl = ""
    if inp & 0x8 != 0:
        fl += 'L'
    if inp & 0x2 != 0:
        fl += 'G'
    if inp & 0x4 != 0:
        fl += 'E'
    if inp & 0x10 != 0:
        fl += 'N'
    if inp & 0x1 != 0:
        fl += 'z'
    if inp & 0x0 != 0:
        fl += '*'
    return fl

def intr_sys(inp):
    if inp == 0x10:
        return "OPEN (a, b, c)"
    if inp == 0x1:
        return "READ CODE (a, b, c)"
    if inp == 0x04:
        return "READ MEMORY (a, b, c)"
    if inp == 0x8:
        return "WRITE (a, b, c)"
    if inp == 0x20:
        return "SLEEP (a)"
    if inp == 0x2:
        return "exit (a)"


code = None
with open('./vm_code', 'rb') as f:
    code = f.read()

end = False
i=0
j=1
while i + 3 <= len(code):
    op_string = code[i:i+3]
    i = i + 3
    print(hex(j), "\t:\t", end=" ")
    j += 1
    # print(f"{hex(op_string[0])}  {hex(op_string[1])} {hex(op_string[2])}")
    op = op_string[0]
    arg1 = op_string[1]
    arg2 = op_string[2]
    if op == 0x8:
        print("IMM", describe_register(arg1), hex(arg2))
    elif op == 0x2:
        print("ADD", describe_register(arg1), describe_register(arg2))
    elif op == 0x20:
        print("STK", describe_register(arg1), describe_register(arg2))
    elif op == 0x1:
        print("STM" + "*" + describe_register(arg1), "=", describe_register(arg2))
    elif op == 0x4:
        print("LDM", describe_register(arg1), "=*" + describe_register(arg2))
    elif op == 0x10:
        print("CMP", describe_register(arg1), describe_register(arg2))
    elif op == 0x80:
        print("JMP", describe_flag(arg1), describe_flag(arg2))
    elif op == 0x40:
        print("SYS", intr_sys(arg1), describe_register(arg2))
    else:
        print("ERROR")
    