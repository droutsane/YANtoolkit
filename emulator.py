from pwn import *
#issues, one open is not working, and jmp is not working.

valid_registers = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40]
#registers = starts with vmcode+400h, stores abcdsif
registers = {x: 0 for x in valid_registers}
memory = {} #dictionary

#supporting functions
def write_register(register, value):  #rdi: vm_code rsi: middle op code rdx: last op code
    global registers
    if register <=0 or (register != 0x40 and register > 0x20) or register not in valid_registers:
        print("ERROR INVALID REGISTER")
        exit(-1)

    registers[register] = value


#describe register picks abcdsif
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


def describe_instruction():
    pass


def read_flag(inp):
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

def read_register(register): #rdi vm_code rsi 1  rdx 1  op_string_p is the op_str + position
    # if op_string_p == 0x40:
    #     return registers[0]
    # elif op_string_p == 0x1:
    #     return registers[1]
    # elif op_string_p == 0x10:
    #     return registers[2]
    # elif op_string_p == 0x20:
    #     return registers[3]
    # elif op_string_p == 0x4:
    #     return registers[4]
    # elif op_string_p == 0x2:
    #     return registers[5]
    # elif op_string_p == 0x8:
    #     return registers[6]
    global registers
    if register <0 or register not in valid_registers:
        print("ERROR INVALID REGISTER")
        exit(-1)
    
    return registers[register]   


def read_memory(location):
    global memory
    return memory[location]
    

def write_memory(location, value):
    global memory
    memory[location] = value
    


#Main operation functions

def interpret_add(op_string):
    s1 = describe_register(op_string[2])
    s2 = describe_register(op_string[1])
    print(f"[s] ADD {s2} {s1}")
    s3 = read_register(op_string[1])
    s4 = read_register(op_string[2])
    s4 = s4 + s3
    s4 &= 0xff
    write_register(op_string[1], s4)

    
def interpret_stk(op_string): #20 02 01
    s1 = describe_register(op_string[2])
    s2 = describe_register(op_string[1])
    print(f"[s] STK {s2} {s1}")
    op_1 = op_string[2]
    op_2 = op_string[1]
    if op_1 != 0: #push
        s3 = describe_register(op_1) # 01 -> b
        print(f"[s] ... pushing {s3}")
        val = read_register(0x4)  #0
        write_register(0x4, val+1)
        reg_val = read_register(op_1) #0x9
        s5 = read_register(0x4)
        write_memory(s5, reg_val)
    if op_2 != 0:
        s6 = describe_register(op_2)
        print(f"[s] ... popping {s6}")

        val = read_register(0x4)
        mem_val = read_memory(val)

        write_register(op_2, mem_val)
        write_register(0x4, val-1)
        

def interpret_stm(op_string):
    s1 = describe_register(op_string[2])
    s2 = describe_register(op_string[1])
    print(f"[s] STM *{s2} = {s1}")
    s3 = read_register(op_string[2]) #value
    s4 = read_register(op_string[1]) #location
    write_memory(s4, s3)

def interpret_ldm(op_string):
    s1 = describe_register(op_string[2])
    s2 = describe_register(op_string[1])
    print(f"[s] LDM {s2} = *{s1}")
    s3 = read_register(op_string[2]) #315
    s4 = 0x1 #read_memory(s3)
    write_register(op_string[1], s4)


def interpret_cmp(op_string):
    op_1 = op_string[1]
    op_2 = op_string[2]
    s1 = describe_register(op_2)
    s2 = describe_register(op_1)
    print(f"[s] CMP {s2} {s1}")

    reg1_val = read_register(op_1)
    reg2_val = read_register(op_2)
    write_register(0x8, 0x0)
    if abs(reg1_val) < abs(reg2_val):
        val = read_register(0x8)
        val ^= 0x8
        write_register(0x8, val)
    
    if abs(reg1_val) > abs(reg2_val):
        val = read_register(0x8)
        val ^= 0x2
        write_register(0x8, val)

    if reg1_val == reg2_val:
        val = read_register(0x8)
        val ^= 0x4
        write_register(0x8, val)

    if reg1_val != reg2_val:
        val == read_register(0x8)
        val ^= 0x10
        write_register(0x8, val)

    if reg1_val == 0 and reg2_val == 0:
        val = read_register(0x8)
        val ^= 0x1
        write_register(0x8, val)


def interpret_jmp(op_string):
    print("-----------------><--------------------")
    s1 = describe_register(op_string[2])
    s2 = read_flag(op_string[1])
    print(f"[j] JMP {s2} {s1}")

    op_1 = op_string[1]
    op_2 = op_string[2]
    flag = read_register(0x8)
    if op_1 and (op_2 & flag) == 0:
        print("[j] ... NOT TAKEN")
    
    print("[j] ... TAKEN")
    result = read_register(op_2)
    write_register(0x2, result)
    # is_zero1 = False
    # is_zero2 = True
    # val = op_1
    # if op_1 != 0:
    #     val = read_register(0x8)
    #     val &= op_1
    #     if val != 0:
    #         is_zero1 = val == 0
    #         is_zero2 = False

    # if not is_zero2:
    #     print("[j] ... NOT TAKEN")

    # if not is_zero1 or is_zero2:
    #     print("[j] ... TAKEN")
    #     val = read_register(op_2)
    #     write_register(0x2, val)



def get_str_from_mem(base):
    global memory
    new_str = ''
    found = False
    while not found:
        try:
            val = memory[base]
        except KeyError:
            print("KEY ERROR TERMINATED")
            break
        if val == 0:
            break
        else:
            new_str += chr(val)
        base += 1
    return new_str


def interpret_sys(op_string):
    op_1 = op_string[1]
    op_2 = op_string[2]
    s1 = describe_register(op_2)
    print(f"[s] SYS {hex(op_1)} {s1}")
    #open
    if op_1 & 0x10 != 0x0:
        print("[s] ... open")
        # rax           rdi                      rsi            rdx
        #2	  sys_open	const char *filename	int flags	int mode
        mode = read_register(0x10)
        flags = read_flag(0x1)
        idx = read_register(0x40)
        #iske baad ka open kaise call hua wo samajh me nahi aa raha he
        #here we need to call open
        path = b''
        print("FINDING PATH")
        path = get_str_from_mem(0x300 + idx)
        #unsure of what path is
        print(f"CAlling OPEN: path {path} flag {flags} mode {hex(mode)}")
        write_register(op_2, 0xff) #open call karne ke jo return hoga wo pass karna he)
    #read code       
    if op_1 & 0x1 != 0:
        print("[s] ... read_code")
        val = read_register(0x1)
        val = 0x100 - val
        val = val << 2

        val_2 = read_register(0x10)
        count = val if val <= val_2 else val_2

        val1 = read_register(0x1)
        read_buf = val1*3

        fd = read_register(0x40)
        print(f"calling read: fd {fd} buf {hex(read_buf)} count {hex(count)}")

        if fd == 0:
            print("GETTING USER INP")
            inp = input()
            for i in range(len(inp)):
                write_memory(read_buf + i, ord(inp[i]))
            write_register(op_2, len(inp))
    #read memory
    if op_1 & 0x4 != 0:
        print("[s] ... read_memory")
        val = read_register(0x1)
        #yaha bhi 300 nahi hoga lea rdx, [rax+300h]
        read_buf = val # + 0x300 
        valx = 0x100 - val
        val = read_register(0x10)
        count = valx if valx <= val else val
        fd = read_register(0x40)
        print(f"calling read(2): FD {fd} buf {hex(read_buf)} count {hex(count)}")

        if fd == 0:
            print("GETTING USER INP")
            inp = input()
            for i in range(len(inp)):
                write_memory(read_buf + i, ord(inp[i]))
            write_register(op_2, len(inp))
    #write
    if op_1 & 0x8 != 0:
        print("[s] ... write")
        #mem_val = read_memory(300) #lea rdx, [rax+300h], also thsi is mem address
        #isko sayad hum buf bhi likh sakte he, lets see

        val = read_register(0x1)
        buf = val # + 0x300
        val2 = 0x100 - val 
        val3 = read_register(0x10) 
        count = val2 if val2 <= val3 else val3
        fd = read_register(0x40)
        print(f"calling write: fd {fd} buf {hex(buf)} count {hex(count)}")
        #print(memory)
        new_str = get_str_from_mem(buf)  #this is call _write 
        print(new_str)
        write_register(op_2, len(new_str))
    #sleep
    if op_1 & 0x20 != 0:
        print("[s] ... sleep")
        val = read_register(0x40)
        sleep(val/1000)
        write_register(op_2, 0)
    #exit
    if op_1 & 0x2 != 0:
        val = read_register(0x40)
        print(f"Exiting with {val}")
        exit(val)
        
    if op_1 == 0:
        s1 = read_register(op_2)
        s2 = describe_register(op_2)
        print(f"[s] ... return value (in register {s2}: {s1})")
    
    # elif fd == 1 or fd == 2:
    #     print("PRINITNG TO USR")
    #     buf = get_str_from_mem(0x2fd+read_buf)
    #     write_register(op_2, len(buf))
    #     print(buf)
             

def interpret_imm(op_string):  #code, op_string (will fix later)
    s = describe_register(op_string[1])
    v = op_string[2]
    print(f"[s] IMM {s} = {hex(v)}")
    write_register(op_string[1], op_string[2])


elf = './babyrev_level19.0'

def enter_key(p, key):
    recvd = p.recvuntil('read_memory')
    p.sendline(key)
    return recvd

if __name__ == '__main__':
    # p = process(elf)
    # print(enter_key(p, 'HELLO').decode())
    # p.interactive()

    code = None
    with open('./vm_code', 'rb') as f:
        code = f.read()

    #code for interpreter loop
    end = False
    while not end:
        pc = read_register(0x2)
        write_register(0x2, pc+1) 
        pc = pc*3
        op_string = code[pc:pc+3]
        a = read_register(0x40)
        b = read_register(0x1)
        c = read_register(0x10)
        d = read_register(0x20)
        s = read_register(0x4)
        i = read_register(0x2)
        f = read_register(0x8)
        print(f"[V] a:{hex(a)} b:{hex(b)} c:{hex(c)} d:{hex(d)} s:{hex(s)} i:{hex(i)} f:{hex(f)}")
        print(f"[I] op:{hex(op_string[0])} arg1:{hex(op_string[1])} arg2:{hex(op_string[2])}")

        #code for interpret instruction (arguments - rsi: 3 bytes of opcode rdi: vm_code)
        if op_string[0] == 0x8:
            interpret_imm(op_string)
        elif op_string[0] == 0x2:
            interpret_add(op_string)
        elif op_string[0] == 0x20:
            interpret_stk(op_string)
        elif op_string[0] == 0x1:
            interpret_stm(op_string)
        elif op_string[0] == 0x4:
            interpret_ldm(op_string)
        elif op_string[0] == 0x10:
            interpret_cmp(op_string)
        elif op_string[0] == 0x80:
            interpret_jmp(op_string)
        elif op_string[0] == 0x40:
            interpret_sys(op_string)
        print(" ")