from scapy.all import *
import struct
# s='0806'
# print(s[0:2])
# print(s[2:4])
# a=list(s)
# for i in a:
#     print(hex(ord(i))[2:])
# a=list(s)
# for i in a:
#     print(hex(ord(i))[2:])
#十六进制字符串转换为十六进制数字
# s='0x2015'
# a=int(s,16)
# print(a)
def IP_headchecksum(IP_head):
    # 校验和字段设为0
    checksum = 0
    # 得到TP头数据的长度
    headlen = len(IP_head)

    if headlen % 2 == 1:
        #
        IP_head += b'\0'
    i = 0
    while i < headlen:
        temp = struct.unpack('!H', IP_head[i:i + 2])[0]

        checksum = checksum + temp
        i = i + 2
    # 将高16bit与低16位bit相加
    checksum = (checksum >> 16) + (checksum & 0xffff)
    # 将进位与高位的16bit与低16bit再相加
    checksum = checksum + (checksum >> 16)
    # 将强制截断的结果返回(按位取反，取低16位）
    return ~checksum & 0xffff


eth=Ether()
ip=IP(dst='10.8.137.3', src='10.8.137.2')
ipraw = IP(raw(ip))
checksum_scapy = ipraw[IP].chksum
print('scapy自动计算IP首部的校验和是: %04x' %checksum_scapy)


ip.chksum=0
print(ip)
x=raw(ip)
print(x)
ipString=''.join('%02x' %orb(x) for x in x)
print(ipString)
ipbytes=bytearray.fromhex(ipString)
checksum_self = IP_headchecksum(ipbytes)
print('验证计算IP首部的校验和: %04x' %checksum_self)
if(checksum_scapy == checksum_self):
    print('校验和正确')
else:
    print('校验和不正确')
ip.chksum=checksum_self
