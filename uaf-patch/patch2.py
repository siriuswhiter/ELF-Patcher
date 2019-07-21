from pwn import *
import lief

def patch_call(where,end,arch='amd64'):
    length = p32((end-(where+5))&0xffffffff)
    order = '\xe8'+length
    print disasm(order,arch=arch)
    binary.patch_address(where,[ord(i) for i in order])

def patch_far_jmp(where,end,arch='amd64'):
    length = p32((end-(where+5))&0xffffffff)
    order = '\xe9'+length
    print disasm(order,arch=arch)
    binary.patch_address(where,[ord(i) for i in order])


def hjack_func(start_where,start_end,new_where,arch='amd64'):
    # put old_content to new poistion
    length = start_end - start_where
    old_content = binary.get_content_from_virtual_address(start_where,length) 
    binary.patch_address(new_where,old_content)
    patch_far_jmp(new_where+length,start_where+length)
    # edit old poistion's content
    binary.patch_address(start_where,[0x90 for i in range(length-5)])
    patch_far_jmp(start_where+length-5,new_where)

def read_address(address):
    off_list = binary.get_content_from_virtual_address(address,4)
    off_list_str = [str(hex(i)).strip('0x') for i in off_list]
    off_list_str.reverse()
    off = int('0x'+''.join(off_list_str),16)
    return off


if len(sys.argv)!=3:
    print "Usage: python %s <binname> <address>"%sys.argv[0]
    exit(-1)

name = sys.argv[1]
address = int(sys.argv[2],16)

binary = lief.parse(name)
hook = lief.parse('hook')

# 1.0 hook
segment_add= binary.add(hook.segments[0])


# 2.0 find free_addr
_free_ = hook.get_symbol("_free_")
_free_addr =  _free_.value + segment_add.virtual_address
print "_free_addr: "+hex(_free_addr)


# 3.0 add hook's free
patch_addr = _free_addr +10

# get old_free_addr
off1 = read_address(address+1)
free = (address+5+off1)&0xffffffff
# print hex(free)
patch_call(patch_addr,free)



# 4.0 migrate codes

start = int(raw_input("Start address: "),16)
end = int(raw_input("End address: "),16)
# hjack a few codes to new segment
hjack_func(start,end,segment_add.virtual_address+0x30)


# 5.0 patch as _free
patch_call(segment_add.virtual_address+0x30+(address-start),_free_addr)



binary.write(name+"_patch")
