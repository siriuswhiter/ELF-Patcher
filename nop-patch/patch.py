import lief
import sys


if len(sys.argv)!=4:
    print "Usage: python %s <binname> <address> <length>"%sys.argv[0]
    exit(-1)

name = sys.argv[1]
address = int(sys.argv[2],16)
length = int(sys.argv[3])


binary = lief.parse(name)
binary.patch_address(address,[ord('\x90') for i in range(length)])
binary.write(name+'_patch')
