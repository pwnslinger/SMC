import idaapi
from idc import *
import binascii

class SMC:

    GlobalCounter = 0
    flag = []

    def decoder(self,from_loc,to_loc,key):
        self.GlobalCounter += 1
        for loc in range(from_loc, to_loc+1):
            temp = idc.Byte(loc) ^ key
            idc.PatchByte(loc,temp)
            SetColor(loc, CIC_ITEM, 0x208020)

        next_inst = from_loc
        ready = False
        xor_check = False
        jmp_dword = False
        
        idc.MakeUnkn(from_loc,1)
        idc.MakeCode(from_loc)

        while next_inst <= to_loc:
 
            #idc.MakeCode(next_inst)
            idaapi.decode_insn(next_inst)
            inst = idc.GetDisasm(next_inst)
            print "inst %s next_inst %x" % (inst, next_inst)
            opndValue = idc.GetOperandValue(next_inst,1)

            if ready and xor_check and jmp_dword:
                self.flag.append(format(key,'x'))
                print '[{0:d}] decoder(0x{1:x},0x{2:x},0x{3:x})'.format(self.GlobalCounter,from_loc,to_loc,key)
                
                
                if self.GlobalCounter >= 10:
                    print ''.join([chr(int(i,16)) for i in self.flag]).strip()
                
                
                return self.decoder(from_loc,to_loc,key)
                
              
            elif "xor" in inst:
                #key = hex(opndValue)
                #print idaapi.cmd.Operands[1].value
                xor_check = True
                key = idc.GetOperandValue(next_inst,1)
                print key
                
            elif "mov" in inst or format(idaapi.get_byte(next_inst),'x') == "BA":
                print idaapi.cmd.Operands[1].value
                to_loc = idaapi.cmd.Operands[1].value
               
            elif format(idaapi.get_byte(next_inst),'x') == "81" or "cmp" in inst:
                print idaapi.cmd.Operands[1].value
                from_loc = idaapi.cmd.Operands[1].value
                ready = True
                
            elif format(idaapi.get_byte(next_inst),'x') == "e9" or "jmp" in inst:
                print 'jmp_dword hitted'
                jmp_dword = True
                
                if idaapi.cmd.Operands[0].type == o_near and "dword" in GetOpnd(next_inst,0):
                
                    offset = int(idaapi.tag_remove(idaapi.ua_outop2(next_inst, 0))[24:-1],16)
                    address = GetOperandValue(next_inst,0)
                    dword_adr = address - offset
                    idc.MakeUnkn(dword_adr,DOUNK_SIMPLE)
                    idc.MakeCode(address)
                
            next_inst = idc.NextHead(next_inst)
            #next_inst += idaapi.decode_insn(next_inst)
            
        print "out of loop"


def main():
	smc = SMC()
	smc.decoder(0x80490b7,0x80490ce,0x21)


if __name__ == "__main__":
    main()