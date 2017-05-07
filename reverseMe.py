import idaapi
from idc import *

class SMC:

    GlobalCounter = 0
    
    def make_unknown(self):
        for seg in Segments():
	   if idc.SegName(seg) == '.text':
	       start = idc.SegStart(seg)
	       end = idc.SegEnd(seg)
	       
	       while start < end:
	           i=idautils.DecodeInstruction(start)
	           if i.Op1.dtyp == FF_DWRD:
	               print "Found an dword_XXX shit!"
	               idc.MakeUnkn(start,DOUNK_SIMPLE)
	           start = NextHead(start)
    
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
        
        #self.make_unknown()        
        #print "---> %s" % to_loc
        
        while True:
 
            #idc.MakeUnkn(next_inst,DOUNK_SIMPLE)
            idc.MakeCode(next_inst)
            idaapi.decode_insn(next_inst)
            inst = idc.GetDisasm(next_inst)
            #print "inst %s next_inst %x" % (inst, next_inst)
            opndValue = idc.GetOperandValue(next_inst,1)

            if ready and xor_check and jmp_dword:
            
                print 'decoder({0:x},{1:x},{2:x})'.format(from_loc,to_loc,key)
                if self.GlobalCounter >= 10:
                    print "5 rounds has been executed..."
                    return
                return self.decoder(from_loc,to_loc,key)
                
            if "xor" in inst:
                #key = hex(opndValue)
                #print idaapi.cmd.Operands[1].value
                xor_check = True
                key = idaapi.cmd.Operands[1].value
                
            elif "mov" in inst:
                #to_loc = hex(opndValue)
                #print idaapi.cmd.Operands[1].value
                to_loc = idaapi.cmd.Operands[1].value
               
            #elif "cmp" in inst:
            elif format(idaapi.get_byte(next_inst),'x') == "81":
                #print idaapi.cmd.Operands[1].value
                from_loc = idaapi.cmd.Operands[1].value
                ready = True
                
            #elif "jmp" in inst:
            elif format(idaapi.get_byte(next_inst),'x') == "e9" or "jmp" in inst:
                jmp_dword = True
                if idaapi.cmd.Operands[0].type == o_near and "dword" in GetOpnd(next_inst,0):
                    offset = int(idaapi.tag_remove(idaapi.ua_outop2(next_inst, 0))[24:-1],16)
                    address = GetOperandValue(next_inst,0)
                    dword_adr = address - offset
                    idc.MakeUnkn(dword_adr,DOUNK_SIMPLE)
                    idc.MakeCode(address)
                
                
            #next_inst = idc.NextHead(next_inst)
            #print idaapi.decode_insn(next_inst)
            next_inst += idaapi.decode_insn(next_inst)
            
        print "out of loop"

#decoder(0x8049774,0x804978B,0x18)
#decoder(0x8049774,0x804978B,0x21)
#decoder(0x804A025,0x804A03C,0x9b)
#decoder(0x804A025,0x804A03C,0x8e)

def main():
	smc = SMC()
	
	#smc.make_unknown()
	smc.decoder(0x8048A45,0x8048A5C,0x0BC)


if __name__ == "__main__":
    main()

'''
decoder(8048e91,8048ea8,18)
decoder(8048f0e,8048f25,21)
decoder(8049774,804978b,9b)
decoder(804a025,804978b,9b) --> ?? should be 0x8e
'''