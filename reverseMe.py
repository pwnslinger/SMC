import idaapi
from idc import *
import binascii

class SMC:

    GlobalCounter = 0
    flag = []
	
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
                self.flag.append(format(key,'x'))
                print '[{0:d}] decoder({1:x},{2:x},{3:x})'.format(self.GlobalCounter,from_loc,to_loc,key)
                
                
                if self.GlobalCounter >= 54:
                    print ''.join([chr(int(i,16)) for i in self.flag]).strip()
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
[1] decoder(8048e91,8048ea8,18)
[2] decoder(8048f0e,8048f25,21)
[3] decoder(8049774,804978b,9b)
[4] decoder(804a025,804a03c,8e)
[5] decoder(8049085,804909c,f3)
[6] decoder(8049981,8049998,8f)
[7] decoder(8048d97,8048dae,9c)
[8] decoder(8049d1e,8049d35,fd)
[9] decoder(80492dd,80492f4,81)
[10] decoder(804af48,804af5f,6a)
[11] decoder(804ac73,804ac8a,b)
[12] decoder(804a3c2,804a3d9,2d)
[13] decoder(804a59d,804a5b4,8)
[14] decoder(8049102,8049119,96)
[15] decoder(804a183,804a19a,4f)
[16] decoder(8048964,804897b,4d)
[17] decoder(804ac0f,804ac26,f7)
[18] decoder(804b010,804b027,9a)
[19] decoder(804ad86,804ad9d,67)
[20] decoder(80485c7,80485de,3f)
[21] decoder(804a840,804a857,63)
[22] decoder(804881f,8048836,3d)
[23] decoder(80495fd,8049614,cf)
[24] decoder(804a8bd,804a8d4,8b)
[25] decoder(80487ed,8048804,70)
[26] decoder(8049742,8049759,69)
[27] decoder(8048a2c,8048a43,60)
[28] decoder(80482f2,8048309,17)
[29] decoder(804a9b7,804a9ce,ab)
[30] decoder(80489c8,80489df,6f)
[31] decoder(80491fc,8049213,c9)
[32] decoder(804a520,804a537,fb)
[33] decoder(8049855,804986c,c7)
[34] decoder(804862b,8048642,6d)
[35] decoder(804adb8,804adcf,13)
[36] decoder(804830b,8048322,fc)
[37] decoder(804aa66,804aa7d,e8)
[38] decoder(804a4a3,804a4ba,6a)
[39] decoder(8048e14,8048e2b,98)
[40] decoder(804980a,8049821,13)
[41] decoder(8048531,8048548,78)
[42] decoder(80491e3,80491fa,5d)
[43] decoder(804914d,8049164,f4)
[44] decoder(804ad6d,804ad84,eb)
[45] decoder(80496c5,80496dc,6e)
[46] decoder(8049db4,8049dcb,2d)
[47] decoder(804a9d0,804a9e7,4e)
[48] decoder(8049a7b,8049a92,57)
[49] decoder(804a7dc,804a7f3,82)
[50] decoder(804909e,80490b5,91)
[51] decoder(80496de,80496f5,9e)
[52] decoder(8048aa9,8048ac0,ab)
[53] decoder(8049b5c,8049b73,98)
[54] decoder(804b2f0,804b307,42)
'''