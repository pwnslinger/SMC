import idaapi
from idc import *

class SMC:

    GlobalCounter = 0
    def decoder(self,from_loc,to_loc,key):
        self.GlobalCounter += 1
        for loc in range(from_loc, to_loc+1):
            temp = idc.Byte(loc) ^ key
            idc.PatchByte(loc,temp)
            SetColor(loc, CIC_ITEM, 0x208020)

        next_inst = from_loc
        ready = False

        while next_inst <= to_loc:
            idaapi.decode_insn(next_inst)
            inst = idc.GetDisasm(next_inst)
            print "inst %s next_inst %x" % (inst, next_inst)
            next_inst += idaapi.decode_insn(next_inst)
            opndValue = idc.GetOperandValue(next_inst,1)

            if ready:
                print 'decoder(%s,%s,%s)' % (from_loc,to_loc,key)
                if self.GlobalCounter >= 5:
                    return
                return self.decoder(from_loc,to_loc,key)
            if "xor" in inst:
                key = hex(opndValue)

            elif "mov" in inst:
                to_loc = hex(opndValue)

            elif "cmp" in inst:
                print idaapi.cmd.Operands[1].value
                from_loc = idaapi.cmd.Operands[1].value
                ready = True



#decoder(0x8049774,0x804978B,0x21)
#decoder(0x804A025,0x804A03C,0x8e)

def main():
	smc = SMC()
	smc.decoder(0x8048A45,0x8048A5C,0x0BC)


if __name__ == "__main__":
    main()
