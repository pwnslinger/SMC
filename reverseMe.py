import idaapi
from idc import *

class SMC:

	def decoder(self,from_loc,to_loc,key):

		for loc in range(to_loc,from_loc-1,-1):
			temp = idc.Byte(loc) ^ key
			idc.PatchByte(loc,temp)
	        SetColor(loc, CIC_ITEM, 0x208020)
	        
		next_inst = from_loc
		ready = False

		while next_inst <= to_loc:
			inst = idc.GetDisasm(next_inst)
	    	opndValue = idc.GetOperandValue(next_inst,1)

	    	if ready:
	    		print 'decoder(%s,%s,%s)' % (from_loc,to_loc,key)
	    		return decoder(from_loc,to_loc,key)

			if "xor" in inst:
			    key = hex(opndValue)

			elif "mov" in inst:
			    to_loc = hex(opndValue)

			elif "cmp" in inst:
			    from_loc = hex(opndValue)
			    ready = True

			next_inst = idc.NextHead(next_inst)


#decoder(0x8049774,0x804978B,0x21)
#decoder(0x804A025,0x804A03C,0x8e)

def main():
	smc = SMC()
	smc.decoder(0x8048A45,0x8048A5C,0x0BC)


if __name__ == "__main__":
    main()  