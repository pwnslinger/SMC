from pdb import pm
import os
from miasm2.jitter.csts import EXCEPT_INT_XX
from miasm2.analysis.sandbox import Sandbox_Linux_x86_32

# Insert here user defined methods

# Parse arguments
parser = Sandbox_Linux_x86_32.parser(description="ELF sandboxer")
parser.add_argument("filename", help="ELF Filename")
options = parser.parse_args()

# Create sandbox
sb = Sandbox_Linux_x86_32(options.filename, options, globals())

#Handle INT \x80 exception and dump memory region
def dump(jitter):
	print sb.jitter.vm
	print 'interrupt!'
	dump_data = sb.jitter.vm.get_mem(0x8048000,0x4000)
	open('dump.bin', 'wb').write(dump_data)
	return False

sb.jitter.add_exception_handler(EXCEPT_INT_XX,dump)

# Run
sb.run()