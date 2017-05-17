from pdb import pm
import os
from miasm2.os_dep.common import heap
from miasm2.core.types import Ptr, Str, Array, set_allocator
from string import ascii_letters
from miasm2.jitter.csts import EXCEPT_INT_XX, PAGE_READ, PAGE_WRITE, EXCEPT_ACCESS_VIOL
from miasm2.analysis.sandbox import Sandbox_Linux_x86_32

# Insert here user defined methods

# Parse arguments
parser = Sandbox_Linux_x86_32.parser(description="ELF sandboxer")
parser.add_argument("filename", help="ELF Filename")
options = parser.parse_args()

# Create sandbox
sb = Sandbox_Linux_x86_32(options.filename, options, globals())

'''
passwd_addr = 0x141111
argzero_addr = 0x141166

sb.jitter.vm.add_memory_page(passwd_addr,PAGE_READ | PAGE_WRITE,ascii_letters[:30] + '\x00','required input')
sb.jitter.vm.add_memory_page(argzero_addr,PAGE_READ,'reverseMe\x00','argv[0] -> program path')

sb.jitter.push_uint32_t(passwd_addr) #argv[1]
sb.jitter.push_uint32_t(argzero_addr) #argv[0]
sb.jitter.push_uint32_t(0x2) #argc

'''

#Set default allocator from class heap()
set_allocator(heap().vm_alloc)

#implementing argv[] array busing core types of miasm2
argv_t = Array(Ptr("<I",Str()),3)
argv = argv_t.lval(sb.jitter.vm)

MemStrAnsi = Str().lval

argv[0].val = MemStrAnsi.from_str(sb.jitter.vm, "./reverseMe").get_addr()
argv[1].val = MemStrAnsi.from_str(sb.jitter.vm, ascii_letters[:28]).get_addr()
argv[2].val = 0

sb.jitter.push_uint32_t(argv[2].val) #argv[2]
sb.jitter.push_uint32_t(argv[1].val) #argv[1]
sb.jitter.push_uint32_t(argv[0].val) #argv[0]
sb.jitter.push_uint32_t(0x2) #argc

#Handle INT \x80 exception and dump memory region
def dump(jitter):
	print sb.jitter.vm
	print 'interrupt!'
	dump_data = sb.jitter.vm.get_mem(0x8048000,0x4000)
	open('dump2.bin', 'wb').write(dump_data)
	return False

#Continue execution from the place occured
def cont_exec(jitter):
	sb.jitter.cpu.EAX = 0x1337
	#make ineffective exception (reset)
	sb.jitter.cpu.set_exception(0)
	return True

'''
#handle not mapped virtual memory error
def dichotomy_search(jitter):
	Global_counter=0
	for i in range(11,52):
		sb.jitter.vm.reset_memory_page_pool()
		sb.jitter.init_stack()
		sb.jitter.vm.add_memory_page(passwd_addr,PAGE_READ | PAGE_WRITE,ascii_letters[:i],'required input')
		sb.jitter.push_uint32_t(passwd_addr) #argv[1]
		sb.jitter.push_uint32_t(argzero_addr) #argv[0]
		sb.jitter.push_uint32_t(0x2) #argc
		#make ineffective exception (reset)
		sb.jitter.cpu.set_exception(0)
		sb.jitter.init_run(sb.entry_point)
		sb.jitter.continue_run()
		return True
'''


sb.jitter.add_exception_handler(EXCEPT_INT_XX,dump)
#sb.jitter.add_exception_handler(EXCEPT_ACCESS_VIOL,dichotomy_search)

# Run
sb.run()