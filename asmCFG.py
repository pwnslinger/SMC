import os
from miasm2.analysis.binary import Container
from miasm2.analysis.machine import Machine

container = Container.from_stream(open('dump.bin'))
bin_stream = container.bin_stream

#machine name = container.arch
machine = Machine(container.arch)

#fireup disasm engine
mdis = machine.dis_engine(bin_stream)

#Return an AsmCFG instance containing disassembled blocks
#https://github.com/cea-sec/miasm/pull/309
blocks = mdis.dis_multibloc(container.entry_point)

open('AsmCFG.dot','w+').write(blocks.dot())

for head in blocks.heads():
	for child in blocks.reachable_sons(head):
		print child
