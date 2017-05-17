import os
from miasm2.analysis.binary import Container
from miasm2.analysis.machine import Machine
from miasm2.core.graph import DiGraphSimplifier, MatchGraphJoker

container = Container.from_stream(open('dump2.bin'))
bin_stream = container.bin_stream

#machine name = container.arch
machine = Machine(container.arch)

#fireup disasm engine
mdis = machine.dis_engine(bin_stream)

#Return an AsmCFG instance containing disassembled blocks
#https://github.com/cea-sec/miasm/pull/309
blocks = mdis.dis_multibloc(container.entry_point)

#open('AsmCFG_input.dot','w+').write(blocks.dot())


'''
for head in blocks.heads():
	for child in blocks.reachable_sons(head):
		print child

'''

filter_block = lambda block: (len(block.lines)==2 and \
							block.lines[0].name == 'PUSH' and \
							block.lines[1].name == 'MOV')

#parent joker node for the first block in MatchGraph / defining a filter for 
#first two consecutive lines in  block.lines[i].name (PUSH,MOV)

parent = MatchGraphJoker(restrict_in=False, filt=filter_block, name='root')

middle = MatchGraphJoker(restrict_in=False, filt=lambda block: (block.lines[0].name == 'XOR'), name='middle')

last = MatchGraphJoker(restrict_out=False, name='end')

# MatchGraph with a loop on middle joker node
expgraph = parent >> middle >> last
expgraph += middle >> middle

#open('MatchGraphJoker.dot','w').write(expgraph.dot())

def pass_remove_junkcode(dgs,graph):

	for block in expgraph.match(graph):

		#connect each predesseccor of MatchGraph to its equivalent successor in AsmGraph
		for pred in graph.predecessors(block[parent]):
			for succ in graph.successors(block[last]):
				#graph.add_edge(pred,succ,graph.edges2constraint[(block[last],succ)])
				graph.add_edge(pred,succ,graph.edges2constraint[(pred,block[parent])])

		#removing junk codes between block[parent] -> block[last]
		for joker , node in block.iteritems():
			graph.del_node(node)


dgs = DiGraphSimplifier()
dgs.enable_passes([pass_remove_junkcode])
#new_graph = dgs.apply_simp(blocks)
new_graph = dgs(blocks)

flag = []

for block in new_graph.walk_depth_first_forward(new_graph.heads()[0]):
	if len(block.lines) == 3 and "XOR" in block.lines[1].name:
		key = block.lines[1].args[1]
		flag.append(key)

print 'flag is: '+''.join(chr(i) for i in flag)

#open('JunkRemoved_middle_restrictin_dump2.dot','w').write(new_graph.dot())