#https://blog.csdn.net/chence19871/article/details/50727935

from idaapi import *
 
class FuncPath(DBG_Hooks):
 
    # Our breakpoint handler
    def dbg_bpt(self, tid, ea):
        print "[*] Hit: 0x%08x" % ea
        return 1
 
# Add our function coverage debugger hook
debugger = FuncPath ()
debugger.hook()
 
current_addr = ScreenEA()
 
# Find all functions and add breakpoints
for function in Functions(SegStart( current_addr ), SegEnd( current_addr )):
    AddBpt( function )
    SetBptAttr( function, BPTATTR_FLAGS, BPT_ENABLED|BPT_TRACE)
 
num_breakpoints = GetBptQty()
 
print "[*] Set %d breakpoints." % num_breakpoints
