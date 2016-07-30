import idaapi
import idautils
import idc
import obj
import consts

###global items###
funcList = []
funcHistogram = []
#################



def init():
    print "TODO"
#generate a list of function objects

#generate a list of segment Objects

#create a histogram of functions and how often they are called

def checkString(ea):
    tmpEa = idc.PrevAddr(ea)
    extended = 0
    while chr(idc.Byte(tmpEa)) in string.printable:
        tmpEa = idc.PrevAddr(tmpEa)
        extended = extended + 1
    return extended

def autoMakeStrings():
    count = 0
    addrs = []
    for string in idautils.Strings():
        if idc.isASCII(idc.GetFlags(string.ea)):
            continue
        ext_size = checkString(string.ea)
        strat_ea = string.ea-ext_size
        endEa = string.ea+string.length
        idc.makeUnknown(startEa,endEa-startEa,0)
        if idc.MakeStr(startEa,endEa):
            count = count +  1
    print "Created %d new strings out of %d available" % (count,idautils.Strings().size)

def makeNumOffses(numOffsets):
    curAddr = idc.ScreenEa()
    for i in range(0,numOffsets):
        idc.OpOff(curAddr,0,0)
        curAddr = idc.NextHead(curAddr)

def makeRangeOffsets(startAddr,endAddr):
    curAddr = startAddr
    while(curAddr <= endAddr):
        idc.OpOff(curAddr,0,0)
        curAddr = idc.NextHead(curAddr)


def makeStrOffsets():
    for string in idautils.Strings():
        currLoc = 0
        while currLoc != MAX_EA:
            xRefLoc = idc.FindBinary(currLoc,1,hex(string.ea).rstrip('L'),radix=16)
            curLoc = idc.NextHead(xRefLoc)
            if xRefLoc != MAX_EA:
                idc.OpOff(xRefLoc,0,0)
#this function should sort the list of functions by number of times they are called and generate a Z score
def getMostCalledFuncs():
    print "TODO"

#this function should sort the function list by number of function pointers and print them all out
def getFuncPtrs():
    print "TODO"
