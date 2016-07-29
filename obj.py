import consts
import idaapi
import idautils
import idc
import re

class Function(object):
    """docstring for Function"""
    def __init__(self, startEa, endEa):
        self.startEa = startEa
        self.endEa = endEa
        self.numFps = 0
        self.fpList = []
        self.numXrefs = 0
        self.setNumXrefs()
        self.setFpList()

        @classmethod
        def setNumXrefs(self):
            for xref in idautils.XrefsTo(self.startEa):
                self.numXrefs = self.numXrefs + 1

        def makeXrefs(self):
            curAddr = 0
            while curAddr < MAX_EA:
                xRefLoc = idc.FindBinary(currLoc,1,hex(string.ea).rstrip('L'),radix=16)
                if xRefLoc != MAX_EA:
                    idc.OpOff(xRefLoc,0,0)
            self.setNumXrefs() #updatding the number of xrefs

        @classmethod
        def setFpList(slef):

            print "TODO"

        def getFpList(self):
            return self.fpList


class Segment(object):
    """docstring for Segment"""
    def __init__(self, start,end):
        self.startEa = start
        self.endEa = end
