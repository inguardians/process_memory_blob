#!/usr/bin/env python

###############################################
# Name: process_memory_blob.py
# Version: 0.1
# Company: InGuardians, Inc.
# Start Date: December 09, 2013
#
# Purpose:
#
#   This script can be used to process binary files
#   dumped from embedded memory components. It is 
#   intended to help locate interesting information 
#   in the sea of \xffs.  It provides two basic 
#   functions.  First is to search the binary file 
#   and show the contents of offsets that contain 
#   data other than \xff\xff or \x00\x00. This 
#   should help locate data for review. NOTE: you 
#   WILL miss things this way, it is merely a helper.
#   The second function is to check the entropy at
#   different offsets throughout the file.
#
# NOTE:
#
# Developers: 
#   Cutaway (Don C. Weber)
#
# Resources:
#
# TODO: 
#
# Change Log:
#
############################################
import os,sys
import math
import string
import re

# Globals
separator = "==================================="
DEBUG  = False
INF    = False
SKIP   = 0x100    # Default Skip size 256 bytes
PCNT   = 32       # Default Number of bytes to print
OCNT   = 4        # Default Number of \xff bytes to check for
NULLS  = False    # Check for \x00 same length as \xff
ENTRO  = False    # Check data for entropy
BASE64 = False    # Check data for base64-ness
SMAGIC = False    # Check data for magic-based strings

MAGIC_STRINGS = ['MZ','GIF87a','GIF89a']

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''


#################
# Thank you altas: https://code.google.com/p/rfcat/
def makeFriendlyAscii(instring):
    out = []
    start = 0
    last = -1
    instrlen = len(instring)

    for cidx in xrange(instrlen):
        if (0x20 < ord(instring[cidx]) < 0x7f):
            if last < cidx-1:
                out.append( "." * (cidx-1-last))
                start = cidx
            last = cidx
        else:
            if last == cidx-1:
                out.append( instring[ start:last+1 ] )

    if last != cidx:
        out.append( "." * (cidx-last) )
    else: # if start == 0:
        out.append( instring[ start: ] )

    return ''.join(out)
#################

#################
# Thank you Ero Carrera: http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
# Process data block and determine entropy score
def H(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

# This function is mainly for printing to a graph
def entropy_scan (data, block_size) :
    for block in ( data[x:block_size+x] for x in range (len (data) - block_size) ):
        yield H (block)
#################


def locate_offset(data):
    # Search through the file skipping to logical areas that might 
    # contain data.  Mark that location
    offsets = []
    for e in range(0,len(data),SKIP):
        if inf[e:e+OCNT] not in NO_DATA:
            offsets.append(e)
    return offsets

        

def list_entropy(offsets,data):
    # Search each offset and then test the first 256 bytes
    E_MIN = 2.0     # Ignore anything below 2
    E_MID = 4.0     # These may be a bit interesting
    E_MAX = 7.0     # These should be what we are looking for

    # If we are checking entropy the data should be at least 256 bytes long
    BSIZE = 256

    if DEBUG: print "offsets:",offsets
    print separator
    print "OFFSETS     :  ENTROPY"
    print separator
    for e in offsets:
        entropy = H(data[e:e+BSIZE])
        # Check the level and highlight if interesting
        if entropy > E_MIN:
            if entropy > E_MID:
                if entropy > E_MAX:
                    entropy = bcolors.FAIL + str(entropy) + bcolors.ENDC
                else:
                    entropy = bcolors.WARNING + str(entropy) + bcolors.ENDC
            print "0x"+'{:08x}'.format(e)," : ",entropy
    print separator + '\n'
        
def print_offset(offsets,data):

    # Search through the file skipping to logical areas that might 
    # contain data.  Output a particular size
    for e in offsets:
        tmp = inf[e:e+PCNT]
        print "0x"+'{:08x}'.format(e)+":"
        print separator
        #print tmp.encode('hex')," | ",repr(tmp)
        print tmp.encode('hex')," | ",makeFriendlyAscii(tmp)
        print separator + '\n'
        
def print_offset_b64(offsets,data):

    # Search through the file skipping to logical areas that might 
    # contain data.  Output the data as found and after being base64
    # decoded.
    for e in offsets:
        tmp = inf[e:e+PCNT]
        if all(x in string.printable for x in tmp) and (tmp[0:4] != tmp[4:8]):
            try:
                tmp2 = tmp.decode('base64')
            except:
                continue
            print "0x"+'{:08x}'.format(e)+":"
            print separator
            print tmp.encode('hex')," | ",tmp2
            print separator + '\n'

def print_magic(data):
    # Roll through a list of magic strings to search on
    for e in MAGIC_STRINGS:
        # Let's just print the first 64 bytes
        #patt = re.compile(r"%s.{64}"%e)
        patt = re.compile(r"%s"%e)
        for m in patt.finditer(data):
            print "0x"+'{:08x}'.format(m.start())+":",e
            print separator
            print data[m.start():m.start() + PCNT], "  |  ", makeFriendlyAscii(data[m.start():m.start() + PCNT])
            print separator + '\n'


def usage():
    print sys.argv[0] + ' [-h] [-d] [-n int] [-l int] [-s int] [-m] [-M list] [-e] [-z] [-f <binary file>]'
    print "    -h: This is it."
    print "    -d: Turn on debugging.  Default: off"
    print "    -n <int>: number of concequtive 0xff to test for no data at this location."
    print "    -l <int>: number of bytes to print when data is located."
    print "    -s <int>: number of bytes to skip forward during testing."
    print "    -f <binary file>: binary file that contains the data."
    print "    -e: Perform entropy testing.  No data is printed, just highlighted entropy scores."
    print "    -b: Perform base64 printing."
    print "    -m: Perform magic-based searching and printing."
    print "    -M: Perform magic-based searching and printing. List must be comma separated with no spaces nor non-ASCII characters nor comma."
    print "    -z: Default testing is for 0xff.  This will add 0x00 to the testing."
    print ""
    print "All data is printed to standard out."
    print ""
    print "You should consider the size of the blob as well.  This script process different points"
    print "of the file and then goes back and prints from the locations.  So, the object created"
    print "will not be too large.  But, if there are a LOT of locations to print the list will"
    print "get large.  Python has two issues: large objects and slow printing.  Therefore, a large"
    print "file might slow your system down due to memory usage (for the large object) and CPU"
    print "usage for printing to the screen.  You can fix this by rewriting this in C or by"
    print "using a better memory processor."
    sys.exit()


if __name__ == "__main__":

    ops = ['-h','-d','-f', '-s','-l','-n','-z','-e', '-b', '-m', '-M']
    if len(sys.argv) < 2:
        usage()

    while len(sys.argv) > 1:
        op = sys.argv.pop(1)
        if op == '-h':
            usage()
        if op == '-d':
            DEBUG = True
        if op == '-f':
            INF = sys.argv.pop(1)
        if op == '-l':
            PCNT = int(sys.argv.pop(1))
        if op == '-n':
            OCNT = int(sys.argv.pop(1))
        if op == '-s':
            SKIP = int(sys.argv.pop(1))
        if op == '-z':
            NULLS = True
        if op == '-e':
            ENTRO = True
        if op == '-b':
            BASE64 = True
        if op == '-m':
            SMAGIC = True
        if op == '-M':
            SMAGIC = True
            MAGIC_STRINGS = sys.argv.pop(1).split(',')
        if op not in ops:
            usage()

    # Read in binary file
    if not INF:
        usage()
    inf = open(INF,'rb').read()

    # Print magic data
    if SMAGIC:
        print_magic(inf)
        sys.exit()

    # Process file and get offsets of interest
    offsets = []
    NO_DATA = ['\xff' * OCNT]    # NO_DATA is used to detect when there is no data at a location
    if NULLS:
        NO_DATA.append('\x00'*OCNT)
    offsets = locate_offset(inf)

    # Do entropy testing
    if ENTRO:
        list_entropy(offsets,inf)
        sys.exit()

    # Print data
    if BASE64:
        print_offset_b64(offsets,inf)
        sys.exit()

    # Default
    print_offset(offsets,inf)
            
