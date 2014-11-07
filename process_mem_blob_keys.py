#!/usr/bin/env python

###############################################
# Name: process_memory_blob_keys.py
# Version: 0.1
# Company: InGuardians, Inc.
# Start Date: December 12, 2013
#
# Purpose:
#
#   This script can be used to process binary files
#   dumped from embedded memory components. It is 
#   intended to help locate potential key information.
#   Each byte is processed and the following KEY_LEN
#   bytes are tested for entropy.  If the values have
#   an entropy that is equal to or higher than the
#   average entropy for random strings of that length
#   then it is stored in a list.  This list is then 
#   processed to see if the following item is merely
#   one byte after the previous value.  If so, then
#   it is not likely a key of the length you are 
#   searching for, and it is dropped.
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
from progressBar import *


# I picked these values after looking at the 
# lowest result from 10 different H(os.urandom(16)) entropy values
key_entropy = {10:3.321,14:3.52,16:3.875,24:4.334,28:4.593,32:4.625,40:5.1,44:5.141,48:5.334,64:5.675,80:5.869,88:6.019,128:6.41,140:6.536,144:6.591,160:6.68,224:6.97,256:7.1,264:7.102,384:7.4,512:7.5,960:7.758,1024:7.7,1920:7.88,2048:7.8,4096:7.9}

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

# Print the data at each offset
def print_results(data,offsets,key_len):
    print "Potential Keys:",len(offsets)
    print "============================="
    for e in offsets:
        print "OFFSET: %s | Entropy %s | Data %s"%(hex(e),H(data[e:e+ (key_len - 1)]),data[e:e+(key_len - 1)].encode('hex'))
    print "============================="

# Removes concecutive entries from the offset list.
# Logic is, if there is a concencutive entry then the
# data we have is longer than the key_len
def purge_results(offsets):
    # Monitor for consecutive items else we
    # will store the last value of the
    # consecutive values
    print "Purging results"
    print "WARNING: This could produce false negatives and should only be run after an full run has been analyzed."
    seen = 0
    newoffs = []
    #for e in range(len(offsets)-1):
    for e in range(len(offsets)):
        #if offsets[e] != (offsets[e+1] - 1):
        if (e + 1) == len(offsets):
            if not seen:
                newoffs.append(offsets[e])
            break
        if offsets[e] != (offsets[e+1] - 1):
            if seen:
                seen = 0
            else:
                newoffs.append(offsets[e])
        else:
            seen = 1
    return newoffs


# Search each byte of data and the test the entropy for the key_len
def process_data(data,key_len):
    offsets = []
    # If redirecting into a file we might not want to show progress
    if SHOW:
        pb = 0
        blocks = len(data)/key_len
        progress = progressBar(0, len(data) - key_len, 77)
    for e in range(len(data)):

        # Don't look behind
        if e == 0:
            print "\nStarting. Processing byte-by-byte of %d bytes. Please be patient."%len(data)
            #continue

        # If redirecting into a file we might not want to show progress
        if SHOW and (progress.amount < (len(data) - key_len)):
            # Use progress bar to help user
            pb += 1
            progress(pb)

        # Don't go past the end
        #if (e + key_len + 1) >= len(data):
        #print "keylen",key_len," : data",len(data)
        if (e + key_len) > len(data):
            print "Done. Patience pays off. Hopefully.\n"
            break
        # Note: you must use float for this test.
        #if H(data[e:e+key_len]) >= key_entropy[key_len]:
        if H(data[e:e+(key_len - 1)]) >= key_entropy[key_len]:
            offsets.append(e)
            #print "Storing offset",offsets
        #else:
            #print "not storing"
    return offsets

def usage():
    print sys.argv[0] + ' [-h] [-d] [-k int] [-f <binary file>]'
    print "    -h: This is it."
    print "    -d: Turn on debugging.  Default: off"
    print "    -p: Turn on purging to filter consecutive items. This could generate false negatives.  Default: off"
    print "    -s: Turn off progress bar. This is useful when redirecting to a file.  Default: on"
    print "    -k <int>: number of bytes in key"
    print "    -f <binary file>: binary file that contains the data."
    print ""
    print "All data is printed to standard out."
    print ""
    sys.exit()

if __name__ == "__main__":

    ops = ['-h','-d','-f','-k','-p']
    if len(sys.argv) < 2:
        usage()

    # Default to 16 byte key length
    KEY_LEN = 16
    PURGE   = False
    SHOW    = True

    while len(sys.argv) > 1:
        op = sys.argv.pop(1)
        if op == '-h':
            usage()
        if op == '-d':
            DEBUG = True
        if op == '-p':
            PURGE = True
        if op == '-s':
            SHOW = False
        if op == '-f':
            INF = sys.argv.pop(1)
        if op == '-k':
            KEY_LEN = int(sys.argv.pop(1))
        if op not in ops:
            usage()

    # Read in binary file
    if not INF:
        usage()
    inf = open(INF,'rb').read()

    offsets = []
    if not key_entropy.has_key(KEY_LEN):
        print "WARNING: Key Length Entropty Not Computed. Please update"
        sys.exit()
    offsets = process_data(inf,KEY_LEN)
    if PURGE:
        offsets = purge_results(offsets)
    print_results(inf,offsets,KEY_LEN)
