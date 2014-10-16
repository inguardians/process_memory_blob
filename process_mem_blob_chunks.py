#!/usr/bin/env python

###############################################
# Name: process_memory_blob_chunks.py <infile> <outfile>
# Version: 0.1
# Company: InGuardians, Inc.
# Start Date: December 12, 2013
#
# Purpose:
#
#       Sometimes DataFlash is dumped with page markers 
#       (for lack of a better term). These usually occur
#       every 256 bytes. These markers mess up things 
#       like firmware and other data.  Thus, we need to 
#       get rid of these page markers.
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
import os, sys

INF = sys.argv[1]
ONF = sys.argv[2]

data = open(INF,'rb').read()
onf  = open(ONF,'wb')

FIRST = False
#FIRST = True
cnt   = 0
cnt1  = 0

if FIRST:
    for e in data:
        if cnt == 256:
            cnt = 0
            cnt1 = 0
        if cnt1 == 8 and cnt <= 255:
            onf.write(e)
            cnt += 1
            continue
        cnt1 += 1
else:
    for e in data:
        if cnt < 256:
            onf.write(e)
        if cnt >= 256:
            if cnt1 < 8:
                cnt1 += 1
            if cnt1 == 8:
                cnt1 = 0
                cnt = 0
                continue
        cnt += 1

onf.close()

