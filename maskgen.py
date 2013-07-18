#!/usr/bin/python
# MaskGen - Generate Password Masks
#
# This tool is part of PACK (Password Analysis and Cracking Kit)
#
# VERSION 0.0.2
#
# Copyright (C) 2013 Peter Kacherginsky
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution. 
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys
import csv
import datetime
from operator import itemgetter
from optparse import OptionParser

import code
VERSION = "0.0.2"


class MaskGen:
    def __init__(self):
        # Masks collections with meta data
        self.masks = dict()
        self.lengthmasks = dict()

        self.minlength = 0
        self.maxlength = sys.maxint

        self.maxtime = sys.maxint

        self.complexity = sys.maxint
        self.occurrence = 0

        # PPS (Passwords per Second) Cracking Speed
        self.pps = 1000000000

        self.checkmask = False
        self.showmasks = False

        # Counter for total masks coverage
        self.total_occurrence = 0

    def getcomplexity(self, mask):
        """ Return mask complexity. """
        count = 1
        for char in mask[1:].split("?"):
            if char == "l":   count *= 26
            elif char == "u": count *= 26
            elif char == "d": count *= 10
            elif char == "s": count *= 33
            else: print "[!] Error, unknown mask ?%s in a mask %s" % (char,mask)

        return count

    def loadmasks(self, filename):
        """ Load masks and apply filters. """
        maskReader = csv.reader(open(args[0],'r'), delimiter=',', quotechar='"')

        for (mask,occurrence) in maskReader:

            mask_occurrence = int(occurrence)
            mask_length = len(mask)/2
            mask_complexity = self.getcomplexity(mask)

            self.total_occurrence =+ mask_occurrence

            # Apply filters based on occurrence, length, complexity and time
            if mask_occurrence >= self.occurrence and \
               mask_complexity <= self.complexity and \
               mask_length <= self.maxlength      and \
               mask_length >= self.minlength:
        
                self.masks[mask] = dict()
                self.masks[mask]['length'] = mask_length
                self.masks[mask]['occurrence'] = mask_occurrence
                self.masks[mask]['complexity'] = mask_complexity
                self.masks[mask]['time'] = mask_complexity/self.pps
                self.masks[mask]['optindex'] = mask_complexity/mask_occurrence

    def print_optimal_index_masks(self):
        print "[*] Masks sorted by optimal index."

        sample_time = 0
        sample_occurrence = 0

        # TODO Group by time here 1 minutes, 1 hour, 1 day, 1 month, 1 year....
        #      Group by length   1,2,3,4,5,6,7,8,9,10....
        #      Group by occurrence 10%, 20%, 30%, 40%, 50%....

        for mask in sorted(self.masks.keys(), key=lambda mask: self.masks[mask]['optindex'], reverse=False):

            time_human = "EXCEEDED" if self.masks[mask]['time'] > 60*60*24 else str(datetime.timedelta(seconds=self.masks[mask]['time']))
            print "[{:<2}] {:<30} [{:>8}] [{:>7}] ".format(self.masks[mask]['length'], mask, time_human, self.masks[mask]['occurrence'])

            sample_occurrence =+ self.masks[mask]['occurrence']
            sample_time =+ self.masks[mask]['time']
            if sample_time > self.maxtime:
                print "[!] Estimated runtime exceeded."
                break

        print "[*] Coverage is %d%% (%d/%d)" % (sample_occurrence*100/self.total_occurrence,sample_occurrence,self.total_occurrence)
        #print "[*] Total time [%dd|%dh|%dm|%ds]" % (sample_time/60/60/24,sample_time/60/60,sample_time/60,sample_time)

if __name__ == "__main__":

    header  = "                       _ \n"
    header += "     MaskGen %s    | |\n" % VERSION
    header += "      _ __   __ _  ___| | _\n"
    header += "     | '_ \ / _` |/ __| |/ /\n"
    header += "     | |_) | (_| | (__|   < \n"
    header += "     | .__/ \__,_|\___|_|\_\\\n"
    header += "     | |                    \n"
    header += "     |_| iphelix@thesprawl.org\n"
    header += "\n"

    parser = OptionParser("%prog [options] masksfile.csv", version="%prog "+VERSION)


    parser.add_option("--minlength", dest="minlength",help="Minimum password length", type="int", metavar="8")
    parser.add_option("--maxlength", dest="maxlength",help="Maximum password length", type="int", metavar="8")
    parser.add_option("--maxtime", dest="maxtime",help="Maximum total time (optimized)", type="int", metavar="")
    parser.add_option("--complexity", dest="complexity",help="maximum password complexity", type="int", metavar="")
    parser.add_option("--occurrence", dest="occurrence",help="minimum times mask was used", type="int", metavar="")
    parser.add_option("--checkmask", dest="checkmask",help="check mask coverage", metavar="?u?l ?l ?l ?l ?l ?d")
    parser.add_option("--showmasks", dest="showmasks",help="Show matching masks", action="store_true", default=False)
    parser.add_option("--pps", dest="pps",help="Passwords per Second", type="int", metavar="1000000000")
    parser.add_option("-o", "--masksoutput", dest="masks_output",help="Save masks to a file", metavar="masks.hcmask")
    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")
    (options, args) = parser.parse_args()

    # Print program header
    if not options.quiet: 
        print header

    if len(args) != 1:
        parser.error("no masks file specified")
        exit(1)

    # Constants
    total_occurrence = 0
    sample_occurrence = 0
    sample_time = 0

    print "[*] Analysing masks: %s" % args[0]

    maskgen = MaskGen()

    if options.minlength: maskgen.minlength = options.minlength
    if options.maxlength: maskgen.maxlength = options.maxlength

    if options.maxtime: maskgen.maxtime = options.maxtime

    if options.complexity: maskgen.complexity = options.complexity
    if options.occurrence: maskgen.occurrence = options.occurrence

    if options.pps: maskgen.pps = options.pps

    if options.checkmask: maskgen.checkmask = options.checkmask
    if options.showmasks: maskgen.showmasks = options.showmask
    
    # Load masks
    maskgen.loadmasks(args[0])
    maskgen.print_optimal_index_masks()



