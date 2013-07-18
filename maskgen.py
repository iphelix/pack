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

import csv, string
import datetime
from operator import itemgetter
from optparse import OptionParser

VERSION = "0.0.2"

# PPS (Passwords per Second) Cracking Speed
pps = 1000000000

# Global Variables
mastermasks = dict()
allmasks = dict()

##################################################################
## Calculate complexity of a single mask
##################################################################
def complexity(mask):
    count = 1
    for char in mask[1:].split("?"):

        # Loweralpha
        if char == "l": 
            count *= 26

        # Upperalpha
        elif char == "u": 
            count *= 26

        # Numeric
        elif char == "d": 
            count *= 10

        # Special
        elif char == "s": 
            count *= 33

        # Unknown mask
        else: 
            print "[!] Error, unknown mask ?%s in a mask %s" % (char,mask)

    return count

###################################################################
## Calculate complexity of a complex mask
###################################################################
def maskcomplexity(mask):
    combined_complexity = 1
    for submask in mask.split():
        combined_complexity *= complexity(submask)

    return combined_complexity

###################################################################
## Check if complex mask matches a sample mask
###################################################################
def matchmask(checkmask,mask):
    length = len(mask)/2
    checklength = len(checkmask.split(" "))

    if length == checklength:
        masklist = mask[1:].split("?")
        for i, submask in enumerate(checkmask.split(" ")):
            for char in submask[1:].split("?"):
                if char == masklist[i]:
                    break
            else:
                return False
        else:
            return True
    else:
        return False

        
###################################################################
## Combine masks
###################################################################
def genmask(mask):
    global mastermasks
    length = len(mask)/2
    
    if not length in mastermasks:
        mastermasks[length] = dict()
    
    for i,v in enumerate(mask[1:].split("?")):

        if not i in mastermasks[length]:
            mastermasks[length][i] = set()

        mastermasks[length][i].add("?%s" % v)

###################################################################
## Store all masks in based on length and count
###################################################################
def storemask(mask,occurrence):
    global allmasks
    length = len(mask)/2
    
    if not length in allmasks:
        allmasks[length] = dict()
    
    allmasks[length][mask] = int(occurrence)

def main():
    # Constants
    total_occurrence = 0
    sample_occurrence = 0
    sample_time = 0

    # TODO: I want to actually see statistical analysis of masks not just based on size but also frequency and time
    # per length and per count

    header  = "                       _ \n"
    header += "     MaskGen 0.0.2    | |\n"  
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
    parser.add_option("--mintime", dest="mintime",help="Minimum time to crack", type="int", metavar="")
    parser.add_option("--maxtime", dest="maxtime",help="Maximum time to crack", type="int", metavar="")
    parser.add_option("--complexity", dest="complexity",help="maximum password complexity", type="int", metavar="")
    parser.add_option("--occurrence", dest="occurrence",help="minimum times mask was used", type="int", metavar="")
    parser.add_option("--checkmask", dest="checkmask",help="check mask coverage", metavar="?u?l ?l ?l ?l ?l ?d")
    parser.add_option("--showmasks", dest="showmasks",help="Show matching masks", action="store_true", default=False)
    parser.add_option("--pps", dest="pps",help="Passwords per Second", type="int", default=pps, metavar="1000000000")
    parser.add_option("-o", "--masksoutput", dest="masks_output",help="Save masks to a file", metavar="masks.hcmask")

    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")
    (options, args) = parser.parse_args()

    # Print program header
    if not options.quiet:
        print header

    if len(args) != 1:
        parser.error("no masks file specified")
        exit(1)

    print "[*] Analysing masks: %s" % args[0]
    maskReader = csv.reader(open(args[0],'r'), delimiter=',', quotechar='"')
    #headerline = maskReader.next()

    # Check the coverage of a particular mask for a given set
    if options.checkmask:
        length = len(options.checkmask.split(" "))

        # Prepare master mask list for analysis
        mastermasks[length] = dict()

        for i, submask in enumerate(options.checkmask.split(" ")):

            mastermasks[length][i] = set()
            for char in submask[1:].split("?"):
                mastermasks[length][i].add("?%s" % char)

        for (mask,occurrence) in maskReader:
            total_occurrence += int(occurrence)
            if matchmask(options.checkmask,mask):
                sample_occurrence += int(occurrence)
                storemask(mask,occurrence)
    
    # Generate masks from a given set
    else:
        for (mask,occurrence) in maskReader:
            total_occurrence += int(occurrence)
        
            if (not options.occurrence or int(occurrence) >= options.occurrence) and \
               (not options.maxlength or len(mask)/2 <= options.maxlength) and \
               (not options.minlength or len(mask)/2 >= options.minlength) and \
               (not options.complexity or complexity(mask) <= options.complexity) and \
               (not options.maxtime or complexity(mask)/options.pps <= options.maxtime) and \
               (not options.mintime or complexity(mask)/options.pps >= options.mintime):
        
                genmask(mask)
                storemask(mask,occurrence)
                sample_occurrence += int(occurrence)

    ####################################################################################
    ## Analysis
    ####################################################################################

    if options.masks_output:
        f = open(options.masks_output,'w+')

    for length,lengthmask in sorted(mastermasks.iteritems()):
        maskstring = ""
        for position,maskset in lengthmask.iteritems(): 
            maskstring += "%s " % string.join(maskset,"")


        length_occurrence = 0
        combined_mask_time = 0
        
        # Calculate occurrence and time complexity of component masks
        # for each password length.
        for mask, occurrence in allmasks[length].iteritems():
            length_occurrence += int(occurrence)
            combined_mask_time += complexity(mask)/options.pps

        sample_time += combined_mask_time

        time_string = "Don't bother."
        if not combined_mask_time > 3784320000:
            time_string = str(datetime.timedelta(seconds=combined_mask_time))

        print "[*] [%d] [%d/%d] [%.02f] [%s]" % (length, length_occurrence, total_occurrence, length_occurrence*100/total_occurrence, time_string)      
         
        if options.showmasks:
            for mask,mask_occurrence in sorted(allmasks[length].iteritems(),key=itemgetter(1),reverse=True):
                mask_time = complexity(mask)/options.pps
                print "    [%d] [%d/%d] [%.02f] [%.02f] [%dd|%dh|%dm|%ds] %s" % (length, mask_occurrence, length_occurrence, mask_occurrence*100/length_occurrence, mask_occurrence*100/total_occurrence,mask_time/60/60/24, mask_time/60/60, mask_time/60, mask_time,mask)

        if options.masks_output:
            for mask,mask_occurrence in sorted(allmasks[length].iteritems(),key=itemgetter(1),reverse=True):
                f.write("%s\n" % mask)
            

    print "[*] Coverage is %%%d (%d/%d)" % (sample_occurrence*100/total_occurrence,sample_occurrence,total_occurrence)
    print "[*] Total time [%dd|%dh|%dm|%ds]" % (sample_time/60/60/24,sample_time/60/60,sample_time/60,sample_time)

if __name__ == "__main__":
    main()
