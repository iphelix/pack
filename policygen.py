#!/usr/bin/python
# PolicyGen - Analyze and Generate password masks according to a password policy
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

import string, random
from optparse import OptionParser, OptionGroup
import itertools

VERSION = "0.0.1"

# PPS (Passwords per Second) Cracking Speed
pps = 1000000000

# Global Variables
sample_time = 0
total_time = 0

##################################################################
# Calculate complexity of a single mask
##################################################################
def complexity(mask):
    count = 1
    for char in mask[1:].split("?"):
        if   char == "l": count *= 26
        elif char == "u": count *= 26
        elif char == "d": count *= 10
        elif char == "s": count *= 33
        else: "[!] Error, unknown mask ?%s" % char

    return count

###################################################################
# Check whether a sample password mask matches defined policy
###################################################################       
def filtermask(maskstring,options):
    global total_time, sample_time
    
    # define character counters
    lowercount = uppercount = digitcount = specialcount = 0
    
    # calculate password complexity and cracking time
    mask_time = complexity(maskstring)/options.pps
    total_time += mask_time
    
    for char in maskstring[1:].split("?"):
        if char == "l": lowercount += 1
        elif char == "u": uppercount += 1
        elif char == "d": digitcount += 1
        elif char == "s": specialcount += 1
            
    # Filter according to password policy
    if lowercount   >= options.minlower   and lowercount   <= options.maxlower and \
       uppercount   >= options.minupper   and uppercount   <= options.maxupper and \
       digitcount   >= options.mindigits  and digitcount   <= options.maxdigits and \
       specialcount >= options.minspecial and specialcount <= options.maxspecial:
        sample_time += mask_time
        if options.verbose:
            print "[*] [%dd|%dh|%dm|%ds] %s [l:%d u:%d d:%d s:%d]" % (mask_time/60/60/24, mask_time/60/60, mask_time/60, mask_time,maskstring,lowercount,uppercount,digitcount,specialcount)
        return True
    else:
        return False


def main():
    # define mask counters
    total_count = sample_count = 0

    header  = "                       _ \n"
    header += "     PolicyGen 0.0.1  | |\n"  
    header += "      _ __   __ _  ___| | _\n"
    header += "     | '_ \ / _` |/ __| |/ /\n"
    header += "     | |_) | (_| | (__|   < \n"
    header += "     | .__/ \__,_|\___|_|\_\\\n"
    header += "     | |                    \n"
    header += "     |_| iphelix@thesprawl.org\n"
    header += "\n"

    # parse command line arguments
    parser = OptionParser("%prog [options]\n\nType --help for more options", version="%prog "+VERSION)
    parser.add_option("--length", dest="length", help="Password length", type="int", default=8, metavar="8")
    parser.add_option("-o", "--output", dest="output",help="Save masks to a file", metavar="masks.txt")
    parser.add_option("--pps", dest="pps", help="Passwords per Second", type="int", default=pps, metavar="1000000000")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose")

    group = OptionGroup(parser, "Password Policy", "Define the minimum (or maximum) password strength policy that you would like to test")
    group.add_option("--mindigits", dest="mindigits", help="Minimum number of digits", default=0, type="int", metavar="1")
    group.add_option("--minlower", dest="minlower", help="Minimum number of lower-case characters", default=0, type="int", metavar="1")
    group.add_option("--minupper", dest="minupper", help="Minimum number of upper-case characters", default=0, type="int", metavar="1")
    group.add_option("--minspecial", dest="minspecial", help="Minimum number of special characters", default=0, type="int", metavar="1")
    group.add_option("--maxdigits", dest="maxdigits", help="Maximum number of digits", default=9999, type="int", metavar="3")
    group.add_option("--maxlower", dest="maxlower", help="Maximum number of lower-case characters", default=9999, type="int", metavar="3")
    group.add_option("--maxupper", dest="maxupper", help="Maximum number of upper-case characters", default=9999, type="int", metavar="3")
    group.add_option("--maxspecial", dest="maxspecial", help="Maximum number of special characters", default=9999, type="int", metavar="3")
    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")
    parser.add_option_group(group)

    (options, args) = parser.parse_args()

    # cleanup maximum occurence options
    if options.maxlower > options.length: options.maxlower = options.length
    if options.maxdigits > options.length: options.maxdigits = options.length
    if options.mindigits > options.length: options.mindigits = options.length
    if options.maxupper > options.length: options.maxupper = options.length
    if options.maxspecial > options.length: options.maxspecial = options.length

    # Print program header
    if not options.quiet:
        print header

    # print current password policy
    print "[*] Password policy:"
    print "[+] Password length: %d" % options.length
    print "[+] Minimum strength: lower: %d, upper: %d, digits: %d, special: %d" % (options.minlower, options.minupper, options.mindigits, options.minspecial)
    print "[+] Maximum strength: lower: %d, upper: %d, digits: %d, special: %d" % (options.maxlower, options.maxupper, options.maxdigits, options.maxspecial)

    if options.output: f = open(options.output, 'w')

    # generate all possible password masks and compare them to policy
    # TODO: Randomize or even statistically arrange matching masks
    for password in itertools.product(['?l','?u','?d','?s'],repeat=options.length):
        if filtermask(''.join(password), options):
            if options.output: f.write("%s\n" % ''.join(password))
            sample_count +=1
        total_count += 1

    if options.output: f.close()

    print "[*] Total Masks:  %d Runtime: [%dd|%dh|%dm|%ds]" % (total_count, total_time/60/60/24, total_time/60/60, total_time/60, total_time)
    print "[*] Policy Masks: %d Runtime: [%dd|%dh|%dm|%ds]" % (sample_count, sample_time/60/60/24, sample_time/60/60, sample_time/60, sample_time)

if __name__ == "__main__":
    main()
