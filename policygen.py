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

import sys, string, random
import datetime
from optparse import OptionParser, OptionGroup
import itertools

VERSION = "0.0.2"

# PPS (Passwords per Second) Cracking Speed
pps = 1000000000

# Global Variables
sample_time = 0
total_time = 0

class PolicyGen:    
    def __init__(self):
        self.output_file = None

        self.minlength  = 8
        self.maxlength  = 8
        self.mindigit   = None
        self.minlower   = None
        self.minupper   = None
        self.minspecial = None
        self.maxdigit   = None
        self.maxlower   = None
        self.maxupper   = None
        self.maxspecial = None


        # PPS (Passwords per Second) Cracking Speed
        self.pps = 1000000000
        self.showmasks = False

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
   
    def generate_masks(self, noncompliant):
        """ Generate all possible password masks matching the policy """

        total_count = 0
        sample_count = 0

        # NOTE: It is better to collect total complexity
        # in order not to lose precision when dividing by pps
        total_complexity = 0
        sample_complexity = 0

        # TODO: Randomize or even statistically arrange matching masks
        for length in xrange(self.minlength, self.maxlength+1):
            print "[*] Generating %d character password masks." % length
            total_length_count = 0
            sample_length_count = 0

            total_length_complexity = 0
            sample_length_complexity = 0

            for masklist in itertools.product(['?d','?l','?u','?s'], repeat=length):

                mask = ''.join(masklist)

                lowercount = 0
                uppercount = 0
                digitcount = 0
                specialcount = 0

                mask_complexity = self.getcomplexity(mask)      
                
                total_length_count += 1
                total_length_complexity += mask_complexity

                # Count charachter types in a mask
                for char in mask[1:].split("?"):
                    if char == "l": lowercount += 1
                    elif char == "u": uppercount += 1
                    elif char == "d": digitcount += 1
                    elif char == "s": specialcount += 1
                        
                # Filter according to password policy
                # NOTE: Perform exact opposite (XOR) operation if noncompliant
                #       flag was set when calling the function.
                if ((not self.minlower or lowercount   >= self.minlower) and \
                   (not self.maxlower or lowercount   <= self.maxlower) and \
                   (not self.minupper or uppercount   >= self.minupper) and \
                   (not self.maxupper or uppercount   <= self.maxupper) and \
                   (not self.mindigit or digitcount   >= self.mindigit) and \
                   (not self.maxdigit or digitcount   <= self.maxdigit) and \
                   (not self.minspecial or specialcount >= self.minspecial) and \
                   (not self.maxspecial or specialcount <= self.maxspecial)) ^ noncompliant :

                    sample_length_count += 1
                    sample_length_complexity += mask_complexity

                    if self.showmasks:
                        mask_time = mask_complexity/self.pps      
                        time_human = ">1 year" if mask_time > 60*60*24*365 else str(datetime.timedelta(seconds=mask_time))
                        print "[{:>2}] {:<30} [l:{:>2} u:{:>2} d:{:>2} s:{:>2}] [{:>8}]  ".format(length, mask, lowercount,uppercount,digitcount,specialcount, time_human)

                    if self.output_file:
                        self.output_file.write("%s\n" % mask)



            total_count += total_length_count
            sample_count += sample_length_count

            total_complexity += total_length_complexity
            sample_complexity += sample_length_complexity


        total_time = total_complexity/self.pps
        total_time_human = ">1 year" if total_time > 60*60*24*365 else str(datetime.timedelta(seconds=total_time))
        print "[*] Total Masks:  %d Time: %s" % (total_count, total_time_human)

        sample_time = sample_complexity/self.pps
        sample_time_human = ">1 year" if sample_time > 60*60*24*365 else str(datetime.timedelta(seconds=sample_time))
        print "[*] Policy Masks: %d Time: %s" % (sample_count, sample_time_human)


if __name__ == "__main__":

    header  = "                       _ \n"
    header += "     PolicyGen %s  | |\n"  % VERSION
    header += "      _ __   __ _  ___| | _\n"
    header += "     | '_ \ / _` |/ __| |/ /\n"
    header += "     | |_) | (_| | (__|   < \n"
    header += "     | .__/ \__,_|\___|_|\_\\\n"
    header += "     | |                    \n"
    header += "     |_| iphelix@thesprawl.org\n"
    header += "\n"

    # parse command line arguments
    parser = OptionParser("%prog [options]\n\nType --help for more options", version="%prog "+VERSION)
    parser.add_option("-o", "--outputmasks", dest="output_masks",help="Save masks to a file", metavar="masks.hcmask")
    parser.add_option("--pps", dest="pps", help="Passwords per Second", type="int", metavar="1000000000")
    parser.add_option("--showmasks", dest="showmasks", help="Show matching masks", action="store_true", default=False)
    parser.add_option("--noncompliant", dest="noncompliant", help="Generate masks for noncompliant passwords", action="store_true", default=False)

    group = OptionGroup(parser, "Password Policy", "Define the minimum (or maximum) password strength policy that you would like to test")
    group.add_option("--minlength", dest="minlength", type="int", metavar="8", default=8, help="Minimum password length")
    group.add_option("--maxlength", dest="maxlength", type="int", metavar="8", default=8, help="Maximum password length")
    group.add_option("--mindigit", dest="mindigit", type="int", metavar="1", help="Minimum number of digits")
    group.add_option("--minlower",  dest="minlower",  type="int", metavar="1", help="Minimum number of lower-case characters")
    group.add_option("--minupper",  dest="minupper",  type="int", metavar="1", help="Minimum number of upper-case characters")
    group.add_option("--minspecial",dest="minspecial",type="int", metavar="1", help="Minimum number of special characters")
    group.add_option("--maxdigit", dest="maxdigit", type="int", metavar="3", help="Maximum number of digits")
    group.add_option("--maxlower",  dest="maxlower",  type="int", metavar="3", help="Maximum number of lower-case characters")
    group.add_option("--maxupper",  dest="maxupper",  type="int", metavar="3", help="Maximum number of upper-case characters")
    group.add_option("--maxspecial",dest="maxspecial",type="int", metavar="3", help="Maximum number of special characters")
    parser.add_option_group(group)

    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")

    (options, args) = parser.parse_args()

    # Print program header
    if not options.quiet:
        print header

    policygen = PolicyGen()

    # Settings    
    if options.output_masks:
        print "[*] Saving generated masks to [%s]" % options.output_masks
        policygen.output_file = open(options.output_masks, 'w')

    # Password policy
    if options.minlength:  policygen.minlength  = options.minlength
    if options.maxlength:  policygen.maxlength  = options.maxlength
    if options.mindigit:   policygen.mindigit   = options.mindigit
    if options.minlower:   policygen.minlower   = options.minlower
    if options.minupper:   policygen.minupper   = options.minupper
    if options.minspecial: policygen.minspecial = options.minspecial
    if options.maxdigit:   policygen.maxdigits  = options.maxdigit
    if options.maxlower:   policygen.maxlower   = options.maxlower
    if options.maxupper:   policygen.maxupper   = options.maxupper
    if options.maxspecial: policygen.maxspecial = options.maxspecial

    # Misc
    if options.pps: policygen.pps = options.pps
    if options.showmasks: policygen.showmasks = options.showmasks

    # Print current password policy
    print "[*] Password policy:"
    print "    Pass Lengths: min:%d max:%d" % (options.minlength,options.maxlength)
    print "    Min strength: l:%s u:%s d:%s s:%s" % (options.minlower, options.minupper, options.mindigit, options.minspecial)
    print "    Max strength: l:%s u:%s d:%s s:%s" % (options.maxlower, options.maxupper, options.maxdigit, options.maxspecial)

    print "[*] Generating [%s] masks." % ("compliant" if not options.noncompliant else "non-compliant")
    policygen.generate_masks(options.noncompliant)