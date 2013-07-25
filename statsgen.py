#!/usr/bin/env python
# StatsGen - Password Statistical Analysis tool
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
import re, operator, string
from optparse import OptionParser, OptionGroup

VERSION = "0.0.2"

class StatsGen:
    def __init__(self):
        self.output_file = None

        # Filters
        self.minlength   = None
        self.maxlength   = None
        self.simplemasks = None
        self.charsets    = None

        # Constants
        self.chars_regex = list()
        self.chars_regex.append(('numeric',re.compile('^[0-9]+$')))
        self.chars_regex.append(('loweralpha',re.compile('^[a-z]+$')))
        self.chars_regex.append(('upperalpha',re.compile('^[A-Z]+$')))
        self.chars_regex.append(('mixedalpha',re.compile('^[a-zA-Z]+$')))
        self.chars_regex.append(('loweralphanum',re.compile('^[a-z0-9]+$')))
        self.chars_regex.append(('upperalphanum',re.compile('^[A-Z0-9]+$')))
        self.chars_regex.append(('mixedalphanum',re.compile('^[a-zA-Z0-9]+$')))
        self.chars_regex.append(('special',re.compile('^[^a-zA-Z0-9]+$')))
        self.chars_regex.append(('loweralphaspecial',re.compile('^[^A-Z0-9]+$')))
        self.chars_regex.append(('upperalphaspecial',re.compile('^[^a-z0-9]+$')))
        self.chars_regex.append(('mixedalphaspecial',re.compile('^[^0-9]+$')))
        self.chars_regex.append(('loweralphaspecialnum',re.compile('^[^A-Z]+$')))
        self.chars_regex.append(('upperalphaspecialnum',re.compile('^[^a-z]+$')))
        self.chars_regex.append(('mixedalphaspecialnum',re.compile('.*')))

        self.masks_regex = list()
        self.masks_regex.append(('alldigit',re.compile('^\d+$', re.IGNORECASE)))
        self.masks_regex.append(('allstring',re.compile('^[a-z]+$', re.IGNORECASE)))
        self.masks_regex.append(('stringdigit',re.compile('^[a-z]+\d+$', re.IGNORECASE)))
        self.masks_regex.append(('digitstring',re.compile('^\d+[a-z]+$', re.IGNORECASE)))
        self.masks_regex.append(('digitstringdigit',re.compile('^\d+[a-z]+\d+$', re.IGNORECASE)))
        self.masks_regex.append(('stringdigitstring',re.compile('^[a-z]+\d+[a-z]+$', re.IGNORECASE)))
        self.masks_regex.append(('allspecial',re.compile('^[^a-z0-9]+$', re.IGNORECASE)))
        self.masks_regex.append(('stringspecial',re.compile('^[a-z]+[^a-z0-9]+$', re.IGNORECASE)))
        self.masks_regex.append(('specialstring',re.compile('^[^a-z0-9]+[a-z]+$', re.IGNORECASE)))
        self.masks_regex.append(('stringspecialstring',re.compile('^[a-z]+[^a-z0-9]+[a-z]+$', re.IGNORECASE)))
        self.masks_regex.append(('stringspecialdigit',re.compile('^[a-z]+[^a-z0-9]+\d+$', re.IGNORECASE)))
        self.masks_regex.append(('specialstringspecial',re.compile('^[^a-z0-9]+[a-z]+[^a-z0-9]+$', re.IGNORECASE)))

        # Stats dictionaries
        self.stats_length = dict()
        self.stats_simplemasks = dict()
        self.stats_advancedmasks = dict()
        self.stats_charactersets = dict()

        self.hiderare = False

        self.filter_counter = 0
        self.total_counter = 0

    def simplemasks_check(self, password):
        for (name,regex) in self.masks_regex:
            if regex.match(password):
                return name
        else:
            return "othermask"

    def characterset_check(self, password):
        for (name,regex) in self.chars_regex:
            if regex.match(password):
                return name
        else:
            return "otherchar"

    def advancedmask_check(self, password):
        mask = list()
        for letter in password:
            if letter in string.digits: mask.append("?d")
            elif letter in string.lowercase: mask.append("?l")
            elif letter in string.uppercase: mask.append("?u")
            else: mask.append("?s")
        return "".join(mask)

    def generate_stats(self, filename):

        f = open(filename,'r')

        for password in f:
            password = password.rstrip('\r\n')
            self.total_counter += 1  
        
            pass_length = len(password)
            characterset = self.characterset_check(password)
            simplemask   = self.simplemasks_check(password)
            advancedmask = self.advancedmask_check(password)

            if (self.charsets == None    or characterset in self.charsets) and \
               (self.simplemasks == None or simplemask in self.simplemasks) and \
               (self.maxlength == None   or pass_length <= self.maxlength) and \
               (self.minlength == None   or pass_length >= self.minlength):

                self.filter_counter += 1         

                if pass_length in self.stats_length:
                    self.stats_length[pass_length] += 1
                else:
                    self.stats_length[pass_length] = 1

                if characterset in self.stats_charactersets:
                    self.stats_charactersets[characterset] += 1
                else:
                    self.stats_charactersets[characterset] = 1

                if simplemask in self.stats_simplemasks:
                    self.stats_simplemasks[simplemask] += 1
                else:
                    self.stats_simplemasks[simplemask] = 1

                if advancedmask in self.stats_advancedmasks:
                    self.stats_advancedmasks[advancedmask] += 1
                else:
                    self.stats_advancedmasks[advancedmask] = 1

        f.close()

    def print_stats(self):
        print "[+] Analyzing %d%% (%d/%d) of passwords" % (self.filter_counter*100/self.total_counter, self.filter_counter, self.total_counter)
        print "    NOTE: Statistics below is relative to the number of analyzed passwords, not total number of passwords"
        print "\n[*] Line Count Statistics..."
        for (length,count) in sorted(self.stats_length.iteritems(), key=operator.itemgetter(1), reverse=True):
            if self.hiderare and not count*100/self.filter_counter > 0: continue
            print "[+] %25d: %02d%% (%d)" % (length, count*100/self.filter_counter, count)

        print "\n[*] Charset statistics..."
        for (char,count) in sorted(self.stats_charactersets.iteritems(), key=operator.itemgetter(1), reverse=True):
            if self.hiderare and not count*100/self.filter_counter > 0: continue
            print "[+] %25s: %02d%% (%d)" % (char, count*100/self.filter_counter, count)

        print "\n[*] Simple Mask statistics..."
        for (simplemask,count) in sorted(self.stats_simplemasks.iteritems(), key=operator.itemgetter(1), reverse=True):
            if self.hiderare and not count*100/self.filter_counter > 0: continue
            print "[+] %25s: %02d%% (%d)" % (simplemask, count*100/self.filter_counter, count)

        print "\n[*] Advanced Mask statistics..."
        for (advancedmask,count) in sorted(self.stats_advancedmasks.iteritems(), key=operator.itemgetter(1), reverse=True):
            if count*100/self.filter_counter > 0:
                print "[+] %25s: %02d%% (%d)" % (advancedmask, count*100/self.filter_counter, count)

            if self.output_file:
                self.output_file.write("%s,%d\n" % (advancedmask,count))

if __name__ == "__main__":

    header  = "                       _ \n"
    header += "     StatsGen %s   | |\n"  % VERSION
    header += "      _ __   __ _  ___| | _\n"
    header += "     | '_ \ / _` |/ __| |/ /\n"
    header += "     | |_) | (_| | (__|   < \n"
    header += "     | .__/ \__,_|\___|_|\_\\\n"
    header += "     | |                    \n"
    header += "     |_| iphelix@thesprawl.org\n"
    header += "\n"

    parser = OptionParser("%prog [options] passwords.txt\n\nType --help for more options", version="%prog "+VERSION)

    filters = OptionGroup(parser, "Password Filters")
    filters.add_option("--minlength", dest="minlength", type="int", metavar="8", help="Minimum password length")
    filters.add_option("--maxlength", dest="maxlength", type="int", metavar="8", help="Maximum password length")
    filters.add_option("--charset", dest="charsets", help="Password charset filter (comma separated)", metavar="loweralpha,numeric")
    filters.add_option("--simplemask", dest="simplemasks",help="Password mask filter (comma separated)", metavar="stringdigit,allspecial")
    parser.add_option_group(filters)

    parser.add_option("-o", "--output", dest="output_file",help="Save masks and stats to a file", metavar="password.masks")
    parser.add_option("--hiderare", action="store_true", dest="hiderare", default=False, help="Hide statistics covering less than 1% of the sample")

    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")
    (options, args) = parser.parse_args()

    # Print program header
    if not options.quiet:
        print header

    if len(args) != 1:
        parser.error("no passwords file specified")
        exit(1)

    print "[*] Analyzing passwords in [%s]" % args[0]

    statsgen = StatsGen()

    if not options.minlength   == None: statsgen.minlength   = options.minlength
    if not options.maxlength   == None: statsgen.maxlength   = options.maxlength
    if not options.charsets    == None: statsgen.charsets    = [x.strip() for x in options.charsets.split(',')]
    if not options.simplemasks == None: statsgen.simplemasks = [x.strip() for x in options.simplemasks.split(',')]

    if options.hiderare: statsgen.hiderare = options.hiderare

    if options.output_file:
        print "[*] Saving advanced masks and occurrences to [%s]" % options.output_file
        statsgen.output_file = open(options.output_file, 'w')

    statsgen.generate_stats(args[0])
    statsgen.print_stats()