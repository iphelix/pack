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
from optparse import OptionParser

VERSION = "0.0.2"

try:
	import psyco
	psyco.full()
	print "[*] Using Psyco to accelerate parsing."
except ImportError:
	print "[?] Psyco is not available. Install Psyco on 32-bit systems for faster parsing."

password_counter = 0

# Constants
chars_regex = list()
chars_regex.append(('numeric',re.compile('^[0-9]+$')))
chars_regex.append(('loweralpha',re.compile('^[a-z]+$')))
chars_regex.append(('upperalpha',re.compile('^[A-Z]+$')))
chars_regex.append(('mixedalpha',re.compile('^[a-zA-Z]+$')))
chars_regex.append(('loweralphanum',re.compile('^[a-z0-9]+$')))
chars_regex.append(('upperalphanum',re.compile('^[A-Z0-9]+$')))
chars_regex.append(('mixedalphanum',re.compile('^[a-zA-Z0-9]+$')))
chars_regex.append(('special',re.compile('^[^a-zA-Z0-9]+$')))
chars_regex.append(('loweralphaspecial',re.compile('^[^A-Z0-9]+$')))
chars_regex.append(('upperalphaspecial',re.compile('^[^a-z0-9]+$')))
chars_regex.append(('mixedalphaspecial',re.compile('^[^0-9]+$')))
chars_regex.append(('loweralphaspecialnum',re.compile('^[^A-Z]+$')))
chars_regex.append(('upperalphaspecialnum',re.compile('^[^a-z]+$')))
chars_regex.append(('mixedalphaspecialnum',re.compile('.*')))

masks_regex = list()
masks_regex.append(('alldigit',re.compile('^\d+$', re.IGNORECASE)))
masks_regex.append(('allstring',re.compile('^[a-z]+$', re.IGNORECASE)))
masks_regex.append(('stringdigit',re.compile('^[a-z]+\d+$', re.IGNORECASE)))
masks_regex.append(('digitstring',re.compile('^\d+[a-z]+$', re.IGNORECASE)))
masks_regex.append(('digitstringdigit',re.compile('^\d+[a-z]+\d+$', re.IGNORECASE)))
masks_regex.append(('stringdigitstring',re.compile('^[a-z]+\d+[a-z]+$', re.IGNORECASE)))
masks_regex.append(('allspecial',re.compile('^[^a-z0-9]+$', re.IGNORECASE)))
masks_regex.append(('stringspecial',re.compile('^[a-z]+[^a-z0-9]+$', re.IGNORECASE)))
masks_regex.append(('specialstring',re.compile('^[^a-z0-9]+[a-z]+$', re.IGNORECASE)))
masks_regex.append(('stringspecialstring',re.compile('^[a-z]+[^a-z0-9]+[a-z]+$', re.IGNORECASE)))
masks_regex.append(('stringspecialdigit',re.compile('^[a-z]+[^a-z0-9]+\d+$', re.IGNORECASE)))
masks_regex.append(('specialstringspecial',re.compile('^[^a-z0-9]+[a-z]+[^a-z0-9]+$', re.IGNORECASE)))

def length_check(password):	
	return len(password)

def masks_check(password):
	for (name,regex) in masks_regex:
		if regex.match(password):
			return name
	else:
		return "othermask"

def chars_check(password):
	for (name,regex) in chars_regex:
		if regex.match(password):
			return name
	else:
		return "otherchar"

def advmask_check(password):
	advmask = list()
	for letter in password:
		if letter in string.digits: advmask.append("?d")
		elif letter in string.lowercase: advmask.append("?l")
		elif letter in string.uppercase: advmask.append("?u")
		else: advmask.append("?s")
	return "".join(advmask)		

def main():
	password_length = dict()
	masks = dict()
	advmasks = dict()
	chars = dict()
	filter_counter = 0
	total_counter = 0

	header  = "                       _ \n"
	header += "     StatsGen 0.0.2   | |\n"  
	header += "      _ __   __ _  ___| | _\n"
	header += "     | '_ \ / _` |/ __| |/ /\n"
	header += "     | |_) | (_| | (__|   < \n"
	header += "     | .__/ \__,_|\___|_|\_\\\n"
	header += "     | |                    \n"
	header += "     |_| iphelix@thesprawl.org\n"
	header += "\n"

	parser = OptionParser("%prog [options] passwords.txt", version="%prog "+VERSION)
	parser.add_option("-l", "--length", dest="length_filter",help="Password length filter.",metavar="8")
	parser.add_option("-c", "--charset", dest="char_filter", help="Password charset filter.", metavar="loweralpha")
	parser.add_option("-m", "--mask", dest="mask_filter",help="Password mask filter", metavar="stringdigit")
	parser.add_option("-o", "--maskoutput", dest="mask_output",help="Save masks to a file", metavar="masks.csv")
	parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")
	(options, args) = parser.parse_args()

	# Print program header
	if not options.quiet:
		print header

	if len(args) != 1:
		parser.error("no passwords file specified")
		exit(1)
	
	print "[*] Analyzing passwords: %s" % args[0]

	f = open(args[0],'r')

	for password in f:
		password = password.strip()
		total_counter += 1	
	
		pass_len = length_check(password)
		mask_set = masks_check(password)
		char_set = chars_check(password)
		advmask = advmask_check(password)

		if (not options.length_filter or str(pass_len) in options.length_filter.split(',')) and \
		   (not options.char_filter or char_set in options.char_filter.split(',')) and \
		   (not options.mask_filter or mask_set in options.mask_filter.split(',')):			
	
			filter_counter += 1			

			try: password_length[pass_len] += 1
			except: password_length[pass_len] = 1

			try: masks[mask_set] += 1
			except: masks[mask_set] = 1

			try: chars[char_set] += 1
			except: chars[char_set] = 1

			try: advmasks[advmask] += 1
			except: advmasks[advmask] = 1

	f.close()

	print "[+] Analyzing %d%% (%d/%d) passwords" % (filter_counter*100/total_counter, filter_counter, total_counter)
	print "    NOTE: Statistics below is relative to the number of analyzed passwords, not total number of passwords"
	print "\n[*] Line Count Statistics..."
	for (length,count) in sorted(password_length.iteritems(), key=operator.itemgetter(1), reverse=True):
		if count*100/filter_counter > 0:
			print "[+] %25d: %02d%% (%d)" % (length, count*100/filter_counter, count)

	print "\n[*] Mask statistics..."
	for (mask,count) in sorted(masks.iteritems(), key=operator.itemgetter(1), reverse=True):
		print "[+] %25s: %02d%% (%d)" % (mask, count*100/filter_counter, count)

	print "\n[*] Charset statistics..."
	for (char,count) in sorted(chars.iteritems(), key=operator.itemgetter(1), reverse=True):
		print "[+] %25s: %02d%% (%d)" % (char, count*100/filter_counter, count)

	print "\n[*] Advanced Mask statistics..."
	for (advmask,count) in sorted(advmasks.iteritems(), key=operator.itemgetter(1), reverse=True):
		if count*100/filter_counter > 0:
			print "[+] %25s: %02d%% (%d)" % (advmask, count*100/filter_counter, count)

	if options.mask_output:
		print "\n[*] Saving Mask statistics to %s" % options.mask_output
		fmask = open(options.mask_output, "w")
		for (advmask,count) in sorted(advmasks.iteritems(), key=operator.itemgetter(1), reverse=True):
			fmask.write("%s,%d\n" % (advmask,count))
		fmask.close()

if __name__ == "__main__":
	main()
