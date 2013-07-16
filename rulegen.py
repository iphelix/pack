#!/usr/bin/env python
# Rulegen.py - Advanced automated password rule and wordlist generator for the 
#              Hashcat password cracker using the Levenshtein Reverse Path 
#              algorithm and Enchant spell checking library.
#
# This tool is part of PACK (Password Analysis and Cracking Kit)
#
# VERSION 0.0.1
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
#
# CHANGELOG: 
# [*] Fixed greedy substitution issue (thanks smarteam)

import sys
import re
import time
import operator
import enchant

from optparse import OptionParser, OptionGroup

VERSION = "0.0.1"

# Testing rules with hashcat --stdout
import subprocess
HASHCAT_PATH = "hashcat-0.42/"

# Rule Generator class responsible for the complete cycle of rule generation
class RuleGen:

    # Initialize Rule Generator class
    def __init__(self,language="en",providers="aspell,myspell",basename='analysis'):

        self.enchant_broker = enchant.Broker()
        self.enchant_broker.set_ordering("*",providers)

        self.enchant = enchant.Dict(language, self.enchant_broker)

        # Output options
        self.basename = basename
        self.output_rules_f = open("%s.rule" % basename, 'w')
        self.output_words_f = open("%s.word" % basename, 'w')

        # Finetuning word generation
        self.max_word_dist = 10
        self.max_words = 10
        self.more_words = False
        self.simple_words = False

        # Finetuning rule generation
        self.max_rule_len = 10
        self.max_rules = 10
        self.more_rules = False
        self.simple_rules = False

        # Debugging options
        self.verbose = False
        self.debug = False
        self.word = None
        self.quiet = False

        ########################################################################
        # Word and Rule Statistics
        self.word_stats = dict()
        self.rule_stats = dict()
        self.password_stats = dict()

        self.numeric_stats_total = 0
        self.special_stats_total = 0
        self.foreign_stats_total = 0

        ########################################################################
        # Preanalysis Password Patterns
        self.password_pattern = dict()
        self.password_pattern["insertion"] = re.compile('^[^a-z]*(?P<password>.+?)[^a-z]*$', re.IGNORECASE)
        self.password_pattern["email"] = re.compile('^(?P<password>.+?)@[A-Z0-9.-]+\.[A-Z]{2,4}', re.IGNORECASE)
        self.password_pattern["alldigits"] = re.compile('^(\d+)$', re.IGNORECASE)
        self.password_pattern["allspecial"]= re.compile('^([^a-z0-9]+)$', re.IGNORECASE)

        ########################################################################
        # Hashcat Rules Engine
        self.hashcat_rule = dict()

        # Dummy rule
        self.hashcat_rule[':'] = lambda x: x                                    # Do nothing

        # Case rules
        self.hashcat_rule["l"] = lambda x: x.lower()                            # Lowercase all letters
        self.hashcat_rule["u"] = lambda x: x.upper()                            # Capitalize all letters
        self.hashcat_rule["c"] = lambda x: x.capitalize()                       # Capitalize the first letter
        self.hashcat_rule["C"] = lambda x: x[0].lower() + x[1:].upper()         # Lowercase the first found character, uppercase the rest
        self.hashcat_rule["t"] = lambda x: x.swapcase()                         # Toggle the case of all characters in word
        self.hashcat_rule["T"] = lambda x,y: x[:y] + x[y].swapcase() + x[y+1:]  # Toggle the case of characters at position N
        self.hashcat_rule["E"] = lambda x: " ".join([i[0].upper()+i[1:] for i in x.split(" ")]) # Upper case the first letter and every letter after a space

        # Rotation rules
        self.hashcat_rule["r"] = lambda x: x[::-1]                              # Reverse the entire word
        self.hashcat_rule["{"] = lambda x: x[1:]+x[0]                           # Rotate the word left
        self.hashcat_rule["}"] = lambda x: x[-1]+x[:-1]                         # Rotate the word right

        # Duplication rules
        self.hashcat_rule["d"] = lambda x: x+x                                  # Duplicate entire word
        self.hashcat_rule["p"] = lambda x,y: x*y                                # Duplicate entire word N times
        self.hashcat_rule["f"] = lambda x: x+x[::-1]                            # Duplicate word reversed
        self.hashcat_rule["z"] = lambda x,y: x[0]*y+x                           # Duplicate first character N times
        self.hashcat_rule["Z"] = lambda x,y: x+x[-1]*y                          # Duplicate last character N times
        self.hashcat_rule["q"] = lambda x: "".join([i+i for i in x])            # Duplicate every character
        self.hashcat_rule["y"] = lambda x,y: x[:y]+x                            # Duplicate first N characters
        self.hashcat_rule["Y"] = lambda x,y: x+x[-y:]                           # Duplicate last N characters

        # Cutting rules
        self.hashcat_rule["["] = lambda x: x[1:]                                # Delete first character
        self.hashcat_rule["]"] = lambda x: x[:-1]                               # Delete last character
        self.hashcat_rule["D"] = lambda x,y: x[:y]+x[y+1:]                      # Deletes character at position N
        self.hashcat_rule["'"] = lambda x,y: x[:y]                              # Truncate word at position N
        self.hashcat_rule["x"] = lambda x,y,z: x[:y]+x[y+z:]                    # Delete M characters, starting at position N
        self.hashcat_rule["@"] = lambda x,y: x.replace(y,'')                    # Purge all instances of X

        # Insertion rules
        self.hashcat_rule["$"] = lambda x,y: x+y                                # Append character to end
        self.hashcat_rule["^"] = lambda x,y: y+x                                # Prepend character to front
        self.hashcat_rule["i"] = lambda x,y,z: x[:y]+z+x[y:]                    # Insert character X at position N

        # Replacement rules
        self.hashcat_rule["o"] = lambda x,y,z: x[:y]+z+x[y+1:]                  # Overwrite character at position N with X
        self.hashcat_rule["s"] = lambda x,y,z: x.replace(y,z)                   # Replace all instances of X with Y
        self.hashcat_rule["L"] = lambda x,y: x[:y]+chr(ord(x[y])<<1)+x[y+1:]    # Bitwise shift left character @ N
        self.hashcat_rule["R"] = lambda x,y: x[:y]+chr(ord(x[y])>>1)+x[y+1:]    # Bitwise shift right character @ N
        self.hashcat_rule["+"] = lambda x,y: x[:y]+chr(ord(x[y])+1)+x[y+1:]     # Increment character @ N by 1 ascii value
        self.hashcat_rule["-"] = lambda x,y: x[:y]+chr(ord(x[y])-1)+x[y+1:]     # Decrement character @ N by 1 ascii value
        self.hashcat_rule["."] = lambda x,y: x[:y]+x[y+1]+x[y+1:]               # Replace character @ N with value at @ N plus 1
        self.hashcat_rule[","] = lambda x,y: x[:y]+x[y-1]+x[y+1:]               # Replace character @ N with value at @ N minus 1

        # Swappping rules
        self.hashcat_rule["k"] = lambda x: x[1]+x[0]+x[2:]                      # Swap first two characters
        self.hashcat_rule["K"] = lambda x: x[:-2]+x[-1]+x[-2]                   # Swap last two characters
        self.hashcat_rule["*"] = lambda x,y,z: x[:y]+x[z]+x[y+1:z]+x[y]+x[z+1:] if z > y else x[:z]+x[y]+x[z+1:y]+x[z]+x[y+1:] # Swap character X with Y

        ########################################################################
        # Common numeric and special character substitutions (1337 5p34k)
        self.leet = dict()
        self.leet["1"] = "i"
        self.leet["2"] = "z"
        self.leet["3"] = "e"
        self.leet["4"] = "a"
        self.leet["5"] = "s"
        self.leet["6"] = "b"
        self.leet["7"] = "t"
        self.leet["8"] = "b"
        self.leet["9"] = "g"
        self.leet["0"] = "o"
        self.leet["!"] = "i"
        self.leet["|"] = "i"
        self.leet["@"] = "a"
        self.leet["$"] = "s"
        self.leet["+"] = "t"

    ############################################################################
    # Calculate Levenshtein edit path matrix
    def levenshtein(self,word,password):
        matrix = []

        # Generate and populate the initial matrix
        for i in xrange(len(password) + 1):
            matrix.append([])
            for j in xrange(len(word) + 1):
                if i == 0:
                    matrix[i].append(j)
                elif j == 0:
                    matrix[i].append(i)
                else:
                    matrix[i].append(0)

        # Calculate edit distance for each substring
        for i in xrange(1,len(password) + 1):
            for j in xrange(1,len(word) + 1):
                if password[i-1] == word[j-1]:
                    matrix[i][j] = matrix[i-1][j-1]
                else:
                    insertion    = matrix[i-1][j] + 1
                    deletion     = matrix[i][j-1] + 1
                    substitution = matrix[i-1][j-1] + 1
                    matrix[i][j] = min(insertion, deletion, substitution)

        return matrix

    ############################################################################
    # Print word X password matrix
    def levenshtein_print(self,matrix,word,password):
        print "      %s" % "  ".join(list(word))
        for i,row in enumerate(matrix):
            if i == 0: print " ",
            else:      print password[i-1],
            print " ".join("%2d" % col for col in row)

    ############################################################################
    # Reverse Levenshtein Path Algorithm by Peter Kacherginsky
    # Generates a list of edit operations necessary to transform a source word
    # into a password. Edit operations are recorded in the form:
    #         (operation, password_offset, word_offset)
    # Where an operation can be either insertion, deletion or replacement.
    def levenshtein_reverse_path(self,matrix,word,password):
        paths = self.levenshtein_reverse_recursive(matrix,len(matrix)-1,len(matrix[0])-1,0)
        return [path for path in paths if len(path) <= matrix[-1][-1]]

    # Calculate reverse Levenshtein paths (recursive, depth first, short-circuited)
    def levenshtein_reverse_recursive(self,matrix,i,j,path_len):

        if i == 0 and j == 0 or path_len > matrix[-1][-1]:
            return [[]]
        else:
            paths = list()

            cost = matrix[i][j]

            # Calculate minimum cost of each operation
            cost_delete = cost_insert = cost_equal_or_replace = sys.maxint
            if i > 0: cost_insert = matrix[i-1][j]
            if j > 0: cost_delete = matrix[i][j-1]
            if i > 0 and j > 0: cost_equal_or_replace = matrix[i-1][j-1]
            cost_min = min(cost_delete, cost_insert, cost_equal_or_replace)

            # Recurse through reverse path for each operation
            if cost_insert == cost_min:
                insert_paths = self.levenshtein_reverse_recursive(matrix,i-1,j,path_len+1)
                for insert_path in insert_paths: paths.append(insert_path + [('insert',i-1,j)])            

            if cost_delete == cost_min:
                delete_paths = self.levenshtein_reverse_recursive(matrix,i,j-1,path_len+1)
                for delete_path in delete_paths: paths.append(delete_path + [('delete',i,j-1)])

            if cost_equal_or_replace == cost_min:
                if cost_equal_or_replace == cost:
                    equal_paths = self.levenshtein_reverse_recursive(matrix,i-1,j-1,path_len)
                    for equal_path in equal_paths: paths.append(equal_path)
                else:
                    replace_paths = self.levenshtein_reverse_recursive(matrix,i-1,j-1,path_len+1)
                    for replace_path in replace_paths: paths.append(replace_path + [('replace',i-1,j-1)])

            return paths

    ############################################################################
    def load_custom_wordlist(self,wordlist_file):
        self.enchant = enchant.request_pwl_dict(wordlist_file)

    ############################################################################
    # Generate source words
    def generate_words_collection(self,password):

        if self.debug: print "[*] Generating source words for %s" % password

        words = []
        if not self.simple_words: suggestions = self.generate_advanced_words(password)
        else: suggestions = self.generate_simple_words(password)

        best_found_distance = sys.maxint

        unique_suggestions = []
        for word in suggestions:
            word = word.replace(' ','')
            word = word.replace('-','')
            if not word in unique_suggestions:
                unique_suggestions.append(word)

        # NOTE: Enchant already returned a list sorted by edit distance, so
        #       we simply need to get the best edit distance of the first word
        #       and compare the rest with it
        for word in unique_suggestions:

            matrix = self.levenshtein(word,password)
            edit_distance = matrix[-1][-1]

            # Record best edit distance and skip anything exceeding it
            if not self.more_words:
                if edit_distance < best_found_distance:
                    best_found_distance = edit_distance
                elif edit_distance > best_found_distance:
                    if self.verbose: print "[-] %s => {best distance exceeded: %d (%d)} => %s" % (word,edit_distance,best_found_distance,password)
                    break

            if edit_distance <= self.max_word_dist:
                if self.debug: print "[+] %s => {edit distance: %d (%d)} = > %s" % (word,edit_distance,best_found_distance,password)
                words.append((word,matrix,password))

                if not word in self.word_stats: self.word_stats[word] = 1
                else: self.word_stats[word] += 1

            else:
                if self.verbose: print "[-] %s => {max distance exceeded: %d (%d)} => %s" % (word,edit_distance,self.max_word_dist,password)

        return words

    ############################################################################
    # Generate simple words
    def generate_simple_words(self,password):
        if self.word: 
            return [self.word]
        else:
            return self.enchant.suggest(password)[:self.max_words]

    ############################################################################
    # Generate advanced words
    def generate_advanced_words(self,password):
        if self.word: 
            return [self.word]
        else:
            # Remove non-alpha prefix and appendix
            insertion_matches = self.password_pattern["insertion"].match(password)
            if insertion_matches:
                password = insertion_matches.group('password')

            # Email split
            email_matches = self.password_pattern["email"].match(password)
            if email_matches:
                password = email_matches.group('password')

            # Replace common special character replacements (1337 5p34k)
            preanalysis_password = ''
            for c in password:
                if c in self.leet: preanalysis_password += self.leet[c]
                else: preanalysis_password += c
            password = preanalysis_password

            if self.debug: "[*] Preanalysis Password: %s" % password

            return self.enchant.suggest(password)[:self.max_words]

    ############################################################################
    # Hashcat specific offset definition 0-9,A-Z
    def int_to_hashcat(self,N):
        if N < 10: return N
        else: return chr(65+N-10)

    def hashcat_to_int(self,N):
        if N.isdigit(): return int(N)
        else: return ord(N)-65+10

    ############################################################################
    # Generate hashcat rules
    def generate_hashcat_rules_collection(self, lev_rules_collection):

        hashcat_rules_collection = []

        min_hashcat_rules_length = sys.maxint
        for (word,rules,password) in lev_rules_collection:

            if self.simple_rules: 
                hashcat_rules = self.generate_simple_hashcat_rules(word,rules,password)
            else: 
                hashcat_rules = self.generate_advanced_hashcat_rules(word,rules,password)

            if not hashcat_rules == None:
                
                hashcat_rules_length = len(hashcat_rules)

                if hashcat_rules_length <= self.max_rule_len: 
                    hashcat_rules_collection.append((word,hashcat_rules,password))

                    # Determine minimal hashcat rules length
                    if hashcat_rules_length < min_hashcat_rules_length:
                        min_hashcat_rules_length = hashcat_rules_length
                else:
                    if self.verbose: print "[!] %s => {max rule length exceeded: %d (%d)} => %s" % (word,hashcat_rules_length,self.max_rule_len,password)
            else:
                print "[!] Processing FAILED: %s => ;( => %s" % (word,password)
                print "    Sorry about that, please report this failure to"
                print "    the developer: iphelix [at] thesprawl.org"


        # Remove suboptimal rules
        if not self.more_rules:
            min_hashcat_rules_collection = []
            for (word,hashcat_rules,password) in hashcat_rules_collection:

                hashcat_rules_length = len(hashcat_rules)
                if hashcat_rules_length == min_hashcat_rules_length:
                    min_hashcat_rules_collection.append((word,hashcat_rules,password))
                else:
                    if self.verbose: print "[!] %s => {rule length suboptimal: %d (%d)} => %s" % (word,hashcat_rules_length,min_hashcat_rules_length,password)

            hashcat_rules_collection = min_hashcat_rules_collection

        return hashcat_rules_collection

    ############################################################################
    # Generate basic hashcat rules using only basic insert,delete,replace rules
    def generate_simple_hashcat_rules(self,word,rules,password):
        hashcat_rules = []

        if self.debug: print "[*] Simple Processing %s => %s" % (word,password)

        # Dynamically apply rules to the source word
        # NOTE: Special case were word == password this would work as well.
        word_rules = word

        for (op,p,w) in rules:

            if self.debug: print "\t[*] Simple Processing Started: %s - %s" % (word_rules, " ".join(hashcat_rules))

            if op == 'insert':
                hashcat_rules.append("i%s%s" % (self.int_to_hashcat(p),password[p]))
                word_rules = self.hashcat_rule['i'](word_rules,p,password[p])

            elif op == 'delete':
                hashcat_rules.append("D%s" % self.int_to_hashcat(p))
                word_rules = self.hashcat_rule['D'](word_rules,p)

            elif op == 'replace':
                hashcat_rules.append("o%s%s" % (self.int_to_hashcat(p),password[p]))
                word_rules = self.hashcat_rule['o'](word_rules,p,password[p])

        if self.debug: print "\t[*] Simple Processing Ended: %s => %s => %s" % (word_rules, " ".join(hashcat_rules),password)

        # Check if rules result in the correct password
        if word_rules == password:
            return hashcat_rules
        else:
            if self.debug: print "[!] Simple Processing FAILED: %s => %s => %s (%s)" % (word," ".join(hashcat_rules),password,word_rules)
            return None


    ############################################################################
    # Generate advanced hashcat rules using full range of available rules
    def generate_advanced_hashcat_rules(self,word,rules,password):
        hashcat_rules = []

        if self.debug: print "[*] Advanced Processing %s => %s" % (word,password)

        # Dynamically apply and store rules in word_rules variable.
        # NOTE: Special case where word == password this would work as well.
        word_rules = word

        # Generate case statistics
        password_lower = len([c for c in password if c.islower()])
        password_upper = len([c for c in password if c.isupper()])

        for i,(op,p,w) in enumerate(rules):

            if self.debug: print "\t[*] Advanced Processing Started: %s - %s" % (word_rules, " ".join(hashcat_rules))

            if op == 'insert':
                hashcat_rules.append("i%s%s" % (self.int_to_hashcat(p),password[p]))
                word_rules = self.hashcat_rule['i'](word_rules,p,password[p])

            elif op == 'delete':
                hashcat_rules.append("D%s" % self.int_to_hashcat(p))
                word_rules = self.hashcat_rule['D'](word_rules,p)

            elif op == 'replace':

                # Detecting global replacement such as sXY, l, u, C, c is a non
                # trivial problem because different characters may be added or
                # removed from the word by other rules. A reliable way to solve
                # this problem is to apply all of the rules the the source word
                # and keep track of its state at any given time. At the same
                # time, global replacement rules can be tested by completing
                # the rest of the rules using a simplified engine.

                # The sequence of if statements determines the priority of rules

                # This rule was made obsolete by a prior global replacement
                if word_rules[p] == password[p]:
                    if self.debug: print "\t[*] Advanced Processing Obsolete Rule: %s - %s" % (word_rules, " ".join(hashcat_rules))

                # Swapping rules
                elif p < len(password)-1 and p < len(word_rules)-1 and word_rules[p] == password[p+1] and word_rules[p+1] == password[p]:
                    # Swap first two characters
                    if p == 0 and self.generate_simple_hashcat_rules( self.hashcat_rule['k'](word_rules), rules[i+1:],password):
                        hashcat_rules.append("k")
                        word_rules = self.hashcat_rule['k'](word_rules)
                    # Swap last two characters
                    elif p == len(word_rules)-2 and self.generate_simple_hashcat_rules( self.hashcat_rule['K'](word_rules), rules[i+1:],password):
                        hashcat_rules.append("K")
                        word_rules = self.hashcat_rule['K'](word_rules)
                    # Swap any two characters (only adjacent swapping is supported)
                    elif self.generate_simple_hashcat_rules( self.hashcat_rule['*'](word_rules,p,p+1), rules[i+1:],password):
                        hashcat_rules.append("*%s%s" % (self.int_to_hashcat(p),self.int_to_hashcat(p+1)))
                        word_rules = self.hashcat_rule['*'](word_rules,p,p+1)
                    else:
                        hashcat_rules.append("o%s%s" % (self.int_to_hashcat(p),password[p]))
                        word_rules = self.hashcat_rule['o'](word_rules,p,password[p])
               
                # Case Toggle: Uppercased a letter
                elif word_rules[p].islower() and word_rules[p].upper() == password[p]:

                    # Toggle the case of all characters in word (mixed cases)
                    if password_upper and password_lower and self.generate_simple_hashcat_rules( self.hashcat_rule['t'](word_rules), rules[i+1:],password):
                        hashcat_rules.append("t")
                        word_rules = self.hashcat_rule['t'](word_rules)

                    # Capitalize all letters
                    elif self.generate_simple_hashcat_rules( self.hashcat_rule['u'](word_rules), rules[i+1:],password):
                        hashcat_rules.append("u")
                        word_rules = self.hashcat_rule['u'](word_rules)

                    # Capitalize the first letter
                    elif p == 0 and self.generate_simple_hashcat_rules( self.hashcat_rule['c'](word_rules), rules[i+1:],password):
                        hashcat_rules.append("c")
                        word_rules = self.hashcat_rule['c'](word_rules)

                    # Toggle the case of characters at position N
                    else:
                        hashcat_rules.append("T%s" % self.int_to_hashcat(p))
                        word_rules = self.hashcat_rule['T'](word_rules,p)

                # Case Toggle: Lowercased a letter
                elif word_rules[p].isupper() and word_rules[p].lower() == password[p]:

                    # Toggle the case of all characters in word (mixed cases)
                    if password_upper and password_lower and self.generate_simple_hashcat_rules( self.hashcat_rule['t'](word_rules), rules[i+1:],password):
                        hashcat_rules.append("t")
                        word_rules = self.hashcat_rule['t'](word_rules)

                    # Lowercase all letters
                    elif self.generate_simple_hashcat_rules( self.hashcat_rule['l'](word_rules), rules[i+1:],password):
                        hashcat_rules.append("l")
                        word_rules = self.hashcat_rule['l'](word_rules)

                    # Lowercase the first found character, uppercase the rest
                    elif p == 0 and self.generate_simple_hashcat_rules( self.hashcat_rule['C'](word_rules), rules[i+1:],password):
                        hashcat_rules.append("C")
                        word_rules = self.hashcat_rule['C'](word_rules)

                    # Toggle the case of characters at position N
                    else:
                        hashcat_rules.append("T%s" % self.int_to_hashcat(p))
                        word_rules = self.hashcat_rule['T'](word_rules,p)

                # Special case substitution of 'all' instances (1337 $p34k)
                elif word_rules[p].isalpha() and not password[p].isalpha() and self.generate_simple_hashcat_rules( self.hashcat_rule['s'](word_rules,word_rules[p],password[p]), rules[i+1:],password):

                    # If we have already detected this rule, then skip it thus
                    # reducing total rule count.
                    # BUG: Elisabeth => sE3 sl1 u o3Z sE3 => 31IZAB3TH
                    #if not "s%s%s" % (word_rules[p],password[p]) in hashcat_rules:
                    hashcat_rules.append("s%s%s" % (word_rules[p],password[p]))
                    word_rules = self.hashcat_rule['s'](word_rules,word_rules[p],password[p])
                    
                # Replace next character with current
                elif p < len(password)-1 and p < len(word_rules)-1 and password[p] == password[p+1] and password[p] == word_rules[p+1]:
                    hashcat_rules.append(".%s" % self.int_to_hashcat(p))
                    word_rules = self.hashcat_rule['.'](word_rules,p)

                # Replace previous character with current
                elif p > 0 and w > 0 and password[p] == password[p-1] and password[p] == word_rules[p-1]:
                    hashcat_rules.append(",%s" % self.int_to_hashcat(p))
                    word_rules = self.hashcat_rule[','](word_rules,p)

                # ASCII increment
                elif ord(word_rules[p]) + 1 == ord(password[p]):
                    hashcat_rules.append("+%s" % self.int_to_hashcat(p))
                    word_rules = self.hashcat_rule['+'](word_rules,p)

                # ASCII decrement
                elif ord(word_rules[p]) - 1 == ord(password[p]):
                    hashcat_rules.append("-%s" % self.int_to_hashcat(p))
                    word_rules = self.hashcat_rule['-'](word_rules,p)

                # SHIFT left
                elif ord(word_rules[p]) << 1 == ord(password[p]):
                    hashcat_rules.append("L%s" % self.int_to_hashcat(p))
                    word_rules = self.hashcat_rule['L'](word_rules,p)

                # SHIFT right
                elif ord(word_rules[p]) >> 1 == ord(password[p]):
                    hashcat_rules.append("R%s" % self.int_to_hashcat(p))
                    word_rules = self.hashcat_rule['R'](word_rules,p) 

                # Position based replacements.
                else:
                    hashcat_rules.append("o%s%s" % (self.int_to_hashcat(p),password[p]))
                    word_rules = self.hashcat_rule['o'](word_rules,p,password[p])            

        if self.debug: print "\t[*] Advanced Processing Ended: %s %s" % (word_rules, " ".join(hashcat_rules))

        ########################################################################
        # Prefix rules
        last_prefix = 0
        prefix_rules = list()
        for hashcat_rule in hashcat_rules:
            if hashcat_rule[0] == "i" and self.hashcat_to_int(hashcat_rule[1]) == last_prefix:
                prefix_rules.append("^%s" % hashcat_rule[2])
                last_prefix += 1
            elif len(prefix_rules):
                hashcat_rules = prefix_rules[::-1]+hashcat_rules[len(prefix_rules):]
                break
            else:
                break
        else:       
            hashcat_rules = prefix_rules[::-1]+hashcat_rules[len(prefix_rules):]

        ####################################################################
        # Appendix rules
        last_appendix = len(password) - 1
        appendix_rules = list()
        for hashcat_rule in hashcat_rules[::-1]:
            if hashcat_rule[0] == "i" and self.hashcat_to_int(hashcat_rule[1]) == last_appendix:
                appendix_rules.append("$%s" % hashcat_rule[2])
                last_appendix-= 1
            elif len(appendix_rules):
                hashcat_rules = hashcat_rules[:-len(appendix_rules)]+appendix_rules[::-1]
                break
            else:
                break
        else:
            hashcat_rules = hashcat_rules[:-len(appendix_rules)]+appendix_rules[::-1]

        ####################################################################
        # Truncate left rules
        last_precut = 0
        precut_rules = list()
        for hashcat_rule in hashcat_rules:
            if hashcat_rule[0] == "D" and self.hashcat_to_int(hashcat_rule[1]) == last_precut:
                precut_rules.append("[")
            elif len(precut_rules):
                hashcat_rules = precut_rules[::-1]+hashcat_rules[len(precut_rules):]
                break
            else:
                break
        else:       
            hashcat_rules = precut_rules[::-1]+hashcat_rules[len(precut_rules):]

        ####################################################################
        # Truncate right rules
        last_postcut = len(password)
        postcut_rules = list()
        for hashcat_rule in hashcat_rules[::-1]:
            
            if hashcat_rule[0] == "D" and self.hashcat_to_int(hashcat_rule[1]) >= last_postcut:
                postcut_rules.append("]")
            elif len(postcut_rules):
                hashcat_rules = hashcat_rules[:-len(postcut_rules)]+postcut_rules[::-1]
                break
            else:
                break
        else:
            hashcat_rules = hashcat_rules[:-len(postcut_rules)]+postcut_rules[::-1]

        # Check if rules result in the correct password
        if word_rules == password:
            return hashcat_rules
        else:
            if self.debug: print "[!] Advanced Processing FAILED: %s => %s => %s (%s)" % (word," ".join(hashcat_rules),password,word_rules)
            return None

    ############################################################################
    def print_hashcat_rules(self,hashcat_rules_collection):

        for word,rules,password in hashcat_rules_collection:
            hashcat_rules_str = " ".join(rules or [':'])
            if self.verbose: print "[+] %s => %s => %s" % (word, hashcat_rules_str, password)

            if not hashcat_rules_str in self.rule_stats: self.rule_stats[hashcat_rules_str] = 1
            else: self.rule_stats[hashcat_rules_str] += 1

            self.output_rules_f.write("%s\n" % hashcat_rules_str)
            self.output_words_f.write("%s\n" % word)

    ############################################################################
    def verify_hashcat_rules(self,hashcat_rules_collection):

        for word,rules,password in hashcat_rules_collection:

            f = open("%s/test.rule" % HASHCAT_PATH,'w')
            f.write(" ".join(rules))
            f.close()

            f = open("%s/test.word" % HASHCAT_PATH,'w')
            f.write(word)
            f.close()

            p = subprocess.Popen(["%s/hashcat-cli64.bin" % HASHCAT_PATH,"-r","%s/test.rule" % HASHCAT_PATH,"--stdout","%s/test.word" % HASHCAT_PATH], stdout=subprocess.PIPE)
            out, err = p.communicate()
            out = out.strip()

            if out == password:
                hashcat_rules_str = " ".join(rules or [':'])
                if self.verbose: print "[+] %s => %s => %s" % (word, hashcat_rules_str, password)

                if not hashcat_rules_str in self.rule_stats: self.rule_stats[hashcat_rules_str] = 1
                else: self.rule_stats[hashcat_rules_str] += 1

                self.output_rules_f.write("%s\n" % hashcat_rules_str)
                self.output_words_f.write("%s\n" % word)
            else:
                print "[!] Hashcat Verification FAILED: %s => %s => %s (%s)" % (word," ".join(rules or [':']),password,out)

    ############################################################################
    # Analyze a single password
    def analyze_password(self,password):
        if self.verbose: print "[*] Analyzing password: %s" % password
        if self.verbose: start_time = time.clock()


        # Skip all numeric passwords
        if password.isdigit(): 
            if self.verbose: print "[!] %s => {skipping numeric} => %s" % (password,password)
            self.numeric_stats_total += 1

        # Skip passwords with less than 25% of alpha character
        # TODO: Make random word detection more reliable based on word entropy.
        elif len([c for c in password if c.isalpha()]) < len(password)/4:
            print "[!] %s => {skipping alpha less than 25%%} => %s" % (password,password)
            self.special_stats_total += 1

        # Only check english ascii passwords for now, add more languages in the next version
        elif [c for c in password if ord(c) < 32 or ord(c) > 126]:
            if self.verbose: print "[!] %s => {skipping non ascii english} => %s" % (password,password)
            self.foreign_stats_total += 1

        # Analyze the password
        else:

            if not password in self.password_stats: self.password_stats[password] = 1
            else: self.password_stats[password] += 1

            # Short-cut words already in the dictionary
            if self.enchant.check(password):

                # Record password as a source word for stats
                if not password in self.word_stats: self.word_stats[password] = 1
                else: self.word_stats[password] += 1

                hashcat_rules_collection = [(password,[],password)]

            # Generate rules for words not in the dictionary
            else:

                # Generate source words list
                words_collection = self.generate_words_collection(password)

                # Generate levenshtein rules collection for each source word
                lev_rules_collection = []
                for word,matrix,password in words_collection:

                    # Generate multiple paths to get from word to password
                    lev_rules = self.levenshtein_reverse_path(matrix,word,password)
                    for lev_rule in lev_rules:
                        lev_rules_collection.append((word,lev_rule,password))

                # Generate hashcat rules collection
                hashcat_rules_collection = self.generate_hashcat_rules_collection(lev_rules_collection)

            # Print complete for each source word for the original password
            if self.hashcat:
                self.verify_hashcat_rules(hashcat_rules_collection)
            else:
                self.print_hashcat_rules(hashcat_rules_collection)

        if self.verbose: print "[*] Finished analysis in %.2f seconds" % (time.clock()-start_time)

    ############################################################################
    # Analyze passwords file
    def analyze_passwords_file(self,passwords_file):
        print "[*] Analyzing passwords file: %s:" % passwords_file

        f = open(passwords_file,'r')

        password_count = 0
        analysis_start = time.clock()
        try:        
            for password in f:
                password = password.strip()
                if len(password) > 0:

                    if password_count != 0 and password_count % 1000 == 0:
                        current_analysis_time = time.clock() - analysis_start
                        if not self.quiet: print "[*] Processed %d passwords in %.2f seconds at the rate of %.2f p/sec" % (password_count, current_analysis_time, float(password_count)/current_analysis_time )

                    password_count += 1
                    self.analyze_password(password)
        except (KeyboardInterrupt, SystemExit):
            print "\n[*] Rulegen was interrupted."


        analysis_time = time.clock() - analysis_start
        print "[*] Finished processing %d passwords in %.2f seconds at the rate of %.2f p/sec" % (password_count, analysis_time, float(password_count)/analysis_time )

        password_stats_total = sum(self.password_stats.values())
        print "[*] Analyzed %d passwords (%0.2f%%)" % (password_stats_total,float(password_stats_total)*100.0/float(password_count))
        print "[-] Skipped %d all numeric passwords (%0.2f%%)" % (self.numeric_stats_total, float(self.numeric_stats_total)*100.0/float(password_stats_total))
        print "[-] Skipped %d passwords with less than 25%% alpha characters (%0.2f%%)" % (self.special_stats_total, float(self.special_stats_total)*100.0/float(password_stats_total))
        print "[-] Skipped %d passwords with non ascii characters (%0.2f%%)" % (self.foreign_stats_total, float(self.foreign_stats_total)*100.0/float(password_stats_total))

        print "\n[*] Top 10 word statistics"
        top100_f = open("%s-top100.word" % self.basename, 'w')
        word_stats_total = sum(self.word_stats.values())
        for i,(word,count) in enumerate(sorted(self.word_stats.iteritems(), key=operator.itemgetter(1), reverse=True)[:100]):
            if i < 10: print "[+] %s - %d (%0.2f%%)" % (word, count, float(count)*100/float(word_stats_total))
            top100_f.write("%s\n" % word)
        top100_f.close()
        print "[*] Saving Top 100 words in %s-top100.word" % self.basename

        print "\n[*] Top 10 rule statistics"
        top100_f = open("%s-top100.rule" % self.basename, 'w')
        rule_stats_total = sum(self.rule_stats.values())
        for i,(rule,count) in enumerate(sorted(self.rule_stats.iteritems(), key=operator.itemgetter(1), reverse=True)[:100]):
            if i < 10: print "[+] %s - %d (%0.2f%%)" % (rule, count, float(count)*100/float(rule_stats_total))
            top100_f.write("%s\n" % rule)
        top100_f.close()
        print "[*] Saving Top 100 rules in %s-top100.rule" % self.basename

        print "\n[*] Top 10 password statistics"
        top100_f = open("%s-top100.password" % self.basename, 'w')
        password_stats_total = sum(self.password_stats.values())
        for i,(password,count) in enumerate(sorted(self.password_stats.iteritems(), key=operator.itemgetter(1), reverse=True)[:100]):
            if i < 10: print "[+] %s - %d (%0.2f%%)" % (password, count, float(count)*100/float(password_stats_total))
            top100_f.write("%s\n" % password)
        top100_f.close()
        print "[*] Saving Top 100 passwords in %s-top100.password" % self.basename

        f.close()

if __name__ == "__main__":

    header  = "                       _ \n"
    header += "     RuleGen 0.0.1    | |\n"  
    header += "      _ __   __ _  ___| | _\n"
    header += "     | '_ \ / _` |/ __| |/ /\n"
    header += "     | |_) | (_| | (__|   < \n"
    header += "     | .__/ \__,_|\___|_|\_\\\n"
    header += "     | |                    \n"
    header += "     |_| iphelix@thesprawl.org\n"
    header += "\n"


    parser = OptionParser("%prog [options] passwords.txt", version="%prog "+VERSION)

    parser.add_option("-b","--basename", help="Output base name. The following files will be generated: basename.words, basename.rules and basename.stats", default="analysis",metavar="rockyou")
    parser.add_option("-w","--wordlist", help="Use a custom wordlist for rule analysis.", metavar="wiki.dict")
    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")

    wordtune = OptionGroup(parser, "Fine tune source word generation:")
    wordtune.add_option("--maxworddist", help="Maximum word edit distance (Levenshtein)", type="int", default=10, metavar="10")
    wordtune.add_option("--maxwords", help="Maximum number of source word candidates to consider", type="int", default=5, metavar="5")
    wordtune.add_option("--morewords", help="Consider suboptimal source word candidates", action="store_true", default=False)
    wordtune.add_option("--simplewords", help="Generate simple source words for given passwords", action="store_true", default=False)
    parser.add_option_group(wordtune)

    ruletune = OptionGroup(parser, "Fine tune rule generation:")
    ruletune.add_option("--maxrulelen", help="Maximum number of operations in a single rule", type="int", default=10, metavar="10")
    ruletune.add_option("--maxrules", help="Maximum number of rules to consider", type="int", default=5, metavar="5")
    ruletune.add_option("--morerules", help="Generate suboptimal rules", action="store_true", default=False)
    ruletune.add_option("--simplerules", help="Generate simple rules insert,delete,hashcat",action="store_true", default=False)
    parser.add_option_group(ruletune)

    spelltune = OptionGroup(parser, "Fine tune spell checker engine:")
    spelltune.add_option("--providers", help="Comma-separated list of provider engines", default="aspell,myspell", metavar="aspell,myspell")
    parser.add_option_group(spelltune)

    debug = OptionGroup(parser, "Debuggin options:")
    debug.add_option("-v","--verbose", help="Show verbose information.", action="store_true", default=False)
    debug.add_option("-d","--debug", help="Debug rules.", action="store_true", default=False)
    debug.add_option("--password", help="Process the last argument as a password not a file.", action="store_true", default=False)
    debug.add_option("--word", help="Use a custom word for rule analysis", metavar="Password")
    debug.add_option("--hashcat", help="Test generated rules with hashcat-cli", action="store_true", default=False)
    parser.add_option_group(debug)

    (options, args) = parser.parse_args()

    # Print program header
    if not options.quiet:
        print header

    if len(args) < 1:
        parser.error("no passwords file specified")
        exit(1)

    rulegen = RuleGen(language="en", providers=options.providers, basename=options.basename)

    # Finetuning word generation
    rulegen.max_word_dist=options.maxworddist
    rulegen.max_words=options.maxwords
    rulegen.more_words=options.morewords
    rulegen.simple_words=options.simplewords

    # Finetuning rule generation
    rulegen.max_rule_len=options.maxrulelen
    rulegen.max_rules=options.maxrules
    rulegen.more_rules=options.morerules
    rulegen.simple_rules=options.simplerules

    # Debugging options
    rulegen.word = options.word
    rulegen.verbose=options.verbose
    rulegen.debug = options.debug
    rulegen.hashcat = options.hashcat
    rulegen.quiet = options.quiet

    # Custom wordlist
    if not options.word:
        if options.wordlist: rulegen.load_custom_wordlist(options.wordlist)
        print "[*] Using Enchant '%s' module. For best results please install" % rulegen.enchant.provider.name
        print "    '%s' module language dictionaries." % rulegen.enchant.provider.name

    if not options.quiet:
        print "[*] Saving rules to %s.rule" % options.basename
        print "[*] Saving words to %s.word" % options.basename
        print "[*] Press Ctrl-C to end execution and generate statistical analysis."

    # Analyze a single password or several passwords in a file
    if options.password: rulegen.analyze_password(args[0])
    else: rulegen.analyze_passwords_file(args[0])