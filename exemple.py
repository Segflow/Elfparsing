#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
#    Copyright (C) 2012-06 Jonathan Salwan - http://www.twitter.com/jonathansalwan
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from sys import argv, exit
from Elfparsing import Elf

if __name__ == "__main__":

   if len(argv) < 2:
      print "Syntax: %s <binary>" %(argv[0])
      exit(-1)

   binary = Elf(argv[1])
   if binary.isElf():
      print "Is a Elf binary"
      print "Entry point : %x" %(binary.getEntryPoint())

      print "Section .text addr %x" %(binary.getSectionDataByName(".text", "sh_addr"))
      section_text = binary.extractRawSectionByName(".text")
      print "Size section .text : %d" %(len(section_text)) # same result with binary.getSectionDataByName(".text", "sh_size")

      if binary.symbolsFound():
         print "Symbols found"
         print "Addr of main function : %x" %(binary.getSymbolAddrByName("main"))
   else:
      print "Is not a Elf binary."

   exit(0)

