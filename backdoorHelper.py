'''
Thrown together in a day, sorry for the sloppy code
Having "fun" with PEfiles...
A couple functions taken from https://github.com/v-p-b/peCloakCapstone/
'''

import pefile
import binascii
import re
import sys
from capstone import *

filename = sys.argv[1]
pe = pefile.PE(filename)
sections = [x for x in pe.sections]
entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase


def find_entry_point_section(pe, eop_rva):

    for section in sections:
        if section.contains_rva(eop_rva):
            return section

    return None


def firstInstruction(file_path):

    try:
        pe = pefile.PE(file_path, fast_load=True)
        # AddressOfEntryPoint if guaranteed to be the first byte executed.
        eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        code_section = find_entry_point_section(pe, eop)
        if not code_section:
            return

        print("[+] OPCODE TO REMEMBER... ( ENTRY ): "
              "{:#x} [size: {:#x}]".format(code_section.PointerToRawData,
                                          code_section.SizeOfRawData))
        # get first 10 bytes at entry point and dump them
        code_at_oep = code_section.get_data(eop, 10)
	global entryOpcode
	entryOpcode = '\\x' + '\\x'.join("{:02x}".format(ord(c)) for c in code_at_oep)
	print entryOpcode

    except pefile.PEFormatError as pe_err:
        print("[-] error while parsing file {}:\n\t{}".format(file_path, pe_err))


def hexMe():

	global hexed
	hexed = []

	with open(filename, 'rb') as file:
		content = file.read()
		hexPE = binascii.hexlify(content)
		hexed += re.findall('..', hexPE)

	print "[*] Binary stored as hex with a length of ", len(hexed), '\n'


def findCave(size):

	for section in sections:
		print "[?] Looking for a codecave in ", section.Name

		locationInFile = section.PointerToRawData
		virtualOffset = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
		rawSize = section.SizeOfRawData
		nullCount = 0

		for x in range(locationInFile, locationInFile+rawSize):

			if hexed[x] == '00':
				nullCount += 1
			else:
				nullCount = 0

			virtualOffset += 1

			if nullCount > size:
				print '[!]Cave found at ',  hex(virtualOffset-nullCount)
				nullCount = 0


def main():
	firstInstruction(filename)
	hexMe()
	findCave(int(sys.argv[2]))


if __name__ == "__main__":
	if len(sys.argv) != 3:
		print "**********************"
		print "USAGE: python backdoorHelper.py (PEFILE) (SHELLCODE LENGTH)"
		print "**********************"
		sys.exit()
	main()
