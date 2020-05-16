import pefile
import sys

malware_file = sys.argv[1]
pe = pefile.PE(malware_file)

malware = False
addr = []
ints = []
names = []
count = 0
i = 0

if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
	#print "%s \t %s \t %s"  % (hex(exp.address + pe.OPTIONAL_HEADER.ImageBase), exp.name, exp.ordinal)
        addr.append(hex(exp.address + pe.OPTIONAL_HEADER.ImageBase))
	names.append(exp.name)

#rule 1
str = addr[0]
for x in addr:
	if x != str:
		count = 0
	if x == str:
		count += 1
	if count == 3:
		malware = True
		print "\nThis is malware! Rule 1 broken"
		break

#rule 2
count = 1 #reset count from prev rule

for x in addr: #convert hex mem addr to dec mem addr
	ints.append(int(x, 0))

offset = ints[1] - ints[0] #test rule 2
for x in range(1, len(ints)):
	if ints[x] - offset == ints[(x-1)]:
		if offset == 0:
			count = 0
		count += 1
	if ints[x] - offset != ints[(x-1)]:
		offset = ints[x] - ints[(x-1)]
	if count == 3:
		malware = True
		print "\nThis is malware! Rule 2 broken"
		break

#rule 3
names.sort()
for x in range(1, len(names)):
	if names[x] == names [(x-1)]:
		malware = True
		print "\nThis is malware! Rule 3 broken"
		break

if malware == False:
	print "No malware found!"
