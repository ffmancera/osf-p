#!/usr/bin/python2

import argparse, textwrap

def parse_arguments():
	description_msg = '''\
			   This script reads a file containing p0f\'s raw
			   signature format and parses it to "pf.os" signature
			   format. To know more about p0f, please refer to
			   http://lcamtuf.coredump.cx/p0f3/.

			   If you have any problem adding your signature,
			   please do not hesitate to contact me at
			   ffmancera@riseup.net'''

	parser = argparse.ArgumentParser(description=textwrap.dedent(description_msg),
				         formatter_class=argparse.RawDescriptionHelpFormatter)
	required_arg = parser.add_argument_group('required arguments')
	required_arg.add_argument('-f', '--file', help='input file with the p0f\'s raw signatures', required=True)
	required_arg.add_argument('-o', '--output', help='output file with the "pf.os" signatures format', required=True)
	args = parser.parse_args()

	return args.file, args.output

def find_fingerprint(filename, output):
	try:
		file_object = open(filename, 'r')
	except:
		print('%s not found or you do not have permission to read it.' % filename)
		exit()

	osf_signatures = []

	for line in file_object:
		sig_elements = line.split(':')
		ittl_sum = sig_elements[1].split('+')
		ittl = int(ittl_sum[0]) + int(ittl_sum[1])

		if (sig_elements[2] == 0):
			olen = 60
		mss = int(sig_elements[3])
		wsize_tuple = sig_elements[4].split(',')

		if (wsize_tuple[0].split('*')[0] == 'mss'):
			wwww = 'S' + wsize_tuple[0].split('*')[1]
		elif (wsize_tuple[0].split('*')[0] == 'mtu'):
			wwww = 'T' + wsize_tuple[0].split('*')[1]
		elif (wsize_tuple[0].isdigit()):
			wwww = wsize_tuple[0]
		else:
			wwww = '*'

		scale = wsize_tuple[1]

		df = 0
		timestamp_type = 'T'
		quirks = sig_elements[6].split(',')
		for quirk in quirks:
			if (quirk == 'df'):
				df = 1
			elif (quirk == 'ts1-'):
				timestamp_type = timestamp_type + '0'
			else:
				continue

		olayout = sig_elements[5].split(',')
		options_seq = ''
		for i, option in enumerate(olayout):
			if (option == 'nop'):
				options_seq = options_seq + 'N'
			elif (option == 'mss'):
				options_seq = options_seq + 'M*'
			elif (option == 'ws'):
				options_seq = options_seq + 'W' + scale
			elif (option == 'sok'):
				options_seq = options_seq + 'S'
			elif (option == 'ts'):
				options_seq = options_seq + timestamp_type
			if (i == len(olayout) - 1):
				break
			options_seq = options_seq + ','

		osf_signatures.append(wwww + ":" + str(ittl) + ":" + str(df) + ":" + "60" + ":" + options_seq)

	file_object.close()
	write_signatures(osf_signatures, output)

def write_signatures(osf_signatures, output):
	output_file = open(output, 'a')

	for i, signature in enumerate(osf_signatures):
		print("Signature " + str(i+1) + "detected:\n")
		os_genre = raw_input("Introduce the OS genre:\n")
		os_version = raw_input("Introduce the OS version:\n")
		os_subtype = raw_input("Introduce the OS subtype:\n")
		os_details = raw_input("Introduce the OS details:\n")

		osf_formatted_signature = signature + ":" + os_genre + ":" + os_version + ":" + os_subtype + ":" + os_details
		print("Final result signature " + str(i) + ": " + osf_formatted_signature)
		output_file.write(osf_formatted_signature + "\n")

	print("All signatures have been written in " + output + ". Please consider to update the file with this new signature.")

if __name__ == "__main__":
	filename, output = parse_arguments()
	find_fingerprint(filename, output)
