#!/bin/env python
##
 # classify IPv6 address based on Assignment Policy
 #
 # * COMMAND
 #	.pcap file は、IPv6 パケットのみ含むことが前提
 #	$ zcat input.pcap.gz | tcpdump -n -t -r- src port 25 or dst port 25 ... | python ipv6dump.py '0000-00-00' > output.csv
 #
 # * ATTENTION
 #	- Privacy でも偶然 SLAAC の形で生成されてしまった場合は、SLAAC に分類されてしまう
 #	- Privacy は、3桁以上（1ブロックのみ2桁を許容）のランダム値を抽出しているため、仮に Manual であっても Privacy に分類される
 #	- Wordy は、漏れがある可能性がある
 #
 # ( c ) @jp1125
 ##

import sys,re

# ftp, dns, http, ephemeral
gPort = ["25","53","80"]

# for TYPE
gMac = re.compile("ff:fe[0-9a-f]{2}:[0-9a-f]{0,4}$")			# SLAAC
gLow = re.compile("::([0-9a-f]{1,4})$")							# Low-byte
gIP4 = re.compile("((:(\d|\d\d|1\d\d|2[0-4]\d|25[0-5])){4})$")	# IPv4-based
gT64 = re.compile("^2002((:[0-9a-f]{1,4}){2})")					# 6to4
gIsa = re.compile(":5efe((:[0-9a-f]{1,4}){2})$")				# ISATAP
gTrd = re.compile("^2000:")										# Teredo
gPri1 = re.compile(":[0-9a-f]{2,4}:[0-9a-f]{3,4}:[0-9a-f]{3,4}:[0-9a-f]{3,4}$")	# Priacy
gPri2 = re.compile(":[0-9a-f]{3,4}:[0-9a-f]{2,4}:[0-9a-f]{3,4}:[0-9a-f]{3,4}$")	# Priacy
gPri3 = re.compile(":[0-9a-f]{3,4}:[0-9a-f]{3,4}:[0-9a-f]{2,4}:[0-9a-f]{3,4}$")	# Priacy
gPri4 = re.compile(":[0-9a-f]{3,4}:[0-9a-f]{3,4}:[0-9a-f]{3,4}:[0-9a-f]{2,4}$")	# Priacy
gWord = re.compile("(add|bed|dad|1ce|1:2eed|babe|beef|booc|cafe|c0de|c0ff:ee|dead|fade|face|feed|f00d|0000|1111|2222|3333|4444|5555|6666|7777|8888|9999|aaaa|bbbb|cccc|dddd|eeee|ffff)")	# Wordy

####

##
 # dump IPv6 address info
 #
 # 	* dump file format (.csv)
 # 		id,addr,type,prefix,as,src_dst,port,oui,low,word,ipv4,date
 ##
def dump(_date):
	pckt = re.compile("^vlan.*?IP6 (.*?)\.(.*?) > (.*?)\.(.*?): .*?$")
	ex = re.compile("frag")
	observed_pckt1 = []
	observed_pckt2 = []

	for line in sys.stdin:
		if (ex.search(line)):
			continue
		if (pckt.search(line)):
			pckt_grp = pckt.search(line)

			src_addr = pckt_grp.group(1)
			src_port = pckt_grp.group(2)
			dst_addr = pckt_grp.group(3)
			dst_port = pckt_grp.group(4)

			# e.g. A port against port 25 is 'eph25'
			if src_port in gPort:
				dst_port = "eph"+src_port
			if dst_port in gPort:
				src_port = "eph"+dst_port

			# ftp, dns, http, ephemeral
			if (src_port in gPort or dst_port in gPort):
				buf = "%s.%s>%s.%s" % (src_addr,src_port,dst_addr,dst_port)
				if buf in observed_pckt2 or buf in observed_pckt1:
					continue
				else:
					observed_pckt1.append(buf)
					observed_pckt2.append(buf)
					# look 3 packets
					if len(observed_pckt2)==3:
						observed_pckt2.pop(0)

				# extract src addr
				srcipv6_type = getType(src_addr)
				src_pref = get64Prefix(src_addr)
				src_oui  = ""
				src_low  = ""
				src_word = ""
				src_ipv4 = ""
				if ("SLAAC" in srcipv6_type[0]):
					src_oui  = getOui(src_addr)
					if src_oui=="":	# miss extract "ff:fe" as SLAAC
						srcipv6_type[0].replace("SLAAC", "")
						if srcipv6_type[0]=="":
							srcipv6_type[0]="Manual"
				if ("Low-byte"	in srcipv6_type[0]):
					src_low  = srcipv6_type[1]["Low-byte"]
				if ("Wordy"		in srcipv6_type[0]):
					src_word = srcipv6_type[1]["Wordy"]
				if ("IPv4"		in srcipv6_type[0]):
					src_ipv4 = srcipv6_type[1]["IPv4"]
				if ("6to4"		in srcipv6_type[0]):
					src_ipv4 = srcipv6_type[1]["6to4"]
				if ("ISATAP"	in srcipv6_type[0]):
					src_ipv4 = srcipv6_type[1]["ISATAP"]

				# extract dst addr
				dstipv6_type = getType(dst_addr)
				dst_pref = get64Prefix(dst_addr)
				dst_oui  = ""
				dst_low  = ""
				dst_word = ""
				dst_ipv4 = ""
				if ("SLAAC" in dstipv6_type[0]):
					dst_oui  = getOui(dst_addr)
					if dst_oui=="":	# miss extract "ff:fe" as SLAAC
						dstipv6_type[0].replace("SLAAC", "")
						if dstipv6_type[0]=="":
							dstipv6_type[0]="Manual"
				if ("Low-byte"	in dstipv6_type[0]):
					dst_low  = dstipv6_type[1]["Low-byte"]
				if ("Wordy"		in dstipv6_type[0]):
					dst_word = dstipv6_type[1]["Wordy"]
				if ("IPv4"		in dstipv6_type[0]):
					dst_ipv4 = dstipv6_type[1]["IPv4"]
				if ("6to4"		in dstipv6_type[0]):
					dst_ipv4 = dstipv6_type[1]["6to4"]
				if ("ISATAP"	in dstipv6_type[0]):
					dst_ipv4 = dstipv6_type[1]["ISATAP"]

				# dump
				# id,addr,type,prefix,as,port,oui,low,word,ipv4,date
				print "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % ("",src_addr,srcipv6_type[0],src_pref,"",src_port,src_oui,src_low,src_word,src_ipv4,_date)
				print "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % ("",dst_addr,dstipv6_type[0],dst_pref,"",dst_port,dst_oui,dst_low,dst_word,dst_ipv4,_date)


##
 # get Type of IPv6 address
 # 	type: SLAAC,Low-byte,ISATAP,IPv4,6to4,Teredo,Wordy,Privacy,Manual
 #	info: Low-byte, IPv4 addr in ISATAP, IPv4 addr, IPv4 addr in 6to4, Word
 #
 # 	_addr: IPv6 address
 # 	@return [type, additional info]
 ##
def getType(_addr):
	global gMac,gLow,gIsa,gIP4,gT64,gTrd,gWord,gPri1,gPri2,gPri3,gPri4
	ipv6_type = []
	additional_info  = {"Low-byte":"","ISATAP":"","6to4":"","IPv4":"","Wordy":""}

	if (gMac.search(_addr)):
		ipv6_type.append("SLAAC")

	if (gLow.search(_addr)):
		ipv6_type.append("Low-byte")
		buf_grp = gLow.search(_addr)
		additional_info["Low-byte"] = buf_grp.group(1)

	if (gIsa.search(_addr)):
		ipv6_type.append("ISATAP")
		buf_grp = gIsa.search(_addr)
		additional_info["ISATAP"] = buf_grp.group(1)[1:]

	if (gIP4.search(_addr)):
		ipv6_type.append("IPv4")
		buf_grp = gIP4.search(_addr)
		additional_info["IPv4"] = buf_grp.group(1)[1:]

	if (gT64.search(_addr)):
		ipv6_type.append("6to4")
		buf_grp = gT64.search(_addr)
		additional_info["6to4"] = buf_grp.group(1)[1:]

	if (gTrd.search(_addr)):
		ipv6_type.append("Teredo")

	if (gWord.search(_addr)):
		ipv6_type.append("Wordy")
		buf_grp = gWord.search(_addr)
		additional_info["Wordy"] = buf_grp.group(1)

	if ("SLAAC"  not in ipv6_type and
		"IPv4"   not in ipv6_type and
		"ISATAP" not in ipv6_type and
		(gPri1.search(_addr) or
		 gPri2.search(_addr) or
		 gPri3.search(_addr) or
		 gPri4.search(_addr))):
		ipv6_type.append("Privacy")

	# manual input
	if ipv6_type==["6to4"]:
		return ["6to4/Manual", additional_info]
	elif ipv6_type==[]:
		return ["Manual",""]
	else:
		return ["/".join(ipv6_type), additional_info]


##
 # get OUI from IPv6 address (SLAAC)
 #
 # 	_addr: IPv6 address
 # 	@return OUI or empty
 ##
def getOui(_addr):
	# for OUI
	oui_re1 = re.compile(".*?:.*?:.*?:.*?:(.*?):(.*?)ff:fe[0-9a-f]{2}:[0-9a-f]{0,4}$")
	oui_re2 = re.compile("::(.*?):(.*?)ff:fe[0-9a-f]{2}:[0-9a-f]{0,4}")
	oui_re3 = re.compile("::(.*?)ff:fe[0-9a-f]{2}:[0-9a-f]{0,4}$")

	## for U/G bit
	ug_hash = {"0":"2","1":"3","2":"0","3":"1",
			   "4":"6","5":"7","6":"4","7":"5",
			   "8":"a","9":"b","a":"8","b":"9",
			   "c":"e","d":"f","e":"c","f":"d"}

	oui_grp = ""
	if oui_re1.search(_addr):
		oui_grp = oui_re1.search(_addr)
	elif oui_re2.search(_addr):
		oui_grp = oui_re2.search(_addr)

	if oui_grp != "":
		oui_upper = oui_grp.group(1)

		# upper OUI
		# extract U/G bit
		oui0 = "0"
		ug   = "0"	# oui1
		oui2 = "00"
		if len(oui_upper) == 4:
			oui0 = oui_upper[0]
			ug   = oui_upper[1]
			oui2 = oui_upper[2:]
		elif len(oui_upper) == 3:
			ug   = oui_upper[0]
			oui2 = oui_upper[1:]
		elif len(oui_upper) == 2:
			oui2 = oui_upper
		elif len(oui_upper) == 1:
			oui2 = "0" + oui_upper

		# lower OUI
		oui_lower = oui_grp.group(2)
		if len(oui_lower)==1:
			oui3 = "0" + oui_lower
		elif len(oui_lower)==0:
			oui3 = "00"
		else:
			oui3 = oui_lower
		return oui0 + ug_hash[ug] + oui2 + oui3

	elif oui_re3.search(_addr):
		oui_grp = oui_re3.search(_addr)
		oui_str = oui_grp.group(1)
		if len(oui_str)==1:
			oui_str = "0" + oui_str
		elif oui_str0=="":
			oui_str = "00"
		return "0200" + oui_str

	else:
		return ""


##
 # get /64 Prefix from IPv6 address
 #
 # 	_addr: IPv6 address
 # 	@return PREFIX::64 or empty
 #  e.g.
 #		2001:db8::1234 -> 2001:db8::/64
 #		2001:db8:db8:db8:db8:db8:db8:db8 -> 2001:db8:db8:db8::/64
 ##
def get64Prefix(_addr):
	pre4 = re.compile("^(.+?):(.+?):(.+?):(.+?):")
	pre3 = re.compile("^(.+?):(.+?):(.+?):")
	pre2 = re.compile("^(.+?):(.+?):")
	pre1 = re.compile("^(.+?):")

	prefix=[]
	if pre4.search(_addr):
		p = pre4.search(_addr)
		prefix.append(p.group(1))
		prefix.append(p.group(2))
		prefix.append(p.group(3))
		prefix.append(p.group(4))
	elif pre3.search(_addr):
		p = pre3.search(_addr)
		prefix.append(p.group(1))
		prefix.append(p.group(2))
		prefix.append(p.group(3))
	elif pre2.search(_addr):
		p = pre2.search(_addr)
		prefix.append(p.group(1))
		prefix.append(p.group(2))
	elif pre1.search(_addr):
		p = pre1.search(_addr)
		prefix.append(p.group(1))

	if prefix != []:
		return ":".join(prefix) + "::/64"
	else:
		return ""


####

def usage():
	print "****"
	print "paramater is not satisfied."
	print "-- COMMAND --"
	print "zcat input.pcap.gz | tcpdump -n -t -r- vlan | python ipv6dump.py '0000-00-00' >> output.csv"
	print "****"
	print ""
	sys.exit()

if __name__=='__main__':
	try:
		args = sys.argv[1:]
		date = args[0]
	except:
		usage()

	dump(date)

