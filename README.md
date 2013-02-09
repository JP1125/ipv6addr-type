ipv6addr-type
=============

classify IPv6 addresses based on Assignment Policy

---

### Assignment Policy

* SLAAC
	- use MAC address with 'ff:fe'
	- 2001:db8::1234:00ff:fe00:abcd
* Privacy
	- use random value
	- 2001:db8::1234:5678:90ab:cdef
* IPv4-based
	- use IPv4 information
	- 2001:db8::192:168:0:1
* Low-byte
	- use compression syntax
	- 2001:db8::1
* Wordy
	- use words and/or continuous value
	- 2001:db8::1111:aaaa:dead:beaf
* 6to4 (RFC3056)
	- 2002:IPV4:ADDR::/48
* ISATAP (RFC4214)
	- ::5EFE:<IPv4 ADDR>
* Teredo (RFC4380)
	- 2000:0000/32

* Manual
	- the others

