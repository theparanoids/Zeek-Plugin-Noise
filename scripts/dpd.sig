# Generated by binpac_quickstart

signature dpd_noise {
	
	ip-proto == udp
        payload /^\x01\x00\x00\x00/
	
	enable "noise"
}

