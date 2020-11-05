// Generated by binpac_quickstart

#ifndef ANALYZER_PROTOCOL_NOISE_NOISE_H
#define ANALYZER_PROTOCOL_NOISE_NOISE_H

#include "events.bif.h"


#include "analyzer/protocol/udp/UDP.h"

#include "noise_pac.h"

namespace analyzer { namespace NOISE {

class NOISE_Analyzer

: public analyzer::Analyzer {

public:
	NOISE_Analyzer(Connection* conn);
	virtual ~NOISE_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new NOISE_Analyzer(conn); }

protected:
	binpac::NOISE::NOISE_Conn* interp;
	
};

} } // namespace analyzer::* 

#endif
