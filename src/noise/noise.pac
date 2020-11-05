%include binpac.pac
%include bro.pac

%extern{
	#include "events.bif.h"
%}

analyzer NOISE withcontext {
	connection: NOISE_Conn;
	flow:       NOISE_Flow;
};

%include noise-protocol.pac
%include noise-analyzer.pac
