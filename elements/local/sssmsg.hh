#ifndef CLICK_SSSMSG__HH
#define CLICK_SSSMSG__HH

#include <click/element.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>

CLICK_DECLS

/*
=c
SSSMsg()
=s
Generates a SSS Msg packet using an IPv4 packet as input.
=d
The input packet data must be a valid IPv4 packet.
*/
class SSSMsg : public Element {
	//Packet **gen_pkt(Packet *p, uint8_t shares, uint8_t threshold);
	int headroom = sizeof(click_ether);
	uint8_t _shares; // number of encoded packets to create/send
	uint8_t _threshold; // number required by recv. to reconstruct
    bool _encrypt; // should we be encrypting or decrypting

	public:
		SSSMsg();
		~SSSMsg();

		const char *class_name() const { return "SSSMsg"; }
		const char *port_count() const { return "PORTS_1_1X2"; }
		const char *processing() const { return "h"; } // push processing

		// for settings of element when creating it e.g., SSMsg(3,2)
		int configure(Vector<String> &conf, ErrorHandler *errh);

		void push(int port, Packet *p);
};

CLICK_ENDDECLS

#endif
