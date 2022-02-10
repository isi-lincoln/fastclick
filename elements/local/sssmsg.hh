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
	Packet *gen_pkt(Packet *p, uint8_t shares, uint8_t threshold);
	int headroom = sizeof(click_ether);

	public:
		SSSMsg();
		~SSSMsg();

		const char *class_name() const { return "SSSMsg"; }
		const char *port_count() const { return "1/1"; }
		const char *processing() const { return AGNOSTIC; }

		Packet *simple_action(Packet *p);
};

CLICK_ENDDECLS

#endif
