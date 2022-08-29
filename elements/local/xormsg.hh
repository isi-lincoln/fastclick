#ifndef CLICK_XORMSG__HH
#define CLICK_XORMSG__HH

#include <unordered_map>
#include <vector>
#include <mutex> // cache handling

#include <click/element.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <include/click/packet.hh> // packet defn.

#include "xorproto.hh"

CLICK_DECLS

/*
=c
XORMsg()
=s
Generates a XOR Msg packet using an IPv4 packet as input.
=d
The input packet data must be a valid IPv4 packet.
*/
class XORMsg : public Element {
	uint8_t _ifaces; // number of links out

	// 0: encode, 1: decode
	uint8_t _function;

    // unique identifiers for the xor'd packets
	uint64_t _sym_a;
	uint64_t _sym_b;


	public:
		XORMsg();
		~XORMsg();
		// key1: ipv4 destination, value packet
		std::unordered_map<uint32_t, std::vector<std::string> > pkt_send; 
		// key1: ipv4 destination, key2: flow id, value: packet
		std::unordered_map<uint32_t, std::unordered_map<uint32_t, std::vector<unsigned char*> > > pkt_recv; 
		std::mutex send_mut; // mutex for critical section
		std::mutex recv_mut; // mutex for critical section

		const char *class_name() const { return "XORMsg"; }
		const char *port_count() const { return "1-/1-"; } // depending on directionality, 1/3+ or 3+/1
		const char *processing() const { return PUSH; } // push processing

		// for settings of element when creating it e.g., SSMsg(3,2)
		int configure(Vector<String> &conf, ErrorHandler *errh);
		int initialize(ErrorHandler *errh);

		// push required for push element (see processing)
		void push(int port, Packet *p);

		// make these public functions to inherit members
		void encode(int port, Packet *p);
		void decode(int port, Packet *p);
};

CLICK_ENDDECLS

#endif
