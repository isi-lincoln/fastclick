#ifndef CLICK_SSSMSG__HH
#define CLICK_SSSMSG__HH

#include <unordered_map>

#include <click/element.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>

//using namespace std;

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

 	// should we be encrypting/decrypting/forwarding
	// 0: encrypt, 1: decrypt, 2: forward
	uint8_t _function;

	// when we initialize for security we should pick randomly and
	// then we need to do overflow checking on 32bit
	uint32_t _flowid;

	/* will use this to store packets for decryption */
	// < host >: <id, pkt>
    	std::unordered_map<uint32_t, std::unordered_map<uint32_t, SSSProto>> storage; 

	public:
		SSSMsg();
		~SSSMsg();

		const char *class_name() const { return "SSSMsg"; }
		const char *port_count() const { return "PORTS_1_1X2"; }
		const char *processing() const { return "h"; } // push processing

		// for settings of element when creating it e.g., SSMsg(3,2)
		int configure(Vector<String> &conf, ErrorHandler *errh);

		// push required for push element (see processing)
		void push(int port, Packet *p);

		// make these public functions to inherit members
		void encrypt(int port, Packet *p);
		void decrypt(int port, Packet *p);
};

CLICK_ENDDECLS

#endif
