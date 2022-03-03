#ifndef CLICK_SSSMSG__HH
#define CLICK_SSSMSG__HH

#include <unordered_map>
#include <vector>
//#include <mutex> // cache handling

#include <click/element.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>

#include "sssproto.hh"
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
        //std::mutex cache_mut;           // mutex for critical section

	/* will use this to store packets for decryption */
	// < host >: <id, pkt>
    	std::unordered_map<uint32_t, std::unordered_map<uint32_t, std::vector<const SSSProto*> > > storage; 
    	//std::unordered_map<uint32_t, std::unordered_map<uint32_t, bool> > complete;

	public:
		SSSMsg();
		~SSSMsg();


		const char *class_name() const { return "SSSMsg"; }
		const char *port_count() const { return "1-/1-"; } // depending on directionality, 1/3+ or 3+/1
		const char *processing() const { return PUSH; } // push processing

		// for settings of element when creating it e.g., SSMsg(3,2)
		int configure(Vector<String> &conf, ErrorHandler *errh);
		int initialize(ErrorHandler *errh);

		// push required for push element (see processing)
		void push(int port, Packet *p);

		// make these public functions to inherit members
		void encrypt(int port, Packet *p);
		void decrypt(int port, Packet *p);
		void forward(int port, Packet *p);

                std::vector<std::string> SplitData(int threshold, int nShares, std::string secret);
		std::string RecoverData(int thresh, std::vector<std::string> shares);
};

CLICK_ENDDECLS

#endif
