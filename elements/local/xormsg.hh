#ifndef CLICK_XORMSG__HH
#define CLICK_XORMSG__HH

#include <unordered_map>
#include <vector>
#include <mutex> // cache handling
#include <chrono> // timer
#include <tuple>

#include <click/element.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <include/click/packet.hh> // packet defn.

#include "xorproto.hh"

CLICK_DECLS

class PacketData{
    public:
	const unsigned char *nh;
	const unsigned char *mh;

        std::string data;
        unsigned long long id; // unique identifier

        std::chrono::high_resolution_clock::time_point timestamp;

        // constructors
        PacketData() {}
        PacketData(std::string d, unsigned long long i, std::chrono::high_resolution_clock::time_point ts) : data(d), id(i), timestamp(ts) {}
        ~PacketData();

	void SetHeaders(const unsigned char *n, const unsigned char *m) {
	    nh = n;
	    mh = m;
	}
};

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

    // symbols to use (assume 3 minimum)
    uint8_t _symbols;

    // latency for stray packets that dont have other packets
    // to XOR with
    unsigned long _latency;

    // unique identifiers for the xor'd packets
    uint64_t _sym_a;
    uint64_t _sym_b;


    public:
        XORMsg();
        ~XORMsg();

        std::unordered_map<uint32_t, std::vector<PacketData*> > send_storage; 
        std::unordered_map<uint64_t, std::vector<std::tuple<uint8_t, std::string, unsigned long long> > > recv_storage;
        std::unordered_map<uint64_t, std::string> solutions;

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
        void forward(int port, Packet *p);

        void send_packets(std::vector<XORProto*> pkts, const unsigned char* nh, const unsigned char* mh, unsigned long dhost);
	void latency_checker();
};


CLICK_ENDDECLS

#endif
