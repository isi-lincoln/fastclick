#ifndef CLICK_XORMSG__HH
#define CLICK_XORMSG__HH

#include <unordered_map>
#include <vector>
#include <mutex> // cache handling
#include <chrono> // timer
#include <tuple>

//#include <click/element.hh>
#include <click/batchelement.hh>
#include <click/timer.hh>
//#include <click/task.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <include/click/packet.hh> // packet defn.

#include "xorproto.hh"

CLICK_DECLS

class PacketData {
    public:
	Packet *pkt; // packet data itself
        unsigned long long id; // unique identifier
        std::chrono::high_resolution_clock::time_point timestamp;
	std::string data;

        // constructors
        PacketData() {}
        PacketData(Packet *p, unsigned long long i, std::chrono::high_resolution_clock::time_point ts) : pkt(p), id(i), timestamp(ts) {
            data = std::string(reinterpret_cast<const char *>(p->data()), p->length());
	}
        ~PacketData();

	std::string GetData() {
            return data;
	}

	unsigned long GetDataLength() {
            return data.length();
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

const unsigned func_encode = 0;
const unsigned func_decode = 1;
const unsigned func_forward = 2;

class XORMsg : public BatchElement {

    // 0: encode, 1: decode
    uint8_t _function;

    // symbols to use (assume 3 minimum)
    uint8_t _symbols;

    // latency for stray packets that dont have other packets
    // to XOR with
    unsigned long _latency;

    // timer for each time check
    unsigned long _timer;

    // mtu of each link if known prior
    unsigned long _mtu;

    // if the latency is 0, disable threading
    bool _disable_threads;

    // threads
    unsigned _threads;

    public:
        XORMsg();
        ~XORMsg();

        std::unordered_map<uint32_t, std::vector<PacketData*> > send_storage; 
        std::unordered_map<uint64_t, std::vector<std::tuple<uint8_t, std::string, unsigned long long> > > recv_storage;
        Spinlock elock;
        Spinlock dlock;
        std::unordered_map<uint32_t, PacketBatch* > ebatch; 
        std::unordered_map<uint32_t, PacketBatch* > dbatch; 

        std::unordered_map<uint64_t, std::string> solutions;

        const char *class_name() const { return "XORMsg"; }
        const char *port_count() const { return "1-/1-"; } // depending on directionality, 1/3+ or 3+/1
        const char *processing() const { return PUSH; } // push processing

        // for settings of element when creating it e.g., SSMsg(3,2)
        int configure(Vector<String> &conf, ErrorHandler *errh);
        int initialize(ErrorHandler *errh);

        // push required for push element (see processing)
        void push(int port, Packet *p);

        // make these public functions to inherit members
        //void encode(int port, Packet *p);
        //void decode(int port, Packet *p);
        void encode(int port, unsigned long longest, PacketBatch *pb);
        void decode(int port, PacketBatch *pb);
        void forward(int port, Packet *p);

        void send_packets(std::vector<XORProto*> pkts, const unsigned char* nh, const unsigned char* mh, unsigned long dhost);
	void latency_checker();

	// for handling the multithreading / task management
	bool run_task(Task *task);
	// push but for batch operations
	// 
#if HAVE_BATCH
	void push_batch(int port, PacketBatch *p);
#endif

    private:
        class State {
            public:
                //State() : encode_batch(0), decode_batch(0), timers(0) {};
                State() : encode_batch(0), decode_batch(0), tasks(0) {};
                std::unordered_map<uint32_t, PacketBatch* > encode_batch; 
                std::unordered_map<uint32_t, PacketBatch* > decode_batch; 
                //Timer*  timers;
                Task*  tasks;

        };

        per_thread<State> _state;
};


CLICK_ENDDECLS

#endif
