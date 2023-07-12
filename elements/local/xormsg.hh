#ifndef CLICK_XORMSG__HH
#define CLICK_XORMSG__HH

#include <unordered_map>
#include <vector>
#include <mutex> // cache handling
#include <chrono> // timer
#include <tuple>
#include <map>

//#include <click/element.hh>
#include <click/batchelement.hh>
#include <click/timer.hh>
//#include <click/task.hh>
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


class XORMsg : public BatchElement {

    // 0: encode, 1: decode
    uint8_t _function;
    const unsigned func_encode = 0;
    const unsigned func_decode = 1;

    // symbols to use (assume 3 minimum)
    uint8_t _symbols;

    // timer for each time check
    unsigned long _timer;

    // mtu of each link if known prior
    unsigned long _mtu;

    // threads
    unsigned _threads;

    // packet size
    // 0 = do nothing, - = means random, + means fixed length
    int _pkt_size;

    public:
        XORMsg();
        ~XORMsg();

        Spinlock dlock;
        Spinlock plock;
        
        //std::vector<std::pair<uint64_t, Timestamp>> sorted_ids;
        std::unordered_map<uint64_t, std::vector<Packet*> > decode_map; 
        //std::unordered_map<uint8_t, std::vector<Packet*> > encode_send_map; 
        std::vector<PacketBatch*> pb_mem;

        const char *class_name() const { return "XORMsg"; }
        const char *port_count() const { return "1-/1-"; } // depending on directionality, 1/3+ or 3+/1
        const char *processing() const { return PUSH; } // push processing

        // for settings of element when creating it e.g., SSMsg(3,2)
        int configure(Vector<String> &conf, ErrorHandler *errh);
        int initialize(ErrorHandler *errh);

        // push required for push element (see processing)
        void push(int port, Packet *p);

        // make these public functions to inherit members
        void encode(int port, unsigned long longest, std::vector<Packet*> pb);
        void decode(int port, std::vector<Packet*> pb);

        void send_packets(std::vector<XORProto*> pkts, const unsigned char* nh, const unsigned char* mh, unsigned long dhost);

        // for handling the multithreading / task management
        bool loop_helper();
        bool run_task(Task *task);
        void run_timer(Timer *timer);

#if HAVE_BATCH
    void push_batch(int port, PacketBatch *p);
#endif

    private:
        class State {
            public:
                //State() : encode_batch(0), decode_batch(0), timers(0) {};
                //State() : encode_batch(0), decode_batch(0), tasks(0), timers(0) {};
                State() : tasks(0), timers(0) {};
                //std::unordered_map<uint32_t, PacketBatch* > encode_batch; 
                //std::unordered_map<uint32_t, PacketBatch* > decode_batch; 
                Timer*  timers;
                Task*  tasks;
        };

        per_thread<State> _state;
};


CLICK_ENDDECLS

#endif
