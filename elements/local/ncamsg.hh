#ifndef CLICK_NCAMSG__HH
#define CLICK_NCAMSG__HH

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

#include "ncaproto.hh"

CLICK_DECLS


/*
=c
NCAMsg()
=s
Generates a Coded Msg packet using an IPv4 packet as input.
=d
The input packet data must be a valid IPv4 packet.
*/


class NCAMsg : public BatchElement {

    // TODO: initialization of protocol
    // should handshake these values
    uint8_t _links = 3;
    uint32_t _pp = 0x11d;

    // 0: encode, 1: decode
    uint8_t _function;
    const unsigned func_encode = 0;
    const unsigned func_decode = 1;

    // timer for each time check or use task
    unsigned long _timer;

    // mtu of each link if known prior
    unsigned long _mtu;

    // threads
    unsigned _threads;

    // packet size
    // 0 = do nothing, - = means random, + means fixed length
    int _pkt_size;

    public:
        NCAMsg();
        ~NCAMsg();

        Spinlock dlock;
        
        std::unordered_map<uint64_t, std::vector<Packet*> > decode_map; 
        std::vector<PacketBatch*> pb_mem;

        const char *class_name() const { return "NCAMsg"; }
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

        void send_packets(std::vector<NCAProto*> pkts, const unsigned char* nh, const unsigned char* mh, unsigned long dhost);

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
                State() : tasks(0), timers(0) {};
                Timer*  timers;
                Task*  tasks;
        };

        per_thread<State> _state;
};


CLICK_ENDDECLS

#endif
