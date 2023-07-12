#ifndef CLICK_SSSMSG__HH
#define CLICK_SSSMSG__HH

#include <unordered_map>
#include <vector>
#include <mutex> // cache handling

#include <click/element.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <click/batchelement.hh>
#include <click/timer.hh>
#include <click/task.hh>

#include "sssproto.hh"

CLICK_DECLS

/*
=c
SSSMsg()
=s
Generates a SSS Msg packet using an IPv4 packet as input.
=d
The input packet data must be a valid IPv4 packet.
*/


class SSSMsg : public BatchElement {
    int headroom = sizeof(click_ether);
    uint8_t _shares; // number of encoded packets to create/send
    uint8_t _threshold; // number required by recv. to reconstruct
    uint8_t _function; // encode / decode
    uint32_t _timer; // when handling time outs or timer-based actions
    uint32_t _mtu; // max MTU of link - otherwise we need to fragment
    int _pkt_size; // size of packets
    const unsigned func_encrypt = 0;
    const unsigned func_decrypt = 1;

    public:
        SSSMsg();
        ~SSSMsg();

        std::unordered_map<uint64_t, std::unordered_map<uint64_t, std::vector<std::string> > > storage; 
        std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint64_t> > completed; 
        std::mutex cache_mut; // mutex for critical section

        const char *class_name() const { return "SSSMsg"; }
        const char *port_count() const { return "1-/1-"; } // depending on directionality, 1/3+ or 3+/1
        const char *processing() const { return PUSH; } // push processing

        // for settings of element when creating it e.g., SSMsg(3,2)
        int configure(Vector<String> &conf, ErrorHandler *errh);
        int initialize(ErrorHandler *errh);

        // push required for push element (see processing)
        void push(int port, Packet *p);

#if HAVE_BATCH
        void push_batch(int port, PacketBatch *p);
        void run_timer(Timer *timer);
        bool run_task(Task *task);
        void encrypt2(Packet *p);
        void decrypt2(std::vector<Packet*> pb);
        Spinlock dlock;
        std::unordered_map<uint64_t, std::vector<Packet*> > flow_map; 
        bool loop_helper();
#endif

        // make these public functions to inherit members
        void encrypt(int port, Packet *p);
        void decrypt(int port, Packet *p);

        std::vector<std::string> SplitData(int threshold, int nShares, std::string secret);
        std::string RecoverData(int thresh, std::vector<std::string> shares);


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
