// click files
#include <click/config.h>
#include <click/args.hh> // Args, for configure
#include <click/ipaddress.hh> // ip address
#include <include/click/packet.hh> // pkt make
#include <click/etheraddress.hh> // eth address
#include <clicknet/ip.h> // ip header checksum
#include <clicknet/icmp.h> // icmp header checksum
#include <clicknet/tcp.h> // tcp header checksum
#include <clicknet/udp.h> // udp header checksum

// protocol files
#include "xorproto.hh"
#include "xormsg.hh"

// handling shared cache
//#include <mutex>          // std::mutex
#include <assert.h>    // sanity check
#include<iostream>
#include <random>  // random device

CLICK_DECLS

XORMsg::XORMsg() { };
XORMsg::~XORMsg() { };

// allow the user to configure the ifaces and threshold amounts
int XORMsg::configure(Vector<String> &conf, ErrorHandler *errh) {
    uint8_t ifaces;
    uint8_t function;
    if (Args(conf, this, errh)
        .read_mp("INTERFACES", ifaces) // 
        .read_mp("PURPOSE", function) // positional
        .complete() < 0){
            return -1;
    }

    _ifaces = ifaces;
    _function = function;

    return 0;
}

/*
 * encode the 3 packets into 3 xor'd packets
 * 
 * takes in 3 packets per send window.  Each packet is then
 * added to a linear combination, and each combination is sent
 * over one of atleast 3 network interfaces.  So no data is sent
 * in the clear, and per link, it is impossible to compute the packet
 * unless another packet is known or information is leaked or is
 * highly repetivite.
*/
void XORMsg::encode(int ports, Packet *p) {
    // packet is too large
    if (p->length() > XORPROTO_DATA_LEN) {
        fprintf(stderr, "packet length too large for xoring\n");
        return;
    }

    // saftey checks
    if (!p->has_mac_header()) {
        fprintf(stderr, "xor doesnt know how to handle this packet (no L2).\n");
        return;
    }

    const click_ether *mch = (click_ether *) p->data();
    const unsigned char *mh = p->mac_header();

    // only handle ip packets
    if (htons(mch->ether_type) != ETHERTYPE_IP) {
        fprintf(stderr, "xor handling non-ipv4 packet: %x\n", htons(mch->ether_type));
        return;
    }

    // packets need to be annotated before parsing
    if (!p->has_network_header()) {
        fprintf(stderr, "xor doesnt know how to handle this packet (no L3).\n");
        return;
    }

    printf("in encode\n");

    // we want to retrieve the ip header information, mainly the ipv4 dest
    const unsigned char *nh = p->network_header();
    const click_ip *iph = p->ip_header();

    unsigned long iplen = iph->ip_hl << 2;
    unsigned long total_length = p->length();
    unsigned long header_length = sizeof(click_ether)+sizeof(click_ip);
    unsigned long data_length = total_length - header_length;

    unsigned long dst_host = IPAddress(iph->ip_dst.s_addr);

    int version = 0;
    int flowid = _flowid++; // packet tracking


    // so now we are going to be using a mutex and our class map
    // to store packets until we reach the window threshold (3).

    // lock before we start working on map
    send_mut.lock();

    // check if destination is in packet queue send
    auto t = pkt_send.find(dst_host);

    // if destination missing from packet send, add packet - wait for more.
    if (t == pkt_send.end()) {
        printf("[none] adding %s to list\n", IPAddress(dst_host).s().c_str());
        pkt_send[dst_host].push_back(p);
        send_mut.unlock();
        return;
    }

    // _ifaces must be at least 3
    // if the number of packets plus this packet is less than 3/interfaces
    // add this packet to the send and wait for more
    if (pkt_send[dst_host].size()+1 < _ifaces) {
        printf("[under] adding %s to list\n", IPAddress(dst_host).s().c_str());
        pkt_send[dst_host].push_back(p);
        send_mut.unlock();
        return;
    }

    // we've passed the previous checks, so we have 2 stored in map, plus
    // this packet we are operating on now.
    printf("have enough packets to begin xor'ing\n");

    // now we are going to take those packets out of the map, and orientate
    // this vector such that the longest packet in bytes is at the front of
    // the vector while the smallest is at the back.  This will help us with
    // applying padding of packets given we know with respect to the largest,
    // the total size ordering and how to apply the pad.
    std::vector<Packet*> pkt_vec;
    unsigned long longest = p->length();
    unsigned long smallest = p->length();
    pkt_vec.push_back(p);

    for (auto x : pkt_send[dst_host]) {
        if (x->length() >= longest) {
            longest = x->length();
            pkt_vec.insert(pkt_vec.begin(), x); // front of queue
            continue;
        }
        if (x->length() <= smallest) {
            smallest = x->length();
            pkt_vec.push_back(x); // back of the queue
            continue;
        }
    }

    printf("after vector\n");

    // create an array of xor header packets for sending out
    XORProto *xorpkt_arr[3];

    // now lets create the xor packets.
    // we will create _iface variations, but lets think of that as 3 concretely for now
    // 1: pkt1 ^ pkt2 ^ pkt3
    // 2: pkt1 ^ pkt2 (xor 1 computes pkt3)
    // 3: pkt2 ^ pkt3 (xor 1 computes pkt1) [final step is take 2,3 computations xor 1 to get pk2]

    unsigned long bpad = longest-pkt_vec[1]->length();
    unsigned long cpad = longest-pkt_vec[2]->length();

    // i'll start with hand crafting these
    xorpkt_arr[0] = new XORProto;
    xorpkt_arr[0]->Len = longest;
    xorpkt_arr[0]->BPadd = bpad;
    xorpkt_arr[0]->CPadd = cpad;
    xorpkt_arr[0]->Version = version;
    xorpkt_arr[0]->Flowid = flowid;

    // generates 4 bytes of *random
    std::random_device rd;

    // need to create new B/C packets with same length as A, will always be in bytes
    WritablePacket *newB = pkt_vec[1]->put(bpad);
    WritablePacket *newC = pkt_vec[2]->put(cpad);

    // very performance inefficient, better to do a single insert than many.
    // better to maximize rng generation    

    // this is the end of the data after we put() to make the packet longest.
    // so this loop is going from end_data() towards data() filling in unallocated
    // memory with some psuedo rng.
    for (int i = 1; i < bpad+1; i++) { // offset as one, because we need to initial rewind by 1
       uint8_t rng = rd() & 0xff; // this is 32 bits, so we could be smart or lazy
       memcpy(newB->end_data()-i, &rng, sizeof(uint8_t));
    }

    const unsigned char *zz = newC->end_data();
    for (int i = 1; i < cpad+1; i++){
       uint8_t rng = rd() & 0xff; // this is 32 bits, so we could be smart or lazy
       memcpy((void*)zz, &rng, sizeof(uint8_t));
       zz--; // go back a byte towards data()
    }

    // now we add to them.

    for (int i = 0; i < 3; ++i) {
        WritablePacket *data;

        if (i != 0) {
            xorpkt_arr[i] = new XORProto;
            memcpy(xorpkt_arr[i], xorpkt_arr[0], sizeof(XORProto));
            data = Packet::make(pkt_vec[1]->data(), sizeof(XORProto)+header_length);
        } else {
            data = Packet::make(pkt_vec[0]->data(), sizeof(XORProto)+header_length);
        }
        // we done screwed up.
        if (!data) return;

	xorpkt_arr[i]->Pktid = i;

        // clear data field of packet
        memset(xorpkt_arr[i]->Data, 0, XORPROTO_DATA_LEN);

        const unsigned char *dp = data->data();
        const unsigned char *ap = pkt_vec[0]->data();
        const unsigned char *bp = newB->data();
        const unsigned char *cp = newC->data();
        switch(i) {
            case 0:
                 for (int i = 0; i < longest; i++){
                     uint8_t t = (*(ap+i)^*(bp+i)^*(cp+i))&0xff;
                     memcpy((void*)(dp+i), &t, sizeof(uint8_t)); 
                 }
                 break;
            case 1:
                 for (int i = 0; i < longest; i++){
                     uint8_t t = (*(ap+i)^*(bp+i))&0xff;
                     memcpy((void*)(dp+i), &t, sizeof(uint8_t)); 
                 }
                 break;
            case 2:
                 for (int i = 0; i < longest; i++){
                     uint8_t t = (*(bp+i)^*(cp+i))&0xff;
                     memcpy((void*)(dp+i), &t, sizeof(uint8_t)); 
                 }
                 break;
            default:
                 break;
        }
        // copy over packet
        memcpy(xorpkt_arr[i]->Data, data->data(), longest);

        // add space at the front to put back on the old ip and mac headers
        Packet *ip_pkt = data->push(sizeof(click_ip));
        memcpy((void*)ip_pkt->data(), nh, sizeof(click_ip));

        Packet *new_pkt = data->push_mac_header(sizeof(click_ether));
        memcpy((void*)new_pkt->data(), mh, sizeof(click_ether));

        // remove extra unused data at end of packet
        data->take(XORPROTO_DATA_LEN-longest);

        // send packet out the given port
        output(i).push(new_pkt);
    }

    // remove all the packets from the queue that we just sent, then release mutex
    pkt_send.erase(dst_host);
    send_mut.unlock();
}



/*
 * decode:  take in 3 packets of the same window (flowid).
 * and begin the decode process - have 3 variables and 3 knowns.
 *
*/
void XORMsg::decode(int ports, Packet *p) {

    printf("in decode\n");
    // packet is too large
    if (p->length() > XORPROTO_DATA_LEN) {
        fprintf(stderr, "packet length too large for xorting\n");
        return;
    }

    // saftey checks
    if (!p->has_mac_header()) {
        fprintf(stderr, "xor doesnt know how to handle this packet (no L2).\n");
        return;
    }

    const click_ether *mch = (click_ether *) p->data();
    const unsigned char *mach = p->mac_header();

    if (htons(mch->ether_type) != ETHERTYPE_IP) {
        fprintf(stderr, "xor handling non-ipv4 packet: %x\n", htons(mch->ether_type));
        return;
    }
    
    if (!p->has_network_header()) {
        fprintf(stderr, "xor doesnt know how to handle this packet (no L3).\n");
        return;
    }

    // we want to retrieve the headers to save for later
    // This requires the marking of the ip packet
    const click_ip *iph = p->ip_header();
    //const click_ip *iph = (click_ip*)(p->data()+sizeof(click_ether));
    unsigned long iplen = iph->ip_hl << 2;
    unsigned long total_length = p->length();
    unsigned long header_length = sizeof(click_ether) + sizeof(click_ip);
    unsigned long data_length = total_length - header_length;

    unsigned long dst_host = IPAddress(iph->ip_dst.s_addr);

    // following from when we encoded our data and put our xor data into
    // the pkt data field, we now need to extract it
    const XORProto *xorpkt = reinterpret_cast<const XORProto *>(p->data()+header_length);
    unsigned long encode_length = xorpkt->Len;
    long unsigned flow = xorpkt->Flowid;


    // lock before we start working on map
    recv_mut.lock();

    auto t = pkt_recv.find(dst_host);

    if (t == pkt_recv.end()) {
        printf("[nh] adding %s:%lu to recv\n", IPAddress(dst_host).s().c_str(), flow);
        pkt_recv[dst_host][flow].push_back(p);
        recv_mut.unlock();
        return;
    }

    // this is the container/map for this dst_host
    auto dst_host_map = pkt_recv.at(dst_host);
    auto flowid = dst_host_map.find(flow);

    // map exists but there is no flowid, so add it
    if (flowid == dst_host_map.end()) {
        printf("[nf] adding %s:%lu to recv\n", IPAddress(dst_host).s().c_str(), flow);
        pkt_recv[dst_host][flow].push_back(p);
        recv_mut.unlock();
        return;
    }

    // flowids do exist in the map, so check if we need to append ours
    // or if we are ready to do some computation
    //
    // including this packet, we still do not have enough to compute
    if (pkt_recv[dst_host][flow].size()+1 < _ifaces) {
        printf("[under] adding %s:%lu to recv\n", IPAddress(dst_host).s().c_str(), flow);
        pkt_recv[dst_host][flow].push_back(p);
        recv_mut.unlock();
        return;
    }

    printf("have enough packets to reconstruct\n");

    // so now we have all packets, lets put them in a vector based on their pktid
    std::vector<const XORProto*> pkt_vec;
    pkt_vec.push_back(xorpkt);
    unsigned int tail = xorpkt->Pktid;
    unsigned int head = xorpkt->Pktid;

    std::vector<Packet*> queue = pkt_recv[dst_host][flow];

    for (auto x : queue) {
    	const XORProto *xorp = reinterpret_cast<const XORProto *>(x->data()+header_length);
        if (xorp->Pktid >= tail) {
            pkt_vec.push_back(xorp);
            tail = xorp->Pktid;
        }
        if (xorp->Pktid <= head) {
            pkt_vec.insert(pkt_vec.begin(), xorp);
            head = xorp->Pktid;
        }
    }

    // 1: pkt1 ^ pkt2 ^ pkt3
    // 2: pkt1 ^ pkt2 (xor 1 computes pkt3)
    // 3: pkt2 ^ pkt3 (xor 1 computes pkt1) [final step is take 2,3 computations xor 1 to get pk2]
 
    const unsigned char *xp = pkt_vec[0]->Data;
    const unsigned char *yp = pkt_vec[1]->Data;
    const unsigned char *zp = pkt_vec[2]->Data;

    unsigned long longest = xorpkt->Len;
    WritablePacket* a = Packet::make(NULL, longest);
    WritablePacket* b = Packet::make(NULL, longest);
    WritablePacket* c = Packet::make(NULL, longest);
    const unsigned char *ap = a->data();
    const unsigned char *bp = b->data();
    const unsigned char *cp = c->data();

    // compute solution to matrix
    for (int i = 0; i < longest; i++){
        uint8_t t = (*(xp+i)^*(yp+i))&0xff;
        memcpy((void*)(cp+i), &t, sizeof(uint8_t)); 
    }
    for (int i = 0; i < longest; i++){
        uint8_t t = (*(xp+i)^*(zp+i))&0xff;
        memcpy((void*)(ap+i), &t, sizeof(uint8_t)); 
    }
    for (int i = 0; i < longest; i++){
        uint8_t t = (*(yp+i)^*(cp+i))&0xff;
        memcpy((void*)(bp+i), &t, sizeof(uint8_t)); 
    }

    unsigned long bpad = xorpkt->BPadd;
    unsigned long cpad = xorpkt->CPadd;
    b->take(bpad);
    c->take(cpad);


/*
    for (int i = 0; i< 3; i++) {
        Packet *data;
        switch(i){
            case: 0
                data = a;
                break;
            case: 1
                data = b;
                break;
            case: 0
                data = c;
                break;
        }
        // add space at the front to put back on the old ip and mac headers
        Packet *ip_pkt = data->push(sizeof(click_ip));
        memcpy((void*)ip_pkt->data(), nh, sizeof(click_ip));
    
        Packet *new_pkt = data->push_mac_header(sizeof(click_ether));
        memcpy((void*)new_pkt->data(), mh, sizeof(click_ether));
    
        // remove extra unused data at end of packet
        data->take(XORPROTO_DATA_LEN-longest);
    
        // send packet out the given port
        output(i).push(new_pkt);
    }
*/

   output(0).push(a);
   output(0).push(b);
   output(0).push(c);
}


// TODO random generation
// TODO bounds checking on overflow - does this matter? we will force app to manage staleness
int XORMsg::initialize(ErrorHandler *errh) {
    _flowid = 0; // shits and giggles we just always random this, 2**32 on collision for good times
    return 0;
}

/*
 * Generates a XORMsg packet from a packet.
 *
 * Requires that the packet is IP, and has been checked.
 *
 * So we recieve a packet, and we need create the encoded chunks
 * then send that out to each of the connected ports.
 */
void XORMsg::push(int ports, Packet *p) {

    // TODO: packet length bounds check.
    if (p->length() > 5000) {
        // too large
    }

    printf("in push\n");

    if (_function == 0) {
        encode(ports, p); // split packets
    } else if (_function == 1 ) {
        decode(ports, p);   // recombine packets
    } else {
        // panic
    }

    // free this packet
    p->kill();

    return;
};

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(XORMsg)
