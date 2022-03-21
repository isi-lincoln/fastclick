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
 * if only a single packet in the queue for too long, just send packet(s).
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

    if (htons(mch->ether_type) != ETHERTYPE_IP) {
        fprintf(stderr, "xor handling non-ipv4 packet: %x\n", htons(mch->ether_type));
        return;
    }

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


    // lock before we start working on vector
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

    printf("have enough packets to begin xor'ing\n");

    // we have enough to compute, create vector of the data
    std::vector<Packet*> pkt_vec;
    unsigned long longest = p->length();
    unsigned long smallest = p->length();
    pkt_vec.push_back(p);

    // because we hold the mutex, this should always be _ifaces in length
    // we will order the packets based on size to help later on.
    // pkt vector is largest [0] to smallest [2]
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
            memcpy(xorpkt_arr[i], xorpkt_arr[0], sizeof(XORProto));
            data = Packet::make(pkt_vec[0]->data(), sizeof(XORProto)+header_length);
        } else {
            data = Packet::make(pkt_vec[1]->data(), sizeof(XORProto)+header_length);
        }
        // we done screwed up.
        if (!data) return;

        // clear data field of packet
        memset(xorpkt_arr[i]->Data, 0, XORPROTO_DATA_LEN);

        const unsigned char *dp = data->data();
        const unsigned char *ap = pkt_vec[0]->data();
        const unsigned char *bp = newB->data();
        const unsigned char *cp = newC->data();
        switch(i) {
            case 0:
                 for (int i = 0; i < longest; i++){
                     memcpy((void*)dp, (void*)((uint8_t)*ap^(uint8_t)*bp^(uint8_t)*cp), sizeof(uint8_t));
                     dp++;
                     ap++;
                     bp++;
                     cp++;
                 }
                 break;
            case 1:
                 for (int i = 0; i < longest; i++){
                     memcpy((void*)dp, (void*)((uint8_t)*ap^(uint8_t)*bp), sizeof(uint8_t));
                     dp++;
                     ap++;
                     bp++;
                 }
                 break;
            case 2:
                 for (int i = 0; i < longest; i++){
                     memcpy((void*)dp, (void*)((uint8_t)*bp^(uint8_t)*cp), sizeof(uint8_t));
                     dp++;
                     bp++;
                     cp++;
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
 * agg
 *
 * takes in multiple encoded packet, decodes them, and sends a single
 * message out the interface.
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
    //std::cout << EtherAddress(mch->ether_shost).unparse().c_str() << " -> " << EtherAddress(mch->ether_dhost).unparse().c_str() << "\n";
    //printf("%s -> %s\n", IPAddress(iph->ip_src.s_addr).s().c_str(), IPAddress(iph->ip_dst.s_addr).s().c_str());
    
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

    // following from when we encoded our data and put our xor data into
    // the pkt data field, we now need to extract it
    const XORProto *xorpkt = reinterpret_cast<const XORProto *>(p->data()+header_length);
    unsigned long encode_length = xorpkt->Len;
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
