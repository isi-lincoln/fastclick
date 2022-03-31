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
#include <algorithm> // sort

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
    printf("in encode\n");
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
    printf("after mac header checks\n");

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

    printf("aftera ip header checks\n");


    // we want to retrieve the ip header information, mainly the ipv4 dest
    const unsigned char *nh = p->network_header();
    const click_ip *iph = p->ip_header();

    unsigned long iplen = iph->ip_hl << 2;
    unsigned long total_length = p->length();
    unsigned long header_length = sizeof(click_ether)+sizeof(click_ip);
    unsigned long data_length = total_length - header_length;

    unsigned long dst_host = IPAddress(iph->ip_dst.s_addr);

    int version = 0;

    // we need to serialize the packet, so we will serialize it as a string
    unsigned char* dtemp;
    dtemp = (unsigned char*) malloc(total_length);
    memcpy(dtemp, p->data(), total_length);
    std::string sdtemp((char*) dtemp, total_length);

    // so now we are going to be using a mutex and our class map
    // to store packets until we reach the window threshold (3).

    // lock before we start working on map
    send_mut.lock();

    // check if destination is in packet queue send
    auto t = pkt_send.find(dst_host);

    // if destination missing from packet send, add packet - wait for more.
    if (t == pkt_send.end()) {
        printf("[none] adding %s to list\n", IPAddress(dst_host).s().c_str());
        pkt_send[dst_host].push_back(sdtemp);
        send_mut.unlock();
        return;
    }

    // _ifaces must be at least 3
    // if the number of packets plus this packet is less than 3/interfaces
    // add this packet to the send and wait for more
    if (pkt_send[dst_host].size()+1 < _ifaces) {
        printf("[under] adding %s to list\n", IPAddress(dst_host).s().c_str());
        pkt_send[dst_host].push_back(sdtemp);
        send_mut.unlock();
        return;
    }


    // we've passed the previous checks, so we have 2 stored in map, plus
    // this packet we are operating on now.
    printf("have enough packets to begin xor'ing\n");

    /*
    for (int i = 0; i < total_length; i++){
         printf("%02x", *(p->data()+i)&0xff);
    }
    printf("\n");
    for (int i = 0; i < total_length; i++){
         printf("%02x", *(sdtemp.c_str()+i)&0xff);
    }
    printf("\n");
    */

    // now we are going to take those packets out of the map, and orientate
    // this vector such that the longest packet in bytes is at the front of
    // the vector while the smallest is at the back.  This will help us with
    // applying padding of packets given we know with respect to the largest,
    // the total size ordering and how to apply the pad.
    //
    // we solve c a b  => x.Order(c), y.Order(a), z.Order(b)
    //
    std::vector<std::string> str_vec;
    str_vec.push_back(sdtemp);

    for (auto x : pkt_send[dst_host]) {
        str_vec.push_back(x);
    }

    std::vector<std::string> orig_vec = str_vec;

    // this sort is largest to smallest based on packet size
    std::sort( str_vec.begin( ), str_vec.end( ), [ ]( const std::string lhs, const std::string rhs ) {
        return lhs.size() > rhs.size();
    });

    // the mapping between length and order
    std::vector<uint8_t> shuffle;
    for (int i = 0; i < orig_vec.size(); i++ ) {
        for (int j = 0; j < str_vec.size(); j++ ) {
		if (orig_vec[i].compare(str_vec[j]) == 0){
			shuffle.push_back(j);
			break;
		}
	}
    }
    printf("orig order:\n");
    for (auto x : orig_vec) {
        printf("%ld ", x.size());
    }
    printf("\n");

    printf("new order:\n");
    for (auto x : shuffle) {
        printf("%d ", x);
    }
    printf("\n");


    std::vector<Packet*> pkt_vec;
    for (auto x : str_vec) {
        Packet *data = Packet::make(x.c_str(), x.length());
        pkt_vec.push_back(data);
    }

    /*
    std::vector<Packet*> pkt_vec;
    pkt_vec.push_back(p);

    for (auto x : pkt_send[dst_host]) {
        Packet *data = Packet::make(x.c_str(), x.length());
        pkt_vec.push_back(data);
    }

    // this sort is largest to smallest based on packet length
    std::sort( pkt_vec.begin( ), pkt_vec.end( ), [ ]( const Packet* lhs, const Packet* rhs ) {
        return lhs->length() > rhs->length();
    });
    */

    unsigned long longest= pkt_vec[0]->length();
    //printf("pkt lengths: a: %ld, b: %ld, c: %ld\n", pkt_vec[0]->length(), pkt_vec[1]->length(), pkt_vec[2]->length());

    // create an array of xor header packets for sending out
    XORProto *xorpkt_arr[3];

    // now lets create the xor packets.
    // we will create _iface variations, but lets think of that as 3 concretely for now
    // 1: pkt1 ^ pkt2 ^ pkt3
    // 2: pkt1 ^ pkt2 (xor 1 computes pkt3)
    // 3: pkt2 ^ pkt3 (xor 1 computes pkt1) [final step is take 2,3 computations xor 1 to get pk2]

    unsigned long bpad = longest-pkt_vec[1]->length();
    unsigned long cpad = longest-pkt_vec[2]->length();
    printf("setting pads: b: %ld, c: %ld\n", bpad, cpad);

    // i'll start with hand crafting these
    xorpkt_arr[0] = new XORProto;
    xorpkt_arr[0]->Len = longest;
    xorpkt_arr[0]->BPadd = bpad;
    xorpkt_arr[0]->CPadd = cpad;
    xorpkt_arr[0]->Version = version;
    xorpkt_arr[0]->Flowid = _flowid++;

    // generates 4 bytes of *random
    std::random_device rd;

    unsigned char newB[longest];
    unsigned char newC[longest];
    memcpy(&newB, pkt_vec[1]->data(), longest-bpad);
    memcpy(&newC, pkt_vec[2]->data(), longest-cpad);

    // very performance inefficient, better to do a single insert than many.
    // better to maximize rng generation    

    // this is the end of the data after we put() to make the packet longest.
    // so this loop is going from end_data() towards data() filling in unallocated
    // memory with some psuedo rng.
    //
    printf("lb: %ld, lc: %ld, longest: %ld\n", longest-bpad, longest-cpad, longest);

    /*
    for (int i = longest-bpad; i < longest; i++) {
       uint8_t rng = rd() & 0xff; // this is 32 bits, so we could be smart or lazy
       memcpy(&newB+i, &rng, sizeof(uint8_t));
    }
    for (int i = longest-cpad; i < longest; i++) {
       uint8_t rng = rd() & 0xff; // this is 32 bits, so we could be smart or lazy
       memcpy(&newC+i, &rng, sizeof(uint8_t));
    }
    */
    printf("b\n");


    printf("a\n");
    for (int i = 0; i < longest; i++){
        uint8_t t = (*(pkt_vec[0]->data()+i))&0xff;  // a ^ b ^ c
        printf("%02x", t);
    }
    printf("\n");
    printf("b\n");
    for (int i = 0; i < longest; i++){
        uint8_t t = (*(newB+i))&0xff;  // a ^ b ^ c
        printf("%02x", t);
    }
    printf("\n");
    printf("c\n");
    for (int i = 0; i < longest; i++){
        uint8_t t = (*(newC+i))&0xff;  // a ^ b ^ c
        printf("%02x", t);
    }
    printf("\n");


    // now we add to them.

    for (int i = 0; i < 3; ++i) {

        if (i != 0) {
            xorpkt_arr[i] = new XORProto;
            memcpy(xorpkt_arr[i], xorpkt_arr[0], sizeof(XORProto));
        }

	xorpkt_arr[i]->Order = shuffle[i];
	xorpkt_arr[i]->Pktid = i;

        printf("sent. flow: %lu, pkt: %u, len: %lu\n", xorpkt_arr[0]->Flowid, i, longest);

        // clear data field of packet
        memset(xorpkt_arr[i]->Data, 0, XORPROTO_DATA_LEN);

        const unsigned char *dp = xorpkt_arr[i]->Data;
        const unsigned char *ap = pkt_vec[0]->data();
        const unsigned char *bp = newB;
        const unsigned char *cp = newC;
        switch(i) {
            case 0:
                 printf("x\n");
                 for (int i = 0; i < longest; i++){
                     uint8_t t = (*(ap+i)^*(bp+i)^*(cp+i))&0xff;  // a ^ b ^ c
                     memcpy((void*)(dp+i), &t, sizeof(uint8_t)); 
                     printf("%02x", t);
                 }
                 printf("\n");
                 break;
            case 1:
                 printf("y\n");
                 for (int i = 0; i < longest; i++){
                     uint8_t t = (*(ap+i)^*(bp+i))&0xff;	  // a ^ b
                     memcpy((void*)(dp+i), &t, sizeof(uint8_t)); 
                     printf("%02x", t);
                 }
                 printf("\n");
                 break;
            case 2:
                 printf("z\n");
                 for (int i = 0; i < longest; i++){
                     uint8_t t = (*(bp+i)^*(cp+i))&0xff;	  // b ^ c
                     memcpy((void*)(dp+i), &t, sizeof(uint8_t)); 
                     printf("%02x", t);
                 }
                 printf("\n");
                 break;
            default:
                 break;
        }
        WritablePacket *data = Packet::make(xorpkt_arr[i], sizeof(XORProto)+header_length);
        // we done screwed up.
        if (!data) return;

        // add space at the front to put back on the old ip and mac headers
        Packet *ip_pkt = data->push(sizeof(click_ip));
        memcpy((void*)ip_pkt->data(), nh, sizeof(click_ip));

        Packet *new_pkt = data->push_mac_header(sizeof(click_ether));
        memcpy((void*)new_pkt->data(), mh, sizeof(click_ether));

        // remove extra unused data at end of packet
        new_pkt->take(XORPROTO_DATA_LEN-longest+header_length);


        const click_ip *xa = reinterpret_cast<const click_ip *>(new_pkt->data()+sizeof(click_ether));

        std::cout << IPAddress(xa->ip_src.s_addr).s().c_str()  << " -> " << IPAddress(xa->ip_dst.s_addr).s().c_str() << "\n";


        // send packet out the given port
        output(i).push(new_pkt);

        printf("send: after push\n");
    }

    // remove all the packets from the queue that we just sent, then release mutex
    pkt_send.erase(dst_host);
    send_mut.unlock();
    printf("send: after unlock\n");
    
    for (int i = 0; i < 3; i++){
       delete(xorpkt_arr[i]);
    }
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
    std::cout << IPAddress(iph->ip_src.s_addr).s().c_str()  << " -> " << IPAddress(iph->ip_dst.s_addr).s().c_str() << "\n";

    // following from when we encoded our data and put our xor data into
    // the pkt data field, we now need to extract it
    const XORProto *xorpkt = reinterpret_cast<const XORProto *>(p->data()+header_length);
    unsigned long encode_length = xorpkt->Len;
    long unsigned flow = xorpkt->Flowid;
    long unsigned pktid = xorpkt->Pktid;

    printf("recv'd. flow: %lu, pkt: %lu, len: %lu, order: %u\n", flow, pktid, encode_length, xorpkt->Order);

    // allocate memory for the xor data to store in vector.
    unsigned char* dtemp;
    dtemp = (unsigned char*) malloc(sizeof(XORProto)+encode_length);
    memcpy(dtemp, p->data()+header_length, sizeof(XORProto)+encode_length); // only want the xor header and data

    // lock before we start working on map
    recv_mut.lock();

    auto t = pkt_recv.find(dst_host);

    if (t == pkt_recv.end()) {
        printf("[nh] adding %s:%lu to recv\n", IPAddress(dst_host).s().c_str(), flow);
        printf("id: %ld\n", pktid);
        pkt_recv[dst_host][flow].push_back(dtemp);
        recv_mut.unlock();
	for (int i = 0; i < data_length; i++){
	     printf("%02x", *(p->data()+i)&0xff);
	}
        printf("\n");
        return;
    }

    // this is the container/map for this dst_host
    auto dst_host_map = pkt_recv.at(dst_host);
    auto flowid = dst_host_map.find(flow);

    // map exists but there is no flowid, so add it
    if (flowid == dst_host_map.end()) {
        printf("[nf] adding %s:%lu to recv\n", IPAddress(dst_host).s().c_str(), flow);
        printf("id: %ld\n", pktid);
        pkt_recv[dst_host][flow].push_back(dtemp);
        recv_mut.unlock();
	for (int i = 0; i < data_length; i++){
	     printf("%02x", *(p->data()+i)&0xff);
	}
        printf("\n");
        return;
    }


    // flowids do exist in the map, so check if we need to append ours
    // or if we are ready to do some computation
    //
    // including this packet, we still do not have enough to compute
    if (pkt_recv[dst_host][flow].size()+1 < _ifaces) {
        printf("[under] adding %s:%lu to recv\n", IPAddress(dst_host).s().c_str(), flow);
        printf("id: %ld\n", pktid);
        pkt_recv[dst_host][flow].push_back(dtemp);
        recv_mut.unlock();
	for (int i = 0; i < data_length; i++){
	     printf("%02x", *(p->data()+i)&0xff);
	}
        printf("\n");
        return;
    }

    printf("have enough packets to reconstruct\n");

    // so now we have all packets, lets put them in a vector based on their pktid
    std::vector<const XORProto*> pkt_vec;
    pkt_vec.push_back(xorpkt);

    /*
    printf("id: %ld\n", pktid);
    for (int i = 0; i < data_length; i++){
	printf("%x", *(p->data()+i)&0xff);
    }
    printf("\n");
    */

    for (auto & x : pkt_recv[dst_host][flow]) {
    	const XORProto *xorp = reinterpret_cast<const XORProto *>(x);
        pkt_vec.push_back(xorp);
    }

    // this sort is smallest to largest based on packet id
    std::sort( pkt_vec.begin( ), pkt_vec.end( ), [ ]( const XORProto* lhs, const XORProto* rhs ) {
        return lhs->Pktid < rhs->Pktid;
    });

    // showuld have 3 in here now
    for (auto & x : pkt_vec) {
        printf("flow: %lu, pkt: %d\n", x->Flowid, x->Pktid);
    }

    printf("x\n");
    for (int i = 0; i < total_length; i++){
         printf("%02x", *(pkt_vec[0]->Data+i)&0xff);
    }
    printf("\n");
    printf("y\n");
    for (int i = 0; i < total_length; i++){
         printf("%02x", *(pkt_vec[1]->Data+i)&0xff);
    }
    printf("\n");
    printf("z\n");
    for (int i = 0; i < total_length; i++){
         printf("%02x", *(pkt_vec[2]->Data+i)&0xff);
    }
    printf("\n");

 
    unsigned long longest = xorpkt->Len;

    unsigned long bpad = xorpkt->BPadd;
    unsigned long cpad = xorpkt->CPadd;

    printf("longest: %ld, bpad: %ld, cpad: %ld\n", longest, bpad, cpad);

    WritablePacket* a = Packet::make(NULL, longest);
    WritablePacket* b = Packet::make(NULL, longest-bpad);
    WritablePacket* c = Packet::make(NULL, longest-cpad);

    const unsigned char *xp = pkt_vec[0]->Data; // a^b^c
    const unsigned char *yp = pkt_vec[1]->Data; // a^b
    const unsigned char *zp = pkt_vec[2]->Data; // b^c

    const unsigned char *ap = a->data();
    const unsigned char *bp = b->data();
    const unsigned char *cp = c->data();

    printf("c\n");
    // 1: pkt1 ^ pkt2 ^ pkt3

    // compute solution to matrix - solve for c (a ^ b ^ c ^ ( a ^ b)) => c
    // C: pkt1 ^ pkt2 (xor 1 computes pkt3)
    for (int i = 0; i < longest; i++){
        uint8_t t = (*(xp+i)^*(yp+i))&0xff;
        printf("%02x", t);
        memcpy((void*)(cp+i), &t, sizeof(uint8_t)); 
    }
    printf("\n");

    printf("a\n");
    // solve for a ( a ^ b ^ c ^ (b ^ c ))  => a
    // A: pkt2 ^ pkt3 (xor 1 computes pkt1)
    for (int i = 0; i < longest-bpad; i++){
        uint8_t t = (*(xp+i)^*(zp+i))&0xff;
        printf("%02x", t);
        memcpy((void*)(ap+i), &t, sizeof(uint8_t)); 
    }
    printf("\n");

    printf("b\n");
    // solve for b ( a ^ b ^ ( a)) => b
    for (int i = 0; i < longest-cpad; i++){
        uint8_t t = (*(yp+i)^*(cp+i))&0xff;
        printf("%02x", t);
        memcpy((void*)(bp+i), &t, sizeof(uint8_t)); 
    }
    printf("\n");

    const click_ip *xa = reinterpret_cast<const click_ip *>(a->data()+sizeof(click_ether));
    const click_ip *xb = reinterpret_cast<const click_ip *>(b->data()+sizeof(click_ether));
    const click_ip *xc = reinterpret_cast<const click_ip *>(c->data()+sizeof(click_ether));

    a->set_mac_header(a->data());
    b->set_mac_header(b->data());
    c->set_mac_header(c->data());

    //std::cout << IPAddress(xa->ip_src.s_addr).s().c_str()  << " -> " << IPAddress(xa->ip_dst.s_addr).s().c_str() << "\n";
    //std::cout << IPAddress(xb->ip_src.s_addr).s().c_str()  << " -> " << IPAddress(xb->ip_dst.s_addr).s().c_str() << "\n";
    //std::cout << IPAddress(xc->ip_src.s_addr).s().c_str()  << " -> " << IPAddress(xc->ip_dst.s_addr).s().c_str() << "\n";

    std::vector<std::tuple<uint8_t, Packet*>> send_vec;
    send_vec.push_back(std::make_tuple(pkt_vec[0]->Order,a));
    send_vec.push_back(std::make_tuple(pkt_vec[1]->Order,b));
    send_vec.push_back(std::make_tuple(pkt_vec[2]->Order,c));

    std::sort( send_vec.begin( ), send_vec.end( ), [ ]( const std::tuple<uint8_t, Packet*> lhs, const std::tuple<uint8_t, Packet*> rhs ) {
        return std::get<0>(lhs) > std::get<0>(rhs);
    });

    output(0).push(std::get<1>(send_vec[0]));
    output(0).push(std::get<1>(send_vec[1]));
    output(0).push(std::get<1>(send_vec[2]));

    /*
    output(0).push(a); // largest
    output(1).push(b);
    output(2).push(c); // smallest
    */

    recv_mut.unlock();
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
    printf("in push\n");
    // TODO: packet length bounds check.
    if (p->length() > 5000) {
        // too large
    }


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
