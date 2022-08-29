//#define DEBUG 1
#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...)    fprintf(stdout, fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args...)
#endif


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

//#include <mutex>          // std::mutex
#include <assert.h>    // sanity check
#include <iostream>

#include <iostream>
#include <cstdlib>
#include <sstream> // istream
#include <emmintrin.h> // _mm_loadu_si128

CLICK_DECLS

XORMsg::XORMsg() { };
XORMsg::~XORMsg() { };


// update IP packet checksum
void ip_check(WritablePacket *p) {
    click_ip *iph = (click_ip *) p->data();
    iph->ip_sum = 0;
    iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));
}

// allow the user to configure the shares and threshold amounts
int XORMsg::configure(Vector<String> &conf, ErrorHandler *errh) {
    uint8_t shares;
    uint8_t threshold;
    uint8_t function;
    if (Args(conf, this, errh)
        .read_mp("symbols", symbols) // positional
        .read_mp("PURPOSE", function) // positional
        .complete() < 0){
            return -1;
    }

    /*
     * if symbols is greater than two, then we need to create & manage
     * a matrix to track outstanding symbols and be intelligent about
     * the generation across xor'd packets
     */
    if (symbols > 2) {
        // print error
        return -1;
    }

    // having a single symbol makes no sense.
    if (symbols < 2) {
        return -1;
    }

    _symbols = symbols;
    _function = function;

    return 0;
}


XORProto* sub_encode(Packet* a, Packet *b) {
    unsigned long a_len = a->length();
    unsigned long b_len = b->length();
    unsigned long padding;
    unsigned long longest;
    unsigned long smallest;
    if (a_len > b_len) {
        padding = a_len-b_len;
        longest = a_len;
        smallest = b_len;
    } else {
        padding = b_len-a_len;
        longest = b_len;
        smallest = a_len;
    }

    XORProto xorpkt = new XORProto;
    xorpkt->SymbolA = rand();
    xorpkt->SymbolB = rand();
    xorpkt->Version = 0;
    xorpkt->Len = longest;
    memset(xorpkt->Data, 0, XORPROTO_DATA_LEN)

    // for sse/ssse 128 bit vectors maybe ifdef here for avx
    uint64_t chunks = smallest >> 4ULL;

    for (int i = 0; i < chunks ; ++i){
        // load our packets into vectors
        __m128i x = _mm_loadu_si128 (((__m128i *)a->data()) + i);
        __m128i y = _mm_loadu_si128 (((__m128i *)b->data()) + i);
        // xor and our vector back into our xor data buffer
        _mm_storeu_si128 (((__m128i *)xorpkt->Data) + i, _mm_xor_si128 (x, y));
    }

    // now the left over chunks (padding+vector alignment) we do by hand
    for (unsigned long j = chunks << 4ULL; j < smallest; ++j) {
        // check 1, vector alignment, if lets say our packet is 162 bits.
        // we get 1 full vector (128) and 34 left over bits.
        // we need to then take them as bytes (4 bytes) and 2 left over bits
        // I believe that click aligns on bytes, if not, we got a problem
        xorpkt->Data[j] = a->data()+j ^ b->data()+j;
    }
        

    for (unsigned long j = 0; j < padding; ++j) {
        // check 2, we are beyond smallest, into padding territory, so we need
        // being adding noise to xor to match the longest packet
        
        // TODO: noise/rand - but we want to know this noise, for the other packet we
        // send so we can cancel it out with the garbo
        xorpkt->Data[j] = a_len > b_len ? (a->data()+j+smallest)^j : (b->data()+j+smallest)^j;
    }


}

/*
 * Take x (2 for now) packets, and xor them together.
 * Then generate a noise packet for the destination's kernel
 * to toss that we can use to xor again to create 2 xor'd
 * paths.
 *
 * -> A  -- path1 --> A^B
 * -> B  -- path2 --> B^G (where G is noise)
*/

void XORMsg::encode(int ports, Packet *p) {
    // packet is too large
    if (p->length() > XORPROTO_DATA_LEN) {
        fprintf(stderr, "packet length too large for xor function\n");
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

    unsigned long total_length = p->length();

    DEBUG_PRINT("in encode: %lu\n", total_length);

    // taking as input a Packet
    // this packet has an ethernet header which we want to keep for decrypt
    // it also has the ip header, and the data contents.
    // we would ideally like to keep all this entact, then decrypt can fudge
    // the headers and checksum

    // we want to retrieve the ip header information, mainly the ipv4 dest
    const unsigned char *nh = p->network_header();
    const click_ip *iph = p->ip_header();

    // TODO: data assumptions on lengths
    unsigned long iplen = iph->ip_hl << 2;
    unsigned long header_length = DEFAULT_MAC_LEN + iplen;
    unsigned long data_length = total_length - header_length;

    // source ip address is the share host (originator of data)
    // ip_src is in_addr struct
    unsigned long src_host = IPAddress(iph->ip_src.s_addr);
    // initial version of protocol
    int version = 0;
    int flowid = _flowid++; // see notes on randomizing this for fun

    std::string str_data (reinterpret_cast<const char *>(p->data()+header_length), data_length);
    std::vector<std::string> encoded = XORMsg::SplitData(_threshold, _shares, str_data);

    //DEBUG_PRINT("Data In: %s -- %s\n",str_data.c_str(), str_data);
    //DEBUG_PRINT("Data In: %lu -- %lu -- %lu\n", strlen(str_data.c_str()), data_length, encoded[0].size());

    XORProto *xorpkt_arr[_shares];


    unsigned long new_pkt_size = 0;

    // now lets create the shares
    for (int i = 0; i < _shares; ++i) {
        xorpkt_arr[i] = new XORProto;
	// diff between data and encode is the xor
        xorpkt_arr[i]->Len = encoded[i].size();
        xorpkt_arr[i]->Sharehost = src_host;
        xorpkt_arr[i]->Version = version;
        xorpkt_arr[i]->Flowid = flowid;
        xorpkt_arr[i]->Shareid = i;
	//xorpkt_arr[i]->Magic = XORMAGIC;
	
	// write the XOR encoded data
        memcpy(xorpkt_arr[i]->Data, &encoded[i][0], encoded[i].size());

        // create our new packet, size is the header (XORProto), minus max data size - actual data size (gives us actual data size)
	// so our new packet should just be XORProto+XORData size
        WritablePacket *pkt = Packet::make(xorpkt_arr[i], (sizeof(XORProto)-(XORPROTO_DATA_LEN-encoded[i].size())));

        // we done screwed up.
	if (!pkt) return;

        // add space at the front to put back on the old ip and mac headers
	Packet *ip_pkt = pkt->push(sizeof(click_ip));
	memcpy((void*)ip_pkt->data(), nh, sizeof(click_ip));

	// update ip packet size = ip header + xor header + xor data
	// TODO/NOTE: these lines in overwritting the ip header are only needed when using Linux Forwarding.
        click_ip *iph2 = (click_ip *) ip_pkt->data();
	iph2->ip_len = ntohs( sizeof(click_ip) + (sizeof(XORProto)-(XORPROTO_DATA_LEN-encoded[i].size())) );
	// END NOTE

	// This sets/annotates the network header as well as pushes into packet
	Packet *new_pkt = pkt->push_mac_header(sizeof(click_ether));
	memcpy((void*)new_pkt->data(), mh, sizeof(click_ether));


        // update the ip header checksum for the next host in the path
        ip_check(pkt);


	new_pkt_size = pkt->length();

        // send packet out the given port
        output(i).push(new_pkt);
    }

   DEBUG_PRINT("original size: %lu  ~~~ xor size: %lu\n", p->length(), new_pkt_size);
}



/*
 * decrypt
 *
 * takes in multiple encoded packet, decodes them, and sends a single
 * message out the interface.
 *
*/
void XORMsg::decrypt(int ports, Packet *p) {

   DEBUG_PRINT("in decrypt\n");
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
    const unsigned char *mh = p->mac_header();

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

    const unsigned char *nh = p->network_header();

    // we want to retrieve the headers to save for later
    // This requires the marking of the ip packet
    const click_ip *iph = p->ip_header();
    //const click_ip *iph = (click_ip*)(p->data()+sizeof(click_ether));
    unsigned long iplen = iph->ip_hl << 2;
    unsigned long total_length = p->length();
    unsigned long header_length = DEFAULT_MAC_LEN + iplen;
    unsigned long data_length = total_length - header_length;

    // following from when we encoded our data and put our xor data into
    // the pkt data field, we now need to extract it
    const XORProto *xorpkt = reinterpret_cast<const XORProto *>(p->data()+header_length);
    unsigned long encode_length = xorpkt->Len;

    long unsigned host = xorpkt->Sharehost;
    long unsigned flow = xorpkt->Flowid;

    std::string data(&xorpkt->Data[0], &xorpkt->Data[0] + xorpkt->Len);


    /* NOTE: for mutex you need to recompile all code to get it to work. */
    cache_mut.lock();
    /******************** CRITICAL REGION - KEEP IT SHORT *****************/
    /* Error when using mutex.
     * click: malloc.c:2379: sysmalloc: Assertion `(old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned long) old_end & (pagesize - 1)) == 0)' failed.
     * Aborted
     *
     */

    // check if this packet destination is already in our storage queue
    auto t = storage.find(host);

    auto tt = completed.find(host);

    if (tt != completed.end()) {
        auto comp_map = completed.at(host);
        auto comp_it = comp_map.find(flow);
        // packet has already been completed, dont do anything with this one
        if (comp_it != comp_map.end()){
                DEBUG_PRINT("finished sending coded packet. dropping this one\n");
    		completed[host][flow]++;
		// we've already sent the file, and recieved all the messages, so delete from completed
		if (completed[host][flow] == _shares-_threshold){
			completed[host].erase(flow);
		}
                cache_mut.unlock();
                return;
        }
    }

    if (t == storage.end()) {
        DEBUG_PRINT("[nh] adding %s:%lu to cache\n", IPAddress(host).s().c_str(), flow);
        storage[host][flow].push_back(data);
        cache_mut.unlock();
        return;
    }

    // this is the container/map for this host
    auto host_map = storage.at(host);
    auto flowid = host_map.find(flow);

    // map exists but there is no flowid, so add it
    if (flowid == host_map.end()) {
        DEBUG_PRINT("[nf] adding %s:%lu to cache\n", IPAddress(host).s().c_str(), flow);
        storage[host][flow].push_back(data);
        cache_mut.unlock();
        return;
    }

    // flowids do exist in the map, so check if we need to append ours
    // or if we are ready to do some computation
    //
    // including this packet, we still do not have enough to compute
    //
    if (storage[host][flow].size()+1 < _threshold) {
        DEBUG_PRINT("[under] adding %s:%lu to cache\n", IPAddress(host).s().c_str(), flow);
        storage[host][flow].push_back(data);
        cache_mut.unlock();
        return;
    }

    DEBUG_PRINT("have enough packets to reconstruct\n");

    // we have enough to compute, create vector of the data
    std::vector<std::string> encoded;
    encoded.push_back(data);
    for (auto x : storage[host][flow]) {
        encoded.push_back(x);
    }

    // get back the secret
    std::string pkt_data = XORMsg::RecoverData(_threshold, encoded);

    DEBUG_PRINT("Data Out: %lu -- %lu\n", strlen(pkt_data.c_str()), pkt_data.length());


    WritablePacket *pkt = Packet::make(pkt_data.length());
    memcpy((void*)pkt->data(), pkt_data.c_str(), pkt_data.length());

    // add space at the front to put back on the old ip and mac headers
    // ip header first
    Packet *ip_pkt = pkt->push(sizeof(click_ip));
    memcpy((void*)ip_pkt->data(), nh, sizeof(click_ip));


    // TODO/NOTE: these lines in overwritting the ip header are only needed when using Linux Forwarding.
    click_ip *iph2 = (click_ip *) ip_pkt->data();
    iph2->ip_len = ntohs( sizeof(click_ip) +  pkt_data.length());
    // END NODE

    // mac header next (so its first in the packet)
    Packet *new_pkt = pkt->push_mac_header(sizeof(click_ether));
    memcpy((void*)new_pkt->data(), mh, sizeof(click_ether));

    // update the ip header checksum for the next host in the path
    ip_check(pkt);

    DEBUG_PRINT("xor size: %lu ~~~~ original size: %lu\n", p->length(), new_pkt->length());

    // ship it
    output(0).push(pkt);

    storage[host].erase(flow);
    // prevent sending duplicated packets after we've reached threshold shares
    completed[host][flow] = 1;
    cache_mut.unlock();
}

// TODO
void XORMsg::forward(int ports, Packet *p) {
    // check the xormsg header and forward out all other interfaces
    // todo on specifying which interfaces
    //
    // Debugging
    //const click_ether *mch = (click_ether *) p->data();
    //std::cout << "forwarding packet: " << EtherAddress(mch->ether_shost).unparse().c_str() << " -> " << EtherAddress(mch->ether_dhost).unparse().c_str() << "\n";
    output(0).push(p);
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
    if (p->length() > 8000) {
        // too large
    }

    if (_function == 0) {
        encrypt(ports, p);
    } else if (_function == 1 ) {
        decrypt(ports, p);
    } else if (_function == 2 ) {
        forward(ports, p);
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
