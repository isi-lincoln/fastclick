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
#include <cstdint> // ULLONG_MAX
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

std::random_device r;
std::seed_seq seed{ r(), r(), r(), r(), r(), r(), r(), r() };
std::mt19937 eng(seed);

unsigned long long get_64_rand() {
    std::uniform_int_distribution< unsigned long long > uid(0, ULLONG_MAX);
    return uid(eng);
}

uint8_t get_8_rand() {
    std::uniform_int_distribution< uint8_t > uid(0, UCHAR_MAX);
    return uid(eng);
}


class PacketData{
	public:
		std::string data;
		unsigned long long id; // unique identifier
		// constructors
		PacketData() {}
    	PacketData(std::string d, std::string i) : data(d), id(i) {}
};

void populate_packet(void* buffer, unsigned long long length) {
    int fd = open("/dev/urandom", O_RDONLY);
    assert(fd > 0); 
    read(fd, rand_buffer, length);
	return
}

/*
 */
std::vector<XORProto*> sub_encode(std::vector<PacketData*> pd) {
	// validate we are trying to encode at least 2 packets
	if (pd.size() < 2) {
		fprintf(stderr, "number of packets to encode must be greater than 1.\n");
		return;
	}

	// packet attributes
    unsigned long longest;

	std::vector<unsigned long> lengths;
	for (auto i : pd) {
		lengths.push_back(i->length());
	}

	// find smallest and longest sized packets, excluding 0 length if given
	unsigned long longest = std::max_element(lengths.begin(), lengths.end());

	// we want minimum 3 packets
	if (pd.size() == 2) {
		// some non-zero probability of collision 2**48
		// TODO: check with current ids to make that probability 0
		unsigned long long new_rand = get_64_rand() & 0xffffffffffff;
		PacketData x = new PacketData("", new_rand);
		pd.push_back(x);
	}

	// rand_length just adds some data to the end of the packets to distort
	// distribution sizes.  Since the original packet will include the actual
	// packet length, the padded data will be removed by kernel (or decode).
    unsigned long rand_length;

	// here for performance we just want to make sure that our random length
	// wont go over 1500 bytes which on most networks is the MTU and prevent
	// packet fragmentation

	unsigned long normal_mtu = 1500*8 - XORPKT_HEADER_LEN*8;
	unsigned long jumbo_mtu = 7800*8 - XORPKT_HEADER_LEN*8;
    if (long(normal_mtu) - long(longest) > 0) {
		std::uniform_int_distribution< unsigned long> uid(longest, normal_mtu);
		rand_length = unsigned long(uid(eng));

		// fudge the numbers to fit in vectors nicely
		unsigned int x = rand_length % 128;
		if (x != 0) {
			unsigned int added = 128 - x;
			if (rand_length+added > normal_mtu){
				if (rand_length-x < longest) {
					rand_length = rand_length + added; // penalty for mtu breach
				} else {
					rand_length = rand_length -x;
				}
			} else {
				rand_length = rand_length + added;
			}
		}
    } else if (longest == normal_mtu) {
        rand_length = longest;
    } else if (long(jumbo_mtu) - long(longest) > 0) { // leave space for xorpacket header
		std::uniform_int_distribution< unsigned long> uid(longest, jumbo_mtu);
		rand_length = unsigned long(uid(eng));

		// fudge the numbers to fit in vectors nicely
		unsigned int x = rand_length % 128;
		if (x != 0) {
			unsigned int added = 128 - x;
			if (rand_length+added > jumbo_mtu){
				if (rand_length-x < longest) {
					rand_length = rand_length + added; // penalty for mtu breach
				} else {
					rand_length = rand_length -x;
				}
			} else {
				rand_length = rand_length + added;
			}
		}
    } else {
        rand_length = longest;
    }



	for ( auto i : pd ) {
		unsigned long str_len = i->data->length();
		long padding = rand_length - str_len;
		if (padding <= 0) {
			assert(padding >= 0); // should never be negative
			continue; // same length as random length already
		}
		// we need to append data to our packet
		void* buf = malloc(buffer, padding);
		populate_packet(buf, padding);
		i->data.append(buf);
		free(buf);
	}

	// TODO: for > 3 we may need to do some linear algerbra
	std::vector<XORProto*> xordata;
	unsigned int counter = 0;
	for ( auto i: pd ){
		XORProto xorpkt_ = new XORProto;
		xorpkt_->Version = 0;
		xorpkt_->Len = rand_length;
		memset(xorpkt_->Data, 0, rand_length)

		// a^b^c
		assert(rand_length % 128==0);
    	uint64_t chunks = rand_length >> 4ULL;
		if (counter==0) {
			xorpkt_->SymbolA = pd[0]->id;
			xorpkt_->SymbolB = pd[1]->id;
			xorpkt_->SymbolC = pd[2]->id;
			for (int i = 0; i < chunks ; ++i){
				// load our packets into vectors
				__m128i x = _mm_loadu_si128 (((__m128i *)pd[0]->data) + i);
				__m128i y = _mm_loadu_si128 (((__m128i *)pd[1]->data()) + i);
				__m128i z = _mm_loadu_si128 (((__m128i *)pd[2]->data()) + i);
				// xor and our vector back into our xor data buffer
				_mm_storeu_si128 (((__m128i *)xorpkt->Data) + i, _mm_xor_si128 (_mm_xor_si128 (x, y), z));
			}
		// a^b
		} else if (counter==1) {
			xorpkt_->SymbolA = pd[0]->id;
			xorpkt_->SymbolB = pd[1]->id;
			xorpkt_->SymbolC = 0;
			for (int i = 0; i < chunks ; ++i){
				// load our packets into vectors
				__m128i x = _mm_loadu_si128 (((__m128i *)pd[0]->data) + i);
				__m128i y = _mm_loadu_si128 (((__m128i *)pd[1]->data()) + i);
				// xor and our vector back into our xor data buffer
				_mm_storeu_si128 (((__m128i *)xorpkt->Data) + i, _mm_xor_si128 (x, y));
			}
		// b^c
		} else {
			xorpkt_->SymbolA = 0;
			xorpkt_->SymbolB = pd[1]->id;
			xorpkt_->SymbolC = pd[2]->id;
			for (int i = 0; i < chunks ; ++i){
				// load our packets into vectors
				__m128i y = _mm_loadu_si128 (((__m128i *)pd[1]->data()) + i);
				__m128i z = _mm_loadu_si128 (((__m128i *)pd[2]->data()) + i);
				// xor and our vector back into our xor data buffer
				_mm_storeu_si128 (((__m128i *)xorpkt->Data) + i, _mm_xor_si128 (y, z));
			}
		}
		
		counter++;
	}

	return xordata;
}

/*
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

    //std::string str_data (reinterpret_cast<const char *>(p->data()), total_length);
    std::string data(p->data(), p->length());
	PacketData x = new PacketData(data, get_64_rand()&0xffffffffffff);

    // critical region, lock.
    recv_mut.lock();

    // we have 1 packet, we want to see if we have another packet in the queue
    // if we do, great we can xor
    // if not, we need to wait for another packet

    // check if this packet destination is already in our storage queue
    auto t = storage.find(src_host);
	std::vector<PacketData*> pd;

    // queue does not have any elements for that host
    if (t == storage.end()) {
        storage[host].push_back(x);
        cache_mut.unlock();
        return;
    } else {
        auto host_map = storage.at(host);
        // queue is empty, so add this packet and wait for another to come along
        if (host_map.size() < 2) {
            storage[host].push_back(data);
            cache_mut.unlock();
            return;
        }

		for (auto i : host_map ) {
			pd.push_back(i);
			storage[host].erase(i);
		}

    }
	
	std::vector<PacketData*> pkts = sub_encode(pd);

    //DEBUG_PRINT("Data In: %s -- %s\n",str_data.c_str(), str_data);
    //DEBUG_PRINT("Data In: %lu -- %lu -- %lu\n", strlen(str_data.c_str()), data_length, encoded[0].size());


    unsigned long new_pkt_size = 0;

    // now lets create the shares
    for (auto i: pkts) {
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