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
#include <utility>      // std::pair, std::make_pair
#include <string> // string
#include <random> // random_device
#include <fcntl.h> // RDONLY
#include <algorithm> // max_element

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
    uint8_t symbols;
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

void populate_packet(void* buffer, unsigned long long length) {
    int fd = open("/dev/urandom", O_RDONLY);
    assert(fd > 0); 
    read(fd, buffer, length);
	return;
}

std::vector<XORProto*> sub_encode(std::vector<PacketData*> pd) {
	// validate we are trying to encode at least 2 packets
	if (pd.size() < 2) {
		fprintf(stderr, "number of packets to encode must be greater than 1.\n");
		return {};
	}

	std::vector<unsigned long> lengths;
	for (auto i : pd) {
		lengths.push_back(i->data.length());
	}

	// find smallest and longest sized packets, excluding 0 length if given
	unsigned long longest = *std::max_element(lengths.begin(), lengths.end());

	// we want minimum 3 packets
	if (pd.size() == 2) {
		// some non-zero probability of collision 2**48
		// TODO: check with current ids to make that probability 0
		unsigned long long new_rand = get_64_rand() & 0xffffffffffff;
		PacketData* x = new PacketData("", new_rand);
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
		rand_length = (unsigned long)(uid(eng));

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
		rand_length = (unsigned long)(uid(eng));

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
		unsigned long str_len = i->data.length();
		long padding = rand_length - str_len;
		if (padding <= 0) {
			assert(padding >= 0); // should never be negative
			continue; // same length as random length already
		}
		// we need to append data to our packet
		char* buf = (char*) malloc(padding);
		populate_packet(buf, padding);
		i->data.append((char*)buf);
		free(buf);
	}

	// TODO: for > 3 we may need to do some linear algerbra
	std::vector<XORProto*> xordata;
	unsigned int counter = 0;
	for ( auto i: pd ){
		XORProto *xorpkt = new XORProto;
		xorpkt->Version = 0;
		xorpkt->Len = rand_length;
		memset(xorpkt->Data, 0, rand_length);

		// a^b^c
		unsigned int aligned = rand_length % 128;
		assert(aligned==0);
    	uint64_t chunks = rand_length >> 4ULL;
		if (counter==0) {
			xorpkt->SymbolA = pd[0]->id;
			xorpkt->SymbolB = pd[1]->id;
			xorpkt->SymbolC = pd[2]->id;
			for (int i = 0; i < chunks ; ++i){
				// load our packets into vectors
				__m128i x = _mm_loadu_si128 (((__m128i *)pd[0]->data.c_str()) + i);
				__m128i y = _mm_loadu_si128 (((__m128i *)pd[1]->data.c_str()) + i);
				__m128i z = _mm_loadu_si128 (((__m128i *)pd[2]->data.c_str()) + i);
				// xor and our vector back into our xor data buffer
				_mm_storeu_si128 (((__m128i *)xorpkt->Data) + i, _mm_xor_si128 (_mm_xor_si128 (x, y), z));
			}
		// a^b
		} else if (counter==1) {
			xorpkt->SymbolA = pd[0]->id;
			xorpkt->SymbolB = pd[1]->id;
			xorpkt->SymbolC = 0;
			for (int i = 0; i < chunks ; ++i){
				// load our packets into vectors
				__m128i x = _mm_loadu_si128 (((__m128i *)pd[0]->data.c_str()) + i);
				__m128i y = _mm_loadu_si128 (((__m128i *)pd[1]->data.c_str()) + i);
				// xor and our vector back into our xor data buffer
				_mm_storeu_si128 (((__m128i *)xorpkt->Data) + i, _mm_xor_si128 (x, y));
			}
		// b^c
		} else {
			xorpkt->SymbolA = 0;
			xorpkt->SymbolB = pd[1]->id;
			xorpkt->SymbolC = pd[2]->id;
			for (int i = 0; i < chunks ; ++i){
				// load our packets into vectors
				__m128i y = _mm_loadu_si128 (((__m128i *)pd[1]->data.c_str()) + i);
				__m128i z = _mm_loadu_si128 (((__m128i *)pd[2]->data.c_str()) + i);
				// xor and our vector back into our xor data buffer
				_mm_storeu_si128 (((__m128i *)xorpkt->Data) + i, _mm_xor_si128 (y, z));
			}
		}
		
		counter++;
	}

	return xordata;
}

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
    // this packet has an ethernet header which we want to keep for decode
    // it also has the ip header, and the data contents.
    // we would ideally like to keep all this entact, then decode can fudge
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
    unsigned long dst_host = IPAddress(iph->ip_dst.s_addr);
    // initial version of protocol
    int version = 0;

    std::string pkt_data(reinterpret_cast<const char *>(p->data()), p->length());
    //std::string pkt_data(const_cast<unsigned char*>(p->data()), p->length());

    // critical region, lock.
    send_mut.lock();

    // we have 1 packet, we want to see if we have another packet in the queue
    // if we do, great we can xor
    // if not, we need to wait for another packet

    // check if this packet destination is already in our storage queue
    auto t = send_storage.find(dst_host);
	std::vector<PacketData*> pd;

    // queue does not have any elements for that host
    if (t == send_storage.end()) {
        send_storage[dst_host].push_back(pkt_data);
        send_mut.unlock();
        return;
    } else {
        auto host_map = send_storage.at(dst_host);
        // queue is empty, so add this packet and wait for another to come along
        if (host_map.size() < 2) {
            send_storage[dst_host].push_back(pkt_data);
            send_mut.unlock();
            return;
        }

		for (auto i = host_map.begin(); i != host_map.end(); i++ ) {
			PacketData *x = new PacketData(*i, get_64_rand()&0xffffffffffff);
			pd.push_back(x);
			host_map.erase(i);
		}

    }
    send_mut.unlock();
	
	std::vector<XORProto*> pkts = sub_encode(pd);

    //DEBUG_PRINT("Data In: %s -- %s\n",str_data.c_str(), str_data);
    //DEBUG_PRINT("Data In: %lu -- %lu -- %lu\n", strlen(str_data.c_str()), data_length, encoded[0].size());


    unsigned long new_pkt_size = 0;

	// TODO: this assumes a 1-1 matching between packets being XORd and interfaces
	unsigned iface_counter = 0;
    // now lets create the shares
    for (auto i: pkts) {
        WritablePacket *pkt = Packet::make(i->Data, (sizeof(XORProto)-(XORPROTO_DATA_LEN-i->Len)));

        // we done screwed up.
		if (!pkt) return;

		// add space at the front to put back on the old ip and mac headers
		Packet *ip_pkt = pkt->push(sizeof(click_ip));
		memcpy((void*)ip_pkt->data(), nh, sizeof(click_ip));

		// update ip packet size = ip header + xor header + xor data
		// TODO/NOTE: these lines in overwritting the ip header are only needed when using Linux Forwarding.
		click_ip *iph2 = (click_ip *) ip_pkt->data();
		iph2->ip_len = ntohs( sizeof(click_ip) + (sizeof(XORProto)-(XORPROTO_DATA_LEN-i->Len)) );
		// END NOTE

		// This sets/annotates the network header as well as pushes into packet
		Packet *new_pkt = pkt->push_mac_header(sizeof(click_ether));
		memcpy((void*)new_pkt->data(), mh, sizeof(click_ether));


        // update the ip header checksum for the next host in the path
        ip_check(pkt);

		new_pkt_size = pkt->length();

        // send packet out the given port
        output(iface_counter).push(new_pkt);

		free(i);
		iface_counter++;
    }

   DEBUG_PRINT("original size: %lu  ~~~ xor size: %lu\n", p->length(), new_pkt_size);
}



void XORMsg::decode(int ports, Packet *p) {

   DEBUG_PRINT("in decode\n");
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
	unsigned long long b_id = xorpkt->SymbolB; // assumes symbols dont move

    /* NOTE: for mutex you need to recompile all code to get it to work. */
    recv_mut.lock();

    // check if this packet destination is already in our storage queue
    auto t = recv_storage.find(b_id);

	// so how do we store the data.  3 packets, 3 equations, 3 unknowns
	// if we get 2 packets we can solve for 1 variable. but how do we format
	// it in memory to be eficient?

	// key is the unique id
	// value is pointer to the packet?
	// wait until all packets arrive in order to maintain we send back to
	// kernel in-order
    if (t == recv_storage.end()) {
		auto y = std::make_pair(2, std::string(xorpkt->Data, xorpkt->Len));
        recv_storage[b_id].push_back(y);
		if (xorpkt->SymbolA != 0) {
			y.first = y.first + 1;
        	recv_storage[xorpkt->SymbolA].push_back(y);
		}
		if (xorpkt->SymbolC != 0) {
			y.first = y.first + 4;
        	recv_storage[xorpkt->SymbolC].push_back(y);
		}
        recv_mut.unlock();
        return;
    } else {
        auto host_map = recv_storage.at(b_id);
        // queue is empty, so add this packet and wait for another to come along
        if (host_map.size() < 2) {
			auto y = std::make_pair(2, std::string(xorpkt->Data, xorpkt->Len));
			recv_storage[b_id].push_back(y);
			if (xorpkt->SymbolA != 0) {
				y.first = y.first + 1;
				recv_storage[xorpkt->SymbolA].push_back(y);
			}
			if (xorpkt->SymbolC != 0) {
				y.first = y.first + 4;
				recv_storage[xorpkt->SymbolC].push_back(y);
			}
			recv_mut.unlock();
			return;
        }
    }

    DEBUG_PRINT("have enough packets to reconstruct\n");


	auto host_map = recv_storage.at(b_id);
	recv_mut.unlock();

	std::pair<unsigned int, std::string> x;
	std::pair<unsigned int, std::string> y;
	std::pair<unsigned int, std::string> z;
	for (auto i : host_map) {
		if (i.first == 7) { // a ^ b ^c
			x = i;
		} else if (i.first == 6) { // b ^ c
			y = i;
		} else { // 3 -> a ^ b 
			z = i;
		}
	}

	// solve for a 
	// 6^7
	char* aa= new char[x.second.length()];
	uint64_t long chunks = x.second.length() >> 4ULL;
	for (int i = 0; i < chunks ; ++i){
		// load our packets into vectors
		__m128i xx = _mm_loadu_si128 (((__m128i *)x.second.c_str()) + i);
		__m128i yy = _mm_loadu_si128 (((__m128i *)y.second.c_str()) + i);
		// xor and our vector back into our xor data buffer
		_mm_storeu_si128 (((__m128i *)aa) + i, _mm_xor_si128 (xx, yy));
	}
	std::string a(aa);

	char* cc= new char[z.second.length()];
	for (int i = 0; i < chunks ; ++i){
		// load our packets into vectors
		__m128i xx = _mm_loadu_si128 (((__m128i *)x.second.c_str()) + i);
		__m128i zz = _mm_loadu_si128 (((__m128i *)z.second.c_str()) + i);
		// xor and our vector back into our xor data buffer
		_mm_storeu_si128 (((__m128i *)cc) + i, _mm_xor_si128 (xx, zz));
	}
	std::string c(cc);

	char* bb= new char[y.second.length()];
	for (int i = 0; i < chunks ; ++i){
		// load our packets into vectors
		__m128i aa = _mm_loadu_si128 ((__m128i *)&aa + i);
		__m128i zz = _mm_loadu_si128 (((__m128i *)z.second.c_str()) + i);
		// xor and our vector back into our xor data buffer
		_mm_storeu_si128 (((__m128i *)bb) + i, _mm_xor_si128 (aa, zz));
	}
	std::string b(bb);

	std::vector<std::string> deets;
	deets.push_back(a);
	deets.push_back(b);
	deets.push_back(c);

	for ( auto i : deets ) {
		WritablePacket *pkt = Packet::make(i.length());
		memcpy((void*)pkt->data(), i.c_str(), i.length());

		// add space at the front to put back on the old ip and mac headers
		// ip header first
		Packet *ip_pkt = pkt->push(sizeof(click_ip));
		memcpy((void*)ip_pkt->data(), nh, sizeof(click_ip));


		// TODO/NOTE: these lines in overwritting the ip header are only needed when using Linux Forwarding.
		click_ip *iph2 = (click_ip *) ip_pkt->data();
		iph2->ip_len = ntohs( sizeof(click_ip) +  i.length());
		// END NODE

		// mac header next (so its first in the packet)
		Packet *new_pkt = pkt->push_mac_header(sizeof(click_ether));
		memcpy((void*)new_pkt->data(), mh, sizeof(click_ether));

		// update the ip header checksum for the next host in the path
		ip_check(pkt);

		DEBUG_PRINT("xor size: %lu ~~~~ original size: %lu\n", i->length(), new_pkt->length());

		// ship it
		output(0).push(pkt);
	}

}

// TODO
void XORMsg::forward(int ports, Packet *p) {
    output(0).push(p);
}

// TODO random generation
// TODO bounds checking on overflow - does this matter? we will force app to manage staleness
int XORMsg::initialize(ErrorHandler *errh) {
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
        encode(ports, p);
    } else if (_function == 1 ) {
        decode(ports, p);
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
