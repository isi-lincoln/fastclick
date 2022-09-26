#define DEBUG 1
#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...)    fprintf(stdout, fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args...)
#endif


// click files
#include <click/config.h>
#include <click/args.hh> // Args, for configure
#include <click/ipaddress.hh> // ip address
#include <include/click/packet.hh> // pkt make, set_mac_header
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
#include <tuple> // std::tuple
#include <string> // string
#include <random> // random_device
#include <fcntl.h> // RDONLY
#include <algorithm> // max_element


void print_vector(__m128i v){
    uint16_t val[8];
    memcpy(val, &v, sizeof(val));
    DEBUG_PRINT("%x %x %x %x %x %x %x %x\n",
        val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]);
}

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
     * TODO: We need to manage in/out interfaces in relation to symbols.
     * Symbols should be greater than adversary's control, and more than 2.
     * 2 symbols, and we need to have one be in the clear, which leads to all
     * sorts of attacks to leak the other.  We ideally want more than 2, because
     * it makes life simple with coming up with equations that can be solved
     * without clear text.  May still need to inject noise regardless.
     */
    if (symbols != 3) {
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

unsigned long long get_48_rand() {
    return get_64_rand() & 0xffffffffffff;
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
        PacketData* x = new PacketData("", get_48_rand(), std::chrono::high_resolution_clock::now());
        pd.push_back(x);
    }

    // rand_length just adds some data to the end of the packets to distort
    // distribution sizes.  Since the original packet will include the actual
    // packet length, the padded data will be removed by kernel (or decode).
    unsigned long rand_length = longest;

    // here for performance we just want to make sure that our random length
    // wont go over 1500 bytes which on most networks is the MTU and prevent
    // packet fragmentation

    unsigned long mtu = 1500 - XORPKT_HEADER_LEN;
    unsigned int vector_length = 16; // 128/8

    if (longest % vector_length != 0) {
        unsigned int added = longest % vector_length;
        if (longest <= mtu+(vector_length-added)) {
            rand_length = longest+(vector_length-added);
        }
    }


    // TODO: fix this code
    /*
    unsigned long normal_mtu = 1500 - XORPKT_HEADER_LEN;
    unsigned long jumbo_mtu = 7800 - XORPKT_HEADER_LEN;
    if (long(normal_mtu) - long(longest) > 0) {
        std::uniform_int_distribution< unsigned long> uid(longest, normal_mtu);
        rand_length = (unsigned long)(uid(eng));

        // fudge the numbers to fit in vectors nicely
        unsigned int x = rand_length % vector_length;
        if (x != 0) {
            unsigned int added = vector_length - x;
            if (rand_length+added > normal_mtu){
                if (rand_length-x < longest) {
                    if (longest % vector_length == 0) {
                        rand_length = longest;
                    } else {
                        rand_length = rand_length + added; // penalty for mtu breach
                    }
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
        unsigned int x = rand_length % vector_length;
        if (x != 0) {
            unsigned int added = vector_length - x;
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
    */

    DEBUG_PRINT("array: %lu, longest packet: %lu\n", pd.size(), longest);
    DEBUG_PRINT("random length: %lu\n", rand_length);

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
        xorpkt->Timer = static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::nanoseconds>(i->timestamp.time_since_epoch()).count());
        //DEBUG_PRINT("xor length: %u\n", xorpkt->Len);
        memset(xorpkt->Data, 0, rand_length);

        // a^b^c
        unsigned int aligned = rand_length % vector_length;
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

                /*
                DEBUG_PRINT("a^b: %d\n", i);
                print_vector(x);
                print_vector(y);
                print_vector(_mm_xor_si128 (x, y));
                */
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
        
        xordata.push_back(xorpkt);
        counter++;

        //DEBUG_PRINT("xor length: %u\n", xorpkt->Len);
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
    PacketData *pdd = new PacketData(pkt_data, get_48_rand(), std::chrono::high_resolution_clock::now());

    // critical region, lock.
    send_mut.lock();

    // we have 1 packet, we want to see if we have another packet in the queue
    // if we do, great we can xor
    // if not, we need to wait for another packet

    // check if this packet destination is already in our storage queue
    auto t = send_storage.find(dst_host);
    std::vector<PacketData*> pdv;

    // queue does not have any elements for that host
    if (t == send_storage.end()) {
        DEBUG_PRINT("adding: %llu\n", pdd->id);
        send_storage[dst_host].push_back(pdd);
        send_mut.unlock();
        return;
    } else {
	std::vector<PacketData*> *host_map = &send_storage.at(dst_host);
        // queue is empty, so add this packet and wait for another to come along
        DEBUG_PRINT("adding: %llu\n", pdd->id);
        send_storage[dst_host].push_back(pdd);

        if (host_map->size() < 3) {
            send_mut.unlock();
            return;
        }

        for (auto i = host_map->begin(); i != host_map->end(); ++i ) {
            pdv.push_back(*i);
            //DEBUG_PRINT("removing: %llu\n", (*i)->id);
        }


	// TODO left off here to solve the segfault

	// remove one elemnt from our list to keep a window
	//send_storage.erase(send_storage.at(dst_host).begin());

    }
    send_mut.unlock();
    
    std::vector<XORProto*> pkts = sub_encode(pdv);

    DEBUG_PRINT("a: %llu\n", pkts[0]->SymbolA);
    DEBUG_PRINT("b: %llu\n", pkts[0]->SymbolB);
    DEBUG_PRINT("c: %llu\n", pkts[0]->SymbolC);

    // TODO: this assumes a 1-1 matching between packets being XORd and interfaces
    unsigned iface_counter = 0;
    // now lets create the shares
    for (auto i: pkts) {
	DEBUG_PRINT("port: %u -- out: %u\n", iface_counter, i->Len);
        WritablePacket *pkt = Packet::make(i, (sizeof(XORProto)-(XORPROTO_DATA_LEN-i->Len)));

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

        iph2->ip_p = 0;//144-252
        // update the ip header checksum for the next host in the path
        ip_check(pkt);

        // This sets/annotates the network header as well as pushes into packet
        Packet *new_pkt = pkt->push_mac_header(sizeof(click_ether));
        memcpy((void*)new_pkt->data(), mh, sizeof(click_ether));

        // send packet out the given port
        output(iface_counter).push(new_pkt);

        iface_counter++;
    }

    std::vector<PacketData*> *host_map = &send_storage.at(dst_host);
    host_map->erase(host_map->begin());
    DEBUG_PRINT("storage size: %lu\n", send_storage.at(dst_host).size());

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
    unsigned long long a_id = xorpkt->SymbolA;
    unsigned long long b_id = xorpkt->SymbolB; // assumes symbols dont move
    unsigned long long c_id = xorpkt->SymbolC;

    DEBUG_PRINT("a_decode: %llu\n", a_id);
    DEBUG_PRINT("b_decode: %llu\n", b_id);
    DEBUG_PRINT("c_decode: %llu\n", c_id);
    DEBUG_PRINT("mac: %d, ip: %lu, data: %lu, xor: %lu\n", DEFAULT_MAC_LEN, iplen, data_length, encode_length);

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
        auto id = 2;
        if (a_id != 0) {
            id = id + 1;
        }
        if (c_id != 0) {
            id = id + 4;
        }
        auto y = std::make_tuple(id, std::string(xorpkt->Data, encode_length), xorpkt->Timer);

        recv_storage[b_id].push_back(y);
        if (a_id != 0) {
            recv_storage[a_id].push_back(y);
        }
        if (c_id != 0) {
            recv_storage[c_id].push_back(y);
        }

        recv_mut.unlock();
        return;
    } else {
        auto host_map = recv_storage.at(b_id);
        // queue is empty, so add this packet and wait for another to come along
        if (host_map.size() < 3) {
            auto id = 2;
            if (a_id != 0) {
                id = id + 1;
            }
            if (c_id != 0) {
                id = id + 4;
            }
            auto y = std::make_tuple(id, std::string(xorpkt->Data, encode_length), xorpkt->Timer);

            recv_storage[b_id].push_back(y);
            if (a_id != 0) {
                recv_storage[a_id].push_back(y);
            }
            if (c_id != 0) {
                recv_storage[c_id].push_back(y);
            }

            if (recv_storage[b_id].size() != 3) {
                recv_mut.unlock();
                return;
            }
        }
    }

    DEBUG_PRINT("have enough packets to reconstruct\n");

    auto host_map = recv_storage.at(b_id);
    recv_mut.unlock();

    std::tuple<unsigned int, std::string, unsigned long long> x;
    std::tuple<unsigned int, std::string, unsigned long long> y;
    std::tuple<unsigned int, std::string, unsigned long long> z;
    for (auto i : host_map) {
        DEBUG_PRINT("symbols: %u, data length: %lu\n", std::get<0>(i), std::get<1>(i).length());
        if (std::get<0>(i) == 7) { // a ^ b ^c
            x = i;
        } else if (std::get<0>(i) == 6) { // b ^ c
            y = i;
        } else { // 3 -> a ^ b 
            z = i;
        }
    }

    std::string xs = std::get<1>(x);
    std::string ys = std::get<1>(y);
    std::string zs = std::get<1>(z);
    // TODO: after confirmed correctness, reduce to single loop

    uint64_t long chunks = xs.length() >> 4ULL;
    // solve for a // 1
    // 6^7 // (b^c)^(a^b^c) // x^y
    char* aa = new char[xs.length()];
    std::string a;

    auto aaa = solutions.find(a_id);
    if ( aaa == solutions.end() ) {
        for (int i = 0; i < chunks ; ++i){
            // load our packets into vectors
            __m128i xx = _mm_loadu_si128 (((__m128i *)xs.c_str()) + i);
            __m128i yy = _mm_loadu_si128 (((__m128i *)ys.c_str()) + i);
            // xor and our vector back into our xor data buffer
            _mm_storeu_si128 (((__m128i *)aa) + i, _mm_xor_si128 (xx, yy));
        }
        a = std::string(aa, xs.length());
        //DEBUG_PRINT("a length: %lu, aa: %lu \n", a.length(), xs.length());
    } else {
        a = aa;
        DEBUG_PRINT("a used solution\n");
    }

    // solve for c // 4
    // 3^7 // (a^b)^(a^b^c) // x^z
    char* cc= new char[zs.length()];
    std::string c;

    auto ccc = solutions.find(c_id);
    if ( ccc == solutions.end() ) {
        for (int i = 0; i < chunks ; ++i){
            // load our packets into vectors
            __m128i xx = _mm_loadu_si128 (((__m128i *)xs.c_str()) + i);
            __m128i zz = _mm_loadu_si128 (((__m128i *)zs.c_str()) + i);
            // xor and our vector back into our xor data buffer
            _mm_storeu_si128 (((__m128i *)cc) + i, _mm_xor_si128 (xx, zz));
        }
        c = std::string(cc, zs.length());
        //DEBUG_PRINT("c length: %lu, cc: %lu \n", c.length(), zs.length());
    } else {
        c = cc;
        DEBUG_PRINT("c used solution\n");
    }

    // solve for b // 2
    // 1^3 // a^(a^b) // a^z
    char* bb= new char[ys.length()];
    std::string b;

    auto bbb = solutions.find(b_id);
    if ( bbb == solutions.end() ) {
        for (int i = 0; i < chunks ; ++i){
            // load our packets into vectors
            __m128i aa = _mm_loadu_si128 ((__m128i *)&aa + i);
            __m128i zz = _mm_loadu_si128 (((__m128i *)zs.c_str()) + i);
            // xor and our vector back into our xor data buffer
            _mm_storeu_si128 (((__m128i *)bb) + i, _mm_xor_si128 (aa, zz));
        }
        b = std::string(bb, ys.length());
        //DEBUG_PRINT("b length: %lu, bb: %lu \n", b.length(), ys.length());
    } else {
        b = bb;
        DEBUG_PRINT("b used solution\n");
    }


    // only add a packet to sending out list if it has not already been added
    std::vector<std::string> deets;

    recv_mut.lock();
    auto a_solved = solutions.find(a_id);
    if (a_solved == solutions.end()) {
        deets.push_back(a);
        solutions[a_id] = a;
    }

    auto b_solved = solutions.find(b_id);
    if (b_solved == solutions.end()) {
        deets.push_back(b);
        solutions[b_id] = b;
    }

    auto c_solved = solutions.find(c_id);
    if (c_solved == solutions.end()) {
        deets.push_back(c);
        solutions[c_id] = c;
    }
    recv_mut.unlock();

    for (int i=0; i < a.length(); i++) {
        DEBUG_PRINT("%x", a.c_str()[i]);
    }
    DEBUG_PRINT("\n");


    // add these solutions to memory (later put it in mem cache)

    for ( auto i : deets ) {
        DEBUG_PRINT("orig packet len: %lu\n", i.length());
        WritablePacket *pkt = Packet::make(i.length());
        memcpy((void*)pkt->data(), i.c_str(), i.length());

        // set the original packet header information
        pkt->set_mac_header(pkt->data());
        pkt->set_network_header(pkt->data()+DEFAULT_MAC_LEN);

        // add space at the front to put back on the old ip and mac headers
        // ip header first
        //Packet *ip_pkt = pkt->push(sizeof(click_ip));
        //memcpy((void*)ip_pkt->data(), nh, sizeof(click_ip));


        // TODO/NOTE: these lines in overwritting the ip header are only needed when using Linux Forwarding.
        //click_ip *iph2 = (click_ip *) ip_pkt->data();
        //iph2->ip_len = ntohs( sizeof(click_ip) +  i.length());
        // END NODE
        //DEBUG_PRINT("ip proto: %d, ip length: %d\n", iph2->ip_p, iph2->ip_len);
       

        // update the ip header checksum for the next host in the path
        ip_check(pkt);

        // mac header next (so its first in the packet)
        //Packet *new_pkt = pkt->push_mac_header(sizeof(click_ether));
        //memcpy((void*)new_pkt->data(), mh, sizeof(click_ether));

        //DEBUG_PRINT("2: ip proto: %d, ip length: %d\n", ((click_ip*)(pkt->data()+sizeof(click_ether)))->ip_p, ((click_ip*)(pkt->data()+sizeof(click_ether)))->ip_len);

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
