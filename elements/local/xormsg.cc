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

//#include <mutex>          // std::mutex
#include <assert.h>    // sanity check
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
#include <algorithm> // max_element, find
#include <thread> // thread to handle background routine
#include <errno.h> // get the err for open

// protocol files
#include "xorproto.hh"
#include "xormsg.hh"
#include "bloom/bloom_filter.hpp"

// debuging simd vectors
void print_vector(__m128i v){
    uint16_t val[8];
    memcpy(val, &v, sizeof(val));
    DEBUG_PRINT("%x %x %x %x %x %x %x %x\n",
        val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]);
}

CLICK_DECLS

// globals
// random number generation
std::random_device r;
std::seed_seq seed{ r(), r(), r(), r(), r(), r(), r(), r() };
std::mt19937 eng(seed);
// bloom filter
bloom_filter filter;
// packet queue (dst_host, symbol, arrival time)
std::vector<std::tuple<
    unsigned long, // ip address of dst host
    unsigned long long, // symbol
    std::chrono::high_resolution_clock::time_point> // timestamp
> pkt_queue;

unsigned long long get_64_rand() {
    std::uniform_int_distribution< unsigned long long > uid(0, ULLONG_MAX);
    return uid(eng);
}

// update IP packet checksum
void ip_check(WritablePacket *p) {
    click_ip *iph = (click_ip *) p->data();
    iph->ip_sum = 0;
    iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));
}

// this will attempt to make sure our 48 bit randoms are unique
// TODO: some out of band mgmt to request between nodes a cleaning
// of solutions and bloom filter to reduce the number of times
// rand has to be called to get a unique id - stupid alternative
// restart both every X ofter to remove from memory the ids.
unsigned long long get_48_rand() {
    unsigned long long r48 = get_64_rand() & 0xffffffffffff;
    while (filter.contains(r48)) {
        DEBUG_PRINT("bloom filter request: %llu\n", r48);
        r48 = get_64_rand() & 0xffffffffffff;
    }
    return r48;
}


XORMsg::XORMsg() { };
XORMsg::~XORMsg() { };

// create a memory buffer the size of length filled by urand
void populate_packet(void* buffer, unsigned long long length) {
    DEBUG_PRINT("populate packet\n");
    // urandom fd was return non-0, and I dont really want that to ever be the case
    errno = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (errno !=  0) {
        DEBUG_PRINT("urandom fd returned: %d, errno: %d\n", fd, errno);
        int end = close(fd);
        populate_packet(buffer, length);
        return;
    }
    int size = read(fd, buffer, length); // unused result
    int end = close(fd);
    return;

    /*
    long byte_count;
    for (byte_count = 0; byte_count < length/8; ++byte_count) {
        unsigned long long tmp = get_64_rand();
        memcpy(&buffer + byte_count*8, (void*)tmp, sizeof(unsigned long long));
        //buffer[byte_count*8] = tmp;
    }

    int left_over = length % 8;
    if (left_over > 0) {
        for (int i = 0; i < left_over; i++){
            uint8_t tmp = get_64_rand() && 0xff;
            memcpy(&buffer + ((byte_count*8)+i), (void*)tmp, sizeof(uint8_t));
            //buffer[(byte_count*8)+i] = tmp;
        }
    
    }
    */

    return;
}

// create a PacketData struct filled with random data of size length
PacketData* generate_packet(unsigned long long length) {
    char* buf = (char*) malloc(length);
    populate_packet(buf, length);
    WritablePacket *pkt = Packet::make(buf, length);
    PacketData* x = new PacketData(pkt, get_48_rand(), std::chrono::high_resolution_clock::now());

    free(buf); // TODO, is make copying?
    return x;
}


// work horse for all functions that need to send a packet.
// requires having a L3 (nh) and L2 (mh) header to overwrite before sending the packet.
// because XOR only handles the data of the packet, we need to have an unspoiled header.
void XORMsg::send_packets(std::vector<XORProto*> pkts, const unsigned char* nh, const unsigned char* mh, unsigned long dst_host) {
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
        memcpy((void*)ip_pkt->data(), (void*)nh, sizeof(click_ip));

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
        memcpy((void*)new_pkt->data(), (void*)mh, sizeof(click_ether));

        DEBUG_PRINT("sending packet for interface: %d\n", iface_counter);
        // send packet out the given port
        output(iface_counter).push(new_pkt);

        iface_counter++;
    }

    // remove the packet from the mapping of packets to handle
    send_mut.lock();
    std::vector<PacketData*> *host_map = &send_storage.at(dst_host);
    host_map->erase(host_map->begin(), host_map->end());
    DEBUG_PRINT("storage size: %lu\n", send_storage.at(dst_host).size());
    send_mut.unlock();
}


/*
 * Handles the incoming packets to be coded together (XOR)
*/
std::vector<XORProto*> sub_encode(std::vector<PacketData*> pd, unsigned symbols) {
    // validate we are trying to encode at least 2 packets
    if (pd.size() < 2) {
        fprintf(stderr, "number of packets to encode must be greater than 1.\n");
        return {};
    }

    // go through all the packets
    std::vector<unsigned long> lengths;
    for (auto i : pd) {
        lengths.push_back(i->GetDataLength());
        DEBUG_PRINT("length: %lu\n", i->GetDataLength());
    }

    // find smallest and longest sized packets, excluding 0 length if given
    unsigned long longest = *std::max_element(lengths.begin(), lengths.end());


    // we want minimum 3 packets
    if (pd.size() == symbols-1 ) {
        DEBUG_PRINT("creating a new packet\n\n\n");
        // some non-zero probability of collision 2**48
        // TODO: check with current ids to make that probability 0
        WritablePacket *pkt = Packet::make(std::string("").c_str(), 0);
        PacketData* x = new PacketData(pkt, get_48_rand(), std::chrono::high_resolution_clock::now());
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
        unsigned long str_len = i->GetDataLength();
        long padding = rand_length - str_len;
        if (padding <= 0) {
            assert(padding >= 0); // should never be negative
            continue; // same length as random length already
        }
        // we need to append data to our packet
        char* buf = (char*) malloc(padding);
        DEBUG_PRINT("adding padding to the packet\n");
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


/*
 * Background daemon that will monitor our packet queue.
 *
 * If a packet sits in the queue too long, this function is responsible
 * for generate fake traffic that can then be xor'd with the data.
 *
*/
void XORMsg::latency_checker() {

    std::string function;
    if (_function == 0) {
        function = "encode thread";
    } else if (_function == 1) {
        function = "decode thread";
    } else {
        function = "forwarding thread";
    }
    DEBUG_PRINT("packet latency background begun for %s.\n", function.c_str());
    while(1) {
        auto now = std::chrono::high_resolution_clock::now();
        
        // latency check works on both encode and decode, so use the appropriate datastructures
        if (_function == 0) {
            send_mut.lock();
        } else {
            recv_mut.lock();
        }
        // create lock to begin checking pkt queue, we need to do this quickly
        send_mut.lock();
        auto pkts_in_queue = pkt_queue.size();

        // check if we have an outstanding packet
        // TODO would be to have the top packet already in memory to check
        DEBUG_PRINT("latency: pkts in queue: %ld, symbols: %d.\n", pkts_in_queue, _symbols);
        if (pkts_in_queue >= 1 && pkts_in_queue < _symbols) {
            DEBUG_PRINT("latency: pkts in queue: %ld, symbols: %d.\n", pkts_in_queue, _symbols);
            
            // get the first packet in the queue, because this is fifo
            // first packet will tell us how long all other packets are
            // waiting as well.
            auto dst_host = std::get<0>(pkt_queue[0]);
            auto symbol = std::get<1>(pkt_queue[0]);
            auto ts = std::get<2>(pkt_queue[0]);
            unsigned long length;

            std::vector<PacketData*> pkts;

            // check if the oldest packet has been waiting beyond our wait time
            if (ts + std::chrono::milliseconds(_latency) <= now) {
                 DEBUG_PRINT("latency: over limit: %lu .\n", (now.time_since_epoch() -ts.time_since_epoch()).count());
                 // search our global packet struct
                 auto t = send_storage.find(dst_host);

                 std::vector<PacketData*> host_map = send_storage.at(dst_host);
                 int fake_pkts = _symbols - pkts_in_queue;

                 // copy packets from the global queue to a local one to handle pkt sending
                 for (auto it = host_map.begin(); it != host_map.end(); ++it) {
                 //for (auto i : host_map) {
                     PacketData* y;
                     memcpy(&y, &*it, sizeof(PacketData*));
                     pkts.push_back(y);
                     length = (*it)->data.length();

                     DEBUG_PRINT("before cleanup.\n");
                     // start clearing the memory management
                     host_map.erase(it);
                     pkt_queue.erase(pkt_queue.begin());
                     DEBUG_PRINT("after cleanup.\n");
                 }
                 send_mut.unlock();

                 // TODO: create fake packets 
                 for (int i = 0; i < fake_pkts; i++) {
                     PacketData* xp = generate_packet(length);
                     pkts.push_back(xp);
                 }

                 // actually send the packet off
                 DEBUG_PRINT("before sub.\n");
                 std::vector<XORProto*> xor_pkts = sub_encode(pkts, _symbols);
                 DEBUG_PRINT("after sub.\n");

                 const unsigned char *mh = pkts[0]->pkt->mac_header();
                 const unsigned char *nh = pkts[0]->pkt->network_header();

                 DEBUG_PRINT("before send.\n");
                 send_packets(xor_pkts, nh, mh, dst_host);
                 DEBUG_PRINT("after send.\n");

            } else {
                send_mut.unlock();
            }
        } else {
            send_mut.unlock();
        }

        //until next interation sleep
        std::this_thread::sleep_for(std::chrono::milliseconds(_latency));
    }
}



// allow the user to configure the shares and threshold amounts
int XORMsg::configure(Vector<String> &conf, ErrorHandler *errh) {
    uint8_t symbols;
    uint8_t function;
    unsigned long latency; // measured in milliseconds
    if (Args(conf, this, errh)
        .read_mp("symbols", symbols) // positional
        .read_mp("PURPOSE", function) // positional
        .read_mp("latency", latency) // positional
        .complete() < 0){
            DEBUG_PRINT("Click configure failed.\n");
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
    if (symbols < 3) {
        // print error
        DEBUG_PRINT("Click configure: too few symbols.\n");
        return -1;
    }

    _symbols = symbols;
    _function = function;

    if (latency <= 0) {
        _disable_threads = true;
    } else {
        _disable_threads = false;
        _latency = latency;
    }

    DEBUG_PRINT("Click configure: lantency set: %lu ms.\n", _latency);

    // configure/initialize the bloom filter
    // filter is used for storing unique ids/symbols for xoring
    bloom_parameters parameters;

    // Segfaults if we use UULONG_MAX as the count
    //parameters.projected_element_count = ULLONG_MAX; // How many elements roughly do we expect to insert?
    parameters.projected_element_count = 10000000; // How many elements roughly do we expect to insert?
    parameters.false_positive_probability = 0.00001; // Maximum tolerable false positive probability? (0,1)
    parameters.random_seed = get_64_rand();
    parameters.compute_optimal_parameters();
    filter = bloom_filter(parameters);  //Instantiate Bloom Filter

    // TODO
    if (! _disable_threads){
        std::thread listener(&XORMsg::latency_checker, this);
        listener.detach();
    }

    return 0;
}


uint8_t get_8_rand() {
    std::uniform_int_distribution< uint8_t > uid(0, UCHAR_MAX);
    return uid(eng);
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

    PacketData *pdd = new PacketData(p, get_48_rand(), std::chrono::high_resolution_clock::now());

    // critical region, lock.
    send_mut.lock();

    // add to our bloom filter while in the lock
    filter.insert(pdd->id);

    DEBUG_PRINT("encode: after bloom\n");

    // we have 1 packet, we want to see if we have another packet in the queue
    // if we do, great we can xor
    // if not, we need to wait for another packet

    // check if this packet destination is already in our storage queue
    auto t = send_storage.find(dst_host);
    std::vector<PacketData*> pdv;

    // queue does not have any elements for that host
    if (t == send_storage.end()) {
        DEBUG_PRINT("adding %llu: %lu\n", pdd->id, pdd->GetDataLength());
        send_storage[dst_host].push_back(pdd);
        pkt_queue.push_back(std::make_tuple(dst_host, pdd->id, pdd->timestamp));
        send_mut.unlock();
        return;
    } else {
        std::vector<PacketData*> *host_map = &send_storage.at(dst_host);
        // queue is empty, so add this packet and wait for another to come along
        DEBUG_PRINT("adding %llu: %lu\n", pdd->id, pdd->GetDataLength());
        send_storage[dst_host].push_back(pdd);
        pkt_queue.push_back(std::make_tuple(dst_host, pdd->id, pdd->timestamp));

        if (host_map->size() < _symbols) {
            send_mut.unlock();
            return;
        }

        // if we get here, we have enough packets to handle.
        // so we need to remove packets from pkt_queue (which handles threading)
        DEBUG_PRINT("size1: %lu, size2: %lu\n", host_map->size(), pkt_queue.size());
        for (auto i = host_map->begin(); i != host_map->end(); ++i ) {
            pdv.push_back(*i);

            if (! _disable_threads) {
                for (auto j = pkt_queue.begin(); j != pkt_queue.end(); ++j ) {
                    DEBUG_PRINT("id1: %llu, id2: %llu\n", (*i)->id, std::get<1>(*j));
                    if ((*i)->id == std::get<1>(*j)){
                        DEBUG_PRINT("removing: %llu from pkt queue\n", (*i)->id);
                        pkt_queue.erase(j);
                    }
                }
            }
        }

    }
    send_mut.unlock();
    
    DEBUG_PRINT("calling sub_encode\n");
    std::vector<XORProto*> pkts = sub_encode(pdv, _symbols);

    DEBUG_PRINT("calling send_packets\n");
    send_packets(pkts, nh, mh, dst_host);

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
        if (host_map.size() < _symbols) {
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

            if (recv_storage[b_id].size() != _symbols) {
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

    // TODO: we need a smart way, to check how the 3 packets are related by looking at packet
    // header, and dropping the one that doesnt fit, or dropping all and starting over to
    // avoid livelock
    if ( xs.length() == 0 || ys.length() == 0 || zs.length() == 0 ) {
        DEBUG_PRINT("we have 3 packets, but not all the codes to them\n");
        return;
    }

    // TODO: after confirmed correctness, reduce to single loop

    uint64_t long chunks = xs.length() >> 4ULL;
    // solve for a // 1
    // 6^7 // (b^c)^(a^b^c) // x^y
    char* aa = new char[xs.length()];
    std::string a;
    //std::tuple<std::string, unsigned long long> a;

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
        DEBUG_PRINT("a length: %lu, aa: %lu \n", a.length(), xs.length());
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
        DEBUG_PRINT("c length: %lu, cc: %lu \n", c.length(), zs.length());
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
            //__m128i aa = _mm_loadu_si128 ((__m128i *)&aa + i);
            __m128i xx = _mm_loadu_si128 (((__m128i *)xs.c_str()) + i);
            __m128i yy = _mm_loadu_si128 (((__m128i *)ys.c_str()) + i);
            __m128i zz = _mm_loadu_si128 (((__m128i *)zs.c_str()) + i);
            // xor and our vector back into our xor data buffer
            //_mm_storeu_si128 (((__m128i *)bb) + i, _mm_xor_si128 (aa, zz));
            _mm_storeu_si128 (((__m128i *)bb) + i, _mm_xor_si128 (xx, _mm_xor_si128 (yy, zz)));
        }
        b = std::string(bb, ys.length());
        DEBUG_PRINT("b length: %lu, bb: %lu\n", b.length(), ys.length());
    } else {
        b = bb;
        DEBUG_PRINT("b used solution\n");
    }


    // TODO: sort out why not all 3 packets are being sent, and why they arent being sent consistently

    // only add a packet to sending out list if it has not already been added
    std::vector<std::string> deets;

    recv_mut.lock();
    auto a_solved = solutions.find(a_id);
    if (a_solved == solutions.end()) {
        //solutions[a_id] = a;
    }
    deets.push_back(a);

    auto b_solved = solutions.find(b_id);
    if (b_solved == solutions.end()) {
        //solutions[b_id] = b;
    }
    deets.push_back(b);

    auto c_solved = solutions.find(c_id);
    if (c_solved == solutions.end()) {
        //solutions[c_id] = c;
    }
    deets.push_back(c);
    recv_mut.unlock();


    // add these solutions to memory (later put it in mem cache)

    for ( auto i : deets ) {
        DEBUG_PRINT("padded packet len: %lu\n", i.length());
        WritablePacket *pkt = Packet::make(i.length());
        memcpy((void*)pkt->data(), i.c_str(), i.length());

        // set the original packet header information
        pkt->set_mac_header(pkt->data(), DEFAULT_MAC_LEN);
        pkt->set_network_header(pkt->data()+DEFAULT_MAC_LEN, sizeof(click_ip));
        const click_ip *iph = pkt->ip_header();
        int ip_len = ntohs(iph->ip_len);
        std::string src_host = std::string(IPAddress(iph->ip_src).unparse().mutable_c_str());
        std::string dst_host = std::string(IPAddress(iph->ip_dst).unparse().mutable_c_str());

        DEBUG_PRINT("orig packet: %s -> %s %d\n", src_host.c_str(), dst_host.c_str(), ip_len);
        pkt->take(i.length()-(ip_len+DEFAULT_MAC_LEN));

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
