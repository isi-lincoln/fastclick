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

CLICK_DECLS

#define IP_BYTE_OFF(iph)   ((ntohs((iph)->ip_off) & IP_OFFMASK) << 3)

// globals
// random number generation
std::random_device r;
std::seed_seq seed{ r(), r(), r(), r(), r(), r(), r(), r() };
std::mt19937 eng(seed);
// bloom filter
bloom_filter filter;
// packet queue (dst_host, symbol, arrival time)

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
char* populate_packet(void* buffer, unsigned long long length) {

    //DEBUG_PRINT("populate packet of length: %llu\n", length);
    //FILE* fd = fopen("/dev/urandom", O_RDONLY);
    FILE* fd = fopen("/dev/urandom", "rb");
    if ( fd == NULL) {
        DEBUG_PRINT("failed to open file.\n");
        exit(1);
    }
    size_t res = fread(buffer, sizeof(char), length, fd);
    if (res != length) {
        DEBUG_PRINT("populate packet failed to read length random bytes.\n");
    }

    return (char*)buffer;
}

// work horse for all functions that need to send a packet.
// requires having a L3 (nh) and L2 (mh) header to overwrite before sending the packet.
// because XOR only handles the data of the packet, we need to have an unspoiled header.
void XORMsg::send_packets(
    std::vector<XORProto*> pkts, const unsigned char* nh,
    const unsigned char* mh, unsigned long dst_host) {

    /*
    DEBUG_PRINT("a: %llu\n", pkts[0]->SymbolA);
    DEBUG_PRINT("b: %llu\n", pkts[0]->SymbolB);
    DEBUG_PRINT("c: %llu\n", pkts[0]->SymbolC);
    DEBUG_PRINT("pkts to send: %lu\n", pkts.size());
    */

    // TODO: this assumes a 1-1 matching between packets being XORd and interfaces
    unsigned iface_counter = 0;
    // now lets create the shares
    for (auto i: pkts) {
        //DEBUG_PRINT("port: %u -- out: %u, total size: %lu\n", iface_counter, i->Len, sizeof(XORProto)-(XORPROTO_DATA_LEN-i->Len));
        WritablePacket *pkt = Packet::make(i, (sizeof(XORProto)-(XORPROTO_DATA_LEN-i->Len)));

        // we done screwed up.
        if (!pkt) return;

        // add space at the front to put back on the old ip and mac headers
        Packet *ip_pkt = pkt->push(sizeof(click_ip));
        memcpy((void*)ip_pkt->data(), (void*)nh, sizeof(click_ip));

        // these lines in overwritting the ip header are only needed when using Linux Forwarding.
        click_ip *iph2 = (click_ip *) ip_pkt->data();
        //iph2->ip_len = ntohs( sizeof(click_ip) + (sizeof(XORProto)-(XORPROTO_DATA_LEN-i->Len)) );
        iph2->ip_len = htons( sizeof(click_ip) + (sizeof(XORProto)-(XORPROTO_DATA_LEN-i->Len)) );

        iph2->ip_p = 0;//144-252
        // update the ip header checksum for the next host in the path
        ip_check(pkt);

        // This sets/annotates the network header as well as pushes into packet
        Packet *new_pkt = pkt->push_mac_header(sizeof(click_ether));
        memcpy((void*)new_pkt->data(), (void*)mh, sizeof(click_ether));

        //DEBUG_PRINT("sending packet for interface: %d\n", iface_counter);
        // send packet out the given port

        assert(iface_counter < _symbols);
        //if (!single_interface) {
        output(iface_counter).push(new_pkt);
        //} else {
        //    output(0).push(new_pkt);
        //}

        iface_counter++;
    }

}


/*
 * Handles the incoming packets to be coded together (XOR)
*/
std::vector<XORProto*> sub_encode(PacketBatch* pb, unsigned symbols, unsigned long longest, unsigned long mtu) {
    if (pb->count() != symbols) {
        fprintf(stderr, "number of packets should be equal to symbols.\n");
        return {};
    }

    // rand_length just adds some data to the end of the packets to distort
    // distribution sizes.  Since the original packet will include the actual
    // packet length, the padded data will be removed by kernel (or decode).
    unsigned long total_length = longest;

    // vector can either be 16 byte for SSE/SSSE or 32 for AVX/2
    unsigned int vector_length = 16;

    // TODO: redo this code to actually add padding of good quality
    // TODO: integrate mtu
    if (longest % vector_length != 0) {
        unsigned int added = longest % vector_length;
        total_length = longest+(vector_length-added);
    }

    //DEBUG_PRINT("array: %u, longest: %lu, with padding: %lu\n", pb->count(), longest, total_length);

    // TODO: create arbitrary for size symbol, when symbol != 3
    unsigned long al = pb->first()->length();
    unsigned long bl = pb->first()->next()->length();
    unsigned long cl = pb->tail()->length();
    char* ma[total_length];
    char* mb[total_length]; 
    char* mc[total_length];
    memcpy(ma, pb->first()->data(), al);
    memcpy(mb, pb->first()->next()->data(), bl);
    memcpy(mc, pb->tail()->data(), cl);

    populate_packet(ma+al, total_length-al);
    populate_packet(mb+bl, total_length-bl);
    populate_packet(mc+cl, total_length-cl);

    unsigned long long ar = get_48_rand();
    unsigned long long br = get_48_rand();
    unsigned long long cr = get_48_rand();

    std::vector<XORProto*> xordata;

    for (unsigned counter = 0; counter < symbols; counter++) {
        XORProto *xorpkt = new XORProto;
        xorpkt->Version = 0;
        xorpkt->Len = total_length;
        xorpkt->Timer = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        memset(xorpkt->Data, 0, total_length);

        // a^b^c
        unsigned int aligned = total_length % vector_length;
        //DEBUG_PRINT("total_length: %lu, aligned: %u\n", total_length, aligned);
        assert(aligned==0);
        uint64_t chunks = total_length >> 4ULL;
        if (counter==0) {
            xorpkt->SymbolA = ar;
            xorpkt->SymbolB = br;
            xorpkt->SymbolC = cr;
            for (int i = 0; i < chunks ; ++i){
                // load our packets into vectors
                __m128i x = _mm_loadu_si128 (((__m128i *)ma) + i);
                __m128i y = _mm_loadu_si128 (((__m128i *)mb) + i);
                __m128i z = _mm_loadu_si128 (((__m128i *)mc) + i);
                // xor and our vector back into our xor data buffer
                _mm_storeu_si128 (((__m128i *)xorpkt->Data) + i, _mm_xor_si128 (_mm_xor_si128 (x, y), z));
            }
        // a^b
        } else if (counter==1) {
            xorpkt->SymbolA = ar;
            xorpkt->SymbolB = br;
            xorpkt->SymbolC = 0;
            for (int i = 0; i < chunks ; ++i){
                // load our packets into vectors
                __m128i x = _mm_loadu_si128 (((__m128i *)ma) + i);
                __m128i y = _mm_loadu_si128 (((__m128i *)mb) + i);
                // xor and our vector back into our xor data buffer
                _mm_storeu_si128 (((__m128i *)xorpkt->Data) + i, _mm_xor_si128 (x, y));

            }
        // b^c
        } else {
            xorpkt->SymbolA = 0;
            xorpkt->SymbolB = br;
            xorpkt->SymbolC = cr;
            for (int i = 0; i < chunks ; ++i){
                // load our packets into vectors
                __m128i y = _mm_loadu_si128 (((__m128i *)mb) + i);
                __m128i z = _mm_loadu_si128 (((__m128i *)mc) + i);
                // xor and our vector back into our xor data buffer
                _mm_storeu_si128 (((__m128i *)xorpkt->Data) + i, _mm_xor_si128 (y, z));
            }
        }
        
        xordata.push_back(xorpkt);
    }

    return xordata;
}

// allow the user to configure the shares and threshold amounts
int XORMsg::configure(Vector<String> &conf, ErrorHandler *errh) {
    uint8_t symbols;
    uint8_t function;
    unsigned long latency; 
    unsigned long timer; 
    unsigned long mtu; 
    if (Args(conf, this, errh)
        .read_mp("SYMBOLS", symbols) // positional
        .read_mp("PURPOSE", function) // positional
        .read_mp("LATENCY", latency) // positional
        .read_mp("TIMER", timer) // positional
        .read_mp("MTU", mtu) // positional
        .complete() < 0){
            DEBUG_PRINT("Click configure failed.\n");
            return -1;
    }
    _latency = latency;
    _timer = timer;
    _mtu = mtu;

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


    if (latency >= 0) {
        //for (unsigned i = 0; i < click_max_cpu_ids(); i++) {
        for (unsigned i = 0; i < 1; i++) {
            State &s = _state.get_value_for_thread(i);
            Task* task = new Task(this);
            task->initialize(this,false);
            task->move_thread(i);
            s.timers = new Timer(task);
            s.timers->initialize(this);
            s.timers->move_thread(i);
        }
        _disable_threads = false;
        _latency = latency;
    } else {
        _disable_threads = true;
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

    return 0;
}



uint8_t get_8_rand() {
    std::uniform_int_distribution< uint8_t > uid(0, UCHAR_MAX);
    return uid(eng);
}


void XORMsg::encode(int ports, unsigned long dst, PacketBatch *pb) {
    //DEBUG_PRINT("encode begin\n");

    std::vector<unsigned long> lengths;
    Packet* ph = pb->first();
    for (Packet* cp = pb->first(); cp != 0; cp = cp->next()) {
         // packet is too large
        if (cp->length() > XORPROTO_DATA_LEN) {
            fprintf(stderr, "packet length too large for xor function\n");
            return;
        }
    
        // saftey checks
        if (!cp->has_mac_header()) {
            fprintf(stderr, "xor doesnt know how to handle this packet (no L2).\n");
            return;
        }   

        const click_ether *mch = (click_ether *) cp->data();
    
        if (htons(mch->ether_type) != ETHERTYPE_IP) {
            fprintf(stderr, "xor handling non-ipv4 packet: %x\n", htons(mch->ether_type));
            return;
        }
    
        if (!cp->has_network_header()) {
            fprintf(stderr, "xor doesnt know how to handle this packet (no L3).\n");
            return;
        }

        lengths.push_back(cp->length());
        //DEBUG_PRINT("length: %u\n", cp->length());
    
    }
    // find smallest and longest sized packets, excluding 0 length if given
    unsigned long longest = *std::max_element(lengths.begin(), lengths.end());

    //DEBUG_PRINT("in encode after saftey checks\n");

    //DEBUG_PRINT("calling sub_encode\n");
    std::vector<XORProto*> pkts = sub_encode(pb, _symbols, longest, _mtu);

    //DEBUG_PRINT("calling send_packets\n");
    send_packets(pkts, pb->first()->network_header(), pb->first()->mac_header(), dst);

}


// we want to make sure we send all the correct packets to decode
// we only need to return one set at a time, because we cant have
// a single packet come it that solves across multiple windows
std::pair<PacketBatch*, PacketBatch*> matchBatch(PacketBatch *pb, unsigned symbols)  {

    std::unordered_map<unsigned long long, PacketBatch*> ids;
    PacketBatch* others = nullptr;

    DEBUG_PRINT("mbatch\n");
    // go through our list of packets for decoding and check
    for (Packet* cp = pb->first(); cp != 0; cp = cp->next()) {
        const click_ip *iph = pb->first()->ip_header();
        unsigned long iplen = iph->ip_hl << 2;
        unsigned long header_length = DEFAULT_MAC_LEN + iplen;

        // if the proto is not 0 than this is anot a decode packet
        unsigned proto = iph->ip_p;
        if (proto != 0) {
            if (others) {
                others->append_packet(cp);
            } else {
                others = PacketBatch::make_from_packet(cp);
            }
            continue;
        }

        const XORProto *xorpkt = reinterpret_cast<const XORProto *>(cp->data()+header_length);
        unsigned long long clusterid = xorpkt->SymbolB;

        DEBUG_PRINT("mbatch|  a: %llu  b: %llu  c: %llu\n", xorpkt->SymbolA, clusterid, xorpkt->SymbolC);

        // if id in map, append packet to batch, otherwise create a new packet
        auto iid  = ids.find(clusterid);
        if ( iid == ids.end() ) {
            ids[clusterid] = PacketBatch::make_from_packet(cp);
        } else {
            ids[clusterid]->append_packet(cp);
        }
    }

    PacketBatch* found = nullptr;
    for (auto it : ids) {
        // if we have enough symbols, we need to go back and remove them.
        if (it.second->count() == symbols) {
            found = it.second;
            DEBUG_PRINT("we've found one: %llu, size: %u\n", it.first, it.second->count());
        } else {
            DEBUG_PRINT("not found: %llu, size: %u\n", it.first, it.second->count());
            if (others) {
                others->append_batch(it.second);
            } else {
                others = it.second;
            }
        }
    }

    return std::make_pair(others, found);
}


//void XORMsg::decode(int ports, Packet *p) {
void XORMsg::decode(int ports, PacketBatch *pb) {
    //DEBUG_PRINT("decode begin\n");

    Packet* ph = pb->first();
    unsigned char *nh;
    unsigned char *mh;
    for (Packet* cp = pb->first(); cp != 0; cp = cp->next()) {
         // packet is too large
        if (cp->length() > XORPROTO_DATA_LEN) {
            fprintf(stderr, "packet length too large for xor function\n");
            return;
        }
    
        // saftey checks
        if (!cp->has_mac_header()) {
            fprintf(stderr, "xor doesnt know how to handle this packet (no L2).\n");
            return;
        }   

        const click_ether *mch = (click_ether *) cp->data();
        const unsigned char *mh = cp->mac_header();
    
        if (htons(mch->ether_type) != ETHERTYPE_IP) {
            fprintf(stderr, "xor handling non-ipv4 packet: %x\n", htons(mch->ether_type));
            return;
        }
    
        if (!cp->has_network_header()) {
            fprintf(stderr, "xor doesnt know how to handle this packet (no L3).\n");
            return;
        }

        const unsigned char *nh = cp->network_header();
    
    }


    // TODO: something better here if possible
    const click_ip *iph = pb->first()->ip_header();
    const click_ip *iph2 = pb->first()->next()->ip_header();
    const click_ip *iph3 = pb->tail()->ip_header();

    unsigned long iplen = iph->ip_hl << 2;
    unsigned long header_length = DEFAULT_MAC_LEN + iplen;

    std::string dst_host = std::string(IPAddress(iph->ip_dst).unparse().mutable_c_str());
    //DEBUG_PRINT("in decode after saftey checks: %s (%u)\n", dst_host.c_str(), pb->first()->length());

    // following from when we encoded our data and put our xor data into
    // the pkt data field, we now need to extract it
    const XORProto *xorpktA = reinterpret_cast<const XORProto *>(pb->first()->data()+header_length);
    const XORProto *xorpktB = reinterpret_cast<const XORProto *>(pb->first()->next()->data()+header_length);
    const XORProto *xorpktC = reinterpret_cast<const XORProto *>(pb->tail()->data()+header_length);

    unsigned xa = ((xorpktA->SymbolA != 0) ? 1 : 0) + \
                  ((xorpktA->SymbolB != 0) ? 2 : 0) + \
                  ((xorpktA->SymbolC != 0) ? 4 : 0);

    unsigned xb = ((xorpktB->SymbolA != 0) ? 1 : 0) + \
                  ((xorpktB->SymbolB != 0) ? 2 : 0) + \
                  ((xorpktB->SymbolC != 0) ? 4 : 0);

    unsigned xc = ((xorpktC->SymbolA != 0) ? 1 : 0) + \
                  ((xorpktC->SymbolB != 0) ? 2 : 0) + \
                  ((xorpktC->SymbolC != 0) ? 4 : 0);

    std::string xs;
    std::string ys;
    std::string zs;

    if (xa == 7) {
        xs = std::string(xorpktA->Data, xorpktA->Len);
    } else if (xa == 6) {
        ys = std::string(xorpktA->Data, xorpktA->Len);
    } else {
        zs = std::string(xorpktA->Data, xorpktA->Len);
    }

    if (xb == 7) {
        xs = std::string(xorpktB->Data, xorpktB->Len);
    } else if (xb == 6) {
        ys = std::string(xorpktB->Data, xorpktB->Len);
    } else {
        zs = std::string(xorpktB->Data, xorpktB->Len);
    }

    if (xc == 7) {
        xs = std::string(xorpktC->Data, xorpktC->Len);
    } else if (xc == 6) {
        ys = std::string(xorpktC->Data, xorpktC->Len);
    } else {
        zs = std::string(xorpktC->Data, xorpktC->Len);
    }

    std::string dst_host2 = std::string(IPAddress(iph2->ip_dst).unparse().mutable_c_str());
    std::string dst_host3 = std::string(IPAddress(iph3->ip_dst).unparse().mutable_c_str());
    DEBUG_PRINT("\ta: %s, b: %s, c: %s.\n", dst_host.c_str(), dst_host2.c_str(), dst_host3.c_str());
    DEBUG_PRINT("\ta: %d, b: %d, c: %d.\n", xa, xb, xc);

    // TODO: we need a smart way, to check how the 3 packets are related by looking at packet
    // header, and dropping the one that doesnt fit, or dropping all and starting over to
    // avoid livelock
    if ( xs.length() == 0 || ys.length() == 0 || zs.length() == 0 ) {
        DEBUG_PRINT("we have 3 packets, but not all the codes to them.\n");
        return;
    }

    // TODO: after confirmed correctness, reduce to single loop

    uint64_t long chunks = xs.length() >> 4ULL;
    // solve for a // 1
    // 6^7 // (b^c)^(a^b^c) // x^y
    char* aa = new char[xs.length()];
    std::string a;
    //std::tuple<std::string, unsigned long long> a;

    for (int i = 0; i < chunks ; ++i){
        // load our packets into vectors
        __m128i xx = _mm_loadu_si128 (((__m128i *)xs.c_str()) + i);
        __m128i yy = _mm_loadu_si128 (((__m128i *)ys.c_str()) + i);
        // xor and our vector back into our xor data buffer
        _mm_storeu_si128 (((__m128i *)aa) + i, _mm_xor_si128 (xx, yy));
    }
    a = std::string(aa, xs.length());

    // solve for c // 4
    // 3^7 // (a^b)^(a^b^c) // x^z
    char* cc= new char[zs.length()];
    std::string c;

    for (int i = 0; i < chunks ; ++i){
        // load our packets into vectors
        __m128i xx = _mm_loadu_si128 (((__m128i *)xs.c_str()) + i);
        __m128i zz = _mm_loadu_si128 (((__m128i *)zs.c_str()) + i);
        // xor and our vector back into our xor data buffer
        _mm_storeu_si128 (((__m128i *)cc) + i, _mm_xor_si128 (xx, zz));
    }
    c = std::string(cc, zs.length());

    // solve for b // 2
    // 1^3 // a^(a^b) // a^z
    char* bb= new char[ys.length()];
    std::string b;

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


    // TODO: sort out why not all 3 packets are being sent, and why they arent being sent consistently

    // only add a packet to sending out list if it has not already been added
    std::vector<std::string> deets;

    deets.push_back(a);
    deets.push_back(b);
    deets.push_back(c);


    // add these solutions to memory (later put it in mem cache)

    for ( auto i : deets ) {
        WritablePacket *pkt = Packet::make(i.length());
        memcpy((void*)pkt->data(), i.c_str(), i.length());

        // set the original packet header information
        pkt->set_mac_header(pkt->data(), DEFAULT_MAC_LEN);
        pkt->set_network_header(pkt->data()+DEFAULT_MAC_LEN, sizeof(click_ip));

        const click_ip *iph2 = pkt->ip_header();
        int ip_len = ntohs(iph2->ip_len);
        std::string src_host = std::string(IPAddress(iph2->ip_src).unparse().mutable_c_str());
        std::string dst_host = std::string(IPAddress(iph2->ip_dst).unparse().mutable_c_str());

        if (iph->ip_dst != iph2->ip_dst){
            //DEBUG_PRINT("packet is bogus, dropping\n");
            pkt->kill();
            continue;
        }
        DEBUG_PRINT("%s -> %s ip len: %d, data len: %lu\n", src_host.c_str(), dst_host.c_str(), ip_len, i.length());
        DEBUG_PRINT("frag'd: %d\n", (iph->ip_off & htons(IP_MF)));


        if (!IP_ISFRAG(iph)) {
            // TODO
            if (ip_len > i.length()) {
            } else {
                pkt->take(i.length()-(ip_len+DEFAULT_MAC_LEN));
            }
        } else {
            /* From IP Reassembler element code */
            // calculate packet edges
            int p_off = IP_BYTE_OFF(iph);
            int p_lastoff = p_off + ntohs(iph->ip_len) - (iph->ip_hl << 2);
    
            // check uncommon, but annoying, case: bad length, bad length + offset,
            // or middle fragment length not a multiple of 8 bytes
            if (p_lastoff > 0xFFFF || p_lastoff <= p_off
                || ((p_lastoff & 7) != 0 && (iph->ip_off & htons(IP_MF)) != 0)
                || i.length() < p_lastoff - p_off) {
                pkt->kill();
                return;
            }
            DEBUG_PRINT("taking: %d, final length: %ld\n", p_lastoff-p_off, (i.length() - (p_lastoff - p_off)));
    
            pkt->take(i.length() - (p_lastoff - p_off));
        }
        //pkt->take(i.length()-(ip_len+DEFAULT_MAC_LEN));


        // these lines in overwritting the ip header are only needed when using Linux Forwarding.
        //click_ip *iph3 = (click_ip *) pkt->data()+DEFAULT_MAC_LEN;
        //iph3->ip_len = ntohs( sizeof(click_ip) +  i.length());
        //iph3->ip_len = htons( sizeof(click_ip) +  i.length());

        // update the ip header checksum for the next host in the path
        ip_check(pkt);

        // ship it
        output(0).push(pkt);
    }

}


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
        fprintf(stderr, "packet is too large for link");
        p->kill();
        return;
    }
    if (p->length() > XORPROTO_DATA_LEN) {
        fprintf(stderr, "packet length too large for xor function\n");
        p->kill();
        return;
    }

    // saftey checks
    if (!p->has_mac_header()) {
        fprintf(stderr, "xor doesnt know how to handle this packet (no L2).\n");
        p->kill();
        return;
    }

    // annotate this packet with the current time (time monotonomically increating)
    // we'll use this in our Task function to check if we need to send the packet
    // out before enough natural packets arrive
    p->set_timestamp_anno(Timestamp::now_steady());

    const click_ether *mch = (click_ether *) p->data();
    const unsigned char *mh = p->mac_header();

    if (htons(mch->ether_type) != ETHERTYPE_IP) {
        fprintf(stderr, "xor handling non-ipv4 packet: %x\n", htons(mch->ether_type));
        p->kill();
        return;
    }

    if (!p->has_network_header()) {
        fprintf(stderr, "xor doesnt know how to handle this packet (no L3).\n");
        p->kill();
        return;
    }

    const click_ip *iph = p->ip_header();
    unsigned long dst_host = IPAddress(iph->ip_dst.s_addr);

    // get the state for this thread ( packet batches)
    State &s = _state.get();

    // we have to approach this differently depending on which
    // function is calling push
    //
    if (_function == func_encode) {
        // if there is already a packet in the batch, append this one
        auto sb = s.encode_batch.find(dst_host);
        if ( sb != s.encode_batch.end() ) {
            PacketBatch* pb = sb->second;
            pb->append_packet(p);
        // if the current batch is empty, create a new batch
        } else {
            s.encode_batch[dst_host] = PacketBatch::make_from_packet(p);
        }

        // if we dont have enough packets to do any encoding, schedule
        // the next wake function to check the batch
        if (s.encode_batch[dst_host]->count() < _symbols) {
            // if we have passed in a timer value, then set the next wake up time
            if (_timer >= 0) {
                s.timers->schedule_after(Timestamp::make_usec(_timer));
            }
        // if we have enough packets to do something
        } else {
            // take the packetbatch to send to functions
            PacketBatch* pb = s.encode_batch.at(dst_host);
            s.encode_batch.erase(dst_host);

            encode(ports, dst_host, pb);

            if (_timer >= 0) {
                s.timers->unschedule();
            }

            // after we encode, kill all the packets in the batch
            pb->kill();
        }
    } else if (_function == func_decode ) {
        auto sb = s.decode_batch.find(dst_host);
        if ( sb != s.decode_batch.end() ) {
            PacketBatch* pb = sb->second;
            pb->append_packet(p);
        // if the current batch is empty, create a new batch
        } else {
            s.decode_batch[dst_host] = PacketBatch::make_from_packet(p);
        }

        if (s.decode_batch[dst_host]->count() < _symbols) {
            // nothing we can do but wait for more symbols to come in
            return;
        } else {
            PacketBatch* pb = s.decode_batch.at(dst_host);

            // on decode it is possible that we get xor'd packets in other windows
            // so we need to make sure we handle those appropriately
            // return a packetbatch only if they all have matching ids and enough symbols
            /*
            std::pair<PacketBatch*, PacketBatch*> mbpair = matchBatch(pb, _symbols);
            if (mbpair.first) {
                // update the dst_host with this pair set
                s.decode_batch[dst_host] = mbpair.first;
            } else {
                s.decode_batch.erase(dst_host);
            }
            if (mbpair.second) {
                decode(ports, mbpair.second);
            }
            */
            s.decode_batch.erase(dst_host);
            decode(ports, pb);
        }
    } else if (_function == func_forward ) {
        // dont implement for now
        return;
    } else {
        // panic
        return;
    }

    return;
}

bool XORMsg::run_task(Task *task) {
    State &s = _state.get();

    unsigned long longest = 0;
    for (std::unordered_map<uint32_t, PacketBatch*>::iterator i = s.encode_batch.begin(); i != s.encode_batch.end(); ) {
        unsigned long dst_host = i->first;
        PacketBatch* pb = i->second;
        
        const click_ip *iph = pb->first()->ip_header();
        unsigned proto = iph->ip_p;
        // if our ip proto is set to 0, it means it is a decoded packet
        // we cant do anything with decoded packets
        if (proto == 0) {
            i++;
            continue;
        }

        // check timestamp- if the packet doesnt need to be sent off
        // continue to check next host list
        Timestamp now = Timestamp::now_steady();
        Timestamp ts_pkt = pb->first()->timestamp_anno();
        //DEBUG_PRINT("task: time of first packet: %s, time now: %s, latency: %lu\n", \
        //            ts_pkt.unparse().c_str(), now.unparse().c_str(), _latency);
        if ( now < ts_pkt + Timestamp::make_usec(_latency) ) {
            i++;
            continue;
        }


        unsigned pkts_in_queue = pb->count();
        int pkts_to_generate = _symbols - pkts_in_queue;
        for(Packet* p = pb->first();p != 0;p=p->next()) {
            for ( int count = 0; count < pkts_to_generate; count++ ) {
                unsigned length = p->length();
                if (length > longest) {
                    longest = length;
                }
            }
        }
        //DEBUG_PRINT("task: creating %u packets of size %lu.\n", pkts_to_generate, longest);


        unsigned long iplen = iph->ip_hl << 2;
        unsigned long header_length = DEFAULT_MAC_LEN + iplen;

        // create our new packets
        for (int i = 0; i < pkts_to_generate; i++) {
            WritablePacket *pkt = Packet::make(longest);
            char* ma[longest];
            memcpy(ma, pb->first()->data(), header_length);
            populate_packet(ma+header_length, longest-header_length);

            pb->append_packet(pkt);
        }

        if (pb->count() != _symbols) {
            DEBUG_PRINT("task: not enough packets\n");
            s.timers->schedule_after(Timestamp::make_usec(_timer));
            return false;
        }

        // remove the current item from the map as we've now handled the contents
        i = s.encode_batch.erase(i);

        //DEBUG_PRINT("task before sub.\n");
        std::vector<XORProto*> xor_pkts = sub_encode(pb, _symbols, longest, _mtu);
        //DEBUG_PRINT("task after sub.\n");

        //DEBUG_PRINT("task before send.\n");
        send_packets(xor_pkts, pb->first()->network_header(), pb->first()->mac_header(), dst_host);
        //DEBUG_PRINT("task after send.\n");

    }
    s.timers->schedule_after(Timestamp::make_usec(_timer));

    return true;
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel batch)
EXPORT_ELEMENT(XORMsg)
