//#define DEBUG 1
#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...)    fprintf(stderr, fmt, ## args)
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
//#include "bloom/bloom_filter.hpp"

CLICK_DECLS

#define IP_BYTE_OFF(iph)   ((ntohs((iph)->ip_off) & IP_OFFMASK) << 3)

// globals
// random number generation
std::random_device r;
std::seed_seq seed{ r(), r(), r(), r(), r(), r(), r(), r() };
std::mt19937 eng(seed);
// bloom filter
//bloom_filter filter;
// packet queue (dst_host, symbol, arrival time)

unsigned long long get_64_rand() {
    std::uniform_int_distribution< unsigned long long > uid(0, ULLONG_MAX);
    return uid(eng);
}

// update IP packet checksum
void ip_checksum_update_xor(WritablePacket *p) {
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
    return r48;
}


XORMsg::XORMsg() { };
XORMsg::~XORMsg() { };

FILE* FD = fopen("/dev/urandom", "rb");

// create a memory buffer the size of length filled by urand
char* populate_packet(void* buffer, unsigned long long length) {
    if ( FD == NULL) {
        fprintf(stderr, "failed to open file.\n");
        exit(1);
    }
    size_t res = fread(buffer, sizeof(char), length, FD);
    if (res != length) {
        fprintf(stderr, "populate packet failed to read length random bytes.\n");
    }

    return (char*)buffer;
}

// generate a random number between current and max and make sure modulo vector size
long padding_to_add(unsigned long max, unsigned long current, unsigned long vector) {
    DEBUG_PRINT("max: %lu, current: %lu, vector: %lu\n", max, current, vector);
    assert(max-vector >= current);
    std::uniform_int_distribution< unsigned long > pad(current, max-vector);
    unsigned long tmp = pad(eng);
    if (tmp % vector != 0) {
        unsigned long added = tmp % vector;
        DEBUG_PRINT("tmp: %lu, vector: %lu, added: %lu\n", tmp, vector, added);
        tmp = tmp + (vector-added);
    }
    DEBUG_PRINT("padding value: %lu to current: %lu\n", tmp, current);
    return tmp;
}





// work horse for all functions that need to send a packet.
// requires having a L3 (nh) and L2 (mh) header to overwrite before sending the packet.
// because XOR only handles the data of the packet, we need to have an unspoiled header.
void XORMsg::send_packets(
    std::vector<XORProto*> pkts, const unsigned char* nh,
    const unsigned char* mh, unsigned long dst_host) {

    // TODO: this assumes a 1-1 matching between packets being XORd and interfaces
    unsigned iface_counter = 0;
    // now lets create the shares
    //DEBUG_PRINT("send_pkts size: %lu\n", pkts.size());
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
        ip_checksum_update_xor(pkt);

        // This sets/annotates the network header as well as pushes into packet
        Packet *new_pkt = pkt->push_mac_header(sizeof(click_ether));
        memcpy((void*)new_pkt->data(), (void*)mh, sizeof(click_ether));

        //DEBUG_PRINT("sending packet for interface: %d\n", iface_counter);

        // send packet out the given port
        // we cant batch here because only one packet will go out a single port
        // unless we create a datastructure to hold the packets until timer
        // or threshold
        assert(iface_counter < _symbols);
        output(iface_counter).push(new_pkt);

        iface_counter++;
    }

}


/*
 * Handles the incoming packets to be coded together (XOR)
*/
std::vector<XORProto*> sub_encode(
    std::vector<Packet*> pb, unsigned symbols, unsigned long longest, unsigned long mtu, int ps
) {
    if (pb.size() != symbols) {
        fprintf(stderr, "number of packets should be equal to symbols.\n");
        return {};
    }

    // vector can either be 16 byte for SSE/SSSE or 32 for AVX/2
    unsigned int vector_length = 16;

    // adds random data to the end of each packet
    unsigned long total_length;
    if (ps < 0){
        total_length = padding_to_add(mtu, longest, vector_length);
    } else if (ps == 0) {
        if (longest % vector_length != 0) {
            unsigned int added = longest % vector_length;
            total_length = longest+(vector_length-added);
        } else {
            total_length = longest;
        }
    } else {
        if (ps % vector_length != 0) {
            unsigned int added = ps % vector_length;
            total_length = ps+(vector_length-added);
        } else {
            total_length = ps;
        }
    }

    //DEBUG_PRINT("array: %u, longest: %lu, with padding: %lu\n", pb->count(), longest, total_length);

    // TODO: create arbitrary for size symbol, when symbol != 3
    unsigned long al = pb[0]->length();
    unsigned long bl = pb[1]->length();
    unsigned long cl = pb[2]->length();
    char* ma[total_length];
    char* mb[total_length]; 
    char* mc[total_length];
    memcpy(ma, pb[0]->data(), al);
    memcpy(mb, pb[1]->data(), bl);
    memcpy(mc, pb[2]->data(), cl);

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
        assert(aligned==0);
        uint64_t chunks = total_length >> 4ULL;
        //DEBUG_PRINT("total_length: %lu, aligned: %u, chunks: %lu\n", total_length, aligned, chunks);
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
    unsigned long timer; 
    unsigned long mtu; 
    int pkt_size;
    if (Args(conf, this, errh)
        .read_mp("SYMBOLS", symbols) // positional
        .read_mp("PURPOSE", function) // positional
        .read_mp("TIMER", timer) // positional
        .read_mp("MTU", mtu) // positional
        .read_mp("PACKET", pkt_size) // positional
        .complete() < 0){
            fprintf(stderr, "Click configure failed.\n");
            return -1;
    }
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
        fprintf(stderr, "Click configure: too few symbols.\n");
        return -1;
    }

    _symbols = symbols;
    _function = function;
    _pkt_size = pkt_size;

    _threads = click_max_cpu_ids();

    if (_function == func_decode) {
        unsigned new_threads = _threads;
        DEBUG_PRINT("enabling %u decode threads.\n", new_threads);
        for (unsigned i = 0; i < 1; i++) {
            State &s = _state.get_value_for_thread(i);
            // Task Code
            if (_timer == 0) {
                s.tasks = new Task(this);
                s.tasks->initialize(this,true);
                s.tasks->move_thread(i);
            } else {
                s.timers = new Timer(this);
                s.timers->initialize(this,true);
                float timer_offset = (_timer / new_threads)*i;
                s.timers->reschedule_after_msec((int)floor(timer_offset));
                s.timers->move_thread(i);
                DEBUG_PRINT("starting thread %u in %d ms.\n", i, (int)floor(timer_offset));
            }
        }
    }
    

    fprintf(stdout, "Click: timer lantency set to %lu ms.\n", _timer);

    return 0;
}

void XORMsg::encode(int ports, unsigned long dst, std::vector<Packet*> pb) {
    //DEBUG_PRINT("encode begin\n");

    std::vector<unsigned long> lengths;
    //DEBUG_PRINT("encode size: %lu\n", pb.size());

    for(auto iter=pb.begin(); iter != pb.end(); iter++){
        Packet* p = (*iter);
        //DEBUG_PRINT("pkt length: %u\n", p->length());
        lengths.push_back(p->length());
    }
    //DEBUG_PRINT("find longest\n");
    // find smallest and longest sized packets, excluding 0 length if given
    unsigned long longest = *std::max_element(lengths.begin(), lengths.end());
    //DEBUG_PRINT("longest element: %lu\n", longest);

    std::vector<XORProto*> xor_pkts = sub_encode(pb, _symbols, longest, _mtu, _pkt_size);
    send_packets(xor_pkts, pb[0]->network_header(), pb[0]->mac_header(), dst);

    /*
    DEBUG_PRINT("encoding packet(s) took: %s\n", 
               (Timestamp::now_steady() - pb[0]->timestamp_anno()).unparse().c_str()
    );
    */

    // clear up data
    for (auto i: xor_pkts) { delete i; }
    //xor_pkts.clear();

    //DEBUG_PRINT("end encode\n");
}


void XORMsg::decode(int ports, std::vector<Packet*> pb) {
    //DEBUG_PRINT("decode begin\n");
    if (pb.size() != _symbols){
        DEBUG_PRINT("not correct number of packets to decode\n");
        return;
    }

    // TODO: This assumes _symbols = 3, which so does xormsg.proto
    // so we need to come up with a better symbols method,
    // then we can rewrite this as 2<<X ? : 0 for checks
    const click_ip *iph = pb[0]->ip_header();
    const click_ip *iph2 = pb[1]->ip_header();
    const click_ip *iph3 = pb[2]->ip_header();

    unsigned long iplen = iph->ip_hl << 2;
    unsigned long header_length = DEFAULT_MAC_LEN + iplen;

    std::string dst_host = std::string(IPAddress(iph->ip_dst).unparse().mutable_c_str());
    //DEBUG_PRINT("in decode after saftey checks: %s (%u)\n", dst_host.c_str(), pb->first()->length());

    // following from when we encoded our data and put our xor data into
    // the pkt data field, we now need to extract it
    const XORProto *xorpktA = reinterpret_cast<const XORProto *>(pb[0]->data()+header_length);
    const XORProto *xorpktB = reinterpret_cast<const XORProto *>(pb[1]->data()+header_length);
    const XORProto *xorpktC = reinterpret_cast<const XORProto *>(pb[2]->data()+header_length);

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

    // TODO: we need a smart way, to check how the 3 packets are related by looking at packet
    // header, and dropping the one that doesnt fit, or dropping all and starting over to
    // avoid livelock
    if ( xs.length() == 0 || ys.length() == 0 || zs.length() == 0 ) {
        DEBUG_PRINT("we have 3 packets, but not all the codes to them.\n");
        return;
    }

    uint64_t long chunks = xs.length() >> 4ULL;
    // solve for a // 1
    // 6^7 // (b^c)^(a^b^c) // x^y
    char aa[xs.length()];
    std::string a;

    //DEBUG_PRINT("decode chunks: %lu.\n", chunks);
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
    char cc[zs.length()];
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
    char bb[ys.length()];
    std::string b;

    for (int i = 0; i < chunks ; ++i){
        // load our packets into vectors
        __m128i xx = _mm_loadu_si128 (((__m128i *)xs.c_str()) + i);
        __m128i yy = _mm_loadu_si128 (((__m128i *)ys.c_str()) + i);
        __m128i zz = _mm_loadu_si128 (((__m128i *)zs.c_str()) + i);
        // xor and our vector back into our xor data buffer
        _mm_storeu_si128 (((__m128i *)bb) + i, _mm_xor_si128 (xx, _mm_xor_si128 (yy, zz)));
    }
    b = std::string(bb, ys.length());

    // only add a packet to sending out list if it has not already been added
    std::vector<std::string> deets{a,b,c};

    // add these solutions to memory (later put it in mem cache)

    PacketBatch* ppb = 0;
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
            DEBUG_PRINT("packet is bogus, dropping\n");
            pkt->kill();
            continue;
        }


        if (!IP_ISFRAG(iph)) {
            if (i.length() > (ip_len+DEFAULT_MAC_LEN)) {
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
                continue;
            }

            if(i.length() > (p_lastoff - p_off)){
                pkt->take(i.length() - (p_lastoff - p_off));
            }
        }


        // update the ip header checksum for the next host in the path
        ip_checksum_update_xor(pkt);

        if (ppb == 0) {
            ppb = PacketBatch::make_from_packet(pkt);
        } else {
            ppb->append_packet(pkt);
        }

    }

    // ship it, we've put them all in a batch to reduce whatever latency
    // is cause by shiping out the interface
    output(0).push_batch(ppb);

    DEBUG_PRINT("decoding packet took: %s\n", (Timestamp::now_steady() - pb[0]->timestamp_anno()).unparse().c_str());

}

// TODO random generation
// TODO bounds checking on overflow - does this matter? we will force app to manage staleness
int XORMsg::initialize(ErrorHandler *errh) {
    return 0;
}


int check_packet_header(Packet *p) {
    // TODO: packet length bounds check.
    if (p->length() > 8000) {
        fprintf(stderr, "packet is too large for link\n");
        return -1;
    }
    if (p->length() > XORPROTO_DATA_LEN) {
        fprintf(stderr, "packet length too large for xor function\n");
        return -1 ;
    }
    if (!p->has_mac_header()) {
        fprintf(stderr, "xor doesnt know how to handle this packet (no L2).\n");
        return -1;
    }

    const click_ether *mch = (click_ether *) p->data();
    const unsigned char *mh = p->mac_header();

    if (htons(mch->ether_type) != ETHERTYPE_IP) {
        fprintf(stderr, "xor handling non-ipv4 packet: %x\n", htons(mch->ether_type));
        return -1;
    }

    if (!p->has_network_header()) {
        fprintf(stderr, "xor doesnt know how to handle this packet (no L3).\n");
        return -1;
    }

    return 1;
}


void XORMsg::push_batch(int ports, PacketBatch *pb){
    std::vector<Packet*> vpb;
    FOR_EACH_PACKET(pb,p){
        p->set_timestamp_anno(Timestamp::now_steady());
        vpb.push_back(p);
    }
    //pb_mem.push_back(pb);

    if (_function == func_encode) {
        //DEBUG_PRINT("encode func: %d\n", pb->count());
        // local destination map to use for quick shipping
        std::unordered_map<uint32_t, std::vector<Packet*> > dst_map;

        // for each packet in the batch, check that it is valid
        // and then add it to the local ip_dst map
        for (auto it = vpb.begin(); it != vpb.end(); it++){
            Packet* p = *it;
            int rc = check_packet_header(p);
            if (rc < 0) {
                vpb.erase(it--); // erase current element
                continue;
            }

            const click_ip *iph = p->ip_header();
            unsigned long dst_host = IPAddress(iph->ip_dst.s_addr);

            dst_map[dst_host].push_back(p);
        }

        // now we check that local map for all packets with the same dest
        // while there are enough to encode together, do so, when we have
        // less than the desired amount, we treat like a single packet.
        for (auto const& dm : dst_map){
            std::vector<Packet*> vp = dm.second;
            unsigned long dst_host = dm.first;
            std::vector<char*> tmp;

            // if we dont have enough packets to create symbols, create bogus
            if ( vp.size() % _symbols != 0 ) {
                int pkts_to_generate =  _symbols - (vp.size() % _symbols);
                for (int i = 0; i < pkts_to_generate; i++) {
                    unsigned long temp_length = vp[0]->length();
                    WritablePacket *pkt = Packet::make(temp_length);
                    const click_ip *iph = vp[0]->ip_header();
                    unsigned long iplen = iph->ip_hl << 2;
                    unsigned long header_length = DEFAULT_MAC_LEN + iplen;

                    // this is allocated memory we need to clean up before function end
                    char* ma= new char[temp_length];
                    tmp.push_back(ma);

                    memcpy(ma, vp[0], header_length);
                    populate_packet(ma+header_length, temp_length-header_length);

                    vp.push_back(pkt);
                }
            }

            while(vp.size() > 0) {
                //DEBUG_PRINT("encode many, size: %lu\n", vp.size());
                // create a new packetbatch for encode from the first 3 packets
                // in vector
                std::vector<Packet*> new_pb(vp.begin(), vp.begin()+_symbols);

                // call encode
                encode(ports, dst_host, new_pb);

                vp.erase(vp.begin(), vp.begin()+_symbols);
                for (auto p : new_pb) {
                    if (p) {
                        p->kill();
                    }
                }
                //new_pb.clear();
            }
            
            // clean up our allocated memory
            for (auto m: tmp) {
                delete m;
            }
            //tmp.clear();

        }

        //pb->kill();
    } else if (_function == func_decode) {
        //DEBUG_PRINT("decode func: %d\n", pb->count());

        // local destination map to use for quick shipping
        std::unordered_map<uint32_t, std::vector<Packet*> > dst_map;
        std::unordered_map<unsigned long long, std::vector<Packet*> > sym_map;

        // for each packet in the batch, check that it is valid
        // and then add it to the local ip_dst map
        for (auto it = vpb.begin(); it != vpb.end(); it++){
            Packet* p = *it;
            int rc = check_packet_header(p);
            if (rc < 0) {
                vpb.erase(it--); // erase current element
                if (p) {
                    p->kill();
                }
                continue;
            }

            const click_ip *iph = p->ip_header();
            unsigned long dst_host = IPAddress(iph->ip_dst.s_addr);

            dst_map[dst_host].push_back(p);
        }

        for (auto const& dm : dst_map){
            std::vector<Packet*> dvpb = dm.second;

            for (auto &p : dvpb) {
                const click_ip *iph = p->ip_header();
                unsigned long iplen = iph->ip_hl << 2;
                unsigned long header_length = DEFAULT_MAC_LEN + iplen;
        
                // if the proto is not 0 than this is not a decode packet
                unsigned proto = iph->ip_p;
                if (proto != 0) {
                    if (p) {
                        p->kill();
                    }
                    continue;
                }
        
                const XORProto *xorpkt = reinterpret_cast<const XORProto *>(p->data()+header_length);
                unsigned long long clusterid = xorpkt->SymbolB;
 
                sym_map[clusterid].push_back(p);
            }

            //DEBUG_PRINT("symbol map keys: %lu\n", sym_map.size());
            for (auto const& sm : sym_map){
                std::vector<Packet*> spb = sm.second;
                unsigned long long clusterid = sm.first;
                //DEBUG_PRINT("symbol values: %lu\n", spb.size());
                if (spb.size() < _symbols) {
                    for (auto &p: spb){
                        dlock.acquire();
                        //DEBUG_PRINT("lock acquired 2\n");
                        decode_map[clusterid].push_back(p);
                        dlock.release();
                        //DEBUG_PRINT("lock release 2\n");
                    }
                } else {
                    // This code doesnt get called because encoder function is sending
                    // each packet at once, because we arent packetbatching it out
                    DEBUG_PRINT("calling decode\n");
                    decode(ports, spb);
                    for (auto p: spb){
                        if (p) {
                            p->kill();
                        }
                    }
                }
            }
        }
        
    } else {
        fprintf(stderr, "unknown function. not supported: %d\n", _function);
        return;
    }
}


/*
 * Defunct: Use push_batch()
 * Requires: --enable-batch (--enable-flow) in click configuration parameters
 */
void XORMsg::push(int ports, Packet *p) {
    fprintf(stderr, "push not enabled for xormsg. use push_batch, enable --enable_batch in configuration.\n");
    fprintf(stderr, "FromDevice -> FromDPDKDevice, xormsg requires all elements be in push mode.\n");
    exit(1);
}

bool XORMsg::loop_helper(){
    dlock.acquire();
    std::vector<uint64_t> old_keys;
    /*
    if (decode_map.size() == 0) {
        decode_map.clear();
        dlock.release();
        return true;
    }
    */

    for (auto &dm: decode_map){
        uint64_t cid = dm.first;
        std::vector<Packet*> vp = dm.second;

        if ( vp.size() == 0  ) {
            old_keys.push_back(dm.first);
        } else if ( vp.size() < _symbols ) {
            // remove anything unmatched after 100ms
            if ((Timestamp::now_steady() - vp[0]->timestamp_anno()).msec() > 100) {
                for (auto p : vp){
                    if (p) {
                        p->kill();
                    }
                }
                old_keys.push_back(dm.first);
            }
        } else {
            decode(0, vp);
            for (auto p : vp){
                if (p) {
                    p->kill();
                }
            }
            old_keys.push_back(dm.first);
        }
    }

    /*
    if (old_keys.size() != 0) {
        DEBUG_PRINT("Deleting %lu of %lu keys\n", old_keys.size(), decode_map.size());
    }
    */
    for (auto key: old_keys){
        decode_map.erase(key);
    }

    dlock.release();

    plock.acquire();
    /*
    for (auto it = pb_mem.begin(); it != pb_mem.end(); it++){
        PacketBatch* pb = (*it);
        if (pb) {
            FOR_EACH_PACKET_SAFE(pb,p){
                if (p) {
                    p->kill();
                }
            }
        }
        pb_mem.erase(it--);
    }
    */
    plock.release();

    return true;
}

void XORMsg::run_timer(Timer *task) {
    State &s = _state.get();
    loop_helper();
    //DEBUG_PRINT("rescheduling helper in: %lu ms\n", _timer);
    s.timers->reschedule_after_msec(_timer);
}


//bool XORMsg::run_task(Task *task) { return false; }
bool XORMsg::run_task(Task *task) {
    State &s = _state.get();
    bool rc = loop_helper();
    s.tasks->fast_reschedule();
    return rc;
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel batch)
EXPORT_ELEMENT(XORMsg)
