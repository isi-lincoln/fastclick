#define DEBUG 1
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
#include "ncaproto.hh"
#include "ncamsg.hh"
#include "gferasure/src/gf_random.h"
#include "gferasure/src/gf_matrix.h"
#include "gferasure/src/gf_w.h"
#include "gferasure/src/gf8_ssse3.h"

/*
 * I've pulled these functions out directly and i've swapped the inputs
 * for low and high for my brains sake.  So first input is low table, then high table.
*/
static inline void set_up_htable (gf_8_t m, uint32_t pp, __m128i &ltbl, __m128i &htbl) {
    // set 2 64 bit values _mm_set_epi64x(__int64 b, __int64 a)
    __m128i lv = _mm_set_epi64x (0x0f0e0d0c0b0a0908LL, 0x0706050403020100LL);
    // shifts the 2 64 bit values by count _mm_slli_epi64(__m128i a, int count)
    __m128i hv = _mm_slli_epi64 (lv, 4);
    // set 16 signed 8 bit integers _mm_set1_epi8(char b)
    // so this will but the low bits of the prim poly in poly
    __m128i poly = _mm_set1_epi8 ((int8_t) (pp & 0xff));
    // sets the 128 bits to zero _mm_setzero_si128()
    __m128i zero = _mm_setzero_si128 ();
    uint64_t mul = (uint64_t)m * 0x0101010101010101ULL;
    __m128i t1;


    // __builtin_clz works on 32 bit integers, but we're only using 8 bits!
    int left_bit = __builtin_clz ((uint32_t)m) - 24;
    int i;

    // set both inputs to be 0
    ltbl = _mm_setzero_si128 ();
    htbl = _mm_setzero_si128 ();

    for (i = 7; i > left_bit; --i) {
        // Shift mask bit to high-order for each 8-bit value
        t1 = _mm_set1_epi64x (mul << (uint64_t)i);
        // Add into accumulator (using XOR) if bit in multiplicand is non-zero
        ltbl = _mm_xor_si128 (ltbl, _mm_blendv_epi8 (zero, lv, t1));
        htbl = _mm_xor_si128 (htbl, _mm_blendv_epi8 (zero, hv, t1));
        // Multiply lv and hv by 2 in the Galois field */
        // _mm_blendv_epi8 Selects integer bytes from two using variable mask

        // multiply by 2
        t1 = _mm_blendv_epi8 (zero, poly, lv);
        lv = _mm_xor_si128 (_mm_add_epi8 (lv, lv), t1);
        // multiply by 2
        t1 = _mm_blendv_epi8 (zero, poly, hv);
        hv = _mm_xor_si128 (_mm_add_epi8 (hv, hv), t1);
    }
    // Take care of adding in the last value
    // Shift mask bit to high-order for each 8-bit value
    t1 = _mm_set1_epi64x (mul << (uint64_t)i);
    ltbl = _mm_xor_si128 (ltbl, _mm_blendv_epi8 (zero, lv, t1));
    htbl = _mm_xor_si128 (htbl, _mm_blendv_epi8 (zero, hv, t1));
}

static inline __m128i gf8_mult_const_16 (__m128i v, __m128i ltbl, __m128i htbl) {
    __m128i r_lo, r_hi, hi, lo;

    // loset is because we split the tables for low & high byte results.
    __m128i loset = _mm_set1_epi8 (0x0f);

    // compute the bitwise and between 2 128b values _mm_and_si128
    lo = _mm_and_si128 (loset, v);
    // shift right _mm_srli_epi64, then and with loset
    hi = _mm_and_si128 (loset, _mm_srli_epi64 (v, 4));
    // shuffle the contects of ltbl according to lo _mm_shuffle_epi8
    r_lo = _mm_shuffle_epi8 (ltbl, lo);
    r_hi = _mm_shuffle_epi8 (htbl, hi);
    // return xor of lo and hi bit vectors
    return (_mm_xor_si128 (r_lo, r_hi));
}


/*
 * packet encoding function works as both the encode and decoding
 * of a packet.
 * inputs:
 *   - the packets in raw or encoded form
 *   - a matrix, either encoding or inverse matrix
 *   - the state, which describes the field and irreducible polynomial
 *   - max_bytes, the number of bytes in each packet
 *   - simd_vector_size, in bytes, 16 - 256 or SSE/SSSE3 and 32, 256- AVX/2
 *
*/
std::vector<gf_8_t*> packet_encoding(
    std::vector<gf_8_t*> pb,
    gf_matrix< gf_8_t, gf8_ssse3_state > matrix,
    gf_w_state< gf_8_t, gf8_ssse3_state > state,
    int max_bytes, int simd_vector_size) {

    DEBUG_PRINT("in packet encoding\n");

#ifdef DEBUG
    matrix.print("using matrix for coding");
#endif

    // TODO: also assumes all packets are the same size (max_bytes)
    assert(pb.size() > 0);
    assert(max_bytes % simd_vector_size == 0); //make sure we've padded to adjust for vectors

    int num_packets = pb.size();

    std::vector<gf_8_t*> encoded_packets;

    for (int i = 0; i < num_packets; i++) {
        gf_8_t * enc = new gf_8_t[max_bytes*num_packets];
        for (int j = 0; j < num_packets; j++) {
            // multiply a constant (encoding coefficient) by a region (packet)
            state.mul_region(pb[j], &enc[j*max_bytes], max_bytes, matrix.e(i,j), false, NULL, false);
        }

        // now we have a single array [a0*x, b0*y, c0*z]
        // we need to now XOR each packet with the corresponding packet
        gf_8_t * encF = new gf_8_t[max_bytes];
        // just unrolling here for sake of ease
        uint16_t num_vectors = max_bytes/simd_vector_size;
        for (uint16_t k = 0; k < num_vectors; k++) {
            __m128i t = _mm_loadu_si128 (((__m128i *)enc) + k);
            __m128i u = _mm_loadu_si128 (((__m128i *)enc) + (num_vectors) + k);
            __m128i v = _mm_loadu_si128 (((__m128i *)enc) + 2*(num_vectors) + k);
            _mm_storeu_si128(((__m128i *)encF)+k, _mm_xor_si128(t,_mm_xor_si128(u,v)));
        }

        encoded_packets.push_back(encF);

        delete[] enc;
    }

    //DEBUG_PRINT("in size of encoded packets: %lu\n", encoded_packets.size());
    return encoded_packets;

}

gf_matrix< gf_8_t, gf8_ssse3_state> build_rand_matrix(int dimension, gf_w_state< gf_8_t, gf8_ssse3_state > state) {
    // TODO: Add to protocol for negotiation
    // set up matrix as well.
    // need to template for gf16 as well
    gf_matrix< gf_8_t, gf8_ssse3_state > matrix = gf_matrix< gf_8_t, gf8_ssse3_state >(dimension,dimension, state);

    // create random coding coefficients
    for (int i = 0; i < dimension; i++) {
        for (int j = 0; j < dimension; j++) {
            gf_8_t rand = gf_random_val< gf_8_t > ();
            matrix.e(i,j) = rand;
        }
    }

    gf_matrix< gf_8_t, gf8_ssse3_state > inverse = gf_matrix< gf_8_t, gf8_ssse3_state >(dimension,dimension, state);

    // build a matrix until we randomly ensure it is invertible.
    int result = matrix.invert(&inverse);
    if (result != 0) {
        std::cerr << "inversion failed, creating new\n";
        return build_rand_matrix(dimension, state);
    }

#ifdef DEBUG
    matrix.print("final matrix to use.");
    inverse.print("inverted matrix");
#endif

    //inverse.~gf_matrix();

    return matrix;
}

CLICK_DECLS

#define IP_BYTE_OFF(iph)   ((ntohs((iph)->ip_off) & IP_OFFMASK) << 3)

// globals
// random number generation
std::random_device rrd;
std::seed_seq seeder{ rrd(), rrd(), rrd(), rrd(), rrd(), rrd(), rrd(), rrd() };
std::mt19937 enger(seeder);
// packet queue (dst_host, symbol, arrival time)

unsigned long long get_64bit_rand() {
    std::uniform_int_distribution< unsigned long long > uid(0, ULLONG_MAX);
    return uid(enger);
}

// update IP packet checksum
void ip_checksum_update_nca(WritablePacket *p) {
    click_ip *iph = (click_ip *) p->data();
    iph->ip_sum = 0;
    iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));
}

// this will attempt to make sure our 48 bit randoms are unique
// TODO: some out of band mgmt to request between nodes a cleaning
// of solutions and bloom filter to reduce the number of times
// rand has to be called to get a unique id - stupid alternative
// restart both every X ofter to remove from memory the ids.
unsigned long long get_48bit_rand() {
    unsigned long long r48 = get_64bit_rand() & 0xffffffffffff;
    return r48;
}


NCAMsg::NCAMsg() { };
NCAMsg::~NCAMsg() { };

FILE* FDD = fopen("/dev/urandom", "rb");
int vector_length_in_bytes = 16; // 128 bit, ssse3

// create a memory buffer the size of length filled by urand
void fill_packet_rand(void* buffer, unsigned long long length) {
    if ( FDD == NULL) {
        fprintf(stderr, "failed to open file.\n");
        exit(1);
    }
    size_t res = fread(buffer, sizeof(char), length, FDD);
    if (res != length) {
        fprintf(stderr, "populate packet failed to read length random bytes.\n");
    }
}

// work horse for all functions that need to send a packet.
// requires having a L3 (nh) and L2 (mh) header to overwrite before sending the packet.
// because NCA only handles the data of the packet, we need to have an unspoiled header.
void NCAMsg::send_packets(
    std::vector<NCAProto*> pkts, const unsigned char* nh,
    const unsigned char* mh, unsigned long dst_host) {

    DEBUG_PRINT("in send_packets: %ld\n", pkts.size());
    // TODO: this assumes a 1-1 matching between packets being coded and interfaces
    unsigned iface_counter = 0;

    // now lets create the shares
    for (auto i: pkts) {
        WritablePacket *pkt = Packet::make(i, (sizeof(NCAProto)-(NCAPROTO_DATA_LEN-i->Len)));

        // we done screwed up.
        if (!pkt) {
            DEBUG_PRINT("bad packet\n");
            return;
        }

        // add space at the front to put back on the old ip and mac headers
        Packet *ip_pkt = pkt->push(sizeof(click_ip));
        memcpy((void*)ip_pkt->data(), (void*)nh, sizeof(click_ip));

        // these lines in overwritting the ip header are only needed when using Linux Forwarding.
        click_ip *iph2 = (click_ip *) ip_pkt->data();
        iph2->ip_len = htons( sizeof(click_ip) + (sizeof(NCAProto)-(NCAPROTO_DATA_LEN-i->Len)) );

        iph2->ip_p = 0;//144-252
        // update the ip header checksum for the next host in the path
        ip_checksum_update_nca(pkt);

        // This sets/annotates the network header as well as pushes into packet
        Packet *new_pkt = pkt->push_mac_header(sizeof(click_ether));
        memcpy((void*)new_pkt->data(), (void*)mh, sizeof(click_ether));

        // send packet out the given port
        // we cant batch here because only one packet will go out a single port
        // unless we create a datastructure to hold the packets until timer
        // or threshold
        assert(iface_counter < _links);
        DEBUG_PRINT("pkt out interface\n");
        output(iface_counter).push(new_pkt);

        iface_counter++;
    }

}

// generate a random number between current and max and make sure modulo vector size
long add_padding(unsigned long max, unsigned long current, unsigned long vector) {
    DEBUG_PRINT("max: %lu, current: %lu, vector: %lu\n", max, current, vector);
    assert(max-vector > current);
    std::uniform_int_distribution< unsigned long > pad(current, max-vector);
    unsigned long tmp = pad(enger);
    if (tmp % vector != 0) {
        unsigned long added = tmp % vector;
        DEBUG_PRINT("tmp: %lu, vector: %lu, added: %lu\n", tmp, vector, added);
        tmp = tmp + (vector-added);
    }
    DEBUG_PRINT("padding value: %lu to current: %lu\n", tmp, current);
    return tmp;
}


/*
 * Handles the incoming packets to be coded together (XOR)
*/
std::vector<NCAProto*> sub_encode(
    std::vector<Packet*> pb, unsigned long longest, unsigned long mtu, uint32_t pp, int ps
) {

    DEBUG_PRINT("in sub encode, num packets: %lu, packet setting: %d\n", pb.size()), ps;
    assert(pb.size() > 0);

    std::vector<NCAProto*> ncadata;
    unsigned vector_length = vector_length_in_bytes;
    unsigned packets = pb.size();

    // adds random data to the end of each packet
    unsigned long total_length;
    if (ps < 0){
        total_length = add_padding(mtu, longest, vector_length);
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
    DEBUG_PRINT("total length: %lu\n", total_length);

    const click_ip *iph = pb[0]->ip_header();
    unsigned long iplen = iph->ip_hl << 2;
    unsigned long header_length = DEFAULT_MAC_LEN + iplen;
    unsigned long data_length = total_length-header_length;
    DEBUG_PRINT("data length: %lu\n", data_length);

    std::vector<gf_8_t *> packet_data;

    // ensure each packet is the same length
    for (int i = 0; i < packets; i++) {
        // get length of this packet
        unsigned long t_length = pb[i]->length();
        DEBUG_PRINT("total length: %lu, pkt length: %lu\n", total_length, t_length);
        assert(total_length >= t_length);
        unsigned long to_add_length = total_length - t_length;
        DEBUG_PRINT("to add length: %lu\n", to_add_length);

        // create a buffer to hold our random data
        char* ma[to_add_length];
        fill_packet_rand(ma, to_add_length);

        //gf_8_t * data[data_length];
        gf_8_t * data = new gf_8_t[total_length];

        memcpy(data, pb[i]->data(), pb[i]->length());
        memcpy(data+pb[i]->length(), ma, to_add_length);
        packet_data.push_back(data);
    }

    unsigned long long id = get_48bit_rand();


    // O(n^3) because of inversion cost to ensure matrix invertibility
    gf_w_state< gf_8_t, gf8_ssse3_state > state = gf_w_state< gf_8_t, gf8_ssse3_state >(pp, 1);
    gf_matrix< gf_8_t, gf8_ssse3_state > matrix = build_rand_matrix(packets, state);

    // we've now modified each packet of random length, now we need to do our
    // multiplications.

    std::vector<gf_8_t*> encoded = packet_encoding(packet_data, matrix, state, total_length, vector_length);

    for (auto i: packet_data){
        delete i;
    }
    //matrix.~gf_matrix();

    //matrix.print("encoded matrix");

    //DEBUG_PRINT("on wire: %lu\n", (sizeof(NCAProto)-(NCAPROTO_DATA_LEN-total_length))+DEFAULT_MAC_LEN+iplen);

    for (unsigned counter = 0; counter < packets; counter++) {
        // create our new packet
        NCAProto *ncapkt = new NCAProto;
        ncapkt->Version = 0;
        ncapkt->Len = total_length;
        ncapkt->Pkts = packets;
        memcpy(ncapkt->Data, encoded[counter], total_length);
        delete encoded[counter];

        // so we have Eq = Row <Counter> [ C0 | C1 | C2 ]
        unsigned long long t = matrix.e(counter,0);
        unsigned long long u = matrix.e(counter,1);
        unsigned long long v = matrix.e(counter,2);
        unsigned long long eq = ((counter & 0x3) << 24) ^ \
                                ((t & 0xff) << 16) ^ \
                                ((u & 0xff) << 8) ^ \
                                (v & 0xff);
        ncapkt->Equation = eq;
        ncapkt->Id = id;
        DEBUG_PRINT("id: %llu, eq: %llx\n", id, eq);

        ncadata.push_back(ncapkt);
    }


    return ncadata;
}

// allow the user to configure the shares and threshold amounts
int NCAMsg::configure(Vector<String> &conf, ErrorHandler *errh) {
    uint8_t links;
    uint8_t function;
    unsigned long timer; 
    unsigned long mtu; // in bytes
    int pkt_size; // in bytes
    if (Args(conf, this, errh)
        .read_mp("LINKS", links) // positional
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
    if (links < 2) {
        // print error
        fprintf(stderr, "Click configure: too few symbols.\n");
        return -1;
    }

    _links = links;
    _function = function;
    _pkt_size = pkt_size;

    _threads = click_max_cpu_ids();

    if (_function == func_decode) {
        unsigned new_threads = _threads;
        DEBUG_PRINT("enabling %u decode threads.\n", new_threads);
        //for (unsigned i = 0; i < new_threads; i++) {
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


    if (_timer > 0) {
        fprintf(stdout, "Click: timer lantency set to %lu ms.\n", _timer);
    } else {
        fprintf(stdout, "Click: using task threads\n");
    }

    return 0;
}

void NCAMsg::encode(int ports, unsigned long dst, std::vector<Packet*> pb) {
    DEBUG_PRINT("encode begin\n");

    std::vector<unsigned long> lengths;
    DEBUG_PRINT("encode size: %lu\n", pb.size());

    for(auto iter=pb.begin(); iter != pb.end(); iter++){
        Packet* p = (*iter);
        //DEBUG_PRINT("pkt length: %u\n", p->length());
        lengths.push_back(p->length());
    }
    //DEBUG_PRINT("find longest\n");
    // find smallest and longest sized packets, excluding 0 length if given
    unsigned long longest = *std::max_element(lengths.begin(), lengths.end());
    DEBUG_PRINT("longest element: %lu\n", longest);

    std::vector<NCAProto*> nca_pkts = sub_encode(pb, longest, _mtu, _pp, _pkt_size);
    DEBUG_PRINT("sub encode complete\n");
    send_packets(nca_pkts, pb[0]->network_header(), pb[0]->mac_header(), dst);
    DEBUG_PRINT("send packets complete\n");

    /*
    DEBUG_PRINT("encoding packet(s) took: %s\n", 
               (Timestamp::now_steady() - pb[0]->timestamp_anno()).unparse().c_str()
    );
    */

    // clear up data
    for (auto i: nca_pkts) { delete i; }
    //xor_pkts.clear();

    DEBUG_PRINT("end encode\n");
}

void set_row(uint32_t eq, int row, gf_matrix< gf_8_t, gf8_ssse3_state > *m){
    uint8_t c0 = ((eq >> 16) & 0xff);
    uint8_t c1 = ((eq >> 8) & 0xff);
    uint8_t c2 = (eq & 0xff);
    m->e(row, 0) = c0;
    m->e(row, 1) = c1;
    m->e(row, 2) = c2;
}


void NCAMsg::decode(int ports, std::vector<Packet*> pb) {
    DEBUG_PRINT("decode begin\n");
    if (pb.size() != _links){
        DEBUG_PRINT("not correct number of packets to decode\n");
        return;
    }
    int dimension = _links;

    // following from when we encoded our data and put our xor data into
    // the pkt data field, we now need to extract it
    gf_w_state< gf_8_t, gf8_ssse3_state > state = gf_w_state< gf_8_t, gf8_ssse3_state >(_pp, 1);
    gf_matrix< gf_8_t, gf8_ssse3_state > matrix = gf_matrix< gf_8_t, gf8_ssse3_state >(dimension,dimension, state);

    const click_ip *iph_orig;


    // TODO: assumes _links size = 3
    std::vector<gf_8_t *> packet_data = {NULL, NULL, NULL};
    unsigned long data_length = 0;
    // ensure each packet is the same length
    for (int i = 0; i < dimension; i++) {
        const click_ip *iph = pb[i]->ip_header();
        unsigned long iplen = iph->ip_hl << 2;
        unsigned long header_length = DEFAULT_MAC_LEN + iplen;
        const NCAProto *nca = reinterpret_cast<const NCAProto *>(pb[i]->data()+header_length);
        unsigned position = ((nca->Equation >> 24) & 0x3);

        set_row(nca->Equation, position, &matrix);
        data_length = nca->Len;
        iph_orig = iph;

        gf_8_t * data = new gf_8_t[nca->Len];
        memcpy(data, nca->Data, nca->Len);
        packet_data[position] = data;
    }

    unsigned long iplen = iph_orig->ip_hl << 2;

    gf_matrix< gf_8_t, gf8_ssse3_state > inverse = gf_matrix< gf_8_t, gf8_ssse3_state >(dimension,dimension, state);

    // build a matrix until we randomly ensure it is invertible.
    int result = matrix.invert(&inverse);
    if (result != 0) {
        std::cerr << "something went wrong inverting\n";
    }

#ifdef DEBUG
    matrix.print("decoded matrix");
    inverse.print("inverted matrix");
#endif

    unsigned vector_length = vector_length_in_bytes;
    std::vector<gf_8_t*> uncoded = packet_encoding(packet_data, inverse, state, data_length, vector_length);

    for (auto i: packet_data){
        delete i;
    }
    //matrix.~gf_matrix();
    //inverse.~gf_matrix();

    PacketBatch* ppb = 0;
    for ( int i = 0; i < uncoded.size(); i++) {
        WritablePacket *pkt = Packet::make(data_length);
        memcpy((void*)pkt->data(), uncoded[i], data_length);
        delete uncoded[i];

        // set the original packet header information
        pkt->set_mac_header(pkt->data(), DEFAULT_MAC_LEN);
        pkt->set_network_header(pkt->data()+DEFAULT_MAC_LEN, sizeof(click_ip));
        const click_ip *iph2 = pkt->ip_header();
        int ip_len = ntohs(iph2->ip_len);
        std::string src_host = std::string(IPAddress(iph2->ip_src).unparse().mutable_c_str());
        std::string dst_host = std::string(IPAddress(iph2->ip_dst).unparse().mutable_c_str());
        std::string end_host = std::string(IPAddress(iph_orig->ip_dst).unparse().mutable_c_str());
        DEBUG_PRINT("%s -> (%s) ? [%s]\n", src_host.c_str(), dst_host.c_str(), end_host.c_str());

        if (iph_orig->ip_dst != iph2->ip_dst){
            DEBUG_PRINT("packet is bogus, dropping\n");
            pkt->kill();
            continue;
        }

        if (!IP_ISFRAG(iph_orig)) {
            if (data_length > (ip_len+DEFAULT_MAC_LEN)) {
                pkt->take(data_length-(ip_len+DEFAULT_MAC_LEN));
            }
        } else {
            /* From IP Reassembler element code */
            // calculate packet edges
            int p_off = IP_BYTE_OFF(iph_orig);
            int p_lastoff = p_off + ntohs(iph_orig->ip_len) - (iph_orig->ip_hl << 2);

            // check uncommon, but annoying, case: bad length, bad length + offset,
            // or middle fragment length not a multiple of 8 bytes
            if (p_lastoff > 0xFFFF || p_lastoff <= p_off
                || ((p_lastoff & 7) != 0 && (iph_orig->ip_off & htons(IP_MF)) != 0)
                || data_length < p_lastoff - p_off) {
                pkt->kill();
                continue;
            }

            if(data_length > (p_lastoff - p_off)){
                pkt->take(data_length - (p_lastoff - p_off));
            }
        }

        // update the ip header checksum for the next host in the path
        ip_checksum_update_nca(pkt);

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

int NCAMsg::initialize(ErrorHandler *errh) {
    return 0;
}


int ensure_packet_header(Packet *p) {
    // TODO: packet length bounds check.
    if (p->length() > 8000) {
        fprintf(stderr, "packet is too large for link\n");
        return -1;
    }
    if (p->length() > NCAPROTO_DATA_LEN) {
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


// TODO pick up here tomorrow
void NCAMsg::push_batch(int ports, PacketBatch *pb){
    DEBUG_PRINT("in push batch\n");
    std::vector<Packet*> vpb;
    FOR_EACH_PACKET(pb,p){
        p->set_timestamp_anno(Timestamp::now_steady());
        vpb.push_back(p);
    }

    if (_function == func_encode) {
        DEBUG_PRINT("encode func: %d\n", pb->count());
        // local destination map to use for quick shipping
        std::unordered_map<uint32_t, std::vector<Packet*> > dst_map;

        // for each packet in the batch, check that it is valid
        // and then add it to the local ip_dst map
        for (auto it = vpb.begin(); it != vpb.end(); it++){
            Packet* p = *it;
            int rc = ensure_packet_header(p);
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
            if ( vp.size() % _links != 0 ) {
                int pkts_to_generate =  _links - (vp.size() % _links);
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
                    fill_packet_rand(ma+header_length, temp_length-header_length);
                    pkt->set_mac_header(pkt->data(), DEFAULT_MAC_LEN);
                    pkt->set_network_header(pkt->data()+DEFAULT_MAC_LEN, sizeof(click_ip));

                    vp.push_back(pkt);
                }

                DEBUG_PRINT("created %d fake packets\n", pkts_to_generate);

            }

            while(vp.size() > 0) {
                DEBUG_PRINT("encode many, size: %lu\n", vp.size());
                // create a new packetbatch for  from the first 3 packets
                // in vector
                std::vector<Packet*> new_pb(vp.begin(), vp.begin()+_links);

                // call encode
                encode(ports, dst_host, new_pb);

                vp.erase(vp.begin(), vp.begin()+_links);
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
        DEBUG_PRINT("decode func: %d\n", pb->count());

        // local destination map to use for quick shipping
        std::unordered_map<uint32_t, std::vector<Packet*> > dst_map;
        std::unordered_map<unsigned long long, std::vector<Packet*> > sym_map;

        // for each packet in the batch, check that it is valid
        // and then add it to the local ip_dst map
        for (auto it = vpb.begin(); it != vpb.end(); it++){
            Packet* p = *it;
            int rc = ensure_packet_header(p);
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
        
                const NCAProto *ncapkt = reinterpret_cast<const NCAProto *>(p->data()+header_length);
                unsigned long long clusterid = ncapkt->Id;
 
                sym_map[clusterid].push_back(p);
            }

            DEBUG_PRINT("symbol map keys: %lu\n", sym_map.size());
            for (auto const& sm : sym_map){
                std::vector<Packet*> spb = sm.second;
                unsigned long long clusterid = sm.first;
                DEBUG_PRINT("symbol values: %lu\n", spb.size());
                if (spb.size() < _links) {
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
void NCAMsg::push(int ports, Packet *p) {
    fprintf(stderr, "push not enabled for xormsg. use push_batch, enable --enable_batch in configuration.\n");
    fprintf(stderr, "FromDevice -> FromDPDKDevice, xormsg requires all elements be in push mode.\n");
    exit(1);
}

bool NCAMsg::loop_helper(){
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
        } else if ( vp.size() < _links ) {
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

    /*
    plock.acquire();
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
    plock.release();
    */

    return true;
}

void NCAMsg::run_timer(Timer *task) {
    State &s = _state.get();
    loop_helper();
    //DEBUG_PRINT("rescheduling helper in: %lu ms\n", _timer);
    s.timers->reschedule_after_msec(_timer);
}


//bool NCAMsg::run_task(Task *task) { return false; }
bool NCAMsg::run_task(Task *task) {
    State &s = _state.get();
    bool rc = loop_helper();
    s.tasks->fast_reschedule();
    return rc;
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel batch)
EXPORT_ELEMENT(NCAMsg)
