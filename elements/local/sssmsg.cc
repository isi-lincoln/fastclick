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


// handling shared cache
//#include <mutex>          // std::mutex
#include <assert.h>    // sanity check
#include <iostream>
#include <random> // random number generators

/*****   THIS IS THE CRYPTO SECTION *****/
#include <iostream>
#include <cstdlib>
#include <sstream> // istream

#include <cryptopp/ida.h> // SecretSharing
#include <cryptopp/osrng.h> // RandomNumberGenerator
#include <cryptopp/randpool.h> // RandomPool
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>  // SecBlock
#include <cryptopp/files.h> // FileSource
/*****   THIS IS END CRYPTO SECTION *****/

// protocol files
#include "sssproto.hh"
#include "sssmsg.hh"
#include "xormsg.hh"


std::random_device rr;
std::seed_seq seed2{ rr(), rr(), rr(), rr(), rr(), rr(), rr(), rr() };
std::mt19937 eng2(seed2);
uint64_t get_64_rand2() {
    std::uniform_int_distribution< uint64_t > uid(0, ULLONG_MAX);
    return uid(eng2);
}


CLICK_DECLS

#define IP_BYTE_OFF2(iph)    ((ntohs((iph)->ip_off) & IP_OFFMASK) << 3)

SSSMsg::SSSMsg() { };
SSSMsg::~SSSMsg() { };

FILE* FDDD = fopen("/dev/urandom", "rb");

// create a memory buffer the size of length filled by urand
void fill_packet_rand2(void* buffer, unsigned long long length) {
    if ( FDDD == NULL) {
        fprintf(stderr, "failed to open file.\n");
        exit(1);
    }
    size_t res = fread(buffer, sizeof(char), length, FDDD);
    if (res != length) {
        fprintf(stderr, "populate packet failed to read length random bytes.\n");
    }
}

std::vector<std::string> SSSMsg::SplitData(int threshold, int nShares, std::string secret) {

    // rng
    CryptoPP::AutoSeededRandomPool rng;

    // modify our string into cryptopp vector
    std::vector<CryptoPP::byte> secVec(secret.begin(), secret.end());
    std::vector<CryptoPP::byte> shareVec(nShares);

    CryptoPP::ChannelSwitch *channelSwitch = new CryptoPP::ChannelSwitch;
    //std::string chanName("123");
    //CryptoPP::BufferedTransformation bufTrans = new CryptoPP::BufferedTransformation;
    // initialize channelswitch (moves data from source to sink through filters)
    //CryptoPP::ChannelSwitch *channelSwitch = new CryptoPP::ChannelSwitch(bufTrans, chanName);

    // typedef of StringSource( byte *string, size_t length, pumpall, BufferedTransformation)
    // create a source that uses our secret, and puts a filter (secret sharing) to move the
    // data using our channel switch above
    CryptoPP::SecretSharing *ss = new CryptoPP::SecretSharing(
            rng,
            threshold,
            nShares,
            channelSwitch);
    //CryptoPP::VectorSource source(secVec, true, ss);
    CryptoPP::VectorSource source(secVec, false, ss);


    // from ida example, just use string instead of vector
    std::vector<std::string> strShares(nShares);
    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks(nShares);

    std::string channel;

    // based on the number of shares to generate, we know go through and do the computation
    for (int i = 0; i < nShares; i++)    {
        // creates a new StringSink set to shares[i]
        strSinks[i].reset(new CryptoPP::StringSink(strShares[i]));

        channel = CryptoPP::WordToString<CryptoPP::word32>(i);
            strSinks[i]->Put( (CryptoPP::byte *)channel.data(), 4 ); // 4 because 32/8 is 4
        channelSwitch->AddRoute( channel,*strSinks[i], CryptoPP::DEFAULT_CHANNEL );
        //channelSwitch->AddRoute( channel,*strSinks[i], chanName );

    }

    source.PumpAll();

    return strShares;
}

std::string SSSMsg::RecoverData(int threshold, std::vector<std::string> shares) {
    std::string secret;
    CryptoPP::SecretRecovery recovery(threshold, new CryptoPP::StringSink(secret));

    CryptoPP::vector_member_ptrs<CryptoPP::StringSource> strSources(threshold);

    CryptoPP::SecByteBlock channel(4);
    int i;
    for (i=0; i<threshold; i++)
    {
        strSources[i].reset(new CryptoPP::StringSource(shares[i], false));
        strSources[i]->Pump(4);
        strSources[i]->Get(channel, 4);
        strSources[i]->Attach(new CryptoPP::ChannelSwitch(recovery, std::string((char *)channel.begin(), 4)));
    }

    while (strSources[0]->Pump(256))
        for (i=1; i<threshold; i++)
            strSources[i]->Pump(256);

    for (i=0; i<threshold; i++)
        strSources[i]->PumpAll();

    return secret;
}

// allow the user to configure the shares and threshold amounts
int SSSMsg::configure(Vector<String> &conf, ErrorHandler *errh) {
    uint8_t shares;
    uint8_t threshold;
    uint8_t function;
    uint32_t timer;
    uint32_t mtu;
    int pkt_size; // in bytes
    if (Args(conf, this, errh)
        .read_mp("SHARES", shares) // positional
        .read_mp("THRESHOLD", threshold) // positional
        .read_mp("FUNCTION", function) // positional
        .read_mp("TIMER", timer) // positional
        .read_mp("MTU", mtu) // positional
        .read_mp("PACKET", pkt_size) // positional
        .complete() < 0){
            return -1;
    }

    // shares must be greater than or equal to threshold
    if (threshold >= shares) {
        // print error
        return -1;
    }

    // number of shares must be greater than 1. Otherwise we are not sending packets.
    // number of threshold must be greater than 2. Otherwise we are not encoding.
    if (shares < 1 || threshold < 2) {
        return -1;
    }

    _shares = shares;
    _threshold = threshold;
    _function = function;
    _timer = timer;
    _mtu = mtu;

    int _threads = click_max_cpu_ids();

    if (_function == func_decrypt) {
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

    return 0;
}

int SSSMsg::initialize(ErrorHandler *errh){ return 0; }


// update IP packet checksum
void ip_checksum_update_sss(WritablePacket *p) {
    click_ip *iph = (click_ip *) p->data();
    iph->ip_sum = 0;
    iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));
}

int check_sss_packet_header(Packet *p) {
    // TODO: packet length bounds check.
    if (p->length() > 8000) {
        fprintf(stderr, "packet is too large for link\n");
        return -1;
    }
    if (p->length() > SSSPROTO_DATA_LEN) {
        fprintf(stderr, "packet length too large for sss function\n");
        return -1 ;
    }
    if (!p->has_mac_header()) {
        fprintf(stderr, "sss doesnt know how to handle this packet (no L2).\n");
        return -1;
    }

    const click_ether *mch = (click_ether *) p->data();
    const unsigned char *mh = p->mac_header();

    if (htons(mch->ether_type) != ETHERTYPE_IP) {
        fprintf(stderr, "sss handling non-ipv4 packet: %x\n", htons(mch->ether_type));
        return -1;
    }

    if (!p->has_network_header()) {
        fprintf(stderr, "sss doesnt know how to handle this packet (no L3).\n");
        return -1;
    }

    return 1;
}


/*
 * encrypt
 *
 * takes in a single packet, encodes it and forwards the
 * encoded share out multiple interfaces.
 *
*/

void SSSMsg::encrypt(int ports, Packet *p) {}



/*
 * decrypt
 *
 * takes in multiple encoded packet, decodes them, and sends a single
 * message out the interface.
 *
*/
void SSSMsg::decrypt(int ports, Packet *p) {}

/*
 * Generates a SSSMsg packet from a packet.
 *
 * Requires that the packet is IP, and has been checked.
 *
 * So we recieve a packet, and we need create the encoded chunks
 * then send that out to each of the connected ports.
 */
void SSSMsg::push(int ports, Packet *p) {

    if (_function == 0) {
        encrypt(ports, p);
    } else if (_function == 1 ) {
        decrypt(ports, p);
    }

    // free this packet
    p->kill();

    return;
};

void SSSMsg::run_timer(Timer *timer) {
    loop_helper();
    timer->reschedule_after_msec(_timer);
}

bool SSSMsg::run_task(Task *task) {
    bool rc = loop_helper();
    task->fast_reschedule();
    return rc;
}

void SSSMsg::encrypt2(Packet *p) {
    DEBUG_PRINT("encrypt 2\n");
    unsigned long total_length;
    if (_pkt_size < 0){
        std::uniform_int_distribution< unsigned long > pad(p->length(), _mtu);
        total_length = pad(eng2);
    } else if (_pkt_size == 0) {
        total_length = p->length();
    } else {
        total_length = _pkt_size;
    }
    DEBUG_PRINT("total length: %lu\n", total_length);

    const unsigned char *nh = p->network_header();
    const unsigned char *mh = p->mac_header();
    const click_ip *iph = p->ip_header();

    // initial version of protocol
    int version = 0;
    uint64_t flowid = get_64_rand2();

    std::string str_data(reinterpret_cast<const char *>(p->data()), p->length());
    char ma[total_length-p->length()];
    fill_packet_rand2(&ma, total_length-p->length());
    std::string filler(ma, total_length-p->length());
    str_data += filler;

    //DEBUG_PRINT("encoding\n");
    std::vector<std::string> encoded = SSSMsg::SplitData(_threshold, _shares, str_data);

    //DEBUG_PRINT("Data In: %s -- %s\n",str_data.c_str(), str_data);
    //DEBUG_PRINT("Data In: %lu -- %lu -- %lu\n", strlen(str_data.c_str()), data_length, encoded[0].size());


    unsigned long new_pkt_size = 0;

    // now lets create the shares
    for (int i = 0; i < _shares; ++i) {
        SSSProto* sp = new SSSProto;
        sp->Len = encoded[i].size();
        sp->Version = version;
        sp->Flowid = flowid;
        sp->Shareid = i;
    
        // write the SSS encoded data
        memcpy(sp->Data, &encoded[i][0], encoded[i].size());

        // create our new packet, size is the header (SSSProto), minus max data size - actual data size (gives us actual data size)
    // so our new packet should just be SSSProto+SSSData size
        WritablePacket *pkt = Packet::make(sp, (sizeof(SSSProto)-(SSSPROTO_DATA_LEN-encoded[i].size())));

        // we done screwed up.
        if (!pkt) {
            fprintf(stderr, "failed to create new packet in encypt\n");
            p->kill();
            return;
        }

        // add space at the front to put back on the old ip and mac headers
        Packet *ip_pkt = pkt->push(sizeof(click_ip));
        memcpy((void*)ip_pkt->data(), (void*)nh, sizeof(click_ip));

        click_ip *iph2 = (click_ip *) ip_pkt->data();
        iph2->ip_len = htons( sizeof(click_ip) + (sizeof(SSSProto)-(SSSPROTO_DATA_LEN-encoded[i].size())));

        iph2->ip_p = 0;

        // update the ip header checksum for the next host in the path
        ip_checksum_update_sss(pkt);

        // This sets/annotates the network header as well as pushes into packet
        Packet *new_pkt = pkt->push_mac_header(sizeof(click_ether));
        memcpy((void*)new_pkt->data(), (void*)mh, sizeof(click_ether));

        // send packet out the given port
        DEBUG_PRINT("sending packet out %d interface\n", i);
        output(i).push(new_pkt);
        delete sp;
    }


    //DEBUG_PRINT("original size: %lu  ~~~ sss size: %lu\n", p->length(), new_pkt_size);
}


void SSSMsg::decrypt2(std::vector<Packet*> pb) {

    assert(pb.size() > 0);

    const unsigned char *nh = pb[0]->network_header();
    const unsigned char *mh = pb[0]->mac_header();

    // we have enough to compute, create vector of the data
    std::vector<std::string> encoded;
    for (auto p : pb) {
        const click_ip *iph = p->ip_header();
        unsigned long iplen = iph->ip_hl << 2;
        unsigned long header_length = DEFAULT_MAC_LEN + iplen;
        const SSSProto *ssspkt = reinterpret_cast<const SSSProto *>(p->data()+header_length);
        std::string data(&ssspkt->Data[0], &ssspkt->Data[0] + ssspkt->Len);
        encoded.push_back(data);
    }

    // get back the secret
    std::string pkt_data = SSSMsg::RecoverData(_threshold, encoded);

    //DEBUG_PRINT("Data Out: %lu -- %lu\n", strlen(pkt_data.c_str()), pkt_data.length());

    WritablePacket *pkt = Packet::make(pkt_data.length());
    memcpy((void*)pkt->data(), pkt_data.c_str(), pkt_data.length());

    // set the original packet header information
    pkt->set_mac_header(pkt->data(), DEFAULT_MAC_LEN);
    pkt->set_network_header(pkt->data()+DEFAULT_MAC_LEN, sizeof(click_ip));

    const click_ip *iph2 = pkt->ip_header();
    int ip_len = ntohs(iph2->ip_len);

    if (!IP_ISFRAG(iph2)) {
        if (pkt_data.length() > (ip_len+DEFAULT_MAC_LEN)) {
            pkt->take(pkt_data.length()-(ip_len+DEFAULT_MAC_LEN));
        }
    } else {
        /* From IP Reassembler element code */
        // calculate packet edges
        int p_off = IP_BYTE_OFF2(iph2);
        int p_lastoff = p_off + ntohs(iph2->ip_len) - (iph2->ip_hl << 2);

        // check uncommon, but annoying, case: bad length, bad length + offset,
        // or middle fragment length not a multiple of 8 bytes
        if (p_lastoff > 0xFFFF || p_lastoff <= p_off
            || ((p_lastoff & 7) != 0 && (iph2->ip_off & htons(IP_MF)) != 0)
            || pkt_data.length() < p_lastoff - p_off) {
            pkt->kill();
            return;
        }

        if(pkt_data.length() > (p_lastoff - p_off)){
            pkt->take(pkt_data.length() - (p_lastoff - p_off));
        }
    }


    // update the ip header checksum for the next host in the path
    ip_checksum_update_sss(pkt);



    /*
    memcpy((void*)pkt->data(), pkt_data.c_str(), pkt_data.length());

    // add space at the front to put back on the old ip and mac headers
    // ip header first
    Packet *ip_pkt = pkt->push(sizeof(click_ip));
    memcpy((void*)ip_pkt->data(), nh, sizeof(click_ip));

    click_ip *iph2 = (click_ip *) ip_pkt->data();
    iph2->ip_len = ntohs( sizeof(click_ip) +  pkt_data.length());

    // update the ip header checksum for the next host in the path

    // mac header next (so its first in the packet)
    Packet *new_pkt = pkt->push_mac_header(sizeof(click_ether));
    memcpy((void*)new_pkt->data(), mh, sizeof(click_ether));
    */

    //DEBUG_PRINT("sss size: %lu ~~~~ original size: %lu\n", p->length(), new_pkt->length());

    // ship it
    output(0).push(pkt);
}


void SSSMsg::push_batch(int ports, PacketBatch *pb) {
    DEBUG_PRINT("push_batch\n");
    std::vector<Packet*> vpb;
    FOR_EACH_PACKET_SAFE(pb,p){
        int rc = check_sss_packet_header(p);
        if (rc < 0) {
            p->kill();
        } else {
            p->set_timestamp_anno(Timestamp::now_steady());
            vpb.push_back(p);
        }
    }

    if (_function == func_encrypt) {
        DEBUG_PRINT("calling encrypt\n");
        for (auto p: vpb){
            encrypt2(p);
            p->kill();
        }
    } else if (_function == func_decrypt) {
        for (auto p: vpb){
            const click_ip *iph = p->ip_header();
            unsigned long iplen = iph->ip_hl << 2;
            unsigned long header_length = DEFAULT_MAC_LEN + iplen;
            const SSSProto *ssspkt = reinterpret_cast<const SSSProto *>(p->data()+header_length);
            dlock.acquire();
            DEBUG_PRINT("adding to decrypt\n");
            flow_map[ssspkt->Flowid].push_back(p);
            dlock.release();
        }
    }
}

bool SSSMsg::loop_helper() {
    dlock.acquire();
    //DEBUG_PRINT("in loop lock\n");
    std::vector<uint64_t> old_keys;
    for (auto fm: flow_map){
        uint64_t flow = fm.first;
        std::vector<Packet*> pb = fm.second;

        // if threshold*X < shares, this will cause X duplicate sends
        if (pb.size() >= _threshold){
            DEBUG_PRINT("have enough for threshold\n");
            decrypt2(pb);
            for (auto p: pb) {
                if (p) {
                    p->kill();
                }
            }
            old_keys.push_back(flow);
        } else {
            if ((Timestamp::now_steady() - pb[0]->timestamp_anno()).msec() > 100) {
                DEBUG_PRINT("too old, killing\n");
                for (auto p: pb) {
                    if (p) {
                        p->kill();
                    }
                }
                old_keys.push_back(flow);
            }
        }
    }

    for (auto key: old_keys){
        flow_map.erase(key);
    }

    dlock.release();
    return true;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel batch)
EXPORT_ELEMENT(SSSMsg)
