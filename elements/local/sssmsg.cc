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
#include "sssproto.hh"
#include "sssmsg.hh"

// handling shared cache
//#include <mutex>          // std::mutex
#include <assert.h>    // sanity check
#include<iostream>

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

CLICK_DECLS

SSSMsg::SSSMsg() { };
SSSMsg::~SSSMsg() { };

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

// update IP packet checksum
void ip_check(WritablePacket *p) {
    click_ip *iph = (click_ip *) p->data();
    iph->ip_sum = 0;
    iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));
}

// allow the user to configure the shares and threshold amounts
int SSSMsg::configure(Vector<String> &conf, ErrorHandler *errh) {
    uint8_t shares;
    uint8_t threshold;
    uint8_t function;
    if (Args(conf, this, errh)
        .read_mp("SHARES", shares) // positional
        .read_mp("THRESHOLD", threshold) // positional
        .read_mp("PURPOSE", function) // positional
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

    return 0;
}


/*
 * encrypt
 *
 * takes in a single packet, encodes it and forwards the
 * encoded share out multiple interfaces.
 *
 * XXX: We assume that the click config will handle the MAC rewriting for now
*/

void SSSMsg::encrypt(int ports, Packet *p) {
    // packet is too large
    if (p->length() > SSSPROTO_DATA_LEN) {
        fprintf(stderr, "packet length too large for secret splitting\n");
        return;
    }

    // saftey checks
    if (!p->has_mac_header()) {
        fprintf(stderr, "secret split doesnt know how to handle this packet (no L2).\n");
        return;
    }

    const click_ether *mch = (click_ether *) p->data();
    const unsigned char *mh = p->mac_header();

    if (htons(mch->ether_type) != ETHERTYPE_IP) {
        fprintf(stderr, "secret split handling non-ipv4 packet: %x\n", htons(mch->ether_type));
        return;
    }

    if (!p->has_network_header()) {
        fprintf(stderr, "secret split doesnt know how to handle this packet (no L3).\n");
        return;
    }

    unsigned long total_length = p->length();

   DEBUG_PRINT("in encrypt: %lu\n", total_length);

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
    std::vector<std::string> encoded = SSSMsg::SplitData(_threshold, _shares, str_data);

    DEBUG_PRINT("Data In: %s -- %s\n",str_data.c_str(), str_data);
    DEBUG_PRINT("Data In: %lu -- %lu -- %lu\n", strlen(str_data.c_str()), data_length, encoded[0].size());

    // TODO: Development Code to Verify Correctness
    // re create a backup with the minimum number of shares to meet threshold from original
    /*
    std::vector<std::string> backup = std::vector<std::string>(encoded.begin() + (_shares-_threshold), encoded.end());
    std::vector<std::string> backup2 = std::vector<std::string>(encoded.begin() + (_shares-_threshold), encoded.end());

    std::string rec_pkt_data = SSSMsg::RecoverData(_threshold, backup);

    // assert that the strings are the same value
    assert(str_data.compare(rec_pkt_data)==0);
    printf("recover: %s\n", rec_pkt_data.c_str());
    */

    SSSProto *ssspkt_arr[_shares];


    unsigned long new_pkt_size = 0;

    // now lets create the shares
    for (int i = 0; i < _shares; ++i) {
        ssspkt_arr[i] = new SSSProto;
	// diff between data and encode is the sss
        ssspkt_arr[i]->Len = encoded[i].size();
        ssspkt_arr[i]->Sharehost = src_host;
        ssspkt_arr[i]->Version = version;
        ssspkt_arr[i]->Flowid = flowid;
        ssspkt_arr[i]->Shareid = i;
	//ssspkt_arr[i]->Magic = SSSMAGIC;
	
	// write the SSS encoded data
        memcpy(ssspkt_arr[i]->Data, &encoded[i][0], encoded[i].size());

        // create our new packet, size is the header (SSSProto), minus max data size - actual data size (gives us actual data size)
	// so our new packet should just be SSSProto+SSSData size
        WritablePacket *pkt = Packet::make(ssspkt_arr[i], (sizeof(SSSProto)-(SSSPROTO_DATA_LEN-encoded[i].size())));

        // we done screwed up.
	if (!pkt) return;

        // add space at the front to put back on the old ip and mac headers
	Packet *ip_pkt = pkt->push(sizeof(click_ip));
	memcpy((void*)ip_pkt->data(), nh, sizeof(click_ip));

	// update ip packet size = ip header + sss header + sss data
	// TODO/NOTE: these lines in overwritting the ip header are only needed when using Linux Forwarding.
        click_ip *iph2 = (click_ip *) ip_pkt->data();
	iph2->ip_len = ntohs( sizeof(click_ip) + (sizeof(SSSProto)-(SSSPROTO_DATA_LEN-encoded[i].size())) );
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

   DEBUG_PRINT("original size: %lu  ~~~ sss size: %lu\n", p->length(), new_pkt_size);
}



/*
 * decrypt
 *
 * takes in multiple encoded packet, decodes them, and sends a single
 * message out the interface.
 *
*/
void SSSMsg::decrypt(int ports, Packet *p) {

   DEBUG_PRINT("in decrypt\n");
    // packet is too large
    if (p->length() > SSSPROTO_DATA_LEN) {
        fprintf(stderr, "packet length too large for secret splitting\n");
        return;
    }

    // saftey checks
    if (!p->has_mac_header()) {
        fprintf(stderr, "secret split doesnt know how to handle this packet (no L2).\n");
        return;
    }

    const click_ether *mch = (click_ether *) p->data();
    const unsigned char *mh = p->mac_header();

    if (htons(mch->ether_type) != ETHERTYPE_IP) {
        fprintf(stderr, "secret split handling non-ipv4 packet: %x\n", htons(mch->ether_type));
        return;
    }
    //std::cout << EtherAddress(mch->ether_shost).unparse().c_str() << " -> " << EtherAddress(mch->ether_dhost).unparse().c_str() << "\n";
    //printf("%s -> %s\n", IPAddress(iph->ip_src.s_addr).s().c_str(), IPAddress(iph->ip_dst.s_addr).s().c_str());
    
    if (!p->has_network_header()) {
        fprintf(stderr, "secret split doesnt know how to handle this packet (no L3).\n");
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

    // following from when we encoded our data and put our sss data into
    // the pkt data field, we now need to extract it
    const SSSProto *ssspkt = reinterpret_cast<const SSSProto *>(p->data()+header_length);
    unsigned long encode_length = ssspkt->Len;

    long unsigned host = ssspkt->Sharehost;
    long unsigned flow = ssspkt->Flowid;

    std::string data(&ssspkt->Data[0], &ssspkt->Data[0] + ssspkt->Len);


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
    std::string pkt_data = SSSMsg::RecoverData(_threshold, encoded);

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

    DEBUG_PRINT("sss size: %lu ~~~~ original size: %lu\n", p->length(), new_pkt->length());

    // ship it
    output(0).push(pkt);

    storage[host].erase(flow);
    // prevent sending duplicated packets after we've reached threshold shares
    completed[host][flow] = 1;
    cache_mut.unlock();
}

// TODO
void SSSMsg::forward(int ports, Packet *p) {
    // check the sssmsg header and forward out all other interfaces
    // todo on specifying which interfaces
    //
    // Debugging
    //const click_ether *mch = (click_ether *) p->data();
    //std::cout << "forwarding packet: " << EtherAddress(mch->ether_shost).unparse().c_str() << " -> " << EtherAddress(mch->ether_dhost).unparse().c_str() << "\n";
    output(0).push(p);
}

// TODO random generation
// TODO bounds checking on overflow - does this matter? we will force app to manage staleness
int SSSMsg::initialize(ErrorHandler *errh) {
    _flowid = 0; // shits and giggles we just always random this, 2**32 on collision for good times
    return 0;
}

/*
 * Generates a SSSMsg packet from a packet.
 *
 * Requires that the packet is IP, and has been checked.
 *
 * So we recieve a packet, and we need create the encoded chunks
 * then send that out to each of the connected ports.
 */
void SSSMsg::push(int ports, Packet *p) {

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
EXPORT_ELEMENT(SSSMsg)
