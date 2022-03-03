// click files
#include <click/config.h>
#include <click/args.hh> // Args, for configure
#include <click/ipaddress.hh> // ip address
#include <include/click/packet.hh> // pkt make
#include <click/etheraddress.hh> // eth address

// protocol files
#include "sssproto.hh"
#include "sssmsg.hh"

// handling shared cache
//#include <mutex>          // std::mutex
#include <assert.h>	// sanity check
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

    printf("thresh: %d, shares: %d\n", threshold, nShares);
    printf("secret: %s\n", secret.c_str());
    //printf("channel: %s\n", CryptoPP::DEFAULT_CHANNEL );
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
	//printf("sink1: %s\n", strSinks[i].c_str());
	//printf("shares1: %s\n", strShares[i].c_str());

        channel = CryptoPP::WordToString<CryptoPP::word32>(i);
            strSinks[i]->Put( (CryptoPP::byte *)channel.data(), 4 ); // 4 because 32/8 is 4
        channelSwitch->AddRoute( channel,*strSinks[i], CryptoPP::DEFAULT_CHANNEL );
        //channelSwitch->AddRoute( channel,*strSinks[i], chanName );

	//printf("sink2: %s\n", strSinks[i].c_str());
	//printf("shares2: %s\n", strShares[i].c_str());
	//printf("in encrypt: %s\n", strShares[i].c_str());
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
    }

    if (!p->has_network_header()) {
    fprintf(stderr, "secret split doesnt know how to handle this packet (no L3).\n");
    }

    // XXX: We assume that the click config will handle the MAC rewriting for now
    //

    printf("in encrypt\n");

    // taking as input a Packet
    // this packet has an ethernet header which we want to keep for decrypt
    // it also has the ip header, and the data contents.
    // we would ideally like to keep all this entact, then decrypt can fudge
    // the headers and checksum

    // we want to retrieve the ip header information, mainly the ipv4 dest
    const click_ether *mch = (click_ether *) p->data();
    const unsigned char *mach = p->mac_header();
    const unsigned char *nhd = p->network_header();
    const click_ip *iph = p->ip_header();

    //printf("src mac addr: %s\n", EtherAddress(mch->ether_shost).s().c_str());
    //printf("src ip addr: %s\n", IPAddress(iph->ip_src.s_addr).s().c_str() );

    // our packet then will be the previous packet (p)
    // plus the size of the sssheader plus the size of the protocol
    // message header.
    // TODO: the math here that needs to happen is subtract out the L3->data() field.
    unsigned long length = p->length();

    // source ip address is the share host (originator of data)
    // ip_src is in_addr struct
    unsigned long src_host = IPAddress(iph->ip_src.s_addr);

    // initial version of protocol
    int version = 0; 

    int flowid = _flowid++; // see notes on randomizing this for fun

    printf("after ssspkt settings\n");

    // https://github.com/kohler/click/blob/593d10826cf5f945a78307d095ffb0897de515de/elements/standard/print.cc#L151
    // unsigned char same as uint8_t
    // this is hex, which is f (1111) 4 bits, coming from a byte, so
    // it will take double the space
    char hex_pkt_data[p->length()*2];

    // TODO Assumes data is byte aligned.
    printf("byte length: %u, hex length: %lu\n", p->length(), sizeof(hex_pkt_data));
    const unsigned char *bdata = p->data();
    uint16_t iter = 0;
    for (int j=0; j < p->length(); j++, bdata++) {
      // this is 1 byte at a time, which gets converted to 2 hex values at once.
      sprintf(hex_pkt_data+iter, "%02x", *bdata & 0xff);
      iter += 2;
    }

    std::string str_pkt_data(reinterpret_cast<char*>(hex_pkt_data));

    printf("pkt as hex: %s\n", str_pkt_data.c_str()); 

    // do the hard work to convert data to encoded forms
    std::vector<std::string> encoded = SSSMsg::SplitData(_threshold, _shares, str_pkt_data);

    // XXX: We can recover the data here, but it looks like recover data modifies the vector
    // so we need to do a deep copy of encoded object first.
    /*
    std::string rec_pkt_data = SSSMsg::RecoverData(_threshold, encoded);

    // assert that the strings are the same value
    assert(str_pkt_data.compare(rec_pkt_data)==0);
    printf("secret back: %s\n", rec_pkt_data.c_str());
    */
    printf("after encrypt, encode length: %ld\n", encoded.size());
    /*
    for (int i = 0; i < _shares; ++i) {
      // TODO: Lincoln for tomorrow, it seems that there is data here,
      // so howdo we get it out?!?!?!?
      printf("encode: %d\n", encoded[i].size());
      const char *x = encoded[i].c_str();
      for (int j = 0; j < encoded[i].size(); j++) {
        printf("%x", x[j] & 0xff);
      }
    }
    */
    
    SSSProto *ssspkt_arr[_shares];

    // now lets create the shares
    for (int i = 0; i < _shares; ++i) {
        ssspkt_arr[i] = new SSSProto;
        ssspkt_arr[i]->Len = length;
        ssspkt_arr[i]->Sharehost = src_host;
        ssspkt_arr[i]->Version = version;
        ssspkt_arr[i]->Flowid = flowid;
        ssspkt_arr[i]->Shareid = i;


        uint16_t iter = 0;
        for (int j=0; j < encoded[i].size(); j++) {
	  const char *x = encoded[i].c_str();
          // this is 1 byte at a time, which gets converted to 2 hex values at once.
          sprintf(ssspkt_arr[i]->Data+j, "%01x", x[j] & 0xf);
        }

        // encoded has the same length as the original data
        //strcpy(ssspkt_arr[i]->Data, encoded[i].c_str());
	printf("encoded: %s\n", ssspkt_arr[i]->Data);

        // we would like this to work, which is to copy our encoded data back into the
        // the packet to send out
        Packet *pkt = Packet::make(ssspkt_arr[i], sizeof(SSSProto)+14);
    
        
        // remove some head room from packet to add L2 and L3 headers
        Packet *new_pkt = pkt->push_mac_header(14);
        memcpy((void*)new_pkt->data(), mach, 14);
    
    
	/* ****** validate that we are sending correct data ********** */
        // we want to retrieve the ip header information, mainly the ipv4 dest
        const click_ether *mch = (click_ether *) new_pkt->data();
        //printf("mac source addr: %s\n", EtherAddress(mch->ether_shost).unparse().c_str());
        //printf("mac dest addr: %s\n", EtherAddress(mch->ether_dhost).unparse().c_str());
    
        // following from when we encoded our data and put our sss data into
        // the pkt data field, we now need to extract it
        const SSSProto *ssspkt = reinterpret_cast<const SSSProto *>(new_pkt->data()+14); // 14 is mac offset
    
        printf("ip dest of secret: %s\n", IPAddress(ssspkt->Sharehost).s().c_str());
    
        // send packet out the given port
        output(i).push(new_pkt);
        //output(i).push(pkt);

        // TODO: I forget C memory management, can i free pkt now that output has it
        // or is it only a pointer so i have to wait until output frees it and then
        // i dont have to worry about it?
    }
}


/*
 * decrypt
 *
 * takes in multiple encoded packet, decodes them, and sends a single
 * message out the interface.
 *
*/
void SSSMsg::decrypt(int ports, Packet *p) {

    printf("in decrypt\n");

    //struct SSSProto *ssspkt = new SSSProto;

    // we want to retrieve the ip header information, mainly the ipv4 dest
    const click_ether *mch = (click_ether *) p->data();
    const unsigned char *mach = p->mac_header();

    //printf("mac source addr: %s\n", EtherAddress(mch->ether_shost).unparse().c_str());
    //printf("mac dest addr: %s\n", EtherAddress(mch->ether_dhost).unparse().c_str());

    // following from when we encoded our data and put our sss data into
    // the pkt data field, we now need to extract it
    const SSSProto *ssspkt = reinterpret_cast<const SSSProto *>(p->data()+14); // 14 is mac offset

    printf("ip dest of secret: %s\n", IPAddress(ssspkt->Sharehost).s().c_str());



    //cache_mut.lock();
    /******************** CRITICAL REGION - KEEP IT SHORT *****************/



    // check if this packet destination is already in our storage queue
    auto t = storage.find(ssspkt->Sharehost);
    //auto end = storage.end();

    if (t == storage.end()) {
	printf("[nh] adding %s:%lu to cache\n", IPAddress(ssspkt->Sharehost).s().c_str(), ssspkt->Flowid);
        storage[ssspkt->Sharehost][ssspkt->Flowid].push_back(ssspkt);
    	//cache_mut.unlock();
        return;
    }

    // this is the container/map for this host
    auto host_map = storage.at(ssspkt->Sharehost);
    auto flowid = host_map.find(ssspkt->Flowid);

    // map exists but there is no flowid, so add it
    if (flowid == host_map.end()) {
	printf("[nf] adding %s:%lu to cache\n", IPAddress(ssspkt->Sharehost).s().c_str(), ssspkt->Flowid);
        storage[ssspkt->Sharehost][ssspkt->Flowid].push_back(ssspkt);
        //cache_mut.unlock();
        return;
    }

    // flowids do exist in the map, so check if we need to append ours
    // or if we are ready to do some computation
    //
    // including this packet, we still do not have enough to compute 
    //
    if (storage[ssspkt->Sharehost][ssspkt->Flowid].size()+1 < _threshold) {
	printf("[under] adding %s:%lu to cache\n", IPAddress(ssspkt->Sharehost).s().c_str(), ssspkt->Flowid);
        storage[ssspkt->Sharehost][ssspkt->Flowid].push_back(ssspkt);
        //cache_mut.unlock();
        return;
    }

    // TODO: every message over threshold will cause duplicate packets
    // also handle retransmits? force new flowid?
    //auto tt = complete.find(ssspkt->Sharehost);
    //complete[ssspkt->Sharehost][ssspkt->Flowid] = true;
    ////cache_mut.unlock();

    printf("over, time to reconstruct\n");

    // we have enough to compute, create vector of the data
    std::vector<std::string> encoded;
    encoded.push_back(ssspkt->Data);
    long length = 0;
    for (auto x : storage[ssspkt->Sharehost][ssspkt->Flowid]) {
	length = x->Len; // all the blocks are same size encoded
        encoded.push_back(x->Data);
    }

    // get back the secret
    std::string pkt_data = SSSMsg::RecoverData(_threshold, encoded);

    printf("hex packet: %s\n", pkt_data.c_str());

    // convert from hex back to bytes
    unsigned char data_pkt[length]; // this will be the original packet back as bytes
    const char *hex = pkt_data.c_str();
    for (int i = 0, j=0; i < length; i++, j+=2) {
	sscanf(hex+j, "%2hhx", &data_pkt[i]);
    }

    // attempt to cast the pkt_data back to the packet
    // TODO this
    Packet *pkt = Packet::make((void*)data_pkt, length);

    // TODO assumes that after this we have the ether rewrite
    // that will overwrite the original ether addresses

    Packet *new_pkt = pkt->push_mac_header(14);
    memcpy((void*)new_pkt->data(), mach, 14);

    // ship it
    output(0).push(pkt);

}

// TODO
void SSSMsg::forward(int ports, Packet *p) {
    // check the sssmsg header and forward out all other interfaces
    // todo on specifying which interfaces
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

    printf("in push\n");

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
