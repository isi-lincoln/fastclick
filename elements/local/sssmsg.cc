// click files
#include <click/config.h>
#include <click/args.hh> // Args, for configure

// protocol files
#include "sssmsg.hh"
#include "sssproto.hh"

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
 
using namespace std;
using namespace CryptoPP;

std::vector<std::string> SecretShareData(int threshold, int nShares, std::string secret) {
	// rng
	CryptoPP::AutoSeededRandomPool rng;
	
	// modify our string into cryptopp vector
	std::vector<CryptoPP::byte> secVec(secret.begin(), secret.end());
	std::vector<CryptoPP::byte> shareVec(nShares);

	// initialize channelswitch (moves data from source to sink through filters)
	CryptoPP::ChannelSwitch *channelSwitch;

	// typedef of StringSource( byte *string, size_t length, pumpall, BufferedTransformation)
	// create a source that uses our secret, and puts a filter (secret sharing) to move the
	// data using our channel switch above
	CryptoPP::VectorSource source(secVec, false, new CryptoPP::SecretSharing(
			rng,
			threshold,
			nShares,
			channelSwitch = new CryptoPP::ChannelSwitch
		)
	);


	// from ida example, just use string instead of vector
	std::vector<std::string> strShares(nShares);
	vector_member_ptrs<StringSink> strSinks(nShares);

	std::string channel;

	// based on the number of shares to generate, we know go through and do the computation
	for (int i = 0; i < nShares; i++)	{
		// creates a new StringSink set to shares[i]
		strSinks[i].reset(new StringSink(strShares[i]));

		channel = CryptoPP::WordToString<word32>(i);
        	strSinks[i]->Put( (CryptoPP::byte *)channel.data(), 4 ); // 4 because 32/8 is 4
 		channelSwitch->AddRoute( channel,*strSinks[i], DEFAULT_CHANNEL );
	}

	source.PumpAll();

	return strShares;
}

std::string SecretRecoverData(int threshold, std::vector<std::string> shares) {
	std::string secret;
	CryptoPP::SecretRecovery recovery(threshold, new StringSink(secret));

	vector_member_ptrs<StringSource> strSources(threshold);

	CryptoPP::SecByteBlock channel(4);
	int i;
	for (i=0; i<threshold; i++)
	{
		strSources[i].reset(new StringSource(shares[i], false));
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
/*****   THIS IS END CRYPTO SECTION *****/


CLICK_DECLS

SSSMsg::SSSMsg() { };
SSSMsg::~SSSMsg() { };


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
	struct SSSProto *ssspkt;

	// taking as input a Packet
	// this packet has an ethernet header which we want to keep for decrypt
	// it also has the ip header, and the data contents.
	// we would ideally like to keep all this entact, then decrypt can fudge
	// the headers and checksum

	// we want to retrieve the ip header information, mainly the ipv4 dest
	const click_ip *ip = reinterpret_cast<const click_ip *>(p->data());

	// our packet then will be the previous packet (p)
	// plus the size of the sssheader plus the size of the protocol
	// message header.
	ssspkt->Len = p->length()+sizeof(SSSProto);

	// source ip address is the share host (originator of data)
	ssspkt->Sharehost = ip->ip_src.s_addr;
	
	// initial version of protocol
	ssspkt->Version = 0; 

	ssspkt->Flowid = _flowid++; // see notes on randomizing this for fun


	// convert our ip packet from data into a string
	char* pkt_data;
	std::string str_pkt_data(pkt_data);
	int rc = snprintf(pkt_data, p->length(), "%s", p->data());

	// handle an error 
	if (rc > 0) {
		return;
	}

	// do the hard work to convert data to encoded forms
	std::vector<std::string> encoded = SecretShareData(_threshold, _shares, str_pkt_data);
	
	// now lets create the shares
	for (int i = 0; i < _shares; ++i) {
		Packet *pkt;
		ssspkt->Shareid = i;

		// encoded has the same length as the original data
		strcpy(ssspkt->Data, encoded[i].c_str());

		// we would like this to work, which is to copy our encoded data back into the
		// the packet to send out
        	memcpy((void*)pkt->data(), ssspkt, ssspkt->Len);

		// send packet out the given port
		output(i).push(pkt);
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

	// following from when we encoded our data and put our sss data into
	// the pkt data field, we now need to extract it
	const SSSProto *ssspkt = reinterpret_cast<const SSSProto *>(p->data());

	// check if this packet destination is already in our storage queue
	auto t = storage.find(ssspkt->Sharehost);

	// TODO: get into trouble in multithread with end pointer changing?
	// not found
	if (t == storage.end()) {
		storage[ssspkt->Sharehost][ssspkt->Flowid].push_back(ssspkt);
		return;
	}

	// this is the container/map for this host
	auto host_map = storage.at(ssspkt->Sharehost);
	auto flowid = host_map.find(ssspkt->Flowid);

	// map exists but there is no flowid, so add it
	if (flowid == host_map.end()) {
		storage[ssspkt->Sharehost][ssspkt->Flowid].push_back(ssspkt);
		return;
	}

	// flowids do exist in the map, so check if we need to append ours
	// or if we are ready to do some computation
	//
	// including this packet, we still do not have enough to compute 
	//
	if (storage[ssspkt->Sharehost][ssspkt->Flowid].size()+1 < _threshold) {
		storage[ssspkt->Sharehost][ssspkt->Flowid].push_back(ssspkt);
		return;
	}


	// we have enough to compute, create vector of the data
	std::vector<std::string> encoded;
	encoded.push_back(ssspkt->Data);

	for (auto x : storage[ssspkt->Sharehost][ssspkt->Flowid]) {
		encoded.push_back(x->Data);
	}

	// get back the secret
	std::string pkt_data = SecretRecoverData(_threshold, encoded);

	// attempt to cast the pkt_data back to the packet
	// TODO this
        memcpy((void*)p->data(), (void*)pkt_data.c_str(), p->length());
	

	// ship it
	output(0).push(p);

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
