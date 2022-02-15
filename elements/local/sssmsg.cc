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
    bool encrypt = true;
	if (Args(conf, this, errh)
		.read_mp("SHARES", shares) // positional
		.read_mp("THRESHOLD", threshold) // positional
		.read_mp("ENCRYPT", encrypt) // positional
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
    _encrypt = encrypt;

	return 0;
}


/*
 * encrypt
 *
 * takes in a single packet, encodes it and forwards the
 * encoded share out multiple interfaces.
 *
*/

void encrypt(int ports, Packet *p) {
	struct SSSProto ssspkt;

	// this packet is actually an ip packet wink wink.
	// want this in order to get the ip address.
    const click_ip *ip = reinterpret_cast<const click_ip *>(p->data());

	struct SSSHeader hdr = ssspkt.Header;

	// packet is the size of ip packet + size of our SSSHeader
	hdr.Len = p->length()+sizeof(SSSHeader)+sizeof(SSSProto);

	// source ip address is the share host (originator of data)
	hdr.Sharehost = ip->ip_src.s_addr;
	
	// initial version of protocol
	hdr.Version = 0; 


	// convert our ip packet from data into a string
	char* pkt_data;
	std::string str_pkt_data(pkt_data);
	int rc = snprintf(pkt_data, p->length(), "%s", p->data());

	// handle an error 
	if (rc > 0) {
	}

	// do the hard work to convert data to encoded forms
	std::vector<std::string> encoded = SecretShareData(_threshold, _shares, str_pkt_data);
	
	// now lets create the shares
	for (int i = 0; i < _shares; ++i) {
		Packet *pkt;
		hdr.Shareid = i;

		// encoded has the same length as the original data
		strcpy(ssspkt.Data, encoded[i].c_str());
		//ssspkt.Data = encoded[i].c_str();

		// TODO: i dont remember c
        	memcpy(pkt, &ssspkt, hdr.Len);
		//Packet::make(headroom, pkt, sizeof(SSSProto), 0);

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
void decrypt(int ports, Packet *p) {
    // We need a map (storage) - to store packets until the messages come in.

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

    if (_encrypt) {
        encrypt(ports, p);
    } else {
        decrypt(ports, p);
    }

	// free this packet
	p->kill();

	return;
};

/*
Packet **SSSMsg::simple_action(Packet *p, uint8_t shares, uint8_t threshold) {
	Packet *q[shares];
	for (int i = 0; i <shares; i++){
		q[i] = NULL;
	}

	int len = strnlen((const char *) p->data(), p->length());

	if (len > SSSPROTO_DATA_LEN)
		len = SSSPROTO_DATA_LEN;
	
	String s = String(p->data(), len);
	int delta = SSSPROTO_DATA_LEN - len;

	if (delta > 0)
		s.append_fill('\0', delta);

	click_chatter("DEBUG: p->data() = %s\tp->length() = %d", s.c_str(), p->length());

	if (p->length() > 0 && p->length() <= SSSPROTO_DATA_LEN + 1)
		q = gen_pkt(p,shares,threshold);
	else
		click_chatter("ERROR: Input packet is too big or 0-sized!");

	p->kill();

	return q;
};
*/

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(SSSMsg)
