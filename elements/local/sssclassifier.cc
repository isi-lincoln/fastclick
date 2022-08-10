/*

#include <click/config.h>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include "sssclassifier.hh"
#include "sssproto.hh"

CLICK_DECLS

SSSClassifier::SSSClassifier() { };
SSSClassifier::~SSSClassifier() { };

void SSSClassifier::push(int ports, Packet *p) {
    int sss_port = 0; // sss packets
    int non_port = 1; // non-sss packet port

    if (!p->has_mac_header()) {
        output(non_port).push(p);
        return;
    }

    if (!p->has_network_header()) {
        output(non_port).push(p);
        return;
    }

    // our protocol sits ontop of IP, so if we find it, it will be there
    unsigned long header_length = sizeof(click_ether)+sizeof(click_ip);

    // let us do a bounds check before we get in troubles
    if (p->length() < header_length) {
        output(non_port).push(p);
        return;
    }

    // make sure our SSS proto can also fit in this region before we go accessing
    unsigned long proto_header = sizeof(SSSProto)-SSSPROTO_DATA_LEN;
    if (p->length() < (header_length+proto_header)) {
        output(non_port).push(p);
        return;
    }

    const SSSProto *SSSpkt = reinterpret_cast<const SSSProto *>(p->data()+header_length);
    // this is our SSS protocol packet
    if (SSSpkt->Magic == SSSMAGIC) {
        output(sss_port).push(p);
        return;
    }


    output(non_port).push(p);
};

CLICK_ENDDECLS
EXPORT_ELEMENT(SSSClassifier)

*/

