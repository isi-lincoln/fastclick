// -*- c-basic-offset: 4 -*-
/*
 * upf.{cc,hh} -- extends packet length
 * Eddie Kohler, Tom Barbette
 *
 * Copyright (c) 2004 Regents of the University of California
 * Copyright (c) 2019 KTH Royal Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <string>
#include <click/config.h>
#include "upf.hh"
#include <click/packet_anno.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip.h> // ip header checksum
#include <clicknet/icmp.h> // icmp header checksum
#include <clicknet/tcp.h> // tcp header checksum
#include <clicknet/udp.h> // udp header checksum
#include <clicknet/ether.h>
#include <include/click/packet.hh> // pkt make
CLICK_DECLS

UPF::UPF()
{
}

int
UPF::configure(Vector<String>& conf, ErrorHandler* errh)
{
    _nbytes = 0;
    _maxlength = 0;
    _zero = true;
    _usc = false;
    _verbose = false;
    return Args(conf, this, errh)
        .read_p("LENGTH", _nbytes)
        .read("ZERO", _zero)
        .read("USC", _usc)
        .read("MAXLENGTH", _maxlength)
        .read("VERBOSE", _verbose)
        .complete();

    if (_zero && _usc)
        return errh->error("ZERO and USC are exclusive.");

    return 0;
}

Packet*
UPF::simple_action(Packet* p)
{
    uint32_t nput;
    if (unlikely(_nbytes))
        nput = p->length() < _nbytes ? _nbytes - p->length() : 0;
    else
        nput = EXTRA_LENGTH_ANNO(p);
    if (unlikely(_maxlength) && unlikely(_maxlength < (nput + p->length())))
    {
        if (unlikely(_verbose))
            click_chatter("Tried a too long UPF: %i + %i > %i -> adding only %i bytes",
                    p->length(), nput, _maxlength, _maxlength - p->length());
         nput = _maxlength - p->length();
    }

    if (nput) {
        WritablePacket* q;
        if (_zero) {
            q = p->put(nput);
            if (!q) {
                return 0;
            }
            memset(q->end_data() - nput, 0, nput);
        }
        if (_usc) {
            std::string buf = "USC/ISI-UPF";
            q = p->put(buf.length());
        }

        if (p->has_mac_header()) {
            const click_ether *mch = (click_ether *) p->data();
            const unsigned char *mh = p->mac_header();

            if (htons(mch->ether_type) != ETHERTYPE_IP) {
                fprintf(stderr, "handling non-ipv4 packet: %x\n", htons(mch->ether_type));
                return p;
            }

            if (!p->has_network_header()) {
                fprintf(stderr, "dont know how to handle this packet (no L3).\n");
                return p;
            }

            click_ip *iph = (click_ip *) q->data();
            iph->ip_sum = 0;
            iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));

        }

        p = q;
    }

    SET_EXTRA_LENGTH_ANNO(p, 0);
    return p;
}

CLICK_ENDDECLS

EXPORT_ELEMENT(UPF)
ELEMENT_MT_SAFE(UPF)
