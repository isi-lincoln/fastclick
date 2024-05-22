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
#include <stdio.h>
#include <iostream>
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
    _verbose = false;
    return Args(conf, this, errh)
        .read_p("LENGTH", _nbytes)
        .read_p("SA", _sa)
        .read_p("DA", _da)
        .read("MAXLENGTH", _maxlength)
        .read("VERBOSE", _verbose)
        .complete();

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
        std::string buf = "USC/ISI-UPF";
        q = p->put(buf.length());
        memcpy((void*)(q->end_data()-buf.length()), (void*)buf.c_str(), buf.length());

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


            //const click_ip *iph = q->ip_header();
            click_ip *iph = q->ip_header();
            //click_ip *iph = (click_ip *)q->data();
            std::cout << "src: " << IPAddress(iph->ip_src).unparse().c_str() << "\n";
            std::cout << "dst: " << IPAddress(iph->ip_dst).unparse().c_str() << "\n";
            if (iph->ip_dst != IPAddress(_da)) {
                    return p;
            }
            std::cout << "new src: " << IPAddress(_sa).unparse().c_str() << "\n";
            std::cout << "new dst: " << IPAddress(_da).unparse().c_str() << "\n";

            printf("size change %d -> %ld\n", ntohs(iph->ip_len), ntohs(iph->ip_len)+buf.length());
            iph->ip_len = htons(ntohs(iph->ip_len)+buf.length());
            printf("new length %d\n", ntohs(iph->ip_len));

            printf("proto: %d\n", iph->ip_p);
            if (iph->ip_p == IP_PROTO_ICMP) {

                unsigned hlen = iph->ip_hl << 2;
                unsigned ilen = ntohs(iph->ip_len);
                printf("data in icmp2: %d\n", ilen - hlen);
                click_icmp *icmph = (click_icmp *) (((char *)iph) + hlen);
                printf("before checksum: %x\n", icmph->icmp_cksum);

                icmph->icmp_cksum = 0;
                // so this should be correct - 29 bytes, 10 for data, 11 for mine, 8 for icmp header
                icmph->icmp_cksum = click_in_cksum((unsigned char *)icmph, ilen - hlen);
                printf("after checksum: %x\n", icmph->icmp_cksum);
            } else if (iph->ip_p == IP_PROTO_TCP) {

            } else if (iph->ip_p == IP_PROTO_UDP) {

            }
            printf("proto: %d\n", iph->ip_p);

            iph->ip_sum = 0;
            iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));
            // click_update_in_cksum
            //ip->ip_sum = 0;
            //ip->ip_sum = click_in_cksum((unsigned char *)ip, ip->ip_hl << 2);
            //q->set_ip_header(ip, sizeof(click_ip));


            //q->set_ip_header(iph, sizeof(click_ip));

        }

        p = q;
    }

    SET_EXTRA_LENGTH_ANNO(p, 0);
    return p;
}

CLICK_ENDDECLS

EXPORT_ELEMENT(UPF)
ELEMENT_MT_SAFE(UPF)
