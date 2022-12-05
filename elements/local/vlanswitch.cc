/*
 * vlanswitch.{cc,hh} -- element routes packets to one output of several
 * Douglas S. J. De Couto.  Based on Switch element by Eddie Kohler
 *
 * Copyright (c) 2002 MIT
 * Copyright (c) 2008 Meraki, Inc.
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

#include <click/config.h>
#include "vlanswitch.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
CLICK_DECLS

VlanSwitch::VlanSwitch()
{
}

int
VlanSwitch::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Vector<int> vlans;
    if (Args(conf, this, errh).read_all("VLAN", vlans).complete() < 0)
	return -1;
    _vlans = vlans;
    for (int j=0; j < vlans.size(); ++j) {
	    click_chatter("vlanswitch: port %d = vlan id %d", j,  _vlans[j]);
    }
    return 0;
}

void
VlanSwitch::push(int, Packet *p)
{
    uint16_t vlan_tci = ntohs(VLAN_TCI_ANNO(p)); // vlan-id is the lower 12-bits of the TCI
    int vlanid = (vlan_tci & 0x0FFF);
    int max_output = min(static_cast<int>(_vlans.size()), noutputs());

    for (int output_port = 0; output_port < max_output; ++output_port) {
	    if (_vlans[output_port] == vlanid) {
		    checked_output_push(output_port, p);
		    return;
	    }
    }
    // no match, send to default (last) port
    if (noutputs() > 0)
	    checked_output_push(noutputs() - 1, p);
    // what do we do if there are NO outputs?

#if 0
    int output_port = static_cast<int>(p->anno_u8(_anno));
    if (output_port != 0xFF)
	checked_output_push(output_port, p);
    else { // duplicate to all output ports
	int n = noutputs();
	for (int i = 0; i < n - 1; i++)
	    if (Packet *q = p->clone())
		output(i).push(q);
	output(n - 1).push(p);
    }
#endif
}

CLICK_ENDDECLS
EXPORT_ELEMENT(VlanSwitch)
ELEMENT_MT_SAFE(VlanSwitch)

