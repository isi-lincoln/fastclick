/*
 * discard.{cc,hh} -- element throws away all packets
 * Eddie Kohler
 *
 * Copyright (c) 1999 Massachusetts Institute of Technology.
 *
 * This software is being provided by the copyright holders under the GNU
 * General Public License, either version 2 or, at your discretion, any later
 * version. For more information, see the `COPYRIGHT' file in the source
 * distribution.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include "discard.hh"
#include "error.hh"
#include "confparse.hh"

Discard::Discard()
  : Element(1, 0)
{
}

void
Discard::push(int, Packet *p)
{
  p->kill();
}

bool
Discard::wants_packet_upstream() const
{
  return input_is_pull(0);
}

void
Discard::run_scheduled()
{
  Packet *p = input(0).pull();
  if (p)
    p->kill();
  reschedule();
}

EXPORT_ELEMENT(Discard)
