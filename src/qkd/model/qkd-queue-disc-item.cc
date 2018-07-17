/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016 Universita' degli Studi di Napoli Federico II
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Miralem Mehic <miralem.mehic@ieee.org>
 */

#include "ns3/log.h"
#include "qkd-queue-disc-item.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDQueueDiscItem");

QKDQueueDiscItem::QKDQueueDiscItem (Ptr<Packet> p, 
    const Ipv4Address & source, 
    const Ipv4Address & destination, 
    uint8_t protocol, 
    Ptr<Ipv4Route> route
)
  : QueueDiscItem (p, Address(destination), protocol),
    m_source (source),
    m_destination (destination),
    m_route (route)
{
}

QKDQueueDiscItem::~QKDQueueDiscItem()
{
  NS_LOG_FUNCTION (this);
}

void 
QKDQueueDiscItem::AddHeader (void){}

uint32_t QKDQueueDiscItem::GetSize(void) const
{
  Ptr<Packet> p = GetPacket ();
  NS_ASSERT (p != 0);
  uint32_t ret = p->GetSize ();
  return ret;
}

Ipv4Address
QKDQueueDiscItem::GetSource (void) const
{
  return m_source;
}

Ipv4Address
QKDQueueDiscItem::GetDestination (void) const
{
  return m_destination;
}

Ptr<Ipv4Route>
QKDQueueDiscItem::GetRoute (void) const
{
  return m_route;
}

void
QKDQueueDiscItem::Print (std::ostream& os) const
{ 
  os << GetPacket () << " "
     << "Dst addr " << GetAddress () << " "
     << "proto " << (uint16_t) GetProtocol () << " "
     << "txq " << (uint8_t) GetTxQueueIndex ()
  ;
}

bool
QKDQueueDiscItem::Mark (void)
{
  return false;
}

} // namespace ns3
