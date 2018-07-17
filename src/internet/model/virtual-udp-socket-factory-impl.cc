/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2007 INRIA
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
 * Author: Miralem Mehic <miralem.mehic@ieee.org> after Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */
#include "virtual-udp-socket-factory-impl.h"
#include "virtual-udp-l4-protocol.h"
#include "ns3/socket.h"
#include "ns3/assert.h"

namespace ns3 {

VirtualUdpSocketFactoryImpl::VirtualUdpSocketFactoryImpl ()
  : m_udp (0)
{
}
VirtualUdpSocketFactoryImpl::~VirtualUdpSocketFactoryImpl ()
{
  NS_ASSERT (m_udp == 0);
}

void
VirtualUdpSocketFactoryImpl::SetUdp (Ptr<VirtualUdpL4Protocol> udp)
{
  m_udp = udp;
}

Ptr<Socket>
VirtualUdpSocketFactoryImpl::CreateSocket (void)
{
  return m_udp->CreateSocket ();
}

void 
VirtualUdpSocketFactoryImpl::DoDispose (void)
{
  m_udp = 0;
  VirtualUdpSocketFactory::DoDispose ();
}

} // namespace ns3
