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
 * Author: Miralem Mehic <miralem.mehic@ieee.org> after
 *         Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#include "ns3/object.h"
#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ns3/integer.h"
#include "ns3/boolean.h"
#include "ns3/trace-source-accessor.h"
#include "virtual-udp-socket.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("VirtualUdpSocket");

NS_OBJECT_ENSURE_REGISTERED (VirtualUdpSocket);

TypeId
VirtualUdpSocket::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::VirtualUdpSocket")
    .SetParent<Socket> ()
    .SetGroupName ("Internet")
    .AddAttribute ("RcvBufSize",
                   "VirtualUdpSocket maximum receive buffer size (bytes)",
                   UintegerValue (131072),
                   MakeUintegerAccessor (&VirtualUdpSocket::GetRcvBufSize,
                                         &VirtualUdpSocket::SetRcvBufSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("IpTtl",
                   "socket-specific TTL for unicast IP packets (if non-zero)",
                   UintegerValue (0),
                   MakeUintegerAccessor (&VirtualUdpSocket::GetIpTtl,
                                         &VirtualUdpSocket::SetIpTtl),
                   MakeUintegerChecker<uint8_t> ())
    .AddAttribute ("IpMulticastTtl",
                   "socket-specific TTL for multicast IP packets (if non-zero)",
                   UintegerValue (0),
                   MakeUintegerAccessor (&VirtualUdpSocket::GetIpMulticastTtl,
                                         &VirtualUdpSocket::SetIpMulticastTtl),
                   MakeUintegerChecker<uint8_t> ())
    .AddAttribute ("IpMulticastIf",
                   "interface index for outgoing multicast on this socket; -1 indicates to use default interface",
                   IntegerValue (-1),
                   MakeIntegerAccessor (&VirtualUdpSocket::GetIpMulticastIf,
                                        &VirtualUdpSocket::SetIpMulticastIf),
                   MakeIntegerChecker<int32_t> ())
    .AddAttribute ("IpMulticastLoop",
                   "whether outgoing multicast sent also to loopback interface",
                   BooleanValue (false),
                   MakeBooleanAccessor (&VirtualUdpSocket::GetIpMulticastLoop,
                                        &VirtualUdpSocket::SetIpMulticastLoop),
                   MakeBooleanChecker ())
    .AddAttribute ("MtuDiscover", "If enabled, every outgoing ip packet will have the DF flag set.",
                   BooleanValue (false),
                   MakeBooleanAccessor (&VirtualUdpSocket::SetMtuDiscover,
                                        &VirtualUdpSocket::GetMtuDiscover),
                   MakeBooleanChecker ())
  ;
  return tid;
}

VirtualUdpSocket::VirtualUdpSocket ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

VirtualUdpSocket::~VirtualUdpSocket ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

} // namespace ns3
