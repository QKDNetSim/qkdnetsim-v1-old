/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright 2007 University of Washington
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
 * Author:  Miralem Mehic <miralem.mehic@ieee.org>
 */

#include "ns3/address.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/node.h"
#include "ns3/socket.h"
#include "ns3/udp-socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/virtual-udp-socket-factory.h"
#include "ns3/virtual-tcp-socket-factory.h"
#include "qkd-send.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDSend");

NS_OBJECT_ENSURE_REGISTERED (QKDSend);

TypeId 
QKDSend::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDSend")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<QKDSend> ()
    .AddAttribute ("Protocol", "The type of protocol to use.",
                   TypeIdValue (VirtualTcpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&QKDSend::m_tid),
                   MakeTypeIdChecker ())
    .AddTraceSource ("Tx", "A new packet is created and is sent",
                     MakeTraceSourceAccessor (&QKDSend::m_txTrace),
                     "ns3::Packet::TracedCallback")
  ;
  return tid;
}


QKDSend::QKDSend ()
  : m_socket (0),
    m_peer (),
    m_packetSize (0),
    m_nPackets (0),
    m_nPacketSize (0),
    m_dataRate (0),
    m_sendEvent (),
    m_running (false),
    m_packetsSent (0),
	m_dataSent(0)
{
}

QKDSend::~QKDSend()
{
  m_socket = 0;
}

void
QKDSend::Setup (Ptr<Socket> socket, 
                Address src, 
                Address dst,  
                uint32_t packetSize, 
                uint32_t nPacketsSize, 
                DataRate dataRate)
{
    m_socket = socket;
    m_local = src;
    m_peer = dst;
    m_packetSize = packetSize;
    m_nPacketSize = nPacketsSize;
    m_dataRate = dataRate;
    //  m_device = device;
    InetSocketAddress temp = InetSocketAddress::ConvertFrom (m_peer);
    m_dst = temp.GetIpv4();

    if (!m_socket)
      m_socket = Socket::CreateSocket (GetNode (), m_tid);

    m_timeDelayLimit = 0; 
}

void
QKDSend::StartApplication (void)
{
  NS_LOG_FUNCTION (this);

  m_running = true;
  m_packetsSent = 0;

  /* 
   * TOS  | TOS Decimal | Bits | Means                   | Linux Priority | Band
   * -----|-------------|------|-------------------------|----------------|-----
   * 0x0  |     0-7     | 0    |  Normal Service         | 0 Best Effort  |  1  
   * 0x8  |     8-15    | 4    |  Real-time service      | 2 Bulk         |  2 
   * 0x10 |     16-23   | 8    |  PREMIUM Service        | 6 Interactive  |  0 
   * 0x18 |     24-30   | 12   |  Normal service         | 4 Int. Bulk    |  1
  */

  //m_socket->SetIpTos(10);
  m_socket->SetIpRecvTos(true);
  m_socket->Bind (m_local);
//  m_socket->BindToNetDevice(m_device);
  m_socket->Connect (m_peer);
  SendPacket ();
}

void
QKDSend::StopApplication (void)
{
  NS_LOG_FUNCTION (this);

  m_running = false;
  if (m_sendEvent.IsRunning ())
    {
      Simulator::Cancel (m_sendEvent);
    }

  if (m_socket)
    {
      m_socket->Close ();
    }
}

void
QKDSend::setTimeDelayLimit(uint32_t value){

  NS_LOG_FUNCTION (this << value);
  m_timeDelayLimit = value;
}



void
QKDSend::SendPacket (void)
{
    NS_LOG_FUNCTION (this);

    Ptr<Packet> packet = Create<Packet> (m_packetSize); 
    packet = m_socket->GetNode()->GetObject<QKDManager> ()->MarkEncrypt  (packet, QKDCRYPTO_OTP, QKDCRYPTO_AUTH_VMAC); 
    packet = m_socket->GetNode()->GetObject<QKDManager> ()->MarkMaxDelay (packet, m_timeDelayLimit);

    NS_ASSERT (packet != 0);
    NS_LOG_FUNCTION (this << packet->GetUid() << packet->GetSize() );

    m_txTrace (packet);
    m_socket->Send (packet);
    m_packetsSent++;
    m_dataSent += packet->GetSize();

    if ( m_nPacketSize == 0 ||  m_dataSent < m_nPacketSize )
      ScheduleTx ();

    NS_LOG_FUNCTION(this << "m_nPacketSize:" << m_nPacketSize << "m_dataSent:" << m_dataSent << "m_nPacketSize:" << m_nPacketSize);
}

uint32_t
QKDSend::sendPacketStats(void){
	return m_packetsSent;
}

uint32_t
QKDSend::sendDataStats(void){
	return m_dataSent;
}

void
QKDSend::ScheduleTx (void)
{
  NS_LOG_FUNCTION (this << m_running);

  if (m_running)
  {
    NS_LOG_FUNCTION (this << "QKDSend is running!" << m_running);
    Time tNext (Seconds (m_packetSize * 8 / static_cast<double> (m_dataRate.GetBitRate ())));
    m_sendEvent = Simulator::Schedule (tNext, &QKDSend::SendPacket, this);
  }else{
    NS_LOG_FUNCTION (this << "QKDSend is ***NOT*** running!" << m_running);
  }
}


} // Namespace ns3
