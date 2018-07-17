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
#ifndef QKD_SEND_H
#define QKD_SEND_H

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"
#include "ns3/address.h"
#include "ns3/core-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/qkd-manager.h"

namespace ns3 {

class Address;
class Socket;
class Packet;

/**
 * \ingroup applications 
 * \defgroup QKDSink QKDSink
 *
 * This application was written to complement OnOffApplication, but it
 * is more general so a QKDSink name was selected.  Functionally it is
 * important to use in multicast situations, so that reception of the layer-2
 * multicast frames of interest are enabled, but it is also useful for
 * unicast as an example of how you can write something simple to receive
 * packets at the application layer.  Also, if an IP stack generates 
 * ICMP Port Unreachable errors, receiving applications will be needed.
 */

/**
 * \ingroup QKDSink
 *
 * \brief Receive and consume traffic generated to an IP address and port
 *
 * This application was written to complement OnOffApplication, but it
 * is more general so a QKDSink name was selected.  Functionally it is
 * important to use in multicast situations, so that reception of the layer-2
 * multicast frames of interest are enabled, but it is also useful for
 * unicast as an example of how you can write something simple to receive
 * packets at the application layer.  Also, if an IP stack generates 
 * ICMP Port Unreachable errors, receiving applications will be needed.
 *
 * The constructor specifies the Address (IP address and port) and the 
 * transport protocol to use.   A virtual Receive () method is installed 
 * as a callback on the receiving socket.  By default, when logging is
 * enabled, it prints out the size of packets and their address.
 * A tracing source to Receive() is also available.
 */
class QKDSend : public Application 
{ 
public:
    /**
    * \brief Get the type ID.
    * \return the object TypeId
    */
    static TypeId GetTypeId (void);
    QKDSend ();
    virtual ~QKDSend();
    uint32_t sendDataStats();
    uint32_t sendPacketStats();
    void Setup (Ptr<Socket> socket, Address src, Address dst, uint32_t packetSize, uint32_t nPackets, DataRate dataRate);
    void    setTimeDelayLimit(uint32_t value);
    /// Traced Callback: transmitted packets.
    TracedCallback<Ptr<const Packet> > m_txTrace;

private:

    virtual void StartApplication (void);
    virtual void StopApplication (void);

    void ScheduleTx (void);
    void SendPacket (void);
    
    Ptr<NetDevice>  m_device;
    Ptr<Socket>     m_socket;
    Address         m_peer;
    Address         m_local;
    Ipv4Address     m_dst;
    uint32_t        m_packetSize;
    uint32_t        m_nPackets;
    uint32_t        m_nPacketSize;
    DataRate        m_dataRate;
    EventId         m_sendEvent;
    bool            m_running;
    uint32_t        m_packetsSent;
    uint32_t        m_dataSent;
    TypeId          m_tid;
    uint32_t        m_timeDelayLimit;
};


} // namespace ns3

#endif /* QKD_SINK_H */
