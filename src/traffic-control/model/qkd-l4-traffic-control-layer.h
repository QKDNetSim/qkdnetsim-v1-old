/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 Natale Patriciello <natale.patriciello@gmail.com>
 *               2016 Stefano Avallone <stavallo@unina.it>
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
#ifndef QKDL4TRAFFICCONTROLLAYER_H
#define QKDL4TRAFFICCONTROLLAYER_H

#include "ns3/object.h"
#include "ns3/address.h"
#include "ns3/net-device.h"
#include "ns3/node.h"
#include "queue-disc.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-route.h"
#include "ns3/queue-item.h"
 
#include "ns3/ipv6-address.h"
#include "ns3/sequence-number.h"
#include "ns3/ip-l4-protocol.h" 
#include "ns3/qkd-queue-disc-item.h"

#include <map>
#include <vector>

namespace ns3 {

class Packet;
class QueueDisc;
class NetDeviceQueueInterface;

/**
 * \ingroup traffic-control
 *
 * \brief QKD Traffic control layer definition
 *
 * This layer stays between L4 and any network protocol (e.g. IP).
 * When enabled, it is responsible to analyze packets and to perform actions on
 * them: the most common is scheduling.
 *
 * Basically, we manage only OUT directions! The OUT direction is easy to follow, since it involves
 * direct calls: upper layer (e.g. IP) calls the Send method on an instance of
 * this class, which then calls the Enqueue method of the QueueDisc associated
 * with the device. The Dequeue method of the QueueDisc finally calls the Send
 * method of the NetDevice.
 *
 * The IN direction uses a little trick to reduce dependencies between modules.
 * In simple words, we use Callbacks to connect upper layer (which should register
 * their Receive callback through RegisterProtocolHandler) and NetDevices.
 *
 * An example of the IN connection between this layer and IP layer is the following:
 *\verbatim
  Ptr<QKDL4TrafficControlLayer> tc = m_node->GetObject<QKDL4TrafficControlLayer> ();

  NS_ASSERT (tc != 0);

  m_node->RegisterProtocolHandler (MakeCallback (&QKDL4TrafficControlLayer::Receive, tc),
                                   Ipv4L3Protocol::PROT_NUMBER, device);
  m_node->RegisterProtocolHandler (MakeCallback (&QKDL4TrafficControlLayer::Receive, tc),
                                   ArpL3Protocol::PROT_NUMBER, device);

  tc->RegisterProtocolHandler (MakeCallback (&Ipv4L3Protocol::Receive, this),
                               Ipv4L3Protocol::PROT_NUMBER, device);
  tc->RegisterProtocolHandler (MakeCallback (&ArpL3Protocol::Receive, PeekPointer (GetObject<ArpL3Protocol> ())),
                               ArpL3Protocol::PROT_NUMBER, device);
  \endverbatim
 * On the node, for IPv4 and ARP packet, is registered the
 * QKDL4TrafficControlLayer::Receive callback. At the same time, on the QKDL4TrafficControlLayer
 * object, is registered the callbacks associated to the upper layers (IPv4 or ARP).
 *
 * When the node receives an IPv4 or ARP packet, it calls the Receive method
 * on QKDL4TrafficControlLayer, that calls the right upper-layer callback once it
 * finishes the operations on the packet received.
 *
 * Discrimination through callbacks (in other words: what is the right upper-layer
 * callback for this packet?) is done through checks over the device and the
 * protocol number.
 *
 *
 * \note Additional waiting queues are installed between the L3
 * and L4 ISO/OSI layer to avoid conflicts in decision making
 * which could lead to inaccurate routing. Experimental testing and usage!
 *
 */
class QKDL4TrafficControlLayer : public Object
{
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  /**
   * \brief Get the type ID for the instance
   * \return the instance TypeId
   */
  virtual TypeId GetInstanceTypeId (void) const;

  /**
   * \brief Constructor
   */
  QKDL4TrafficControlLayer ();
 
  /// Typedef for queue disc vector
  typedef std::vector<Ptr<QueueDisc> > QueueDiscVector;
 
  /**
   * \brief This method can be used to set the root queue disc installed on a device
   *
   * \param device the device on which the provided queue disc will be installed
   * \param qDisc the queue disc to be installed as root queue disc on device
   */
  virtual void SetRootQueueDisc (Ptr<QueueDisc> qDisc);

  /**
   * \brief This method can be used to get the root queue disc installed on a device
   *
   * \param device the device on which the requested root queue disc is installed
   * \return the root queue disc installed on the given device
   */
  virtual Ptr<QueueDisc> GetRootQueueDisc (uint32_t index);

  /**
   * \brief This method can be used to remove the root queue disc (and associated
   *        filters, classes and queues) installed on a device
   *
   * \param device the device on which the installed queue disc will be deleted
   */
  virtual void DeleteRootQueueDisc ();

  /**
   * \brief Set node associated with this stack.
   * \param node node to set
   */
  void SetNode (Ptr<Node> node);

  /**
   * \brief Set node associated with this stack.
   * \param node node to set
   */
  Ptr<Node> GetNode ();

  /**
   * \brief Called from upper layer (L4) to queue a packet for the transmission.
   *
   * \param device the device the packet must be sent to
   * \param item a queue item including a packet and additional information
   */
  void Send (Ptr<Packet> packet, 
                      Ipv4Address source,
                      Ipv4Address destination,
                      uint8_t protocol,
                      Ptr<Ipv4Route> route);

  void DeliverToL3 (Ptr<Packet> packet, 
                      Ipv4Address source,
                      Ipv4Address destination,
                      uint8_t protocol,
                      Ptr<Ipv4Route> route);

  void SetDownTarget (IpL4Protocol::DownTargetCallback cb); 

  IpL4Protocol::DownTargetCallback GetDownTarget (void) const; 

protected:

  virtual void DoDispose (void);
  virtual void DoInitialize (void);
  virtual void NotifyNewAggregate (void);
  
  IpL4Protocol::DownTargetCallback m_downTarget;   //!< Callback to send packets over IPv4

private:


  /**
   * \brief Copy constructor
   * Disable default implementation to avoid misuse
   */
  QKDL4TrafficControlLayer (QKDL4TrafficControlLayer const &);
  /**
   * \brief Assignment operator
   * Disable default implementation to avoid misuse
   */
  QKDL4TrafficControlLayer& operator= (QKDL4TrafficControlLayer const &);
  /**
   * \brief Protocol handler entry.
   * This structure is used to demultiplex all the protocols.
   */
  struct ProtocolHandlerEntry {
    Node::ProtocolHandler handler; //!< the protocol handler 
    uint16_t protocol;             //!< the protocol number
    bool promiscuous;              //!< true if it is a promiscuous handler
  };

  /// Typedef for protocol handlers container
  typedef std::vector<struct ProtocolHandlerEntry> ProtocolHandlerList;
  
  /// The node this QKDL4TrafficControlLayer object is aggregated to
  Ptr<Node> m_node;
  /// This vector stores the root queue discs installed on all the devices of the node.
  /// Devices are sorted as in Node::m_devices
  QueueDiscVector m_rootQueueDiscs;
  
  /// This map plays the role of the qdisc field of the netdev_queue struct in Linux
  //std::map<Ptr<NetDevice>, NetDeviceInfo> m_netDeviceQueueToQueueDiscMap;

  ProtocolHandlerList m_handlers;  //!< List of upper-layer handlers
};

} // namespace ns3

#endif // QKDL4TRAFFICCONTROLLAYER_H
