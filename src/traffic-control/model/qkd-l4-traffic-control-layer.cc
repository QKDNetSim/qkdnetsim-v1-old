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

#include "qkd-l4-traffic-control-layer.h"
#include "ns3/log.h"
#include "ns3/object-vector.h"
#include "ns3/packet.h"
#include "ns3/queue-disc.h" 
#include "ns3/qkd-queue-disc-item.h"
#include "ns3/ipv4-header.h"
#include "ns3/qkd-l4-pfifo-fast-queue-disc.h" 

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDL4TrafficControlLayer");

NS_OBJECT_ENSURE_REGISTERED (QKDL4TrafficControlLayer);

TypeId
QKDL4TrafficControlLayer::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDL4TrafficControlLayer")
    .SetParent<Object> ()
    .SetGroupName ("TrafficControl")
    .AddConstructor<QKDL4TrafficControlLayer> ()
    .AddAttribute ("RootQueueDiscList", "The list of root queue discs associated to this QKD Traffic Control layer.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&QKDL4TrafficControlLayer::m_rootQueueDiscs),
                   MakeObjectVectorChecker<QueueDisc> ())
  ;
  return tid;
}

TypeId
QKDL4TrafficControlLayer::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

QKDL4TrafficControlLayer::QKDL4TrafficControlLayer ()
  : Object ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

void
QKDL4TrafficControlLayer::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_node = 0;
  m_rootQueueDiscs.clear ();
  m_handlers.clear (); 
  Object::DoDispose ();
}

void
QKDL4TrafficControlLayer::DoInitialize (void)
{
  NS_LOG_FUNCTION (this);

  //We have only one queue disc for all network devices!
  //Yes, it is not a mistake. We have only one queue disc (with multiple internal queues) for all traffic
  //This queue disc is located between L3 and L4, before IPv4 L3 layer!
  m_rootQueueDiscs[0]->Initialize (); 
  m_rootQueueDiscs[0]->SetNode(m_node);

  /*
  for (uint32_t j = 0; j < m_rootQueueDiscs.size (); j++)
    {
      if (m_rootQueueDiscs[j])
        {
          // initialize the queue disc
          m_rootQueueDiscs[j]->Initialize ();
          m_rootQueueDiscs[j]->SetNode(m_node);
        }
    }
  */
  Object::DoInitialize ();
}

void
QKDL4TrafficControlLayer::SetRootQueueDisc(Ptr<QueueDisc> qDisc)
{
  NS_LOG_FUNCTION (this);

  uint32_t index = m_rootQueueDiscs.size ();
  NS_LOG_FUNCTION (this << "Node: " << m_node->GetId() << "QueueDisc:" << index);

  //We have only one queue disc for all network devices!
  //Yes, it is not a mistake. We have only one queue disc (with multiple internal queues) for all traffic
  //This queue disc is located between L3 and L4, before IPv4 L3 layer!
  if(index == 0){
    m_rootQueueDiscs.resize (index+1); 
    m_rootQueueDiscs[index] = qDisc;
  }

}

Ptr<QueueDisc>
QKDL4TrafficControlLayer::GetRootQueueDisc (uint32_t index)
{
  NS_LOG_FUNCTION (this); 

  NS_ASSERT_MSG (index < m_rootQueueDiscs.size () && m_rootQueueDiscs[index] != 0, "No root queue disc"
                 << " installed on node " << m_node);

  return m_rootQueueDiscs[index];
}

void
QKDL4TrafficControlLayer::DeleteRootQueueDisc ()
{ 
  for (uint32_t j = 0; j < m_rootQueueDiscs.size (); j++)
    {
      if (m_rootQueueDiscs[j])
        {
        // remove the root queue disc 
          m_rootQueueDiscs[j] = 0;
        }
    }
}

void
QKDL4TrafficControlLayer::SetNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION (this << node);
  m_node = node;
}

Ptr<Node>
QKDL4TrafficControlLayer::GetNode ()
{
  NS_LOG_FUNCTION (this);
  return m_node;
}

void
QKDL4TrafficControlLayer::NotifyNewAggregate ()
{
  NS_LOG_FUNCTION (this << m_node);
  if (m_node == 0)
    {
      Ptr<Node> node = this->GetObject<Node> ();
      //verify that it's a valid node and that
      //the node was not set before
      if (node != 0)
        {
          this->SetNode (node);
        }
    }
  NS_LOG_FUNCTION (this << m_node);
  Object::NotifyNewAggregate ();
}

/**
* SEND TO QUEUE
*/
void
QKDL4TrafficControlLayer::Send (Ptr<Packet> p, 
                      Ipv4Address source,
                      Ipv4Address destination,
                      uint8_t protocol,
                      Ptr<Ipv4Route> route)
{
  NS_LOG_FUNCTION (this << p->GetUid() << source << destination << protocol << route);

  NS_LOG_DEBUG ("Protocol number " << protocol);

  Ptr<QKDQueueDiscItem> item = Create<QKDQueueDiscItem> (p, source, destination, protocol, route);
  m_rootQueueDiscs[0]->Enqueue (item);
  m_rootQueueDiscs[0]->Run (); 
}

/**
* FORWARD FROM QUEUE TO LOWER LAERS
*/
void
QKDL4TrafficControlLayer::DeliverToL3 (Ptr<Packet> p, 
                      Ipv4Address source,
                      Ipv4Address destination,
                      uint8_t protocol,
                      Ptr<Ipv4Route> route)
{
  NS_LOG_FUNCTION (this << p->GetUid() << source << destination << protocol << route);
 
  if(m_downTarget.IsNull ()){
    NS_LOG_FUNCTION(this << "m_downTarget on node " << m_node->GetId() << " is EMPTY!!!");
  }else{
    NS_LOG_FUNCTION(this << "m_downTarget on node " << m_node->GetId() << " is valid!");
    m_downTarget (p, source, destination, protocol, route ); 
  }
 
}

/**
* Define Down target which can be IPv4 or Virtual IPv4
*/
void
QKDL4TrafficControlLayer::SetDownTarget (IpL4Protocol::DownTargetCallback callback)
{
  NS_LOG_FUNCTION (this << " on node " << m_node->GetId());
  m_downTarget = callback;
}

IpL4Protocol::DownTargetCallback
QKDL4TrafficControlLayer::GetDownTarget (void) const
{
  NS_LOG_FUNCTION (this);
  return m_downTarget;
}

} // namespace ns3
