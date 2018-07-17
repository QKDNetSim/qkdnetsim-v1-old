/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2007, 2014 University of Washington
 *               2015 Universita' degli Studi di Napoli Federico II
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
 *  Author: Miralem Mehic <miralem.mehic@ieee.org>
 */

#include "ns3/log.h"
#include "ns3/object-factory.h"
#include "ns3/queue.h"
#include "ns3/net-device-queue-interface.h"
#include "ns3/socket.h" 
#include "qkd-l2-pfifo-fast-queue-disc.h"
#include "ns3/qkd-manager.h"
#include "ns3/qkd-queue-disc-item.h" 

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDL2PfifoFastQueueDisc");

NS_OBJECT_ENSURE_REGISTERED (QKDL2PfifoFastQueueDisc);

TypeId QKDL2PfifoFastQueueDisc::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDL2PfifoFastQueueDisc")
    .SetParent<QueueDisc> ()
    .SetGroupName ("TrafficControl")
    .AddConstructor<QKDL2PfifoFastQueueDisc> ()
    .AddAttribute ("MaxSize",
                   "The maximum number of packets accepted by this queue disc.",
                   QueueSizeValue (QueueSize ("1000p")),
                   MakeQueueSizeAccessor (&QueueDisc::SetMaxSize,
                                          &QueueDisc::GetMaxSize),
                   MakeQueueSizeChecker ())
  ;
  return tid;
}

QKDL2PfifoFastQueueDisc::QKDL2PfifoFastQueueDisc ()
  : QueueDisc (QueueDiscSizePolicy::MULTIPLE_QUEUES, QueueSizeUnit::PACKETS)
{
  NS_LOG_FUNCTION (this);
}

QKDL2PfifoFastQueueDisc::~QKDL2PfifoFastQueueDisc ()
{
  NS_LOG_FUNCTION (this);
}

const uint32_t QKDL2PfifoFastQueueDisc::prio2band[16] = {1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1};

bool
QKDL2PfifoFastQueueDisc::DoEnqueue (Ptr<QueueDiscItem> item)
{
  NS_LOG_FUNCTION (this << item);

  if (GetCurrentSize () >= GetMaxSize ())
    {
      NS_LOG_LOGIC ("Queue disc limit exceeded -- dropping packet");
      DropBeforeEnqueue (item, LIMIT_EXCEEDED_DROP);
      return false;
    }

  uint8_t priority = 0;
  SocketPriorityTag priorityTag;
  if (item->GetPacket ()->PeekPacketTag (priorityTag))
    {
      priority = priorityTag.GetPriority ();
    }

  uint32_t band = prio2band[priority & 0x0f];

  bool retval = GetInternalQueue (band)->Enqueue (item);

  // If Queue::Enqueue fails, QueueDisc::DropBeforeEnqueue is called by the
  // internal queue because QueueDisc::AddInternalQueue sets the trace callback

  if (!retval)
    {
      NS_LOG_WARN ("Packet enqueue failed. Check the size of the internal queues");
    }

  NS_LOG_LOGIC ("Number packets band " << band << ": " << GetInternalQueue (band)->GetNPackets ());

  return retval;
}

Ptr<QueueDiscItem>
QKDL2PfifoFastQueueDisc::DoDequeue (void)
{
  NS_LOG_FUNCTION (this);

  Ptr<NetDevice> tempDevice = GetNetDevice();
  NS_LOG_FUNCTION (this << "on node:" << tempDevice->GetNode ()->GetId() );

  uint16_t QKDbufferStatus = tempDevice->GetNode ()->GetObject<QKDManager> ()->FetchStatusForDestinationBuffer(GetNetDevice ());
  NS_LOG_FUNCTION (this << "status" << QKDbufferStatus);

  Ptr<QueueDiscItem> item;

  NS_LOG_LOGIC ("Number packets band 0: " << GetInternalQueue (0)->GetNPackets ());
  NS_LOG_LOGIC ("Number packets band 1: " << GetInternalQueue (1)->GetNPackets ());
  NS_LOG_LOGIC ("Number packets band 2: " << GetInternalQueue (2)->GetNPackets ());
 
  //if buffer is empty then only top priority packet can be transmitted
  if( QKDbufferStatus == QKDBuffer::QKDSTATUS_EMPTY){
      
    NS_LOG_FUNCTION (this << QKDbufferStatus << "QKDBuffer::QKDSTATUS_EMPTY");

    if (GetInternalQueue (0)->GetNPackets ())
    {
      if ((item = StaticCast<QueueDiscItem> (GetInternalQueue (0)->Dequeue ())) != 0)
        {
              NS_LOG_LOGIC ("Popped from band 0: " << item);
              NS_LOG_LOGIC ("Number packets band 0: " << GetInternalQueue (0)->GetNPackets ());
              return item;
        }
    }
  }else{    

    if(QKDbufferStatus == 0)
        NS_LOG_FUNCTION (this << QKDbufferStatus << "QKDBuffer::QKDSTATUS_READY");
    else if(QKDbufferStatus == 1)
        NS_LOG_FUNCTION (this << QKDbufferStatus << "QKDBuffer::QKDSTATUS_WARNING");
    else if(QKDbufferStatus == 2)
        NS_LOG_FUNCTION (this << QKDbufferStatus << "QKDBuffer::QKDSTATUS_CHARGING");
    else if(QKDbufferStatus == 3)
        NS_LOG_FUNCTION (this << QKDbufferStatus << "QKDBuffer::QKDSTATUS_EMPTY");

    for (uint32_t i = 0; i < GetNInternalQueues (); i++)
    {
      if ((item = StaticCast<QueueDiscItem> (GetInternalQueue (i)->Dequeue ())) != 0)
        {
          NS_LOG_LOGIC ("Popped from band " << i << ": " << item);
          NS_LOG_LOGIC ("Number packets band " << i << ": " << GetInternalQueue (i)->GetNPackets ());
          return item;
        }
    }
        
  }   
 
  NS_LOG_LOGIC ("Queue empty");
  return item;
}

Ptr<const QueueDiscItem>
QKDL2PfifoFastQueueDisc::DoPeek (void)
{
  NS_LOG_FUNCTION (this);

  Ptr<const QueueDiscItem> item;

  for (uint32_t i = 0; i < GetNInternalQueues (); i++)
    {
      if ((item = GetInternalQueue (i)->Peek ()) != 0)
        {
          NS_LOG_LOGIC ("Peeked from band " << i << ": " << item);
          NS_LOG_LOGIC ("Number packets band " << i << ": " << GetInternalQueue (i)->GetNPackets ());
          return item;
        }
    }

  NS_LOG_LOGIC ("Queue empty");
  return item;
}

bool
QKDL2PfifoFastQueueDisc::CheckConfig (void)
{
  NS_LOG_FUNCTION (this);
  if (GetNQueueDiscClasses () > 0)
    {
      NS_LOG_ERROR ("QKDL2PfifoFastQueueDisc cannot have classes");
      return false;
    }

  if (GetNPacketFilters () != 0)
    {
      NS_LOG_ERROR ("QKDL2PfifoFastQueueDisc needs no packet filter");
      return false;
    }

  if (GetNInternalQueues () == 0)
    {
      // create 3 DropTail queues with GetLimit() packets each
      ObjectFactory factory;
      factory.SetTypeId ("ns3::DropTailQueue<QueueDiscItem>");
      factory.Set ("MaxSize", QueueSizeValue (GetMaxSize ()));
      AddInternalQueue (factory.Create<InternalQueue> ());
      AddInternalQueue (factory.Create<InternalQueue> ());
      AddInternalQueue (factory.Create<InternalQueue> ());
    }

  if (GetNInternalQueues () != 3)
    {
      NS_LOG_ERROR ("QKDL2PfifoFastQueueDisc needs 3 internal queues");
      return false;
    }

  if (GetInternalQueue (0)-> GetMaxSize ().GetUnit () != QueueSizeUnit::PACKETS ||
      GetInternalQueue (1)-> GetMaxSize ().GetUnit () != QueueSizeUnit::PACKETS ||
      GetInternalQueue (2)-> GetMaxSize ().GetUnit () != QueueSizeUnit::PACKETS)
    {
      NS_LOG_ERROR ("QKDL2PfifoFastQueueDisc needs 3 internal queues operating in packet mode");
      return false;
    }

  for (uint8_t i = 0; i < 2; i++)
    {
      if (GetInternalQueue (i)->GetMaxSize () < GetMaxSize ())
        {
          NS_LOG_ERROR ("The capacity of some internal queue(s) is less than the queue disc capacity");
          return false;
        }
    }

  return true;
}

void
QKDL2PfifoFastQueueDisc::InitializeParams (void)
{
  NS_LOG_FUNCTION (this);
}

} // namespace ns3
