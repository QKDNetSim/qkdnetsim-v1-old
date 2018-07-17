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
 * Author: Miralem Mehic <miralem.mehic@ieee.org>
 */

#include "ns3/log.h"
#include "ns3/pointer.h"
#include "ns3/object-factory.h"
#include "ns3/drop-tail-queue.h"
#include "qkd-l4-pfifo-fast-queue-disc.h"
#include "ns3/qkd-manager.h"
#include "ns3/qkd-queue-disc-item.h"
#include "ns3/qkd-l4-traffic-control-layer.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDL4PfifoFastQueueDisc");

NS_OBJECT_ENSURE_REGISTERED (QKDL4PfifoFastQueueDisc);

TypeId QKDL4PfifoFastQueueDisc::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDL4PfifoFastQueueDisc")
    .SetParent<QueueDisc> ()
    .SetGroupName ("TrafficControl")
    .AddConstructor<QKDL4PfifoFastQueueDisc> ()
    .AddAttribute ("MaxSize",
                   "The maximum number of packets accepted by this queue disc.",
                   QueueSizeValue (QueueSize ("1000p")),
                   MakeQueueSizeAccessor (&QueueDisc::SetMaxSize,
                                          &QueueDisc::GetMaxSize),
                   MakeQueueSizeChecker ())
  
    .AddTraceSource ("DequeueL4", "Dequeue a packet from the queue disc",
                     MakeTraceSourceAccessor (&QKDL4PfifoFastQueueDisc::m_traceDequeueL4),
                     "ns3::QueueItem::TracedCallback")
    .AddTraceSource ("RequeueL4", "Requeue a packet in the queue disc",
                     MakeTraceSourceAccessor (&QKDL4PfifoFastQueueDisc::m_traceRequeueL4),
                     "ns3::QueueItem::TracedCallback")
    .AddTraceSource ("DropL4", "Drop a packet stored in the queue disc",
                     MakeTraceSourceAccessor (&QKDL4PfifoFastQueueDisc::m_traceDropL4),
                     "ns3::QueueItem::TracedCallback")
    .AddTraceSource ("PacketsInQueueL4",
                     "Number of packets currently stored in the queue disc",
                     MakeTraceSourceAccessor (&QKDL4PfifoFastQueueDisc::m_nPacketsL4),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("BytesInQueueL4",
                     "Number of bytes currently stored in the queue disc",
                     MakeTraceSourceAccessor (&QKDL4PfifoFastQueueDisc::m_nBytesL4),
                     "ns3::TracedValueCallback::Uint32")

  ;
  return tid;
}

QKDL4PfifoFastQueueDisc::QKDL4PfifoFastQueueDisc ()
{
  NS_LOG_FUNCTION (this);
}

QKDL4PfifoFastQueueDisc::~QKDL4PfifoFastQueueDisc ()
{
  NS_LOG_FUNCTION (this);
}

const uint32_t QKDL4PfifoFastQueueDisc::prio2band[16] = {1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1};

bool
QKDL4PfifoFastQueueDisc::DoEnqueue (Ptr<QueueDiscItem> i2)
{
  Ptr<QKDQueueDiscItem> item = StaticCast<QKDQueueDiscItem> (i2);
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

Ptr<Node>
QKDL4PfifoFastQueueDisc::GetNode ()
{
  NS_LOG_FUNCTION (this << m_node);
  return m_node;
}

void
QKDL4PfifoFastQueueDisc::SetNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION (this << node);
  m_node = node;
}

/*
  L4 cannot look into buffer statuses!
  It just take the packets from priority queues 
*/ 
Ptr<QueueDiscItem>
QKDL4PfifoFastQueueDisc::DoDequeue (void)
{

    NS_LOG_FUNCTION (this);

    Ptr<QueueDiscItem> item;

    for (uint32_t i = 0; i < GetNInternalQueues (); i++)
      {
        if ((item = GetInternalQueue (i)->Dequeue ()) != 0)
          {
            NS_LOG_LOGIC ("Popped from band " << i << ": " << item);
            NS_LOG_LOGIC ("Number packets band " << i << ": " << GetInternalQueue (i)->GetNPackets ());
            return item;
          }
      }
    
    NS_LOG_LOGIC ("Queue empty");
    return item;
} 

Ptr<const QueueDiscItem>
QKDL4PfifoFastQueueDisc::DoPeek (void) const
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
QKDL4PfifoFastQueueDisc::CheckConfig (void)
{
  NS_LOG_FUNCTION (this);
  if (GetNQueueDiscClasses () > 0)
    {
      NS_LOG_ERROR ("QKDL4PfifoFastQueueDisc cannot have classes");
      return false;
    }

  if (GetNPacketFilters () != 0)
    {
      NS_LOG_ERROR ("QKDL4PfifoFastQueueDisc needs no packet filter");
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
      NS_LOG_ERROR ("QKDL4PfifoFastQueueDisc needs 3 internal queues");
      return false;
    }

  if (GetInternalQueue (0)-> GetMaxSize ().GetUnit () != QueueSizeUnit::PACKETS ||
      GetInternalQueue (1)-> GetMaxSize ().GetUnit () != QueueSizeUnit::PACKETS ||
      GetInternalQueue (2)-> GetMaxSize ().GetUnit () != QueueSizeUnit::PACKETS)
    {
      NS_LOG_ERROR ("QKDL4PfifoFastQueueDisc needs 3 internal queues operating in packet mode");
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
QKDL4PfifoFastQueueDisc::InitializeParams (void)
{
  NS_LOG_FUNCTION (this);
  m_running = false;
}






/*
* We need to reimplement following functions from queue-disc.cc: 
* - Run
* - RunBegin
* - RunEnd
* - Restart
* - DequeuePacket
* - Requeue
* - Transmit
* 
* because they are related to NetDevices and we do not have NetDevices associated on L4 layer!
* However, we implement set of waiting queues on L4 (one set of three waiting queues for all devices)
*/


void
QKDL4PfifoFastQueueDisc::Run (void)
{
  NS_LOG_FUNCTION (this);

  if (RunBeginL4 ())
    {
      uint32_t quota = GetQuota();
      while (RestartL4 ())
        {
          quota -= 1;
          if (quota <= 0)
            {
              /// \todo netif_schedule (q);
              break;
            }
        }
      RunEndL4 ();
    }
}

bool
QKDL4PfifoFastQueueDisc::RunBeginL4 (void)
{
  NS_LOG_FUNCTION (this);
  if (m_running)
    {
      NS_LOG_FUNCTION (this << "running false");
      return false;
    }

  NS_LOG_FUNCTION (this << "running TRUE!");
  m_running = true;
  return true;
}

void
QKDL4PfifoFastQueueDisc::RunEndL4 (void)
{
  NS_LOG_FUNCTION (this);
  m_running = false;
}

bool
QKDL4PfifoFastQueueDisc::RestartL4 (void)
{
  NS_LOG_FUNCTION (this);
  Ptr<QKDQueueDiscItem> item = DequeuePacketL4();
  if (item == 0)
    {
      NS_LOG_LOGIC ("No packet to send");
      return false;
    }

  return TransmitL4 (item);
}

Ptr<QKDQueueDiscItem>
QKDL4PfifoFastQueueDisc::DequeuePacketL4 ()
{
  NS_LOG_FUNCTION (this); 
  Ptr<QKDQueueDiscItem> item;

  // First check if there is a requeued packet
  if (m_requeued != 0)
    {
        // If the queue where the requeued packet is destined to is not stopped, return
        // the requeued packet; otherwise, return an empty packet.
        // If the device does not support flow control, the device queue is never stopped
        item = m_requeued;
        m_requeued = 0;

        m_nPacketsL4--;
        m_nBytesL4 -= item->GetSize ();

        NS_LOG_LOGIC ("m_traceDequeueL4 (p)");
        m_traceDequeueL4 (item);
         
    }
  else
    {
      // If the device is multi-queue (actually, Linux checks if the queue disc has
      // multiple queues), ask the queue disc to dequeue a packet (a multi-queue aware
      // queue disc should try not to dequeue a packet destined to a stopped queue).
      // Otherwise, ask the queue disc to dequeue a packet only if the (unique) queue
      // is not stopped.
      Ptr<QueueDiscItem>  i2;
      i2 = Dequeue ();
      // If the item is not null, return the packet.    
      if(i2 != 0)
        return StaticCast<QKDQueueDiscItem> (i2); 
    }

  return item;
}


void
QKDL4PfifoFastQueueDisc::RequeueL4 (Ptr<QKDQueueDiscItem> item)
{
  NS_LOG_FUNCTION (this << item);
  m_requeued = item;
  /// \todo netif_schedule (q);

  m_nPacketsL4++;       // it's still part of the queue
  m_nBytesL4 += item->GetSize ();
  m_nTotalRequeuedPackets++;
  m_nTotalRequeuedBytes += item->GetSize ();

  NS_LOG_LOGIC ("m_traceRequeueL4 (p)");
  m_traceRequeueL4 (item);
}

bool
QKDL4PfifoFastQueueDisc::TransmitL4 (Ptr<QKDQueueDiscItem> item)
{
  NS_LOG_FUNCTION (this << item); 
  

  Ptr<Packet> p = item->GetPacket ();
  Ptr<QKDL4TrafficControlLayer> QKDTCL = GetNode()->GetObject<QKDL4TrafficControlLayer> (); 

  if(QKDTCL != 0){

    NS_LOG_FUNCTION (this << item << "QKDL4TrafficControlLayer exists!"); 
    QKDTCL->DeliverToL3 (p, item->GetSource(), item->GetDestination(), item->GetProtocol (), item->GetRoute() ); 
    return true;

  }else{

    NS_LOG_FUNCTION (this << item << "QKDL4TrafficControlLayer doesn't exists!"); 
    Ptr<TrafficControlLayer> TCL = GetNode()->GetObject<TrafficControlLayer> ();  
    
    if(TCL != 0){
      TCL->DeliverToL3 (p, item->GetSource(), item->GetDestination(), item->GetProtocol (), item->GetRoute() ); 
      return true;
    }
  }
  return false;
}

} // namespace ns3
