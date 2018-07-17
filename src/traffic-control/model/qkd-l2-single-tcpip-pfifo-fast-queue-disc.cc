/* -*- Mode:C++; c-file-style:" gnu"; indent-tabs-mode:nil; -*- */
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
#include "ns3/queue.h"
#include "ns3/net-device-queue-interface.h"
#include "ns3/socket.h"
#include "pfifo-fast-queue-disc.h"
#include "qkd-l2-single-tcpip-pfifo-fast-queue-disc.h"
#include "ns3/qkd-manager.h" 

namespace ns3 {
 
NS_LOG_COMPONENT_DEFINE ("QKDL2SingleTCPIPPfifoFastQueueDisc");

NS_OBJECT_ENSURE_REGISTERED (QKDL2SingleTCPIPPfifoFastQueueDisc);

TypeId QKDL2SingleTCPIPPfifoFastQueueDisc::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDL2SingleTCPIPPfifoFastQueueDisc")
    .SetParent<QueueDisc> ()
    .SetGroupName ("TrafficControl")
    .AddConstructor<QKDL2SingleTCPIPPfifoFastQueueDisc> ()
    .AddAttribute ("MaxSize",
                   "The maximum number of packets accepted by this queue disc.",
                   QueueSizeValue (QueueSize ("1000p")),
                   MakeQueueSizeAccessor (&QueueDisc::SetMaxSize,
                                          &QueueDisc::GetMaxSize),
                   MakeQueueSizeChecker ())
  ;
  return tid;
}

QKDL2SingleTCPIPPfifoFastQueueDisc::QKDL2SingleTCPIPPfifoFastQueueDisc ()
  : QueueDisc (QueueDiscSizePolicy::MULTIPLE_QUEUES, QueueSizeUnit::PACKETS)
{
  NS_LOG_FUNCTION (this);
}

QKDL2SingleTCPIPPfifoFastQueueDisc::~QKDL2SingleTCPIPPfifoFastQueueDisc ()
{
  NS_LOG_FUNCTION (this);
}

const uint32_t QKDL2SingleTCPIPPfifoFastQueueDisc::prio2band[16] = {1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1};

bool
QKDL2SingleTCPIPPfifoFastQueueDisc::DoEnqueue (Ptr<QueueDiscItem> item)
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
QKDL2SingleTCPIPPfifoFastQueueDisc::DoDequeue (void)
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
QKDL2SingleTCPIPPfifoFastQueueDisc::DoPeek (void)
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
QKDL2SingleTCPIPPfifoFastQueueDisc::CheckConfig (void)
{
  NS_LOG_FUNCTION (this);
  if (GetNQueueDiscClasses () > 0)
    {
      NS_LOG_ERROR ("QKDL2SingleTCPIPPfifoFastQueueDisc cannot have classes");
      return false;
    }

  if (GetNPacketFilters () != 0)
    {
      NS_LOG_ERROR ("QKDL2SingleTCPIPPfifoFastQueueDisc needs no packet filter");
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
      NS_LOG_ERROR ("QKDL2SingleTCPIPPfifoFastQueueDisc needs 3 internal queues");
      return false;
    }

  if (GetInternalQueue (0)-> GetMaxSize ().GetUnit () != QueueSizeUnit::PACKETS ||
      GetInternalQueue (1)-> GetMaxSize ().GetUnit () != QueueSizeUnit::PACKETS ||
      GetInternalQueue (2)-> GetMaxSize ().GetUnit () != QueueSizeUnit::PACKETS)
    {
      NS_LOG_ERROR ("QKDL2SingleTCPIPPfifoFastQueueDisc needs 3 internal queues operating in packet mode");
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
QKDL2SingleTCPIPPfifoFastQueueDisc::InitializeParams (void)
{
  NS_LOG_FUNCTION (this);
  m_running = false;
}
 
/*
* We need to reimplement following functions from queue-disc: 
* - Run
* - RunBegin
* - RunEnd
* - Restart
* - DequeuePacket
* - Requeue
* - Transmit
* 
* because we need to add calls to QKDManager to perform encryption and authentication!
*/

Ptr<Node>
QKDL2SingleTCPIPPfifoFastQueueDisc::GetNode ()
{
  NS_LOG_FUNCTION (this << m_node);
  return m_node;
}

void
QKDL2SingleTCPIPPfifoFastQueueDisc::SetNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION (this << node);
  m_node = node;
}


void
QKDL2SingleTCPIPPfifoFastQueueDisc::Run (void)
{
  NS_LOG_FUNCTION (this);

  if (RunBeginL2 ())
    {
      uint32_t quota = GetQuota();
      
      NS_LOG_FUNCTION (this << "quota" << quota);

      while (RestartL2 ())
        {
          quota -= 1;
          if (quota <= 0)
            {
              /// \todo netif_schedule (q);
              break;
            }
        }
      RunEndL2 ();
    }
}

bool
QKDL2SingleTCPIPPfifoFastQueueDisc::RunBeginL2 (void)
{
  NS_LOG_FUNCTION (this << m_running);
  if (m_running)
    {
      return false;
    }

  m_running = true;
  return true;
}

void
QKDL2SingleTCPIPPfifoFastQueueDisc::RunEndL2 (void)
{
  NS_LOG_FUNCTION (this);
  m_running = false;
}

 

bool
QKDL2SingleTCPIPPfifoFastQueueDisc::RestartL2 (void)
{
  NS_LOG_FUNCTION (this);
  Ptr<QueueDiscItem> item = DequeuePacketL2();
  if (item == 0)
    {
      NS_LOG_LOGIC ("No packet to send");
      return false;
    }

  return TransmitL2 (item);
}

Ptr<QueueDiscItem>
QKDL2SingleTCPIPPfifoFastQueueDisc::DequeuePacketL2 ()
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT (m_devQueueIface);
  Ptr<QueueDiscItem> item;

  // First check if there is a requeued packet
  if (m_requeued != 0)
    {
        // If the queue where the requeued packet is destined to is not stopped, return
        // the requeued packet; otherwise, return an empty packet.
        // If the device does not support flow control, the device queue is never stopped
        if (!m_devQueueIface->GetTxQueue (m_requeued->GetTxQueueIndex ())->IsStopped ())
          {
            item = m_requeued;
            m_requeued = 0;

            m_nPacketsL2--;
            m_nBytesL2 -= item->GetSize ();

            NS_LOG_LOGIC ("m_traceDequeueL2 (p)");
            m_traceDequeueL2 (item);
          }
    }
  else
    {
      // If the device is multi-queue (actually, Linux checks if the queue disc has
      // multiple queues), ask the queue disc to dequeue a packet (a multi-queue aware
      // queue disc should try not to dequeue a packet destined to a stopped queue).
      // Otherwise, ask the queue disc to dequeue a packet only if the (unique) queue
      // is not stopped.
      if (m_devQueueIface->GetNTxQueues ()>1 || !m_devQueueIface->GetTxQueue (0)->IsStopped ())
        {
          item = Dequeue ();
          // If the item is not null, add the header to the packet.
          if (item != 0)
            {
              item->AddHeader ();
            }
          // Here, Linux tries bulk dequeues
        }
    }
  return item;
}

void
QKDL2SingleTCPIPPfifoFastQueueDisc::RequeueL2 (Ptr<QueueDiscItem> item)
{
  NS_LOG_FUNCTION (this << item);
  m_requeued = item;
  /// \todo netif_schedule (q);

  m_nPacketsL2++;       // it's still part of the queue
  //m_nBytesL2 += item->GetSize ();
  //m_nTotalRequeuedPacketsL2++;
  //m_nTotalRequeuedBytesL2 += item->GetSize ();

  NS_LOG_LOGIC ("m_traceRequeueL2 (p)");
  m_traceRequeueL2 (item);
}

bool
QKDL2SingleTCPIPPfifoFastQueueDisc::TransmitL2 (Ptr<QueueDiscItem> item)
{
  NS_LOG_FUNCTION (this << item);
  NS_ASSERT (m_devQueueIface);

  // if the device queue is stopped, requeue the packet and return false.
  // Note that if the underlying device is tc-unaware, packets are never
  // requeued because the queues of tc-unaware devices are never stopped
  if (m_devQueueIface->GetTxQueue (item->GetTxQueueIndex ())->IsStopped ())
    {
      RequeueL2 (item);
      return false;
    }

  // a single queue device makes no use of the priority tag
  if (m_devQueueIface->GetNTxQueues () == 1)
    {
      SocketPriorityTag priorityTag;
      item->GetPacket ()->RemovePacketTag (priorityTag);
    }
 
  //PRIOR SENDING TO NetDevice, send to QKDManager for encryption/authentication
  Ptr<QKDManager> manager = GetNetDevice()->GetNode ()->GetObject<QKDManager> ();
  manager->VirtualSend (item->GetPacket (), GetNetDevice()->GetAddress(), item->GetAddress (), item->GetProtocol (), item->GetTxQueueIndex ());

  // the behavior here slightly diverges from Linux. In Linux, it is advised that
  // the function called when a packet needs to be transmitted (ndo_start_xmit)
  // should always return NETDEV_TX_OK, which means that the packet is consumed by
  // the device driver and thus is not requeued. However, the ndo_start_xmit function
  // of the device driver is allowed to return NETDEV_TX_BUSY (and hence the packet
  // is requeued) when there is no room for the received packet in the device queue,
  // despite the queue is not stopped. This case is considered as a corner case or
  // an hard error, and should be avoided.
  // Here, we do not handle such corner case and always assume that the packet is
  // consumed by the netdevice. Thus, we ignore the value returned by Send and a
  // packet sent to a netdevice is never requeued. The reason is that the semantics
  // of the value returned by NetDevice::Send does not match that of the value
  // returned by ndo_start_xmit.

  // if the queue disc is empty or the device queue is now stopped, return false so
  // that the Run method does not attempt to dequeue other packets and exits
  if (GetNPackets () == 0 || m_devQueueIface->GetTxQueue (item->GetTxQueueIndex ())->IsStopped ())
    {
      return false;
    }

  return true;
}
  
  

} // namespace ns3
