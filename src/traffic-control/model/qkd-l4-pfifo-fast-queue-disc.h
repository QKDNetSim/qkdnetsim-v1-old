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
 * Authors:  Stefano Avallone <stavallo@unina.it>
 *           Tom Henderson <tomhend@u.washington.edu>
 *           Miralem Mehic <miralem.mehic@ieee.org>
 */

#ifndef QKD_L4_PFIFO_FAST_H
#define QKD_L4_PFIFO_FAST_H

#include "ns3/queue-disc.h"
#include "ns3/qkd-buffer.h" 
#include "ns3/ip-l4-protocol.h" 
#include "ns3/qkd-queue-disc-item.h"

namespace ns3 {

/**
 * \ingroup traffic-control
 *
 * Linux pfifo_fast is the default priority queue enabled on Linux
 * systems. Packets are enqueued in three FIFO droptail queues according
 * to three priority bands based on the packet priority.
 *
 * The system behaves similar to three ns3::DropTail queues operating
 * together, in which packets from higher priority bands are always
 * dequeued before a packet from a lower priority band is dequeued.
 *
 * The queue disc capacity, i.e., the maximum number of packets that can
 * be enqueued in the queue disc, is set through the limit attribute, which
 * plays the same role as txqueuelen in Linux. If no internal queue is
 * provided, three DropTail queues having each a capacity equal to limit are
 * created by default. User is allowed to provide queues, but they must be
 * three, operate in packet mode and each have a capacity not less
 * than limit. 
 *
 * \note Additional waiting queues are installed between the L3
 * and L4 ISO/OSI layer to avoid conflicts in decision making
 * which could lead to inaccurate routing. Experimental testing and usage!
 */
class QKDL4PfifoFastQueueDisc : public QueueDisc {
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);
  /**
   * \brief QKDL4PfifoFastQueueDisc constructor
   *
   * Creates a queue with a depth of 1000 packets per band by default
   */
  QKDL4PfifoFastQueueDisc ();

  virtual ~QKDL4PfifoFastQueueDisc(); 

  // Reasons for dropping packets
  static constexpr const char* LIMIT_EXCEEDED_DROP = "Queue disc limit exceeded";  //!< Packet dropped due to queue disc limit exceeded

private:
  /**
   * Priority to band map. Values are taken from the prio2band array used by
   * the Linux pfifo_fast queue disc.
   */
  static const uint32_t prio2band[16];

  virtual bool DoEnqueue (Ptr<QueueDiscItem> item);
  virtual Ptr<QueueDiscItem> DoDequeue (void);
  virtual Ptr<const QueueDiscItem> DoPeek (void) const;
  virtual bool CheckConfig (void);
  virtual void InitializeParams (void);
 
  /**
   * Modelled after the Linux function __qdisc_run (net/sched/sch_generic.c)
   * Dequeues multiple packets, until a quota is exceeded or sending a packet
   * to the device failed.
   */
  void Run (void);

  /**
   * Modelled after the Linux function qdisc_run_begin (include/net/sch_generic.h).
   * \return false if the qdisc is already running; otherwise, set the qdisc as running and return true.
   */
  bool RunBeginL4 (void);

  /**
   * Modelled after the Linux function qdisc_run_end (include/net/sch_generic.h).
   * Set the qdisc as not running.
   */
  void RunEndL4 (void);

  /**
   * Modelled after the Linux function qdisc_restart (net/sched/sch_generic.c)
   * Dequeue a packet (by calling DequeuePacket) and send it to the device (by calling Transmit).
   * \return true if a packet is successfully sent to the device.
   */
  bool RestartL4 (void);

  /**
   * Modelled after the Linux function dequeue_skb (net/sched/sch_generic.c)
   * \return the requeued packet, if any, or the packet dequeued by the queue disc, otherwise.
   */
  Ptr<QKDQueueDiscItem> DequeuePacketL4 (void);

  /**
   * Modelled after the Linux function dev_requeue_skb (net/sched/sch_generic.c)
   * Requeues a packet whose transmission failed.
   * \param p the packet to requeue
   */
  void RequeueL4 (Ptr<QKDQueueDiscItem> p);

  /**
   * Modelled after the Linux function sch_direct_xmit (net/sched/sch_generic.c)
   * Sends a packet to the device and requeues it in case transmission fails.
   * \param p the packet to transmit
   * \return true if the transmission succeeded and the queue is not stopped
   */
  bool TransmitL4 (Ptr<QKDQueueDiscItem> p);
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
 
  bool m_running;                   //!< The queue disc is performing multiple dequeue operations
  uint32_t m_nTotalRequeuedPackets; //!< Total requeued packets
  uint32_t m_nTotalRequeuedBytes;   //!< Total requeued bytes

  TracedValue<uint32_t> m_nPacketsL4; //!< Number of packets in the queue
  TracedValue<uint32_t> m_nBytesL4;   //!< Number of bytes in the queue
  Ptr<Node> m_node;
  Ptr<QKDQueueDiscItem> m_requeued;    //!< The last packet that failed to be transmitted
 
  /// Traced callback: fired when a packet is enqueued
  TracedCallback<Ptr<const QueueItem> > m_traceEnqueueL4; 
    /// Traced callback: fired when a packet is dequeued
  TracedCallback<Ptr<const QueueItem> > m_traceDequeueL4;
    /// Traced callback: fired when a packet is requeued
  TracedCallback<Ptr<const QueueItem> > m_traceRequeueL4;
  /// Traced callback: fired when a packet is dropped
  TracedCallback<Ptr<const QueueItem> > m_traceDropL4;
 
};

} // namespace ns3

#endif /* QKD_PFIFO_FAST_H */
