/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016 Universita' degli Studi di Napoli Federico II
 *               2016 University of Washington
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

#ifndef QKD_PACKET_FILTER_H
#define QKD_PACKET_FILTER_H

#include "ns3/object.h"
#include "ns3/packet-filter.h"
#include "ns3/ipv4-header.h"

namespace ns3 {

/**
 * \ingroup qkd
 * \class QKDPacketFilter
 * \brief QKDPacketFilter is the abstract base class for filters defined for IPv4 packets.
 */
class QKDPacketFilter: public PacketFilter {
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  QKDPacketFilter ();
  virtual ~QKDPacketFilter ();

private:
  virtual bool CheckProtocol (Ptr<QueueDiscItem> item) const;
  virtual int32_t DoClassify (Ptr<QueueDiscItem> item) const = 0;
};


/**
 * \ingroup qkd
 * \class PfifoFastQKDPacketFilter
 * \brief Return the priority corresponding to a given TOS value. 
 *
 * We use it for sorting of packets in waiting queues based on TOS value
 *
 * This function is implemented after the Linux rt_tos2priority
 * function. The usage of the TOS byte has been originally defined by
 * RFC 1349 (http://www.ietf.org/rfc/rfc1349.txt):
 *
 *               0     1     2     3     4     5     6     7
 *           +-----+-----+-----+-----+-----+-----+-----+-----+
 *           |   PRECEDENCE    |          TOS          | MBZ |
 *           +-----+-----+-----+-----+-----+-----+-----+-----+
 *
 * where MBZ stands for 'must be zero'.
 *
 * The Linux rt_tos2priority function ignores the precedence bits and
 * maps each of the 16 values coded in bits 3-6 as follows:
 *
 * Bits 3-6 | Means                   | Linux Priority
 * ---------|-------------------------|----------------
 *     0    |  Normal Service         | Best Effort (0)
 *     1    |  Minimize Monetary Cost | Best Effort (0)
 *     2    |  Maximize Reliability   | Best Effort (0)
 *     3    |  mmc+mr                 | Best Effort (0)
 *     4    |  Maximize Throughput    | Bulk (2)
 *     5    |  mmc+mt                 | Bulk (2)
 *     6    |  mr+mt                  | Bulk (2)
 *     7    |  mmc+mr+mt              | Bulk (2)
 *     8    |  Minimize Delay         | Interactive (6)
 *     9    |  mmc+md                 | Interactive (6)
 *    10    |  mr+md                  | Interactive (6)
 *    11    |  mmc+mr+md              | Interactive (6)
 *    12    |  mt+md                  | Int. Bulk (4)
 *    13    |  mmc+mt+md              | Int. Bulk (4)
 *    14    |  mr+mt+md               | Int. Bulk (4)
 *    15    |  mmc+mr+mt+md           | Int. Bulk (4)
 *
 * RFC 2474 (http://www.ietf.org/rfc/rfc2474.txt) redefines the TOS byte:
 *
 *               0     1     2     3     4     5     6     7
 *           +-----+-----+-----+-----+-----+-----+-----+-----+
 *           |              DSCP                 |     CU    |
 *           +-----+-----+-----+-----+-----+-----+-----+-----+
 *
 * where DSCP is the Differentiated Services Code Point and CU stands for
 * 'currently unused' (actually, RFC 3168 proposes to use these two bits for
 * ECN purposes). The table above allows to determine how the Linux
 * rt_tos2priority function maps each DSCP value to a priority value. Such a
 * mapping is shown below.
 *
 * DSCP | Hex  | TOS (binary) | bits 3-6 | Linux Priority
 * -----|------|--------------|----------|----------------
 * EF   | 0x2E |   101110xx   |  12-13   |  Int. Bulk (4)
 * AF11 | 0x0A |   001010xx   |   4-5    |  Bulk (2)
 * AF21 | 0x12 |   010010xx   |   4-5    |  Bulk (2)
 * AF31 | 0x1A |   011010xx   |   4-5    |  Bulk (2)
 * AF41 | 0x22 |   100010xx   |   4-5    |  Bulk (2)
 * AF12 | 0x0C |   001100xx   |   8-9    |  Interactive (6)
 * AF22 | 0x14 |   010100xx   |   8-9    |  Interactive (6)
 * AF32 | 0x1C |   011100xx   |   8-9    |  Interactive (6)
 * AF42 | 0x24 |   100100xx   |   8-9    |  Interactive (6)
 * AF13 | 0x0E |   001110xx   |  12-13   |  Int. Bulk (4)
 * AF23 | 0x16 |   010110xx   |  12-13   |  Int. Bulk (4)
 * AF33 | 0x1E |   011110xx   |  12-13   |  Int. Bulk (4)
 * AF43 | 0x26 |   100110xx   |  12-13   |  Int. Bulk (4)
 * CS0  | 0x00 |   000000xx   |   0-1    |  Best Effort (0)
 * CS1  | 0x08 |   001000xx   |   0-1    |  Best Effort (0)
 * CS2  | 0x10 |   010000xx   |   0-1    |  Best Effort (0)
 * CS3  | 0x18 |   011000xx   |   0-1    |  Best Effort (0)
 * CS4  | 0x20 |   100000xx   |   0-1    |  Best Effort (0)
 * CS5  | 0x28 |   101000xx   |   0-1    |  Best Effort (0)
 * CS6  | 0x30 |   110000xx   |   0-1    |  Best Effort (0)
 * CS7  | 0x38 |   111000xx   |   0-1    |  Best Effort (0)
 *
 * \param ipTos the TOS value (in the range 0..255)
 * \return The priority value corresponding to the given TOS value
 */
 
class PfifoFastQKDPacketFilter: public QKDPacketFilter {
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  PfifoFastQKDPacketFilter ();
  virtual ~PfifoFastQKDPacketFilter ();

  /**
   * \brief Enumeration of modes of Ipv4 header traffic class semantics
   */
  enum QKDTrafficClassMode
  {
    PF_MODE_TOS,       //!< use legacy TOS semantics to interpret TOS byte
    PF_MODE_DSCP,      //!< use DSCP semantics to interpret TOS byte
  };
  
  uint32_t TosToBand (uint8_t tos) const;

private:

  const uint32_t prio2band[16] = {1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1};

  virtual int32_t DoClassify (Ptr<QueueDiscItem> item) const;
  uint32_t DscpToBand (Ipv4Header::DscpType dscpType) const;

  QKDTrafficClassMode m_trafficClassMode; //!< traffic class mode
};

} // namespace ns3

#endif /* IPV4_PACKET_FILTER */
