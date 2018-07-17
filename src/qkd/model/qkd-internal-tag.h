/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 LIPTEL.ieee.org
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

#ifndef QKD_INTERNAL_TAG_H
#define QKD_INTERNAL_TAG_H

#include <queue>
#include "ns3/packet.h"
#include "ns3/tag.h"
#include "ns3/object.h"

namespace ns3 {


/**
 * \ingroup qkd
 * \class QKDCommandTag
 * \brief QKDCommandTag is used to describe the content of the packet payload.
 *  
 * QKDCommandTag is used in routing protocols to mark the packet that needs to be 
 * analyzed further from L4 layer. For example, we mark DSDV packet using this Tag,
 * by using "SetCommand('R')" and "SetRoutingProtocolNumber(DSDV_PACKET_HEADER_PROTOCOL_NUMBER)"
 * Later, in QCrypto by analyzing the tag we know that the packet contains DSDV headers
 * that needs to be encrypted. Without the tag, there is no way to know what is inside TCP/UDP payload.
 * Tag is removed after encryption.
 * If the tag has some other value, such as "SetCommand('A')" it is not a routing packet, 
 * and the payload of the TCP/UDP header is encrypted as it is. 
 *
 * \note This mechanism is mandatory since in the NS-3 simulator, we cannot provide the packet 
 * with all its headers and payload in a simple array of bytes or simmilar (version 3.29). 
 */

class QKDCommandTag : public Tag
{
public:
    /**
    * \brief Get the TypeId
    *
    * \return The TypeId for this class
    */
    static         TypeId GetTypeId (void);
    virtual        TypeId GetInstanceTypeId (void) const;
    virtual        uint32_t GetSerializedSize (void) const;
    virtual        void Serialize (TagBuffer i) const;
    virtual        void Deserialize (TagBuffer i);
    virtual        void Print (std::ostream &os) const;

    void           SetCommand (char value);
    char           GetCommand (void) const;

    void           SetRoutingProtocolNumber (uint32_t value);
    uint32_t       GetRoutingProtocolNumber (void) const;

private:
    char           m_command;  //!< Used to distinguish between routing and data packet
    uint32_t       m_routingProtocolNumber;  //!< If it is a routing packet, we use this value to distinguish the protocol type
};


/**
 * \ingroup qkd
 * \class QKDInternalTOSTag
 * \brief QKDInternalTOSTag is used to provide info about the TOS/DSCP value 
 * to lower (L2) layer. 
 * 
 * Since TOS/DSCP is usually defind on the Application layer, we use QKDInternalTOSTag
 * to carry the information about the TOS/DSCP to lower layers since encryption
 * and authentication is performed on the L2 layer. Therefore, we need to have 
 * TOS/DSCP value on L2 to enqueue packet in the approripate queue and to 
 * decide wether packet should be transmitted at all (based on priority). 
 * 
 */
class QKDInternalTOSTag : public Tag
{
public:
    /**
    * \brief Get the TypeId
    *
    * \return The TypeId for this class
    */
    static        TypeId GetTypeId (void);
    virtual       TypeId GetInstanceTypeId (void) const;
    virtual       uint32_t GetSerializedSize (void) const;
    virtual       void Serialize (TagBuffer i) const;
    virtual       void Deserialize (TagBuffer i);
    virtual       void Print (std::ostream &os) const;

    void          SetTos (uint8_t tos);
    uint8_t       GetTos (void) const;

private:
    uint8_t         m_tos;  //!< TOS value
};


/**
 * \ingroup qkd
 * \class QKDInternalTag
 * \brief QKDInternalTag is used to carry information from the application layer (L5) 
 * about the encryption and authentication scheme that should be used on L2 when 
 * encrypting and authenticating the packet.
 * 
 * QKDInternalTag carries info about the desired authentication and encryption mechanism
 * to be used in QKDCrypto on L2 when performing cryptographic operations. Also, it
 * carries details about the maximal tolerated delay in QKD network. The function of MaxDelay field
 * is similar to the Time-to-Live (TTL) field in the IP header of conventional networks, 
 * but with the aim of minimizing the consumption of scarce key material in QKD network.
 * 
 */ 
class QKDInternalTag : public Tag
{
public:
  /**
  * \brief Get the TypeId
  *
  * \return The TypeId for this class
  */
  static    TypeId GetTypeId (void);
  virtual   TypeId GetInstanceTypeId (void) const;
  virtual   uint32_t GetSerializedSize (void) const;
  virtual   void Serialize (TagBuffer i) const;
  virtual   void Deserialize (TagBuffer i);
  virtual   void Print (std::ostream &os) const;
 
  void     SetEncryptValue (uint8_t value);
  uint8_t  GetEncryptValue (void) const;

  void     SetAuthenticateValue (uint8_t value);
  uint8_t  GetAuthenticateValue (void) const;

  void     SetMaxDelayValue (uint32_t value);
  uint32_t GetMaxDelayValue (void) const;

private:
  uint8_t   m_encryptValue; //!< Type of encryption scheme to be used
  uint8_t   m_authenticateValue; //!< Type of authentication scheme to be used
  uint32_t  m_maxDelay; //!< maximal tolerated delay
};
}  
// namespace ns3

#endif /* QKD_INTERNAL_TAG_H */


