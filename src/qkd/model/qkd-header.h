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
 * Author: Miralem Mehic <miralem.mehic@ieee.org>, Oliver Mauhart <oliver.maurhart@ait.ac.at>
 */

#ifndef QKD_HEADER_H
#define QKD_HEADER_H

#include <queue>
#include <string>
#include "ns3/packet.h"
#include "ns3/header.h"
#include "ns3/object.h"

namespace ns3 { 

/**
 * \ingroup qkd
 * \class QKDCommandHeader
 * \brief QKDCommandHeader is encrypted with packet payload while QKDHeader is not encrypted!
 *  So QKDCommandHeader is able to carry info about the sensitive intrnal protocol commands 
 *  (LOAD, STORE, DATA...) and the type of first header in the list of headers (IPv4 or IPv6)
 * 
 *      0       4       8               16              24              32
 *      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
 *   0  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
 *      |   Protocol    |                  Command                      |
 *   4  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *
 *      Command:        Protocol Command (HANDSHAKE, DATA, LOAD, LOAD-REQUEST, STORE, ...)
 *      Protocol:       ID of next protocol header in the encrypted header chain
 */     

class QKDCommandHeader : public Header
{
    public:

        /**
        * \brief Constructor
        */
        QKDCommandHeader ();

        /**
        * \brief Get the type ID.
        * \return the object TypeId
        */
        static      TypeId GetTypeId ();
        /**
        * \brief Get the type ID.
        * \return the object TypeId
        */
        TypeId      GetInstanceTypeId () const;

        /**
        * \brief Print the header in the output stream
        */
        void        Print (std::ostream &os) const;
        bool        operator== (QKDCommandHeader const & o) const;
        uint32_t    GetSerializedSize () const;
        void        Serialize (Buffer::Iterator start) const;
        uint32_t    Deserialize (Buffer::Iterator start);

        void 		SetCommand (char value);
        char 	    GetCommand (void) const;

        void 		SetProtocol (uint16_t value);
        uint16_t 	GetProtocol (void) const;

    private:

        char        m_command; //!< command and protocol field used in AIT R10 software. not used in QKD simulation module!
        uint16_t    m_protocol; //!< ipv4 by default. Info about the first protocol header to be decrypted 
};



/**
 * \ingroup qkd
 * \class QKDDelimiterHeader
 * \brief QKDDelimiterHeader sits between the packets and it contains only
 *  one field (m_delimiter) which is actually the size of next header. 
 *  For example, in case of TCP, QKDDelimiterHeader sits between IPv4 and 
 *  TCP indicating the size of TCP header. The order of packets in this 
 *  case is IPv4, QKDDelimiterHeader, TCP, payload... In case of OLSR it 
 *  sits between OlsrPacketHeader and OLSRMessageHEader indicating the 
 *  size of OLSRMessageHeader which can vary. The order of packets in this 
 *  case is IPv4, UPD, OLSRPacketHeader, QKDDelimiterHeader, 
 *  OLSRMessageHeader, OLSRPacketHeader, QKDDelimiterHeader, 
 *  OLSRMessageHeader and etc.
 */   
class QKDDelimiterHeader : public Header
{
    public:

        /**
        * \brief Constructor
        */
        QKDDelimiterHeader ();

        /**
        * \brief Get the type ID.
        * \return the object TypeId
        */
        static      TypeId GetTypeId ();
        /**
        * \brief Get the type ID.
        * \return the object TypeId
        */
        TypeId      GetInstanceTypeId () const;

        /**
        * \brief Print the header in the output stream
        */
        void        Print (std::ostream &os) const;
        bool        operator== (QKDDelimiterHeader const & o) const;
        uint32_t    GetSerializedSize () const;
        void        Serialize (Buffer::Iterator start) const;
        uint32_t    Deserialize (Buffer::Iterator start);
 
        void        SetDelimiterSize (uint32_t value);
        uint32_t    GetDelimiterSize (void) const;

    private: 
        uint8_t    m_delimiter; //<! it is used for dynamic header so we know where header starts and where header stops - Otherwise we do not know how to detect header for enrypted text
};



/**
 * \ingroup qkd
 * \class QKDHeader
 * \brief QKD packet header that carries info about used encryption, auth tag and other.
 *
 * This class represents a single Q3P Message 
 * This is a buffer (== the data sent/received) plus some message stuff
 * It includes the total package from head to toe. This means:
 * It includes the header, the payload and the tag. In this order.
 * This the Q3P message layout:
 * 
 * 
 *      0       4       8               16              24              32
 *      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
 *   0  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                            Length                             |
 *   4  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                            Msg-Id                             |
 *   8  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |   E   |   A   |   Z   | v | r |          Channel              |
 *  12  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |           MaxDelay            |          Timestamp            |
 *  16  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                       Encryption Key Id                       |
 *  20  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Authentication Key Id                     |
 *  24  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                             A-Tag ...                         
 *  28  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                              ... A-Tag                               |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                             Data ...                           
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                ... Data ...                          
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                ... Data                              |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * with:
 * 
 *      Length:         total size of packet, including the length field itself
 *      Msg-Id:         message number (inside a channel)
 *      E:              Type of used encryption cipher where value 0 means unencrypted packet
 *      A:              Type of used authentication algorithm where value 0 means non-authenticated packet
 *      Z:              Type of used compression algorithm where value 0 means non-compressed packet
 *      r:              reserved for future use
 *      V:              Q3P version field: ALWAYS 2 for this implementation
 *      Channel:        Q3P Channel number
 *      MaxDelay:       Maximum tolerated delay
 *      Timestamp:      Timestamp of packet’s generation at the ingress node
 *      Protocols:      List of protocol headers included in carried data (in order)
 *      E-KeyId:        Encryption Key Id
 *      A-KeyId:        Authentication Key Id
 *      Data:           User Data
 *      A-Tag:          Authentication tag
 * 
 */     

class QKDHeader : public Header
{
    public:

        /**
        * \brief Constructor
        */
        QKDHeader ();

        /**
        * \brief Get the type ID.
        * \return the object TypeId
        */
        static TypeId GetTypeId ();
        /**
        * \brief Get the type ID.
        * \return the object TypeId
        */
        TypeId      GetInstanceTypeId () const;

        void        Print (std::ostream &os) const;
        bool        operator== (QKDHeader const & o) const;

        uint32_t    GetSerializedSize () const;

        void        Serialize (Buffer::Iterator start) const;
        uint32_t    Deserialize (Buffer::Iterator start);

        void 		SetLength (uint32_t value);
        uint32_t 	GetLength (void) const;
 
        void 		SetMessageId (uint32_t value);
        uint32_t 	GetMessageId (void) const;

        void 		SetEncrypted (uint32_t value);
        uint32_t  	GetEncrypted (void) const;
 
        void 		SetAuthenticated (uint32_t value);
        uint32_t 	GetAuthenticated (void) const;

        void 		SetZipped (uint8_t value);
        uint8_t 	GetZipped (void) const;
     
        void 		SetVersion (uint8_t value);
        uint8_t 	GetVersion (void) const;
  
        void 		SetChannelId (uint16_t value);
        uint16_t 	GetChannelId (void) const;

        void 		SetEncryptionKeyId (uint32_t value);
        uint32_t 	GetEncryptionKeyId (void) const;

        void 		SetAuthenticationKeyId (uint32_t value);
        uint32_t 	GetAuthenticationKeyId (void) const;

        void 		SetAuthTag (std::string value);
        std::string GetAuthTag (void) const;

        /// Check that type if valid
        bool IsValid () const
        {
        return m_valid;
        }
         
    private:

        uint32_t        m_length;                   //!< message length field 
        uint32_t        m_offset;                   //!< message offset field used with fragmentation 
        uint32_t        m_messageId;                //!< message id field 

        uint8_t         m_encryped;                 //!< is packet encrypted or not 
        uint8_t         m_authenticated;            //!< is packet authenticated or not 
        uint8_t         m_zipped;                   //!< is payload zipped or not 
        uint8_t         m_version;                  //!< flags and version field 
        uint8_t         m_reserved;                 //!< reserved field for further use  
        uint16_t        m_channelId;                //!< QKD channel id

        uint32_t        m_encryptionKeyId;          //!< encryption key id 
        uint32_t        m_authenticationKeyId;      //!< authentication key id 
        std::string     m_authTag;                  //!< authentication tag of the packet 

        bool            m_valid;                    //!< Is QKD Header valid or corrupted

    };


}  
// namespace ns3

#endif /* QKD_HEADER_H */


