/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2005,2006 INRIA
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
 
#ifndef QKDCrypto_H
#define QKDCrypto_H

#include <algorithm>
#include <stdint.h>

#include "ns3/header.h"
#include "ns3/tcp-header.h"
#include "ns3/udp-header.h" 
#include "ns3/icmpv4.h"

#include "ns3/dsdv-packet.h"  
#include "ns3/aodv-packet.h" 
#include "ns3/olsr-header.h" 

#include "ns3/packet.h"
#include "ns3/packet-metadata.h"
#include "ns3/tag.h" 
#include "ns3/object.h"
#include "ns3/callback.h"
#include "ns3/assert.h"
#include "ns3/ptr.h"
#include "ns3/deprecated.h"
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/qkd-buffer.h"
#include "ns3/qkd-header.h"
#include "ns3/qkd-key.h"
#include "ns3/net-device.h"

#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/osrng.h>
#include <crypto++/ccm.h>
#include <crypto++/vmac.h>
#include <crypto++/iterhash.h>
#include <crypto++/secblock.h>
#include <crypto++/sha.h>
#include <vector>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <crypto++/md5.h> 

//ENCRYPTION
#define QKDCRYPTO_OTP 1
#define QKDCRYPTO_AES 2
//AUTHENTICATION
#define QKDCRYPTO_AUTH_VMAC     3
#define QKDCRYPTO_AUTH_MD5      4
#define QKDCRYPTO_AUTH_SHA1     5

namespace ns3 {

/**
 * \ingroup qkd
 * \class QKDCrypto
 * \brief QKD crypto is a class used to perform encryption, decryption, authentication, 
 *  atuhentication-check operations and reassembly of previously fragmented packets.
 *
 *  QKD crypto uses cryptographic algorithms and schemes from
 *  Crypto++ free and open source C++ class cryptographic library. Currently, 
 *  QKDCrypto supports following crypto-graphic algorithms and schemes:
 * • One-Time Pad (OTP) cipher,
 * • Advanced Encryption Standard (AES) block cipher,
 * • VMAC message authentication code (MAC) algorithm,
 * • MD5 MAC algorithm,
 * • SHA1 MAC algorithm.
 *  QKD crypto implements functions for serialization and deserialization of the packet 
 *  into a byte array which is used as the input in cryptographic algorithms and schemes.
 *
 *  QKD crypto is a class used to perform encryption, decryption, authentication, 
 *  authentication-check operations and reassembly of previously fragmented packets. 
 *  QKD crypto uses cryptographic algorithms and schemes from Crypto++ open-source 
 *  C++ class cryptographic library. Currently, QKD crypto supports several cryptographic 
 *  algorithms and cryptographic hashes including One-Time Pad (OTP) cipher, 
 *  Advanced Encryption Standard (AES) block cipher, VMAC message authentication code (MAC) algorithm and other.
 *  Also, QKD crypto implements functions for serialization and deserialization of 
 *  the packet into a byte array which is used as the input in cryptographic algorithms and schemes.
 *
 *  The main idea behind QKDCrypto is to convert packet payload and its header to string and perform cryptographic operations over that string. Since some headers have variable length, 
 *  like TCP or OLSR, then and there is no field indicating the size of these headers (there is only field indicating whole packet size in IPv4 header) it is difficult to distinguish between
 *  packet payload and end of packet's header. Therefore, we use a small trick to add a QKDDelimiterHeader to help us in this process. This header sits between the packets and it contains only
 *  one field (m_delimiter) which is actually the size of next header. For example, in case of TCP, QKDDelimiterHeader sits between IPv4 and TCP indicating the size of TCP header. 
 *  The order of packets in this case is IPv4, QKDDelimiterHeader, TCP, payload... In case of OLSR it sits between OlsrPacketHeader and OLSRMessageHEader indicating the 
 *  size of OLSRMessageHeader which can vary. The order of packets in this case is IPv4, UPD, OLSRPacketHeader, QKDDelimiterHeader, OLSRMessageHeader, OLSRPacketHeader, QKDDelimiterHeader, 
 *  OLSRMessageHeader and etc.
 *
 *  Post taken from ns-3-users google group by Tommaso Pecorella:
 *  https://groups.google.com/forum/#!searchin/ns-3-users/A$20Buffer$20does$20NOT$20hold$20just$20the$20header$20(or$20packet)$20content$2C$20it$20contains$20also$20the$20packet$20metadata.%7Csort:relevance/ns-3-users/zfS7DBVs8RM/XUgaFlHABAAJ
 *
 *  "A Buffer does NOT hold just the header (or packet) content, it contains also the packet metadata. As a consequence it's often much longer than expected.
 *  The buffer size that you need to serialize something is (not a surprise) returned by GetSerializedSize.
 *  If you ask what's the serialized size of an IPv4 header, the answer is... 20 bytes (obvious).
 *  However, the Buffer you just serialized the header into... that's different, because THAT has some metadata to carry. Result: Buffer.GetSerializedSize() -> 32 bytes.
 *  You need a 32 Bytes long array (minimum)
 *  But wait, there's more !
 *  You need to store the array size somewhere. Guess what ? If you serialize a Buffer with a GetSerializedSize equal to 32, you need a 32+4 Bytes array (minimum).
 *  Problem: what about the Deserialize ?
 *  Well, in that case too you should know the amount of bytes to deserialize. If you think it's less or more, an error will be thrown."
 */
class QKDCrypto : public Object
{
public:
     
    /**
    * \brief Constructor
    */
    QKDCrypto ();

    /**
    * \brief Destructor
    */
    virtual ~QKDCrypto ();    
    /**
    * \brief Get the TypeId
    *
    * \return The TypeId for this class
    */
    static TypeId GetTypeId (void);
    
    /**
    *   This functions is an entry point toward deencryption/authentication-check of the packet
    *   Packet is deserialized from string in case when packet was previously encrypted or authentication, 
    *   otherwise, the packet is kept in "Packet" form and only QKDCommandHeader and QKDHeader are removed
    *   @param  Ptr<Packet>
    *   @param  Ptr<QKDBuffer>
    *   @param  uint32_t    channelID
    *   @return std::vector<Ptr<Packet> >
    */ 
    std::vector<Ptr<Packet> > ProcessIncomingPacket (
        Ptr<Packet>     p, 
        Ptr<QKDBuffer>  QKDBuffer,
        uint32_t        channelID
    );

    /**
    *   This functions is used for real decryption process
    *   @param  Ptr<Packet>
    *   @param  Ptr<QKDBuffer>
    *   @return <Ptr<Packet>
    */ 
    Ptr<Packet> Decrypt (Ptr<Packet> p, Ptr<QKDBuffer> QKDBuffer);
     
    /**
    *   This functions is an entry point toward encryption/authentication of the packet
    *   Packet is serialized to string in case when encryption or authentication is required, 
    *   otherwise, the packet is kept in "Packet" form and only QKDCommandHeader and QKDHeader is added
    *   @param  Ptr<Packet>
    *   @param  Ptr<QKDBuffer> 
    *   @param  uint32_t
    *   @return std::vector<Ptr<Packet> >
    */
    std::vector<Ptr<Packet> > ProcessOutgoingPacket (
        Ptr<Packet>     p, 
        Ptr<QKDBuffer>  QKDBuffer,
        uint32_t        channelID
    ); 

    /**
    *   Check whether there is enough resources (key material) to process (encrypt or decrypt) the packet
    *   @param  Ptr<Packet>
    *   @param  uint32_t
    *   @param  Ptr<QKDBuffer> 
    *   @return bool
    */
    bool 
    CheckForResourcesToProcessThePacket(
        Ptr<Packet>             p, 
        uint32_t                TOSBand,
        Ptr<QKDBuffer>          QKDbuffer
    );

private:

    byte m_iv   [ CryptoPP::AES::BLOCKSIZE ];
   
    /**
    *   Help function used to covert std::string to QKDHeader
    *   Function is used in decryption (deserialize process)
    *   @param  std::string input
    *   @return QKDHeader
    */
    QKDHeader StringToQKDHeader(std::string& input);

    /**
    *   Help function used to covert std::string to QKDDelimiterHeader
    *   Function is used in decryption (deserialize process)
    *   @param  std::string input
    *   @return QKDDelimiterHeader
    */
    QKDDelimiterHeader StringToQKDDelimiterHeader(std::string& input);

    /**
    *   Help function used to serialize packet to std::string which is later used for encryption   
    *   @param  Ptr<Packet> p
    *   @return std::string
    */
    std::string PacketToString (Ptr<Packet> p);

    /**
    *   Help function used to convert string to vector<uint8_t>
    *   @param  std::string  input
    *   @return std::vector<uint8_t>
    */
    std::vector<uint8_t> StringToVector(std::string& input);

    /**
    *   Help function used to vector<uint8_t> to convert string
    *   @return std::string  input
    *   @param  std::vector<uint8_t>
    */
    std::string VectorToString(std::vector<uint8_t> inputVector);

    /**
    *   Help function used to covert QKDHeader to vector<uint8_t> which is suitable for encryption
    *   @param QKDHeader qkdheader
    *   @return  std::vector<uint8_t>
    */
    std::vector<uint8_t> QKDHeaderToVector(QKDHeader& qkdHeader);

    /**
    *   Help function used to covert QKDDelimiterHeader to vector<uint8_t> which is suitable for encryption
    *   @param QKDDelimiterHeader qkdheader
    *   @return  std::vector<uint8_t>
    */
    std::vector<uint8_t> QKDDelimiterHeaderToVector(QKDDelimiterHeader& qkdHeader);

    /**
    *   Help function used to create QKDCommandHeader by analyzing tags of the packet
    *   @param  Ptr<Packet> p
    *   @return QKDCommandHeader
    */
    QKDCommandHeader CreateQKDCommandHeader(Ptr<Packet> p);

    /**
    *   One-time cipher
    *   @param  std::string data
    *   @param  Ptr<QKDKey> key
    *   @return std::string
    */
    std::string OTP (const std::string& data, Ptr<QKDKey> key);
        
    /**
    *   AES encryption
    *   @param  std::string data
    *   @param  Ptr<QKDKey> key
    *   @return std::string
    */
    std::string AESEncrypt (const std::string& data, Ptr<QKDKey> key);

    /**
    *   AES decryption
    *   @param  std::string data
    *   @param  Ptr<QKDKey> key
    *   @return std::string
    */
    std::string AESDecrypt (const std::string& data, Ptr<QKDKey> key);

    /**
    *   Help parent function used for calling child authentication functions
    *   @param  std::string data
    *   @param  Ptr<QKDKey> key
    *   @param  uint8_t authentic
    *   @return std::string
    */
    std::string Authenticate(std::string&, Ptr<QKDKey> key, uint8_t authenticationType);

    /**
    *   Help parent function used for calling child authentication functions for authentication check
    *   @param  std::string data
    *   @param  Ptr<QKDKey> key
    *   @param  uint8_t authentic
    *   @return std::string
    */
    Ptr<Packet> CheckAuthentication(Ptr<Packet> p, Ptr<QKDKey> key, uint8_t authenticationType);

    /**
    *   Help function used to encode string to HEX string
    *   @param  std::string data 
    *   @return std::string
    */
    std::string HexEncode(const std::string& data);

    /**
    *   Help function used to decode string to HEX string
    *   @param  std::string data 
    *   @return std::string
    */
    std::string HexDecode(const std::string& data);

    /**
    *   Help function - base64_encode
    *   @param  std::string data
    *   @return std::string
    */
    std::string base64_encode(std::string& s);

    /**
    *   Help function - base64_decode
    *   @param  std::string data
    *   @return std::string
    */
    std::string base64_decode(std::string const& s);

    /**
    *   Authentication function in Wegman-Carter fashion
    *   @param  std::string data
    *   @param  Ptr<QKDKey> key
    *   @return std::string
    */
    std::string VMAC (std::string& inputString, Ptr<QKDKey> key);

    /**
    *   MD5 Authentication function
    *   @param  std::string data
    *   @param  Ptr<QKDKey> key
    *   @return std::string
    */
    std::string MD5 (std::string& inputString);

    /**
    *   SHA1 Authentication function
    *   @param  std::string data
    *   @param  Ptr<QKDKey> key
    *   @return std::string
    */
    std::string SHA1 (std::string& inputString);

    /**
    *   Help function used to compress string
    *   @param  std::string data
    *   @return std::string
    */
    std::string StringCompressEncode(const std::string& data);

    /**
    *   Help function used to decompress string
    *   @param  std::string data
    *   @return std::string
    */
    std::string StringDecompressDecode(const std::string& data);

    /**
    *   Check for reassembly of packet fragments. 
    *   Function needs to store in cache memory fragments until it receives
    *   whole packet. After receiving of whole packet, decryption can be performed
    *   @param Ptr<Packet>
    *   @param Ptr<QKDBuffer>
    *   @return std::vector<Ptr<Packet> >
    */
    std::vector<Ptr<Packet> > CheckForFragmentation (
        Ptr<Packet>         p, 
        Ptr<QKDBuffer>      QKDBuffer
    );

    uint32_t    m_authenticationTagLengthInBits; //!< length of the authentication tag in bits (32 by default)
    
    TracedCallback<Ptr<Packet> > m_encryptionTrace; //!< trace callback for encryption
    TracedCallback<Ptr<Packet> > m_decryptionTrace; //!< trace callback for decryption

    TracedCallback<Ptr<Packet>, std::string > m_authenticationTrace; //!< trace callback for authentication
    TracedCallback<Ptr<Packet>, std::string > m_deauthenticationTrace; //!< trace callback for authentication check
 
	std::map<uint32_t, std::string> m_cacheFlowValues; //!< map used to hold info about fragmented packets

    uint32_t m_qkdHeaderSize;  //!< qkd header size
    uint32_t m_qkdDHeaderSize; //!< qkd delimiter header size

    bool m_compressionEnabled; //!< encryption (ZIP or similar) enabled?
    bool m_encryptionEnabled;  //!< real encryption used?
     

    /////////////////////////////
    //FIXED HEADER SIZES
    ///////////////////////////////

    //IPv4
    uint32_t m_ipv4HeaderSize;      //!< we store details about the ipv4 header size which is later used in decryption

    //ICMPv4
    uint32_t m_icmpv4HeaderSize;
    uint32_t m_icmpv4EchoHeaderSize; 
    uint32_t m_icmpv4TimeExceededHeaderSize;
    uint32_t m_icmpv4DestinationUnreachableHeaderSize;
 
    //UDP
    uint32_t m_udpHeaderSize;

    //OLSR
    uint32_t m_olsrPacketHeaderSize;
 
    //DSDVQ
    uint32_t m_dsdvqHeaderSize;

    //DSDV
    uint32_t m_dsdvHeaderSize; 
        
    //AODV
    uint32_t m_aodvTypeHeaderSize;
    uint32_t m_aodvRrepHeaderSize;
    uint32_t m_aodvRreqHeaderSize;
    uint32_t m_aodvRrepAckHeaderSize;
    uint32_t m_aodvRerrHeaderSize;

    //AODVQ
    uint32_t m_aodvqTypeHeaderSize;
    uint32_t m_aodvqRrepHeaderSize;
    uint32_t m_aodvqRreqHeaderSize;
    uint32_t m_aodvqRrepAckHeaderSize;
    uint32_t m_aodvqRerrHeaderSize;

}; 
} // namespace ns3

#endif /* QKDCrypto_QKD_H */
