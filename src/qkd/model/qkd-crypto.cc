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

#define NS_LOG_APPEND_CONTEXT                                   \
  if (GetObject<Node> ()) { std::clog << "[node " << GetObject<Node> ()->GetId () << "] "; }

#include "qkd-crypto.h"
#include "ns3/packet.h"
#include "ns3/assert.h"
#include "ns3/log.h" 
#include <string>
#include <cstdarg>
#include <iostream>
#include <sstream>
  
#include "ns3/header.h"
#include "ns3/tcp-header.h"
#include "ns3/udp-header.h" 
#include "ns3/icmpv4.h"

#include "ns3/dsdv-packet.h" 
#include "ns3/dsdvq-packet.h" 

#include "ns3/aodv-packet.h"
#include "ns3/aodvq-packet.h"

#include "ns3/olsr-header.h" 

#include "ns3/node.h"
#include "ns3/qkd-internal-tag.h"
#include "ns3/virtual-ipv4-l3-protocol.h"
 
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/copy.hpp>

/**
*   Uncomment to support zlib compression
*
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <boost/iostreams/filtering_stream.hpp>
*/

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDCrypto"); 

NS_OBJECT_ENSURE_REGISTERED (QKDCrypto);
 
static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}
 
TypeId 
QKDCrypto::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDCrypto")
    .SetParent<Object> () 
    .AddAttribute ("CompressionEnabled", "Indicates whether a compression of packets is enabled.",
                    BooleanValue (false),
                    MakeBooleanAccessor (&QKDCrypto::m_compressionEnabled),
                    MakeBooleanChecker ())
    .AddAttribute ("EncryptionEnabled", "Indicates whether a real encryption of packets is enabled.",
                    BooleanValue (false),
                    MakeBooleanAccessor (&QKDCrypto::m_encryptionEnabled),
                    MakeBooleanChecker ())
    
    .AddTraceSource ("PacketEncrypted",
                    "The change trance for currenly ecrypted packet",
                     MakeTraceSourceAccessor (&QKDCrypto::m_encryptionTrace),
                     "ns3::QKDCrypto::PacketEncrypted")
    .AddTraceSource ("PacketDecrypted",
                    "The change trance for currenly decrypted packet",
                     MakeTraceSourceAccessor (&QKDCrypto::m_decryptionTrace),
                     "ns3::QKDCrypto::PacketDecrypted")

    .AddTraceSource ("PacketAuthenticated",
                    "The change trance for currenly authenticated packet",
                     MakeTraceSourceAccessor (&QKDCrypto::m_authenticationTrace),
                     "ns3::QKDCrypto::PacketAuthenticated")
    .AddTraceSource ("PacketDeAuthenticated",
                    "The change trance for currenly deauthenticated packet",
                     MakeTraceSourceAccessor (&QKDCrypto::m_deauthenticationTrace),
                     "ns3::QKDCrypto::PacketDeAuthenticated")
    ; 
  return tid;
}
 
QKDCrypto::QKDCrypto () 
{ 
    NS_LOG_FUNCTION (this); 
    memset( m_iv,  0x00, CryptoPP::AES::BLOCKSIZE );
    m_authenticationTagLengthInBits = 32;//Wegman-Carter default value
    m_qkdHeaderSize = 72;
}

QKDCrypto::~QKDCrypto ()
{
  //NS_LOG_FUNCTION  (this);  
}

std::vector<uint8_t> 
QKDCrypto::StringToVector(
    std::string& input
){
    NS_LOG_FUNCTION( this << input.size() );
    std::vector<uint8_t> outputVector; 
    const uint8_t* p = reinterpret_cast<const uint8_t*>(input.c_str());

    for(uint32_t i=0; i<input.size(); i++)
        outputVector.push_back(p[i]);
    
    //delete p;
    return outputVector;
}

std::string
QKDCrypto::VectorToString(std::vector<uint8_t> inputVector)
{
    NS_LOG_FUNCTION( this << inputVector.size() );

    //Copy from vector to uint8_t array
    uint16_t b = 0;
    uint8_t *messageContent = new uint8_t[inputVector.size()];
    typename std::vector<uint8_t>::iterator itb = inputVector.begin();
    for( ; itb != inputVector.end(); ++itb) 
        messageContent[b++] = *itb;

    //finally create the string
    std::string output = std::string((char*)messageContent, inputVector.size());
    delete[] messageContent;
    return output;
}

std::vector<uint8_t>
QKDCrypto::QKDHeaderToVector(QKDHeader& qkdHeader)
{
    NS_LOG_FUNCTION  ( this << qkdHeader );

    Buffer qkdHeaderBuffer;
    qkdHeaderBuffer.AddAtStart (qkdHeader.GetSerializedSize());//20
    qkdHeader.Serialize(qkdHeaderBuffer.Begin ());

    uint8_t *qkdBuffer = new uint8_t[qkdHeaderBuffer.GetSerializedSize() + 4];
    uint32_t serializeOutput = qkdHeaderBuffer.Serialize(qkdBuffer, qkdHeaderBuffer.GetSerializedSize() + 4);
    NS_LOG_FUNCTION(this << "QKD Header Serialize result: " << serializeOutput << qkdHeaderBuffer.GetSerializedSize() + 4);
    m_qkdHeaderSize = qkdHeaderBuffer.GetSerializedSize() + 4;

    //check if serialized process was sucessful
    NS_ASSERT(serializeOutput != 0);
 
    std::vector<uint8_t> qkdHeaderVector;
    //Add to headers vector which is going to be encrypted 
    for(uint16_t a=0; a<(qkdHeaderBuffer.GetSerializedSize() + 4); a++)
        qkdHeaderVector.push_back(qkdBuffer[a]);

    delete[] qkdBuffer;
    return qkdHeaderVector;
}

std::vector<uint8_t>
QKDCrypto::QKDDelimiterHeaderToVector(QKDDelimiterHeader& qkdDHeader)
{
    NS_LOG_FUNCTION  ( this << qkdDHeader );

    Buffer qkdDHeaderBuffer;
    qkdDHeaderBuffer.AddAtStart (qkdDHeader.GetSerializedSize());//20
    qkdDHeader.Serialize(qkdDHeaderBuffer.Begin ());

    uint8_t *qkdBuffer = new uint8_t[qkdDHeaderBuffer.GetSerializedSize() + 4];
    uint32_t serializeOutput = qkdDHeaderBuffer.Serialize(qkdBuffer, qkdDHeaderBuffer.GetSerializedSize() + 4);
    NS_LOG_FUNCTION(this << "QKD Delimiter Header Serialize result: " << serializeOutput << qkdDHeaderBuffer.GetSerializedSize() + 4);
    m_qkdDHeaderSize = qkdDHeaderBuffer.GetSerializedSize() + 4;

    NS_LOG_FUNCTION (this << "setting m_qkdDHeaderSize to" << m_qkdDHeaderSize);

    //check if serialized process was sucessful
    NS_ASSERT(serializeOutput != 0);
 
    std::vector<uint8_t> qkdDHeaderVector;
    //Add to headers vector which is going to be encrypted 
    for(uint16_t a=0; a<(qkdDHeaderBuffer.GetSerializedSize() + 4); a++){
        qkdDHeaderVector.push_back(qkdBuffer[a]);
    }

    delete[] qkdBuffer;
    return qkdDHeaderVector;
}

QKDHeader
QKDCrypto::StringToQKDHeader(std::string& input)
{
    NS_LOG_FUNCTION (this  
        << input.size()  
    );
 
    const uint8_t* qkdBuffer = reinterpret_cast<const uint8_t*>(input.c_str());  

    //Create QKDBuffer
    Buffer qkdHeaderBuffer;
    qkdHeaderBuffer.Deserialize( qkdBuffer, m_qkdHeaderSize ); 

    //Fetch QKDHeader
    QKDHeader qkdHeader;
    qkdHeader.Deserialize(qkdHeaderBuffer.Begin ());

    NS_LOG_FUNCTION (this << "QKD Header sucessfully Deserialized!" << qkdHeader ); 
    //delete[] qkdBuffer;

    return qkdHeader;
}

QKDDelimiterHeader
QKDCrypto::StringToQKDDelimiterHeader(std::string& input)
{
    NS_LOG_FUNCTION (this  
        << input.size()  
    );
 
    const uint8_t* qkdBuffer = reinterpret_cast<const uint8_t*>(input.c_str());  

    //Create QKDBuffer
    Buffer qkdHeaderBuffer;
    qkdHeaderBuffer.Deserialize( qkdBuffer, m_qkdDHeaderSize ); 

    //Fetch QKDDelimiterHeader
    QKDDelimiterHeader qkdHeader;
    qkdHeader.Deserialize(qkdHeaderBuffer.Begin ());

    NS_LOG_FUNCTION (this << "QKD Delimiter Header sucessfully Deserialized!" << qkdHeader ); 
    //delete qkdBuffer;

    return qkdHeader;
}

QKDCommandHeader
QKDCrypto::CreateQKDCommandHeader(Ptr<Packet> p)
{
    NS_LOG_FUNCTION(this << p);

    QKDCommandTag qkdCommandTag; 
    QKDCommandHeader qkdCommandHeader; 
    
    //Check whether this is routing message from routing protocol
    if(p->PeekPacketTag(qkdCommandTag)){
        /*
        std::cout << "\n......SENDING plain CreateQKDCommandHeader qkdCommandTag....." << p->GetUid() << "..." << p->GetSize() << ".....\n";
        qkdCommandTag.Print(std::cout);
        std::cout << "\n.............................\n"; 
        */
        if(qkdCommandTag.GetCommand () == 'R')
            NS_LOG_FUNCTION (this << "IT IS ROUTING HELLO PACKET!" <<  qkdCommandTag.GetCommand()  );
        else {
            NS_LOG_FUNCTION (this << "IT IS NORMAL PACKET!" << qkdCommandTag.GetCommand () );
        }

        NS_LOG_FUNCTION (this << "RoutingProtocolNumber:" << qkdCommandTag.GetRoutingProtocolNumber ());
        qkdCommandHeader.SetCommand ( qkdCommandTag.GetCommand() );//Routing hello message

    }else
        NS_LOG_FUNCTION (this << "PACKET WITHOUT QKDCOMMAND TAG RECEIVED!");
    
    return qkdCommandHeader;
}


bool 
QKDCrypto::CheckForResourcesToProcessThePacket(
    Ptr<Packet>             p, 
    uint32_t                TOSBand,
    Ptr<QKDBuffer>          QKDbuffer
){

    NS_LOG_FUNCTION(this << p << TOSBand);

    if(QKDbuffer == 0) 
        return false;

    QKDInternalTag tag;
    p->PeekPacketTag(tag);

    uint8_t shouldEncrypt = tag.GetEncryptValue();
    uint8_t shouldAuthenticate = tag.GetAuthenticateValue();
    uint32_t keySize = 0;

    switch (shouldEncrypt)
    {
        case QKDCRYPTO_OTP:
            keySize += p->GetSize() * 8;//in bits
            break;
            
        case QKDCRYPTO_AES:  
            keySize += CryptoPP::AES::MAX_KEYLENGTH;
            break;
    } 
    
    //KEY IS NEEDED ONLY FOR VMAC
    if(shouldAuthenticate == QKDCRYPTO_AUTH_VMAC){
        keySize += m_authenticationTagLengthInBits ;
    }

    uint32_t QKDbufferStatus = QKDbuffer->FetchState(); 
    uint32_t Mcur = QKDbuffer->GetMcurrent();

    NS_LOG_DEBUG ( this 
    << "\tQKDBuffer: \t" << QKDbufferStatus 
    << "\tTOSband: \t" << TOSBand
    << "\tKeySize: \t" << keySize 
    << "\n");
    
    NS_LOG_DEBUG ( this 
    << "\tQKDBuffer Material: \t" << Mcur  
    << "\tKeySize: \t" << keySize 
    << "\t Enough resources: \t" << (float) (Mcur > keySize)
    << "\n");

    //if buffer is empty then only top priority packet can be transmitted
    if(QKDbufferStatus == QKDBuffer::QKDSTATUS_EMPTY && TOSBand != 0){
        NS_LOG_DEBUG(this << "Buffer is empty so only top priority packet can be transmitted! Returning false!");
        return false;
    }
    
    return Mcur > keySize;    
}

std::vector<Ptr<Packet> > 
QKDCrypto::ProcessOutgoingPacket (
    Ptr<Packet>             p, 
    Ptr<QKDBuffer>          QKDbuffer,
    uint32_t                channelID
)
{
    QKDInternalTag tag;
    if(p->PeekPacketTag(tag)) {
        p->RemovePacketTag(tag);
    }
    uint8_t shouldEncrypt = tag.GetEncryptValue();
    uint8_t shouldAuthenticate = tag.GetAuthenticateValue();

    NS_LOG_FUNCTION(this 
        << "Processing outgoing packet \n PacketID:" << p->GetUid() 
        << " of size: " << p->GetSize()
        << "ChannelID:" << channelID
    );
    std::vector<Ptr<Packet> > packetOutput; 

    //QKD INTERNAL NEXT HOP TAG 
    bool QKDInternalTOSTagPresent = false;
    QKDInternalTOSTag qkdNextHopTag; 
    if(p->RemovePacketTag(qkdNextHopTag))
        QKDInternalTOSTagPresent = true; 

    std::string plainText;    
    std::string cipherText;
    std::string authTag;

    QKDHeader qkdHeader;

    /* 
        Convert whole packet to string because of reassembly and fragmentation in the underlying network when TCP is used
        Consider following example: 

            - We crate three packets with three QKD header
            |QKDHeader|***Payload***||QKDHeader|*************Payload|*************|

            - TCP in the underlying network transmit only small part of the packet, that is it creates fragmenatation like:
            |QKDHeader|***Payload*|

            Then we need to store this small fragment and wait until we receive whole packet.

            - In next iteration we receive following small fragment

            |**||QKDHea
        
            It is easy to decrypt the first packet, but it is very dificult to decrypt the second one, because TCP might deliver only 
            small piece of QKD Header, and then we need to deal with half-QKDheader. Therefore, we decide to convert everything into string 
            (payload and QKDHeader), which is easeier for manipulation and storing. 
            It is just the implementation detail in the current version of QKD mosdule


        Also, coversion of packet to string is necessary for packet authentication and encryption
    */

    //Convert whole packet to string, just do it!
    plainText = PacketToString (p);

    // COMPRES PACKET
    if(m_compressionEnabled){
        plainText = StringCompressEncode (plainText); 
        qkdHeader.SetZipped (1);
    }

    //Now perform encryption of the packet
    if(shouldEncrypt > 0){

        NS_LOG_FUNCTION ( "***** ENCRYPTION MODE *****" << shouldEncrypt );

        //////////////////////////////////////////////
        //          ENCRYPTION
        //////////////////////////////////////////////

        Ptr<QKDKey> key; 
        switch (shouldEncrypt)
        {
            case QKDCRYPTO_OTP:

                if(QKDbuffer != 0) 
                    key = QKDbuffer->ProcessOutgoingRequest ( plainText.size() * 8 ); //In bits

                if(key == 0){
                    NS_LOG_FUNCTION ("NO KEY PROVIDED!");
                    NS_LOG_WARN ("NO ENOUGH KEY IN THE BUFFER! BUFFER IS EMPTY! ABORT ENCRYPTION and AUTHENTICATION PROCESS");
                    return packetOutput;
                }else{
                    cipherText = OTP ( plainText, key );
                    m_encryptionTrace (p);
                }
                break;
                
            case QKDCRYPTO_AES: 

                if(QKDbuffer != 0) 
                    key = QKDbuffer->ProcessOutgoingRequest ( CryptoPP::AES::MAX_KEYLENGTH ); //AES in bits

                if(key == 0){
                    NS_LOG_FUNCTION ("NO KEY PROVIDED!");
                    NS_LOG_WARN ("NO ENOUGH KEY IN THE BUFFER! BUFFER IS EMPTY! ABORT ENCRYPTION and AUTHENTICATION PROCESS");
                    return packetOutput;
                }else{
                    cipherText = AESEncrypt ( plainText, key );
                    m_encryptionTrace (p);
                }
                break;
        }

        qkdHeader.SetEncryptionKeyId(key->GetUid()); 
        qkdHeader.SetEncrypted (shouldEncrypt);

        NS_LOG_FUNCTION(this << "Encryption completed!");

    //or continue without encryption
    }else  
        cipherText = plainText;
    
    qkdHeader.SetMessageId( p->GetUid() );
    qkdHeader.SetChannelId(channelID); 
    qkdHeader.SetLength(m_qkdHeaderSize + cipherText.size());

      
    Ptr<Packet> outputPacket;
    //Now perform authentication if it is necessary
    //Note: All encrypted packets MUST be authenticated as well!
    if (shouldEncrypt>0 || shouldAuthenticate>0){
        
        NS_LOG_FUNCTION ( "***** AUTHENTICATION MODE *****" << shouldAuthenticate);

        //////////////////////////////////////////////
        //          AUTHENTICATION
        //////////////////////////////////////////////

        Ptr<QKDKey> key;

        //KEY IS NEEDED ONLY FOR VMAC
        if(shouldAuthenticate == QKDCRYPTO_AUTH_VMAC){

            if(QKDbuffer != 0) 
                key = QKDbuffer->ProcessOutgoingRequest ( m_authenticationTagLengthInBits ); //In bits

            if(key == 0){
                NS_LOG_FUNCTION ("NO KEY PROVIDED!");
                NS_LOG_WARN ("NO ENOUGH KEY IN THE BUFFER! BUFFER IS EMPTY! ABORT ENCRYPTION and AUTHENTICATION PROCESS");
                return packetOutput;
            }
        }else
            key = 0;

        authTag = Authenticate (cipherText, key, shouldAuthenticate);
        m_authenticationTrace(p, authTag);
        NS_LOG_FUNCTION(this << "Adding AUTHTAG to the packet!" << authTag << authTag.size() );

        qkdHeader.SetAuthenticationKeyId(key->GetUid()); 
        qkdHeader.SetAuthTag(authTag); 
        qkdHeader.SetAuthenticated (shouldAuthenticate);

    }else{
        
        NS_LOG_FUNCTION ( "***** PLAIN TEXT MODE *****" );

        //////////////////////////////////////////////
        //          PLAIN TEXT MODE
        //////////////////////////////////////////////
     
        qkdHeader.SetAuthenticated (0);
        qkdHeader.SetEncrypted (0);
    }
    
    /*
     *  Now convert QKDHeader to std::string and merge it with the rest of the packet
    */

    //QKD Header is now ready and it can be encoded into packet
    std::vector<uint8_t> qkdHeaderInVector = QKDHeaderToVector(qkdHeader);

    //Convert whole packet into vector
    std::vector<uint8_t> packetContentInVector = StringToVector( cipherText );

    //Now add qkdheader in the begining of packet vector
    qkdHeaderInVector.insert(qkdHeaderInVector.end(), packetContentInVector.begin(), packetContentInVector.end());

    //Finally convert everything to one string
    std::string finalPayload = VectorToString(qkdHeaderInVector);
    
    //NS_LOG_FUNCTION (this << HexEncode(finalPayload) );
    NS_LOG_FUNCTION( this 
        << "ChannelID:" << channelID
        << "Final packetContent size:" << finalPayload.size()
    ); 

    Ptr<Packet> packet = Create<Packet> ((uint8_t*) finalPayload.c_str(), finalPayload.size()); 
    outputPacket = packet;


    //////////////////////////////////////////////
    // ADDING INTERNAL NEXT HOP TAG
    // This tag is needed since encrypted packet does not have IP, 
    // so it is a problem for QKDManager to reveal information about 
    // the underlying network (socket on which packet needs to be passed)
    //////////////////////////////////////////////

    if(QKDInternalTOSTagPresent){
        NS_LOG_FUNCTION (this << "Adding QKD Internal NextHop Tag!");
        outputPacket->AddPacketTag(qkdNextHopTag);
    }

    /////////////////////////////////////////////
    //  FINALLY, PACKET IS READY
    /////////////////////////////////////////////

    NS_LOG_FUNCTION(this 
        << "Final outgoing packet from QCrypto:" 
        << "PacketID:" << outputPacket->GetUid() 
        << "of size" << outputPacket->GetSize() 
        << "MessageID:" << qkdHeader.GetMessageId()
        << "QKDHeaderLength:" << qkdHeader.GetLength()
        << "ChannelID:" << channelID
    );

    packetOutput.push_back(outputPacket);
    return packetOutput;    
} 

std::string
QKDCrypto::PacketToString (Ptr<Packet> p)
{ 
    NS_LOG_FUNCTION  (this << p->GetUid() << p->GetSize());
    /*
    std::cout << "\n ..................SENDING plain....." << p->GetUid() << "..." <<  p->GetSize() << ".......  \n";
    p->Print(std::cout);                
    std::cout << "\n ............................................  \n"; 
    */
    QKDCommandHeader qkdCommandHeader = CreateQKDCommandHeader(p);

    PacketMetadata::Item item; 
    PacketMetadata::ItemIterator metadataIterator = p->BeginItem();

    uint16_t counter = 0; 
    uint32_t firstNextHeader = 4; //IPv4 by default
    uint16_t headerContentSize = 0;
    std::vector<uint8_t> headerContentVector; 

    NS_LOG_FUNCTION(this << firstNextHeader);


    ////////////////////////////////////
    //  SERALIZE ALL HEADERS OF THE PACKET
    ////////////////////////////////////
 
    while (metadataIterator.HasNext()) {

        item = metadataIterator.Next();
        if(!item.tid.GetUid()) break;

        NS_LOG_FUNCTION(this << "---------");
        NS_LOG_FUNCTION(this << item.tid.GetName() );
             
        ////////////////////////////////////////
        //  IPv4 Header Serialize
        ///////////////////////////////////////

        if(item.tid.GetName() == "ns3::Ipv4Header") 
        {             
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            Ipv4Header* ipv4Header = dynamic_cast<Ipv4Header*> (instance);
            NS_ASSERT(ipv4Header != 0);
            ipv4Header->Deserialize(item.current);
            
            NS_LOG_FUNCTION(this << uint32_t (ipv4Header->GetProtocol()) << qkdCommandHeader);

            Buffer ipHeaderBuffer;
            ipHeaderBuffer.AddAtStart (ipv4Header->GetSerializedSize());//20
             
            NS_LOG_FUNCTION (this << "Ipv4Header Protocol value: " << (uint32_t) ipv4Header->GetProtocol() );
            ipv4Header->Serialize(ipHeaderBuffer.Begin ());
            /*
            std::cout << "\n....IPv4 HEADER....\n"; 
            ipv4Header->Print(std::cout);
            std::cout << "\n...................\n"; 
            */
            
            // finished, clear the header
            headerContentSize += ipv4Header->GetSerializedSize();
            NS_LOG_FUNCTION(this << "IPv4 Header size: " << ipv4Header->GetSerializedSize());
            delete ipv4Header; 

            uint8_t *ipBuffer = new uint8_t[ipHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = ipHeaderBuffer.Serialize(ipBuffer, ipHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "IPv4 Header Serialize result: " << serializeOutput << ipHeaderBuffer.GetSerializedSize() + 4);

            //SET HEADER SIZE
            m_ipv4HeaderSize = ipHeaderBuffer.GetSerializedSize() + 4;

            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);

            //Add to headers vector which is going to be encrypted 
            for(uint16_t a=0; a<(ipHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(ipBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after IPv4: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = 4;  
            NS_LOG_FUNCTION (this << "IPv4 Header serialized" << counter);

            delete[] ipBuffer;
            
        ////////////////////////////////////////
        //  ICMPv4 Header Serialize
        ///////////////////////////////////////

        }else if(item.tid.GetName() == "ns3::Icmpv4Header") 
        { 
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            Icmpv4Header* icmpv4Header = dynamic_cast<Icmpv4Header*> (instance);
            NS_ASSERT(icmpv4Header != 0);
            icmpv4Header->Deserialize(item.current);
            /*      
            std::cout << "\n....icmpv4Header HEADER....\n"; 
            icmpv4Header->Print(std::cout);
            std::cout << "\n...................\n";
            */
            Buffer icmpv4HeaderBuffer;
            icmpv4HeaderBuffer.AddAtStart (icmpv4Header->GetSerializedSize());//8
            icmpv4Header->Serialize(icmpv4HeaderBuffer.Begin ());

            // finished, clear the header
            headerContentSize += icmpv4Header->GetSerializedSize(); 
            NS_LOG_FUNCTION(this << "icmpv4Header  size: " << icmpv4Header->GetSerializedSize());
            delete icmpv4Header; 

            uint8_t *icmpv4Buffer = new uint8_t[icmpv4HeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = icmpv4HeaderBuffer.Serialize(icmpv4Buffer, icmpv4HeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "Icmpv4Header Header Serialize result: " << serializeOutput << icmpv4HeaderBuffer.GetSerializedSize() + 4);

            //SET HEADER SIZE
            m_icmpv4HeaderSize = icmpv4HeaderBuffer.GetSerializedSize() + 4;

            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(icmpv4HeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(icmpv4Buffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after Icmpv4Header: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = 1; 
            NS_LOG_FUNCTION (this << "ICMPv4 Header serialized" << counter);
            delete[] icmpv4Buffer;
                 
        ////////////////////////////////////////
        //   Icmpv4 Destination Unreachable Header Serialize
        ///////////////////////////////////////

        }else if(item.tid.GetName() == "ns3::Icmpv4DestinationUnreachable") 
        { 
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            Icmpv4DestinationUnreachable* header = dynamic_cast<Icmpv4DestinationUnreachable*> (instance);
            NS_ASSERT(header != 0);
            header->Deserialize(item.current);
            /*      
            std::cout << "\n....header HEADER....\n"; 
            header->Print(std::cout);
            std::cout << "\n...................\n";
            */
            Buffer headerBuffer;
            headerBuffer.AddAtStart (header->GetSerializedSize());//8
            header->Serialize(headerBuffer.Begin ());

            // finished, clear the header
            headerContentSize += header->GetSerializedSize(); 
            NS_LOG_FUNCTION(this << "header  size: " << header->GetSerializedSize());
            delete header; 

            uint8_t *headerSerializedBuffer = new uint8_t[headerBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = headerBuffer.Serialize(headerSerializedBuffer, headerBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "Icmpv4DestinationUnreachable Header Serialize result: " << serializeOutput << headerBuffer.GetSerializedSize() + 4);

            //SET HEADER SIZE
            m_icmpv4DestinationUnreachableHeaderSize = headerBuffer.GetSerializedSize() + 4;

            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(headerBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(headerSerializedBuffer[a]);
 
            NS_LOG_FUNCTION ("PLAINTEXT.size after Icmpv4DestinationUnreachable: " << headerContentVector.size() );

            if(counter == 0) firstNextHeader = 1; 
            NS_LOG_FUNCTION (this << "Icmpv4 Destination Unreachable Header serialized" << counter);

            delete[] headerSerializedBuffer;
                       
        ////////////////////////////////////////
        //  ICMPv4 Echo Header Serialize
        ///////////////////////////////////////

        }else if(item.tid.GetName() == "ns3::Icmpv4Echo") 
        { 
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            Icmpv4Echo* header = dynamic_cast<Icmpv4Echo*> (instance);
            NS_ASSERT(header != 0);
            header->Deserialize(item.current);
            /*      
            std::cout << "\n....header HEADER....\n"; 
            header->Print(std::cout);
            std::cout << "\n...................\n";
            */
            Buffer headerBuffer;
            headerBuffer.AddAtStart (header->GetSerializedSize());//8
            header->Serialize(headerBuffer.Begin ());

            // finished, clear the header
            headerContentSize += header->GetSerializedSize();
            NS_LOG_FUNCTION(this << "header  size: " << header->GetSerializedSize());
            delete header; 

            uint8_t *headerSerializedBuffer = new uint8_t[headerBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = headerBuffer.Serialize(headerSerializedBuffer, headerBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "Icmpv4Echo Header Serialize result: " << serializeOutput << headerBuffer.GetSerializedSize() + 4);

            //SET HEADER SIZE
            m_icmpv4EchoHeaderSize = headerBuffer.GetSerializedSize() + 4;

            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(headerBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(headerSerializedBuffer[a]);
 
            NS_LOG_FUNCTION ("PLAINTEXT.size after Icmpv4Echo: " << headerContentVector.size() );

            if(counter == 0) firstNextHeader = 1; 
            NS_LOG_FUNCTION (this << "ICMPv4 Echo Header serialized" << counter);

            delete[] headerSerializedBuffer;

        ////////////////////////////////////////
        //  Icmpv4 Time Exceeded Header Serialize
        ///////////////////////////////////////

        }else if(item.tid.GetName() == "ns3::Icmpv4TimeExceeded") 
        { 
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            Icmpv4TimeExceeded* header = dynamic_cast<Icmpv4TimeExceeded*> (instance);
            NS_ASSERT(header != 0);
            header->Deserialize(item.current);
            /*      
            std::cout << "\n....header HEADER....\n"; 
            header->Print(std::cout);
            std::cout << "\n...................\n";
            */
            Buffer headerBuffer;
            headerBuffer.AddAtStart (header->GetSerializedSize());//8
            header->Serialize(headerBuffer.Begin ());

            // finished, clear the header
            headerContentSize += header->GetSerializedSize();
            NS_LOG_FUNCTION(this << "header  size: " << header->GetSerializedSize());
            delete header; 

            uint8_t *headerSerializedBuffer = new uint8_t[headerBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = headerBuffer.Serialize(headerSerializedBuffer, headerBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "Icmpv4TimeExceeded Header Serialize result: " << serializeOutput << headerBuffer.GetSerializedSize() + 4);

            //SET HEADER SIZE
            m_icmpv4TimeExceededHeaderSize = headerBuffer.GetSerializedSize() + 4;
            
            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(headerBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(headerSerializedBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after Icmpv4TimeExceeded: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = 1; 
            NS_LOG_FUNCTION (this << "Icmpv4 Time Exceeded Header serialized" << counter);

            delete[] headerSerializedBuffer;
                        
        ////////////////////////////////////////
        //  UDP Header Serialize
        ///////////////////////////////////////

        }else if(item.tid.GetName() == "ns3::UdpHeader") 
        { 
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            UdpHeader* udpHeader = dynamic_cast<UdpHeader*> (instance);
            NS_ASSERT(udpHeader != 0);
            udpHeader->Deserialize(item.current);
            /*      
            std::cout << "\n....UDP HEADER....\n"; 
            udpHeader->Print(std::cout);
            std::cout << "\n...................\n";
            */
            Buffer udpHeaderBuffer;
            udpHeaderBuffer.AddAtStart (udpHeader->GetSerializedSize());//8
            udpHeader->Serialize(udpHeaderBuffer.Begin ());

            // finished, clear the header
            headerContentSize += udpHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "udpHeader  size: " << udpHeader->GetSerializedSize());
            delete udpHeader; 

            uint8_t *udpBuffer = new uint8_t[udpHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = udpHeaderBuffer.Serialize(udpBuffer, udpHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "UDP Header Serialize result: " << serializeOutput << udpHeaderBuffer.GetSerializedSize() + 4);

            //SET HEADER SIZE
            m_udpHeaderSize = udpHeaderBuffer.GetSerializedSize() + 4;

            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(udpHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(udpBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after UdpHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = 17; 
            NS_LOG_FUNCTION (this << "UDP Header serialized" << counter);
      
            delete[] udpBuffer;

        ////////////////////////////////////////
        //  TCP Header Serialize
        ///////////////////////////////////////
 
        }else if(item.tid.GetName() == "ns3::TcpHeader") 
        { 
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            TcpHeader* tcpHeader = dynamic_cast<TcpHeader*> (instance);
            NS_ASSERT(tcpHeader != 0);
            tcpHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            tcpHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer tcpHeaderBuffer;
            tcpHeaderBuffer.AddAtStart (tcpHeader->GetSerializedSize());
            tcpHeader->Serialize(tcpHeaderBuffer.Begin ());
            
            // finished, clear the header
            headerContentSize += tcpHeader->GetSerializedSize();//tcpHeader->GetSerializedSize(); 
            NS_LOG_FUNCTION(this << "tcpHeader  size: " << tcpHeader->GetSerializedSize());
            delete tcpHeader;
 
            uint8_t *tcpBuffer = new uint8_t[tcpHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = tcpHeaderBuffer.Serialize(tcpBuffer, tcpHeaderBuffer.GetSerializedSize() + 4); 
            NS_LOG_FUNCTION(this << "TCP Header Serialize result: " << serializeOutput << tcpHeaderBuffer.GetSerializedSize() + 4);

            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
 

            //Create QKDDelimiterHeader which is used for dynamic header so we know where header starts and where header stops
            //Otherwise we do not know how to detect header for enrypted text
            QKDDelimiterHeader qkdDHeader;
            qkdDHeader.SetDelimiterSize ( tcpHeaderBuffer.GetSerializedSize() + 4 ); 

            std::vector<uint8_t> QKDDelimiterHeaderInVector = QKDDelimiterHeaderToVector(qkdDHeader);

            NS_LOG_FUNCTION(this << "Adding QKDDelimiterHeader of size" << QKDDelimiterHeaderInVector.size());
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<QKDDelimiterHeaderInVector.size(); a++)
                headerContentVector.push_back(QKDDelimiterHeaderInVector[a]);
            
            //FINALLY ADD TCP HEADER        
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(tcpHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(tcpBuffer[a]);
  
            NS_LOG_FUNCTION ("PLAINTEXT.size after TcpHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = 6; 
            NS_LOG_FUNCTION (this << "TCP Header serialized" << counter);

            delete[] tcpBuffer;
    
        ////////////////////////////////////////
        //  AODV Type Header Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::aodv::TypeHeader") 
        {  
              
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::aodv::TypeHeader* aodvPositionHeader = dynamic_cast<ns3::aodv::TypeHeader*> (instance);
            NS_ASSERT(aodvPositionHeader != 0);
            aodvPositionHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            aodvPositionHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer aodvHeaderBuffer;
            aodvHeaderBuffer.AddAtStart (aodvPositionHeader->GetSerializedSize()); 
            aodvPositionHeader->Serialize(aodvHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += aodvPositionHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "aodv type Header  size: " << aodvPositionHeader->GetSerializedSize());
            delete aodvPositionHeader; 

            uint8_t *aodvBuffer = new uint8_t[aodvHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = aodvHeaderBuffer.Serialize(aodvBuffer, aodvHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "AODV TypeHeader Serialize result: " << serializeOutput << aodvHeaderBuffer.GetSerializedSize() + 4);
 
            //SET HEADER SIZE
            m_aodvTypeHeaderSize = aodvHeaderBuffer.GetSerializedSize() + 4;
 
            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(aodvHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(aodvBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after aodv::TypeHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = AODV_TYPE_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "AODV TypeHeader serialized" << counter);

            delete[] aodvBuffer;

        ////////////////////////////////////////
        //  AODV Rrep Header Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::aodv::RrepHeader") 
        {  
              
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::aodv::RrepHeader* aodvPositionHeader = dynamic_cast<ns3::aodv::RrepHeader*> (instance);
            NS_ASSERT(aodvPositionHeader != 0);
            aodvPositionHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            aodvPositionHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer aodvHeaderBuffer;
            aodvHeaderBuffer.AddAtStart (aodvPositionHeader->GetSerializedSize()); 
            aodvPositionHeader->Serialize(aodvHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += aodvPositionHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "aodv RrepHeader  size: " << aodvPositionHeader->GetSerializedSize());
            delete aodvPositionHeader; 

            uint8_t *aodvBuffer = new uint8_t[aodvHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = aodvHeaderBuffer.Serialize(aodvBuffer, aodvHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "AODV RrepHeader Serialize result: " << serializeOutput << aodvHeaderBuffer.GetSerializedSize() + 4);
 
            //SET HEADER SIZE
            m_aodvRrepHeaderSize = aodvHeaderBuffer.GetSerializedSize() + 4;
 
            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(aodvHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(aodvBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after aodv::RrepHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = AODV_RREP_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "AODV RrepHeader serialized" << counter);

            delete[] aodvBuffer;
            
        ////////////////////////////////////////
        //  AODV Rreq Header Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::aodv::RreqHeader") 
        {  
              
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::aodv::RreqHeader* aodvPositionHeader = dynamic_cast<ns3::aodv::RreqHeader*> (instance);
            NS_ASSERT(aodvPositionHeader != 0);
            aodvPositionHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            aodvPositionHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer aodvHeaderBuffer;
            aodvHeaderBuffer.AddAtStart (aodvPositionHeader->GetSerializedSize()); 
            aodvPositionHeader->Serialize(aodvHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += aodvPositionHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "aodv RreqHeader  size: " << aodvPositionHeader->GetSerializedSize());
            delete aodvPositionHeader; 

            uint8_t *aodvBuffer = new uint8_t[aodvHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = aodvHeaderBuffer.Serialize(aodvBuffer, aodvHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "AODV RreqHeader Serialize result: " << serializeOutput << aodvHeaderBuffer.GetSerializedSize() + 4);
 
            //SET HEADER SIZE
            m_aodvRreqHeaderSize = aodvHeaderBuffer.GetSerializedSize() + 4;
 
            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(aodvHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(aodvBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after aodv::RreqHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = AODV_RREQ_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "AODV RreqHeader serialized" << counter);

            delete[] aodvBuffer;
            
        ////////////////////////////////////////
        //  AODV Rrep Ack Header Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::aodv::RrepAckHeader") 
        {  
              
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::aodv::RrepAckHeader* aodvPositionHeader = dynamic_cast<ns3::aodv::RrepAckHeader*> (instance);
            NS_ASSERT(aodvPositionHeader != 0);
            aodvPositionHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            aodvPositionHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer aodvHeaderBuffer;
            aodvHeaderBuffer.AddAtStart (aodvPositionHeader->GetSerializedSize()); 
            aodvPositionHeader->Serialize(aodvHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += aodvPositionHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "aodv RrepAckHeader  size: " << aodvPositionHeader->GetSerializedSize());
            delete aodvPositionHeader; 

            uint8_t *aodvBuffer = new uint8_t[aodvHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = aodvHeaderBuffer.Serialize(aodvBuffer, aodvHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "AODV RrepAckHeader Serialize result: " << serializeOutput << aodvHeaderBuffer.GetSerializedSize() + 4);
 
            //SET HEADER SIZE
            m_aodvRrepAckHeaderSize = aodvHeaderBuffer.GetSerializedSize() + 4;
 
            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(aodvHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(aodvBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after aodv::RrepAckHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = AODV_RREP_ACK_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "AODV RrepAckHeader serialized" << counter); 

            delete[] aodvBuffer;
            
        ////////////////////////////////////////
        //  AODV Rrerr Header Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::aodv::RerrHeader") 
        {  
              
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::aodv::RerrHeader* aodvPositionHeader = dynamic_cast<ns3::aodv::RerrHeader*> (instance);
            NS_ASSERT(aodvPositionHeader != 0);
            aodvPositionHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            aodvPositionHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer aodvHeaderBuffer;
            aodvHeaderBuffer.AddAtStart (aodvPositionHeader->GetSerializedSize()); 
            aodvPositionHeader->Serialize(aodvHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += aodvPositionHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "aodv RerrHeader  size: " << aodvPositionHeader->GetSerializedSize());
            delete aodvPositionHeader; 

            uint8_t *aodvBuffer = new uint8_t[aodvHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = aodvHeaderBuffer.Serialize(aodvBuffer, aodvHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "AODV RerrHeader Serialize result: " << serializeOutput << aodvHeaderBuffer.GetSerializedSize() + 4);
 
            //SET HEADER SIZE
            m_aodvRerrHeaderSize = aodvHeaderBuffer.GetSerializedSize() + 4;
 
            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(aodvHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(aodvBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after aodv::RerrHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = AODV_RERR_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "AODV RerrHeader serialized" << counter);

            delete[] aodvBuffer;
            
        ////////////////////////////////////////
        //  AODVQ Type Header Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::aodvq::TypeHeader") 
        {  
              
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::aodvq::TypeHeader* aodvqPositionHeader = dynamic_cast<ns3::aodvq::TypeHeader*> (instance);
            NS_ASSERT(aodvqPositionHeader != 0);
            aodvqPositionHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            aodvqPositionHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer aodvqHeaderBuffer;
            aodvqHeaderBuffer.AddAtStart (aodvqPositionHeader->GetSerializedSize()); 
            aodvqPositionHeader->Serialize(aodvqHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += aodvqPositionHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "aodvq type Header  size: " << aodvqPositionHeader->GetSerializedSize());
            delete aodvqPositionHeader; 

            uint8_t *aodvqBuffer = new uint8_t[aodvqHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = aodvqHeaderBuffer.Serialize(aodvqBuffer, aodvqHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "AODVQ TypeHeader Serialize result: " << serializeOutput << aodvqHeaderBuffer.GetSerializedSize() + 4);
 
            //SET HEADER SIZE
            m_aodvqTypeHeaderSize = aodvqHeaderBuffer.GetSerializedSize() + 4;
 
            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(aodvqHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(aodvqBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after aodvq::TypeHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = AODVQ_TYPE_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "AODVQ TypeHeader serialized" << counter);

            delete[] aodvqBuffer;
            
        ////////////////////////////////////////
        //  AODVQ Rrep Header Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::aodvq::RrepHeader") 
        {  
              
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::aodvq::RrepHeader* aodvqPositionHeader = dynamic_cast<ns3::aodvq::RrepHeader*> (instance);
            NS_ASSERT(aodvqPositionHeader != 0);
            aodvqPositionHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            aodvqPositionHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer aodvqHeaderBuffer;
            aodvqHeaderBuffer.AddAtStart (aodvqPositionHeader->GetSerializedSize()); 
            aodvqPositionHeader->Serialize(aodvqHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += aodvqPositionHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "aodvq RrepHeader  size: " << aodvqPositionHeader->GetSerializedSize());
            delete aodvqPositionHeader; 

            uint8_t *aodvqBuffer = new uint8_t[aodvqHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = aodvqHeaderBuffer.Serialize(aodvqBuffer, aodvqHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "AODVQ RrepHeader Serialize result: " << serializeOutput << aodvqHeaderBuffer.GetSerializedSize() + 4);
 
            //SET HEADER SIZE
            m_aodvqRrepHeaderSize = aodvqHeaderBuffer.GetSerializedSize() + 4;
 
            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(aodvqHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(aodvqBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after aodvq::RrepHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = AODVQ_RREP_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "AODVQ RrepHeader serialized" << counter);

            delete[] aodvqBuffer;

        ////////////////////////////////////////
        //  AODVQ Rreq Header Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::aodvq::RreqHeader") 
        {  
              
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::aodvq::RreqHeader* aodvqPositionHeader = dynamic_cast<ns3::aodvq::RreqHeader*> (instance);
            NS_ASSERT(aodvqPositionHeader != 0);
            aodvqPositionHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            aodvqPositionHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer aodvqHeaderBuffer;
            aodvqHeaderBuffer.AddAtStart (aodvqPositionHeader->GetSerializedSize()); 
            aodvqPositionHeader->Serialize(aodvqHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += aodvqPositionHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "aodvq RreqHeader  size: " << aodvqPositionHeader->GetSerializedSize());
            delete aodvqPositionHeader; 

            uint8_t *aodvqBuffer = new uint8_t[aodvqHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = aodvqHeaderBuffer.Serialize(aodvqBuffer, aodvqHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "AODVQ RreqHeader Serialize result: " << serializeOutput << aodvqHeaderBuffer.GetSerializedSize() + 4);
 
            //SET HEADER SIZE
            m_aodvqRreqHeaderSize = aodvqHeaderBuffer.GetSerializedSize() + 4;
 
            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(aodvqHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(aodvqBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after aodvq::RreqHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = AODVQ_RREQ_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "AODVQ RreqHeader serialized" << counter);

            delete[] aodvqBuffer;

        ////////////////////////////////////////
        //  AODVQ Rrep Ack Header Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::aodvq::RrepAckHeader") 
        {  
              
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::aodvq::RrepAckHeader* aodvqPositionHeader = dynamic_cast<ns3::aodvq::RrepAckHeader*> (instance);
            NS_ASSERT(aodvqPositionHeader != 0);
            aodvqPositionHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            aodvqPositionHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer aodvqHeaderBuffer;
            aodvqHeaderBuffer.AddAtStart (aodvqPositionHeader->GetSerializedSize()); 
            aodvqPositionHeader->Serialize(aodvqHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += aodvqPositionHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "aodvq RrepAckHeader  size: " << aodvqPositionHeader->GetSerializedSize());
            delete aodvqPositionHeader; 

            uint8_t *aodvqBuffer = new uint8_t[aodvqHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = aodvqHeaderBuffer.Serialize(aodvqBuffer, aodvqHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "AODVQ RrepAckHeader Serialize result: " << serializeOutput << aodvqHeaderBuffer.GetSerializedSize() + 4);
 
            //SET HEADER SIZE
            m_aodvqRrepAckHeaderSize = aodvqHeaderBuffer.GetSerializedSize() + 4;
 
            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(aodvqHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(aodvqBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after aodvq::RrepAckHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = AODVQ_RREP_ACK_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "AODVQ RrepAckHeader serialized" << counter); 

            delete[] aodvqBuffer;

        ////////////////////////////////////////
        //  AODVQ Rrerr Header Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::aodvq::RerrHeader") 
        {  
              
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::aodvq::RerrHeader* aodvqPositionHeader = dynamic_cast<ns3::aodvq::RerrHeader*> (instance);
            NS_ASSERT(aodvqPositionHeader != 0);
            aodvqPositionHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            aodvqPositionHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer aodvqHeaderBuffer;
            aodvqHeaderBuffer.AddAtStart (aodvqPositionHeader->GetSerializedSize()); 
            aodvqPositionHeader->Serialize(aodvqHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += aodvqPositionHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "aodvq RerrHeader  size: " << aodvqPositionHeader->GetSerializedSize());
            delete aodvqPositionHeader; 

            uint8_t *aodvqBuffer = new uint8_t[aodvqHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = aodvqHeaderBuffer.Serialize(aodvqBuffer, aodvqHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "AODVQ RerrHeader Serialize result: " << serializeOutput << aodvqHeaderBuffer.GetSerializedSize() + 4);
 
            //SET HEADER SIZE
            m_aodvqRerrHeaderSize = aodvqHeaderBuffer.GetSerializedSize() + 4;
 
            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(aodvqHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(aodvqBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after aodvq::RerrHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = AODVQ_RERR_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "AODVQ RerrHeader serialized" << counter);

            delete[] aodvqBuffer;
             
        ////////////////////////////////////////
        //  OLSR PacketHeader Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::olsr::PacketHeader") 
        {  

            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::olsr::PacketHeader* olsrPositionHeader = dynamic_cast<ns3::olsr::PacketHeader*> (instance);
            NS_ASSERT(olsrPositionHeader != 0);
            olsrPositionHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            olsrPositionHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer olsrHeaderBuffer;
            olsrHeaderBuffer.AddAtStart ( olsrPositionHeader->GetSerializedSize() ); 
            olsrPositionHeader->Serialize(olsrHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += olsrPositionHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "olsr PacketHeader size: " << olsrPositionHeader->GetSerializedSize());
            delete olsrPositionHeader; 

            uint8_t *olsrBuffer = new uint8_t[olsrHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = olsrHeaderBuffer.Serialize(olsrBuffer, olsrHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "olsr PacketHeader Serialize result: " << serializeOutput << olsrHeaderBuffer.GetSerializedSize() + 4);
            
            //SET HEADER SIZE
            m_olsrPacketHeaderSize = olsrHeaderBuffer.GetSerializedSize() + 4;

            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(olsrHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(olsrBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after olsr::PacketHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = OLSR_PACKET_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "olsr PacketHeader serialized" << counter);

            delete[] olsrBuffer;
            
        ////////////////////////////////////////
        //  OLSR MessageHeader Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::olsr::MessageHeader") 
        {  

            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::olsr::MessageHeader* olsrPositionHeader = dynamic_cast<ns3::olsr::MessageHeader*> (instance);
            NS_ASSERT(olsrPositionHeader != 0);
            olsrPositionHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            olsrPositionHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer olsrHeaderBuffer;
            olsrHeaderBuffer.AddAtStart ( olsrPositionHeader->GetSerializedSize() ); 
            olsrPositionHeader->Serialize(olsrHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += olsrPositionHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "olsr MessageHeader size: " << olsrPositionHeader->GetSerializedSize());
            NS_LOG_FUNCTION(this << "olsr MessageHeader type: " << olsrPositionHeader->GetMessageType());
            delete olsrPositionHeader; 

            uint8_t *olsrBuffer = new uint8_t[olsrHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = olsrHeaderBuffer.Serialize(olsrBuffer, olsrHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "olsr MessageHeader Serialize result: " << serializeOutput << olsrHeaderBuffer.GetSerializedSize() + 4);

            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);

            //Create QKDDelimiterHeader which is used for dynamic header so we know where header starts and where header stops
            //Otherwise we do not know how to detect header for enrypted text
            QKDDelimiterHeader qkdDHeader;
            qkdDHeader.SetDelimiterSize ( olsrHeaderBuffer.GetSerializedSize() + 4 ); 

            std::vector<uint8_t> QKDDelimiterHeaderInVector = QKDDelimiterHeaderToVector(qkdDHeader);

            NS_LOG_FUNCTION(this << "Adding QKDDelimiterHeader of size" << QKDDelimiterHeaderInVector.size());
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<QKDDelimiterHeaderInVector.size(); a++)
                headerContentVector.push_back(QKDDelimiterHeaderInVector[a]);
            
            //Finaly add OLSR vector
            //Add to headers vector which is going to be encrypted
            NS_LOG_FUNCTION(this << "Adding OLSR MessageHeader of size" << olsrHeaderBuffer.GetSerializedSize() + 4 );
            for(uint16_t a=0; a<(olsrHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(olsrBuffer[a]);
 
            NS_LOG_FUNCTION ("PLAINTEXT.size after olsr::MessageHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = OLSR_MESSAGE_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "olsr MessageHeader serialized" << counter);

            delete[] olsrBuffer;
            
        ////////////////////////////////////////
        //  DSDVQ Header Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::dsdvq::DsdvqHeader") 
        {  
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::dsdvq::DsdvqHeader* DsdvqHeader = dynamic_cast<ns3::dsdvq::DsdvqHeader*> (instance);
            NS_ASSERT(DsdvqHeader != 0);
            DsdvqHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            DsdvqHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer dsdvqHeaderBuffer; 
            dsdvqHeaderBuffer.AddAtStart (DsdvqHeader->GetSerializedSize());//8
            DsdvqHeader->Serialize(dsdvqHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += DsdvqHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "dsdvq Header  size: " << DsdvqHeader->GetSerializedSize());
            delete DsdvqHeader; 

            uint8_t *dsdvqBuffer = new uint8_t[dsdvqHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = dsdvqHeaderBuffer.Serialize(dsdvqBuffer, dsdvqHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "DSDVQ HelloHeader Serialize result: " << serializeOutput << dsdvqHeaderBuffer.GetSerializedSize() + 4);

            //SET HEADER SIZE
            m_dsdvqHeaderSize = dsdvqHeaderBuffer.GetSerializedSize() + 4;

            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(dsdvqHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(dsdvqBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after dsdvq::DsdvqHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = DSDVQ_PACKET_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "DSDVQ HelloHeader serialized" << counter);
        
            delete[] dsdvqBuffer;
                    ////////////////////////////////////////
        //  DSDV Header Serialize
        ///////////////////////////////////////
        }else if(item.tid.GetName() == "ns3::dsdv::DsdvHeader") 
        {  
            Callback<ObjectBase *> constr = item.tid.GetConstructor();
            NS_ASSERT(!constr.IsNull());
            
            // Ptr<> and DynamicCast<> won't work here as all headers are from ObjectBase, not Object
            ObjectBase *instance = constr();
            NS_ASSERT(instance != 0);
            
            ns3::dsdv::DsdvHeader* DsdvHeader = dynamic_cast<ns3::dsdv::DsdvHeader*> (instance);
            NS_ASSERT(DsdvHeader != 0);
            DsdvHeader->Deserialize(item.current);
            /*
            std::cout << "\n\n"; 
            DsdvHeader->Print(std::cout);
            std::cout << "\n\n";
            */
            Buffer dsdvHeaderBuffer; 
            dsdvHeaderBuffer.AddAtStart (DsdvHeader->GetSerializedSize());//8
            DsdvHeader->Serialize(dsdvHeaderBuffer.Begin ());
 
            // finished, clear the header
            headerContentSize += DsdvHeader->GetSerializedSize();
            NS_LOG_FUNCTION(this << "dsdv Header  size: " << DsdvHeader->GetSerializedSize());
            delete DsdvHeader; 

            uint8_t *dsdvBuffer = new uint8_t[dsdvHeaderBuffer.GetSerializedSize() + 4];
            uint32_t serializeOutput = dsdvHeaderBuffer.Serialize(dsdvBuffer, dsdvHeaderBuffer.GetSerializedSize() + 4);
            NS_LOG_FUNCTION(this << "DSDV HelloHeader Serialize result: " << serializeOutput << dsdvHeaderBuffer.GetSerializedSize() + 4);

            //SET HEADER SIZE
            m_dsdvHeaderSize = dsdvHeaderBuffer.GetSerializedSize() + 4;

            //check if serialized process was sucessful
            NS_ASSERT(serializeOutput != 0);
            
            //Add to headers vector which is going to be encrypted
            for(uint16_t a=0; a<(dsdvHeaderBuffer.GetSerializedSize() + 4); a++)
                headerContentVector.push_back(dsdvBuffer[a]);

            NS_LOG_FUNCTION ("PLAINTEXT.size after dsdv::DsdvHeader: " << headerContentVector.size() );
 
            if(counter == 0) firstNextHeader = DSDV_PACKET_HEADER_PROTOCOL_NUMBER;
            NS_LOG_FUNCTION (this << "DSDV HelloHeader serialized" << counter);

            delete[] dsdvBuffer;           
        
        }else {
            NS_LOG_FUNCTION ( this << item.tid.GetName() << item.tid.GetSize()  << counter );
            //EXIT HERE BECAUSE HEADER WAS NOT PROPERLY DETECTED!
            NS_ASSERT_MSG (1 == 0, "UNKNOWN HEADER RECEIVED!"); 
        }
        counter++;
    }

    uint32_t packetSize = p->GetSize(); 
    NS_LOG_FUNCTION(this << "HEADERS FETCHED!" << headerContentSize << packetSize);
 

    ////////////////////////////////////
    //  SERIALIZE REST OF THE PACKET (payload)
    ////////////////////////////////////
 
    if(headerContentSize - packetSize > 0){

        NS_LOG_FUNCTION(this << "ok, WE ARE READY now to add some payload" << headerContentSize << packetSize); 
        NS_LOG_FUNCTION(this << "Size of payload is: " << packetSize - headerContentSize);

        //Fetch data from the packet
        uint8_t *buffer = new uint8_t[packetSize];
        p->CopyData(buffer, packetSize);

        //and add it to vector to be encrypted    
        for(uint16_t a=headerContentSize; a<packetSize; a++)
            headerContentVector.push_back(buffer[a]);

        delete[] buffer;           
         
    } else 
        NS_LOG_FUNCTION(this << "There is NO data payload!");

    ///////////////////////////////////////////
    //  SERIALIZE QKDCOMMAND HEADER - goes on the end of the packet
    //////////////////////////////////////////

    NS_LOG_FUNCTION (this << "qkdCommandHeader is to be added" << qkdCommandHeader);

    /*
    std::cout << "\n......SENDING plain qkdCommandHeader....." << p->GetUid() << "..." << p->GetSize() << ".....\n";
    qkdCommandHeader.Print(std::cout);
    std::cout << "\n.............................\n"; 
    */

    // SERIALIZE QKDCOMMAND HEADER
    NS_LOG_FUNCTION (this << "qkdCommandHeader.GetCommand" << qkdCommandHeader.GetCommand () );
    NS_LOG_FUNCTION (this << "qkdCommandHeader.GetRoutingProtocolNumber" << (uint32_t) qkdCommandHeader.GetProtocol () );

    //if it is routing routing protocol message
    
    /*
    QKDCommandHeader points to IPv4 which points to TCP/UDP by default. 
    However, when there is GSPRQ header siting between IPv4 and TCP/UDP, 
    QKDCommandHeader has different values:

        value 4 : Header order is following and it is used by default: 
            QKDHeader, QKDCommandHeader, IPv4, TCP/UDP

        DSDVQ_HEADER_PROTOCOL_NUMBER : Header order is following: 
            QKDHeader, QKDCommandHeader, IPv4, DSDVQ

        DSDV_HEADER_PROTOCOL_NUMBER : Header order is following: 
            QKDHeader, QKDCommandHeader, IPv4, DSDV
    */

    QKDCommandTag qkdCommandTag;        

    if( p->PeekPacketTag(qkdCommandTag) && 
        (qkdCommandTag.GetCommand () == 'R' ||
            ( qkdCommandTag.GetRoutingProtocolNumber () == DSDV_PACKET_HEADER_PROTOCOL_NUMBER // DSDV
            || qkdCommandTag.GetRoutingProtocolNumber () == DSDVQ_PACKET_HEADER_PROTOCOL_NUMBER // DSDVQ
            )
        )
    ){
        NS_LOG_FUNCTION (this << "Need to fix QKDCommandHeader Protocol field to : " << qkdCommandTag.GetRoutingProtocolNumber ());
        
        /*
        std::cout << "\n......SENDING plain qkdCommandTag....." << p->GetUid() << "..." << p->GetSize() << ".....\n";
        qkdCommandTag.Print(std::cout);
        std::cout << "\n.............................\n"; 
        */

        qkdCommandHeader.SetProtocol(  static_cast<uint32_t> (qkdCommandTag.GetRoutingProtocolNumber ()) ); 
        p->RemovePacketTag(qkdCommandTag); 
        
        if(qkdCommandHeader.GetProtocol () == DSDV_PACKET_HEADER_PROTOCOL_NUMBER || qkdCommandHeader.GetProtocol () == DSDVQ_PACKET_HEADER_PROTOCOL_NUMBER)
            NS_ASSERT (qkdCommandHeader.GetCommand () == 'R' );
        
    }else{
        NS_LOG_FUNCTION (this << "PACKET WITHOUT QKDCOMMAND TAG RECEIVED!");
        qkdCommandHeader.SetProtocol( 4 ); //IPv4 by default
    }
    NS_LOG_FUNCTION (this << "qkdCommandHeader protocol:" << qkdCommandHeader.GetProtocol());

    Buffer qkdCommandHeaderBuffer;
    qkdCommandHeaderBuffer.AddAtStart (qkdCommandHeader.GetSerializedSize());
    qkdCommandHeader.Serialize(qkdCommandHeaderBuffer.Begin ());
 
    uint8_t *qkdcBuffer = new uint8_t[qkdCommandHeaderBuffer.GetSerializedSize() + 4];
    uint32_t serializeOutput = qkdCommandHeaderBuffer.Serialize(qkdcBuffer, qkdCommandHeaderBuffer.GetSerializedSize() + 4);
 
    //check if serialized process was sucessful
    NS_ASSERT(serializeOutput != 0);
    NS_LOG_FUNCTION(this << "QKDCommand Header Serialize result: " << serializeOutput << qkdCommandHeaderBuffer.GetSerializedSize() + 4);
    NS_LOG_FUNCTION(this << "QKDCommand Header size: " << qkdCommandHeaderBuffer.GetSerializedSize() );
    headerContentSize += qkdCommandHeaderBuffer.GetSerializedSize();
 
    //Add to headers vector which is going to be encrypted 
    for(uint16_t a=0; a<(qkdCommandHeaderBuffer.GetSerializedSize() + 4); a++)
        headerContentVector.push_back(qkdcBuffer[a]);

    delete[] qkdcBuffer;           
         
    NS_LOG_FUNCTION ("PLAINTEXT.size after QKDCommand: " << headerContentVector.size() );

    // QKDCOMMAND HEADER SERIALIZED

    NS_LOG_FUNCTION( this << "headerContentVector:" << headerContentVector.size() ); 
    return VectorToString(headerContentVector);
}

std::vector<Ptr<Packet> > 
QKDCrypto::CheckForFragmentation(Ptr<Packet> p, Ptr<QKDBuffer> QKDBuffer)
{   
    uint32_t channelID = 0;

    if(QKDBuffer != 0) 
        channelID = QKDBuffer->m_bufferID;

    NS_LOG_FUNCTION (this
        << "PacketID:"      << p->GetUid() 
        << "PacketSize:"    << p->GetSize()  
        << "channelID:"     << channelID
    );
    
    uint32_t packetSize = p->GetSize();   
    uint8_t *buffer = new uint8_t[packetSize];
    p->CopyData(buffer, packetSize);
    std::string cipherTextTotal = std::string((char*)buffer, packetSize); 
    NS_LOG_FUNCTION (this << "Whole PDU size of received packet:" << cipherTextTotal.size() );

    delete[] buffer;           
         
    //First check for cannelID and search for previously stored fragments in the cache memory
    std::map<uint32_t, std::string>::iterator a = m_cacheFlowValues.find (channelID);
    if (a == m_cacheFlowValues.end ()){
        std::string tempString;
        m_cacheFlowValues.insert( 
            std::make_pair(  channelID ,  tempString)
        ); 
        a = m_cacheFlowValues.find (channelID);
    } 

    if(a->second.size() > 0){
        NS_LOG_FUNCTION( this << "m_reassemblyCache is not empty, we need to add it to the packet!");
        NS_LOG_FUNCTION( this << "m_reassemblyCache size: " << a->second.size() );
        cipherTextTotal = a->second + cipherTextTotal;
        a->second.clear();
    }

    std::string wholePacketPayloadInString = cipherTextTotal; 
    NS_LOG_FUNCTION (this << "Whole PDU size of received packet + cache:" << wholePacketPayloadInString.size() );

    std::string qkdHeaderText = cipherTextTotal.substr (0, m_qkdHeaderSize );
    NS_LOG_FUNCTION (this << "Croping QKD HEADER! of size " << qkdHeaderText.size() );

    QKDHeader qkdHeader = StringToQKDHeader(qkdHeaderText);

    //Ok ommit first 48 bytes and create a new QKD packet with that content

    cipherTextTotal = cipherTextTotal.substr (m_qkdHeaderSize, cipherTextTotal.size() - m_qkdHeaderSize );
    Ptr<Packet> packetWithQKDHeader = Create<Packet> ((uint8_t*) cipherTextTotal.c_str(), cipherTextTotal.size());
    packetWithQKDHeader->AddHeader(qkdHeader);

    NS_LOG_INFO (this << "packetWithQKDHeader: " << packetWithQKDHeader);

    ///////////////////////////////////
    // Check for fragmentation
    //////////////////////////////////
    
    std::vector<Ptr<Packet> > packetOutput;
       
    uint32_t pointer = 0; 
    bool newQkdHeaderNeeded = false;
    uint32_t cipherTextLength = cipherTextTotal.size();
    Ptr<Packet> tempPacket;

    while(pointer < cipherTextTotal.size()){
 
        NS_LOG_FUNCTION(this << "$$$$$$$$ POINTER ON LOCATION:" << pointer <<  cipherTextTotal.size());

        //if we have less then 48 bytes (highly unlikely)
        if(newQkdHeaderNeeded && cipherTextTotal.size() - pointer <= m_qkdHeaderSize){
            NS_LOG_FUNCTION(this << "we have less then 48 bytes of the packet" << cipherTextTotal.size() );
            a->second += cipherTextTotal.substr (pointer, cipherTextTotal.size() - pointer);
            break;
        } 

        NS_LOG_FUNCTION (this << "Do we need new QKD HEADER:" << newQkdHeaderNeeded);
        QKDHeader qkdHeaderTemp;
        if(newQkdHeaderNeeded){

            //detech qkd header first
            NS_LOG_FUNCTION( this << "Detach QKD header first from pointer:" << pointer );
            std::string tempQKDHeaderText = cipherTextTotal.substr (pointer, m_qkdHeaderSize);

            qkdHeaderTemp = StringToQKDHeader(tempQKDHeaderText);
            pointer += m_qkdHeaderSize;
            NS_LOG_FUNCTION(this << "Pointer:" << pointer);

        }else{
            qkdHeaderTemp = qkdHeader;
            NS_LOG_FUNCTION(this << "qkdHeaderTemp:" << qkdHeaderTemp);
        }

        /*
        *   First check whether we have whole packet or we just received a small fragment. 
        *   If we have a fragment, than we need to wait to obtain full packet and perform decryption. 
        */
        if( cipherTextLength - pointer >= qkdHeaderTemp.GetLength() - m_qkdHeaderSize ){

            NS_LOG_FUNCTION (this << "We have enough material to decrypt the packet!" );

            //we have enough information to decrypt the packet
            std::string tempPacketPayload = cipherTextTotal.substr (pointer, qkdHeaderTemp.GetLength() - m_qkdHeaderSize); 
            tempPacket = Create<Packet> ((uint8_t*) tempPacketPayload.c_str(), tempPacketPayload.size()); 

            NS_LOG_FUNCTION (this << "Whole PDU of the decrypted packet is:" << tempPacketPayload.size() );

            pointer += qkdHeaderTemp.GetLength() - m_qkdHeaderSize;
            NS_LOG_FUNCTION(this << "Pointer:" << pointer);

            tempPacket->AddHeader(qkdHeaderTemp);
            packetOutput.push_back(tempPacket);
            newQkdHeaderNeeded = true;

            NS_LOG_FUNCTION (this 
                << "New packet created!" 
                << tempPacket->GetUid() 
                << " of size " 
                << tempPacket->GetSize() 
            );
            NS_LOG_FUNCTION (this 
                << "UNUSED MATERIAL:" 
                << cipherTextLength - pointer
                << "channelID:"
                << channelID
            ); 
            tempPacket = 0;

        }else{

            NS_LOG_FUNCTION (this << "We do *NOT* have enough material to decrypt the packet! Please wait for it!" );
            NS_LOG_FUNCTION(this << "m_reassemblyCache size: " << a->second.size()  );

            if(pointer == 0){
                NS_LOG_FUNCTION (this << "ADDING TO CACHE - POINTER is " << pointer);
                a->second += wholePacketPayloadInString;
                NS_LOG_FUNCTION(this << "Adding to m_reassemblyCache the rest of the content of size: " << wholePacketPayloadInString.size() );
            }else{
                NS_LOG_FUNCTION (this << "ADDING TO CACHE - POINTER is " << pointer);

                uint32_t cacheFrom = pointer - m_qkdHeaderSize;
                uint32_t cacheLength = wholePacketPayloadInString.size() - cacheFrom;

                NS_LOG_FUNCTION (this  
                    << "Cropping from " << cacheFrom
                    << " by size " << cacheLength
                    << " and adding to cache!"
                );

                std::string restOfContent = cipherTextTotal.substr (
                    cacheFrom,
                    cacheLength
                );

                NS_LOG_FUNCTION(this << "Adding to m_reassemblyCache the rest of the content of size: " << restOfContent.size() );
                a->second += restOfContent;
                NS_LOG_FUNCTION (this << HexEncode(restOfContent) );
            }

            NS_LOG_FUNCTION(this << "m_reassemblyCache size: " << a->second.size() );
            break;
        }
    }

    NS_LOG_FUNCTION(this 
        << "REASSEMBLY COMPLETED with " << packetOutput.size() << " packets "
        << "m_reassemblyCache size: " << a->second.size()
        << "channelID:"
        << channelID
    );


    NS_LOG_FUNCTION(this 
        << "CacheID:"
        << a->first
        << "CacheValue:"
        << a->second.size()
        << "ChannelID:"
        << channelID
    );

    return packetOutput;
 }

std::vector<Ptr<Packet> >
QKDCrypto::ProcessIncomingPacket (
    Ptr<Packet>             p, 
    Ptr<QKDBuffer>          QKDBuffer,
    uint32_t                channelID
)
{
    NS_LOG_FUNCTION (this << "PacketID:" 
        << p->GetUid() 
        << "PacketSize:" 
        << p->GetSize()
        << QKDBuffer
        << "ChannelID:"
        << channelID
    );

    std::vector<Ptr<Packet> > packetOutput = CheckForFragmentation(
        p, 
        QKDBuffer
    );

    // Iterate over appended elements
    for(uint32_t i = 0; i < packetOutput.size(); i++)
    {  
        packetOutput[i] = Decrypt(packetOutput[i], QKDBuffer);
        NS_LOG_FUNCTION(this << "Decrytion completed!" << packetOutput[i]);
    }
    return packetOutput;
}

Ptr<Packet>
QKDCrypto::Decrypt (Ptr<Packet> p, Ptr<QKDBuffer> QKDbuffer) 
{  
    NS_LOG_FUNCTION  ( this << p->GetUid() << p->GetSize() );

    /*
    std::cout << "\n ..................RECEIVED encrpyted............" << p->GetUid() << " ...." << p->GetSize() << " \n";
    p->Print(std::cout);                
    std::cout << "\n ................................................  \n";
    */

    //Before decryption we need to remove the QKDheader
    QKDHeader qkdHeader;

    //If no QKDheader is found, then just return the packet since the packet probabily is not encrpyted!
    p->PeekHeader (qkdHeader);
    if(!qkdHeader.IsValid () ){
        NS_LOG_FUNCTION(this << "UNKNOWN packet received!");
        return p;
    }

    NS_LOG_FUNCTION(this << qkdHeader);
    if (qkdHeader.GetAuthenticated() > 1) {
 
        Ptr<QKDKey> key;
        //KEY IS NEEDED ONLY FOR VMAC
        if(qkdHeader.GetAuthenticated() == QKDCRYPTO_AUTH_VMAC){
            
            if(QKDbuffer != 0) 
                key = QKDbuffer->ProcessIncomingRequest ( qkdHeader.GetAuthenticationKeyId(), m_authenticationTagLengthInBits ); //in bits

            if(key == 0){
                NS_LOG_FUNCTION(this << "UNKNOWN AuthenticationKey ID!");
                NS_LOG_WARN ("NO ENOUGH KEY IN THE BUFFER! BUFFER IS EMPTY! ABORT ENCRYPTION and AUTHENTICATION PROCESS");
                return 0;
            }
        } else
            key = 0;

        Ptr<Packet> pTemp = CheckAuthentication(p, key, qkdHeader.GetAuthenticated() );
        if(pTemp == 0){
            NS_LOG_FUNCTION(this << "Authentication tag is not valid!");
            return 0;return p;   
        }
    }
    p->RemoveHeader (qkdHeader); 
 
    uint32_t packetSize = p->GetSize();  
    //Now fetch the content of the packet
    uint8_t *buffer = new uint8_t[packetSize];
    p->CopyData(buffer, packetSize);  

    std::string cipherText = std::string((char*)buffer, packetSize);
    std::string plainText;

    delete[] buffer;

    ////////////////////////////////////
    //  START DECRYPTION
    //////////////////////////////////// 
    
    if (qkdHeader.GetEncrypted() > 0){
        NS_ASSERT (qkdHeader.GetEncrypted() > 0);

        Ptr<QKDKey> key;
        switch (qkdHeader.GetEncrypted())
        {
            case QKDCRYPTO_OTP: 

                if(QKDbuffer != 0) 
                    key = QKDbuffer->ProcessIncomingRequest ( qkdHeader.GetEncryptionKeyId(), cipherText.size() * 8 );  //in bits

                if(key == 0){
                    NS_LOG_FUNCTION ("NO KEY PROVIDED!");
                    NS_LOG_WARN ("NO ENOUGH KEY IN THE BUFFER! BUFFER IS EMPTY! ABORT ENCRYPTION and AUTHENTICATION PROCESS");
                    return 0;
                }else{
                    plainText = OTP ( cipherText, key );
                }
                break;

            case QKDCRYPTO_AES: 
                
                if(QKDbuffer != 0) 
                    key = QKDbuffer->ProcessIncomingRequest ( qkdHeader.GetEncryptionKeyId(), CryptoPP::AES::MAX_KEYLENGTH ); // in bits

                if(key == 0){
                    NS_LOG_FUNCTION ("NO KEY PROVIDED!");
                    NS_LOG_WARN ("NO ENOUGH KEY IN THE BUFFER! BUFFER IS EMPTY! ABORT ENCRYPTION and AUTHENTICATION PROCESS");
                    return 0;
                }else{
                    plainText = AESDecrypt ( cipherText, key );
                }
                break;
        }
    }else{
        NS_LOG_FUNCTION(this << "Unencrypted packet received!"); 
        plainText = cipherText;
    }
    NS_LOG_FUNCTION ("DECRYPTED PLAINTEXT.size: " << plainText.size() );

    // DECOMPRESS PACKET 
    if(qkdHeader.GetZipped () == 1){
        plainText = StringDecompressDecode (plainText); 
    }

    if ( plainText.size() <= m_ipv4HeaderSize){
       NS_FATAL_ERROR ("The plain text contains less then m_ipv4HeaderSize(36) chars! This should not happen, problem with fragmentation!");
       NS_LOG_FUNCTION (this << plainText);
    }

    std::string ipHeaderPlainText = plainText.substr (0, m_ipv4HeaderSize);
    plainText = plainText.substr(m_ipv4HeaderSize, plainText.size() - m_ipv4HeaderSize);
    NS_LOG_FUNCTION(this << "Decryption of IPv4 Header completed!" << ipHeaderPlainText.size());
    NS_LOG_FUNCTION ("DECRYPTED PLAINTEXT.size after IPv4: " << plainText.size() );

    /////////////////////////////
    // DECRYPT IP HEADER 
    /////////////////////////////
 
    const uint8_t* ipBuffer = reinterpret_cast<const uint8_t*>(ipHeaderPlainText.c_str()); 

    Buffer ipHeaderBuffer;
    ipHeaderBuffer.Deserialize(ipBuffer, m_ipv4HeaderSize); 
    //delete[] ipBuffer;

    Ipv4Header ipv4Header;
    ipv4Header.Deserialize(ipHeaderBuffer.Begin ());

    NS_LOG_FUNCTION(this << "IPv4 Header decrypted");
    NS_LOG_FUNCTION(this << "Ipv4 original protocol:" << static_cast<uint32_t> (ipv4Header.GetProtocol()) ); 

    ///////////////////////////////////
    // FETCH HEADERS FROM DECRYPTED TEXT
    //////////////////////////////////
    NS_LOG_FUNCTION(this << "Fetching headers start!" << p->GetUid() );

    uint32_t counter = 0;
    std::vector<uint32_t> protocols; 

    //First remove QKDCommandHeader 
    NS_LOG_FUNCTION(this << "QKDCommand Header detected!");

    std::string qkdCHeaderText = plainText.substr (plainText.size()-20, 20);
    plainText = plainText.substr (0, plainText.size()-20);
    packetSize = plainText.size();
    const uint8_t* qkdcBuffer = reinterpret_cast<const uint8_t*>(qkdCHeaderText.c_str()); 
    NS_LOG_FUNCTION ("DECRYPTED PLAINTEXT.size after IPv4 and qkdCommandHeader: " << plainText.size() );

    //Create QKDCBuffer
    Buffer qkdcHeaderBuffer;
    qkdcHeaderBuffer.Deserialize(qkdcBuffer, 20);
    //delete[] qkdcBuffer;

    //Fetch QKDCHeader
    QKDCommandHeader qkdCommandHeader;
    qkdCommandHeader.Deserialize(qkdcHeaderBuffer.Begin ());

    NS_LOG_FUNCTION (this << "qkdCommandHeader Deserialized" << qkdCommandHeader);
     
    /*
    std::cout << "\n ..................QKDCommand decrypted............" << p->GetUid() << " ...." << p->GetSize() << " \n";
    qkdCommandHeader.Print(std::cout);                
    std::cout << "\n ................................................  \n";
    */

    /*
    QKDCommandHeader points to IPv4 which points to TCP/UDP by default. 
    However, when there is GSPRQ header siting between IPv4 and TCP/UDP, 
    QKDCommandHeader has different values:
        4 - Header order is following: 
            QKDHeader, QKDCommandHeader, IPv4, TCP/UDP 
        DSDVQ_HEADER_PROTOCOL_NUMBER - Header order is following: 
            QKDHeader, QKDCommandHeader, IPv4, DSDVQ
        DSDV_HEADER_PROTOCOL_NUMBER - Header order is following: 
            QKDHeader, QKDCommandHeader, IPv4, DSDV
    */        
    NS_LOG_FUNCTION (this << "qkdCommandHeader Protocol Value" << qkdCommandHeader.GetProtocol() );

    bool allowIPv4ToPushHeaderInProtocolChain = true;
    if(qkdCommandHeader.GetProtocol () == 4){ 
        protocols.push_back(qkdCommandHeader.GetProtocol());
    }else{ 
        protocols.push_back(4); //ADD Ipv4 by default 
 
        //////////////////////
        // OLSR
        /////////////////////

        //OLSR_PACKET_HEADER_PROTOCOL_NUMBER
        if(qkdCommandHeader.GetProtocol() == OLSR_PACKET_HEADER_PROTOCOL_NUMBER){//147

            NS_LOG_FUNCTION (this << "IT IS OLSR_PACKET_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );

            protocols.push_back( OLSR_MESSAGE_HEADER_PROTOCOL_NUMBER );
            NS_LOG_FUNCTION(this << "NextHeader" <<  OLSR_MESSAGE_HEADER_PROTOCOL_NUMBER );
        
        //OLSR_MESSAGE_HEADER_PROTOCOL_NUMBER
        }else if(qkdCommandHeader.GetProtocol() == OLSR_MESSAGE_HEADER_PROTOCOL_NUMBER){//147

            NS_LOG_FUNCTION (this << "IT IS OLSR_MESSAGE_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );
 
        //////////////////////
        // DSDVQ
        /////////////////////

        }else if(qkdCommandHeader.GetProtocol() == DSDVQ_PACKET_HEADER_PROTOCOL_NUMBER){//147

            NS_LOG_FUNCTION (this << "IT IS DSDVQ_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );
 
        //////////////////////
        // DSDV
        /////////////////////

        }else if(qkdCommandHeader.GetProtocol() == DSDV_PACKET_HEADER_PROTOCOL_NUMBER){//147

            NS_LOG_FUNCTION (this << "IT IS DSDV_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );

        //////////////////////
        // AODV
        /////////////////////      

        }else if(qkdCommandHeader.GetProtocol() == AODV_TYPE_HEADER_PROTOCOL_NUMBER){//41

            NS_LOG_FUNCTION (this << "IT IS AODV_TYPE_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );

        }else if(qkdCommandHeader.GetProtocol() == AODV_RREQ_HEADER_PROTOCOL_NUMBER){//42

            NS_LOG_FUNCTION (this << "IT IS AODV_RREQ_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(AODV_TYPE_HEADER_PROTOCOL_NUMBER); //41
            NS_LOG_FUNCTION(this << "NextHeader" << AODV_TYPE_HEADER_PROTOCOL_NUMBER);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );

        }else if(qkdCommandHeader.GetProtocol() == AODV_RREP_HEADER_PROTOCOL_NUMBER){//43

            NS_LOG_FUNCTION (this << "IT IS AODV_RREP_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(AODV_TYPE_HEADER_PROTOCOL_NUMBER); //41
            NS_LOG_FUNCTION(this << "NextHeader" << AODV_TYPE_HEADER_PROTOCOL_NUMBER);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );

        }else if(qkdCommandHeader.GetProtocol() == AODV_RREP_ACK_HEADER_PROTOCOL_NUMBER){//44

            NS_LOG_FUNCTION (this << "IT IS AODV_RREP_ACK_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(AODV_TYPE_HEADER_PROTOCOL_NUMBER); //41
            NS_LOG_FUNCTION(this << "NextHeader" << AODV_TYPE_HEADER_PROTOCOL_NUMBER);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );

        }else if(qkdCommandHeader.GetProtocol() == AODV_RERR_HEADER_PROTOCOL_NUMBER){//45

            NS_LOG_FUNCTION (this << "IT IS AODV_RERR_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(AODV_TYPE_HEADER_PROTOCOL_NUMBER); //41
            NS_LOG_FUNCTION(this << "NextHeader" << AODV_TYPE_HEADER_PROTOCOL_NUMBER);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );
 
        //////////////////////
        // AODVQ
        /////////////////////      

        }else if(qkdCommandHeader.GetProtocol() == AODVQ_TYPE_HEADER_PROTOCOL_NUMBER){//41

            NS_LOG_FUNCTION (this << "IT IS AODVQ_TYPE_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );

        }else if(qkdCommandHeader.GetProtocol() == AODVQ_RREQ_HEADER_PROTOCOL_NUMBER){//42

            NS_LOG_FUNCTION (this << "IT IS AODVQ_RREQ_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(AODVQ_TYPE_HEADER_PROTOCOL_NUMBER); //41
            NS_LOG_FUNCTION(this << "NextHeader" << AODVQ_TYPE_HEADER_PROTOCOL_NUMBER);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );

        }else if(qkdCommandHeader.GetProtocol() == AODVQ_RREP_HEADER_PROTOCOL_NUMBER){//43

            NS_LOG_FUNCTION (this << "IT IS AODVQ_RREP_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(AODVQ_TYPE_HEADER_PROTOCOL_NUMBER); //41
            NS_LOG_FUNCTION(this << "NextHeader" << AODVQ_TYPE_HEADER_PROTOCOL_NUMBER);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );

        }else if(qkdCommandHeader.GetProtocol() == AODVQ_RREP_ACK_HEADER_PROTOCOL_NUMBER){//44

            NS_LOG_FUNCTION (this << "IT IS AODVQ_RREP_ACK_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(AODVQ_TYPE_HEADER_PROTOCOL_NUMBER); //41
            NS_LOG_FUNCTION(this << "NextHeader" << AODVQ_TYPE_HEADER_PROTOCOL_NUMBER);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );

        }else if(qkdCommandHeader.GetProtocol() == AODVQ_RERR_HEADER_PROTOCOL_NUMBER){//45

            NS_LOG_FUNCTION (this << "IT IS AODVQ_RERR_HEADER_PROTOCOL_NUMBER"); 
            allowIPv4ToPushHeaderInProtocolChain = false;

            protocols.push_back(17); //UDP
            NS_LOG_FUNCTION(this << "NextHeader" << 17);

            protocols.push_back(AODVQ_TYPE_HEADER_PROTOCOL_NUMBER); //41
            NS_LOG_FUNCTION(this << "NextHeader" << AODVQ_TYPE_HEADER_PROTOCOL_NUMBER);

            protocols.push_back(static_cast<uint32_t> (qkdCommandHeader.GetProtocol()));
            NS_LOG_FUNCTION(this << "NextHeader" <<  static_cast<uint32_t> (qkdCommandHeader.GetProtocol()) );

        //////////////////////
        // ICMPv4
        /////////////////////      

        }else if(qkdCommandHeader.GetProtocol() == 4 && ipv4Header.GetProtocol() == 1){

            NS_LOG_FUNCTION (this << "IT IS Icmpv4"); 
            allowIPv4ToPushHeaderInProtocolChain = false;
 
            protocols.push_back(1); //1
            NS_LOG_FUNCTION(this << "NextHeader" << 1); 

        }  
        //protocols.push_back(qkdCommandHeader.GetProtocol());        
    } 

    //Decrease packetSize calculation  
    NS_LOG_FUNCTION(this << "QKDCommand Header decrypted" << qkdcHeaderBuffer.GetSerializedSize() + 4 << packetSize);

    //PLAIN HEADERS - to be used in the loop 

    //UDP
    UdpHeader udpHeader;

    //TCP
    TcpHeader tcpHeader;

    //DSDV
    std::vector<ns3::dsdv::DsdvHeader> dsdvHeaders;

    //DSDVQ
    std::vector<ns3::dsdvq::DsdvqHeader> dsdvqHeaders;

    //OLSR
    ns3::olsr::PacketHeader olsrPacketHeader; 
    std::vector<ns3::olsr::MessageHeader> olsrMessageHeaders;
 
    //AODV
    ns3::aodv::TypeHeader aodvTypeHeader;
    ns3::aodv::RreqHeader aodvRreqHeader;
    ns3::aodv::RrepHeader aodvRrepHeader;
    ns3::aodv::RrepAckHeader aodvRrepAckHeader;
    ns3::aodv::RerrHeader aodvRerrHeader;

    //AODVQ
    ns3::aodvq::TypeHeader aodvqTypeHeader;
    ns3::aodvq::RreqHeader aodvqRreqHeader;
    ns3::aodvq::RrepHeader aodvqRrepHeader;
    ns3::aodvq::RrepAckHeader aodvqRrepAckHeader;
    ns3::aodvq::RerrHeader aodvqRerrHeader;

    //ICMPv4
    ns3::Icmpv4Header Icmpv4Header;
    ns3::Icmpv4Echo Icmpv4EchoHeader;
    ns3::Icmpv4DestinationUnreachable Icmpv4DestinationUnreachableHeader;
    ns3::Icmpv4TimeExceeded Icmpv4TimeExceededHeader;

      
    //-------------- END OF PLAIN HEADERS

    // Iterate over appended elements
    uint32_t i = 0;  
    while(i < protocols.size())
    {  
        NS_LOG_FUNCTION (this << "--------");
        NS_LOG_FUNCTION(this << "Detection started!" 
            << "Protocol: " << protocols[i] 
            << "Counter: "  << counter  
        );

        ///////////////////////////////////////
        //  IPv4
        //////////////////////////////////////

        if(protocols[i] == 4){

            NS_LOG_FUNCTION(this << "IPv4 Header detected!" << counter);
            NS_LOG_FUNCTION (this << "NextHeader value: " << (uint32_t) ipv4Header.GetProtocol() );

            if(allowIPv4ToPushHeaderInProtocolChain)
            protocols.push_back(static_cast<uint32_t> (ipv4Header.GetProtocol()));
             
            NS_LOG_FUNCTION(this << "Ipv4 original protocol:" << static_cast<uint32_t> (ipv4Header.GetProtocol()) ); 
            NS_LOG_FUNCTION(this << "IPv4 Header decrypted");
            /*
            std::cout << "\n ...........ipv4 header decrypted...........\n";
            ipv4Header.Print(std::cout);                
            std::cout << "\n............................................\n";
            */      


        ///////////////////////////////////////
        //  ICMPv4 Header
        //////////////////////////////////////

        }else if(protocols[i] == 1){

            NS_LOG_FUNCTION(this << "ICMPv4 Header detected!" << counter);
 
            std::string icmpv4HeaderText = plainText.substr (counter,counter + m_icmpv4HeaderSize);
            const uint8_t* icmpv4Buffer = reinterpret_cast<const uint8_t*>(icmpv4HeaderText.c_str());

            Buffer icmpv4HeaderBuffer;
            icmpv4HeaderBuffer.Deserialize(icmpv4Buffer, m_icmpv4HeaderSize);  

            Icmpv4Header.Deserialize(icmpv4HeaderBuffer.Begin ()); 
 
            counter += m_icmpv4HeaderSize;

            NS_LOG_FUNCTION(this << "ICMPv4 Header decrypted");
            NS_LOG_FUNCTION(this << "ICMPv4 Header;Type value:" << (uint32_t) Icmpv4Header.GetType() );
            /*
            std::cout << "\n";
            icmpv4TypePosHeader.Print(std::cout);                
            std::cout << "\n";
            */

            protocols.push_back(static_cast<uint32_t> (Icmpv4Header.GetType()));
            //delete[] icmpv4Buffer;
 
        }else if(protocols[i] == Icmpv4Header::ICMPV4_ECHO || protocols[i] == Icmpv4Header::ICMPV4_ECHO_REPLY){// || ECHO_REPLY

            NS_LOG_FUNCTION(this << "ICMPv4 ECHO detected!" << counter);
 
            std::string icmpv4HeaderText = plainText.substr (counter,counter + m_icmpv4EchoHeaderSize);
            const uint8_t* icmpv4Buffer = reinterpret_cast<const uint8_t*>(icmpv4HeaderText.c_str());

            Buffer icmpv4HeaderBuffer;
            icmpv4HeaderBuffer.Deserialize(icmpv4Buffer, m_icmpv4EchoHeaderSize);  

            Icmpv4EchoHeader.Deserialize(icmpv4HeaderBuffer.Begin ()); 
 
            counter += m_icmpv4EchoHeaderSize;

            /*
            std::cout << "\n";
            Icmpv4EchoHeader.Print(std::cout);                
            std::cout << "\n";
            */

            NS_LOG_FUNCTION(this << "ICMPv4 ECHO decrypted"); 
            //delete[] icmpv4Buffer;

        }else if(protocols[i] == Icmpv4Header::ICMPV4_DEST_UNREACH){

            NS_LOG_FUNCTION(this << "ICMPv4 DEST_UNREACH detected!" << counter);
 
            std::string icmpv4HeaderText = plainText.substr (counter,counter + m_icmpv4DestinationUnreachableHeaderSize);
            const uint8_t* icmpv4Buffer = reinterpret_cast<const uint8_t*>(icmpv4HeaderText.c_str());

            Buffer icmpv4HeaderBuffer;
            icmpv4HeaderBuffer.Deserialize(icmpv4Buffer, m_icmpv4DestinationUnreachableHeaderSize);  

            Icmpv4DestinationUnreachableHeader.Deserialize(icmpv4HeaderBuffer.Begin ()); 
 
            counter += m_icmpv4DestinationUnreachableHeaderSize;

            NS_LOG_FUNCTION(this << "ICMPv4 DEST_UNREACH decrypted"); 
            /*
            std::cout << "\n";
            Icmpv4DestinationUnreachableHeader.Print(std::cout);                
            std::cout << "\n";
            */
            //delete[] icmpv4Buffer;

        }else if(protocols[i] == Icmpv4Header::ICMPV4_TIME_EXCEEDED){

            NS_LOG_FUNCTION(this << "ICMPv4 TIME_EXCEEDED detected!" << counter);
 
            std::string icmpv4HeaderText = plainText.substr (counter,counter + m_icmpv4TimeExceededHeaderSize);
            const uint8_t* icmpv4Buffer = reinterpret_cast<const uint8_t*>(icmpv4HeaderText.c_str());

            Buffer icmpv4HeaderBuffer;
            icmpv4HeaderBuffer.Deserialize(icmpv4Buffer, m_icmpv4TimeExceededHeaderSize);  

            Icmpv4TimeExceededHeader.Deserialize(icmpv4HeaderBuffer.Begin ()); 
 
            counter += m_icmpv4TimeExceededHeaderSize;

            NS_LOG_FUNCTION(this << "ICMPv4 TIME_EXCEEDED decrypted"); 
            /*
            std::cout << "\n";
            Icmpv4TimeExceededHeader.Print(std::cout);                
            std::cout << "\n";
            */
            //delete[] icmpv4Buffer;

        ///////////////////////////////////////
        //  UDP
        //////////////////////////////////////

        } else if(protocols[i] == 17){

            NS_LOG_FUNCTION(this << "UDP Header detected!" << counter);

            std::string udpHeaderText = plainText.substr (counter,counter + m_udpHeaderSize);
            const uint8_t* udpBuffer = reinterpret_cast<const uint8_t*>(udpHeaderText.c_str()); 

            Buffer udpHeaderBuffer;
            udpHeaderBuffer.Deserialize(udpBuffer, m_udpHeaderSize);  

            udpHeader.Deserialize(udpHeaderBuffer.Begin ());  
 
            counter += m_udpHeaderSize;

            NS_LOG_FUNCTION(this << "UDP Header decrypted");
            /*
            std::cout << "\n";
            udpHeader.Print(std::cout);                
            std::cout << "\n";
            */
            //delete[] udpBuffer;

        ///////////////////////////////////////
        //  TCP
        //////////////////////////////////////

        } else if(protocols[i] == 6){ 

            //FIRST WE NEED TO FIGURE OUT THE LENGTH OF THIS HEADER
            //Therefore, we crop the QKDDelimiterHeader and read the length of TCP Header

            std::string temp = plainText.substr(counter, m_qkdDHeaderSize); 
            QKDDelimiterHeader qkdDHeader = StringToQKDDelimiterHeader (temp);
            counter += m_qkdDHeaderSize;

            NS_LOG_FUNCTION (this << "TCP size should be " << qkdDHeader.GetDelimiterSize());
 
            std::string tcpHeaderText = plainText.substr(counter, qkdDHeader.GetDelimiterSize());  
            uint32_t tcpheaderSize = tcpHeaderText.size();

            NS_LOG_FUNCTION(this << "TCP Header detected!" << tcpheaderSize );

            const uint8_t* tcpBuffer = reinterpret_cast<const uint8_t*>(tcpHeaderText.c_str()); 

            Buffer tcpHeaderBuffer; 
            tcpHeaderBuffer.Deserialize(tcpBuffer, tcpheaderSize); 

            tcpHeader.Deserialize(tcpHeaderBuffer.Begin ()); 
            counter+=tcpheaderSize;

            NS_LOG_FUNCTION(this << "TCP Header decrypted" << tcpheaderSize);
            /*
            std::cout << "\n";
            tcpHeader.Print(std::cout);                
            std::cout << "\n";
            */ 
            //delete[] tcpBuffer;
         
        ///////////////////////////////////////
        //  DSDVQ
        //////////////////////////////////////

        } else if(protocols[i] == DSDVQ_PACKET_HEADER_PROTOCOL_NUMBER){ 
  
            NS_LOG_FUNCTION(this << "DSDVQ Header detected!" << counter);
 
            std::string dsdvqHeaderText = plainText.substr (counter,counter + m_dsdvqHeaderSize);
            const uint8_t* dsdvqBuffer = reinterpret_cast<const uint8_t*>(dsdvqHeaderText.c_str()); 

            NS_ASSERT(dsdvqHeaderText.size() >= m_dsdvqHeaderSize);
            
            Buffer dsdvqHeaderBuffer;
            dsdvqHeaderBuffer.Deserialize(dsdvqBuffer, m_dsdvqHeaderSize);

            ns3::dsdvq::DsdvqHeader dsdvqHeader;
            dsdvqHeader.Deserialize(dsdvqHeaderBuffer.Begin ());  
            dsdvqHeaders.push_back(dsdvqHeader);
 
            counter += m_dsdvqHeaderSize;
            uint32_t restOfPacket = plainText.size() - counter;

            NS_LOG_FUNCTION(this << "DSDVQ HelloHeader decrypted" << counter << restOfPacket);

            if(restOfPacket > 0 && restOfPacket % m_dsdvqHeaderSize == 0)
                protocols.push_back(DSDVQ_PACKET_HEADER_PROTOCOL_NUMBER);
            /*
            std::cout << "\n";
            dsdvqHeader.Print(std::cout);                
            std::cout << "\n";
            */
            //delete[] dsdvqBuffer;

        ///////////////////////////////////////
        //  DSDV
        //////////////////////////////////////

        } else if(protocols[i] == DSDV_PACKET_HEADER_PROTOCOL_NUMBER){ 
  
            NS_LOG_FUNCTION(this << "DSDV Header detected!" << counter);
 
            std::string dsdvHeaderText = plainText.substr (counter,counter + m_dsdvHeaderSize);
            const uint8_t* dsdvBuffer = reinterpret_cast<const uint8_t*>(dsdvHeaderText.c_str()); 
 
            NS_ASSERT(dsdvHeaderText.size() >= m_dsdvHeaderSize);

            Buffer dsdvHeaderBuffer;
            dsdvHeaderBuffer.Deserialize(dsdvBuffer, m_dsdvHeaderSize);

            ns3::dsdv::DsdvHeader dsdvHeader;
            dsdvHeader.Deserialize(dsdvHeaderBuffer.Begin ());  
            dsdvHeaders.push_back(dsdvHeader);
 
            counter += m_dsdvHeaderSize; 
            uint32_t restOfPacket = plainText.size() - counter;

            NS_LOG_FUNCTION(this << "DSDV HelloHeader decrypted" << counter << restOfPacket);

            if(restOfPacket > 0 && restOfPacket % m_dsdvHeaderSize == 0)
                protocols.push_back(DSDV_PACKET_HEADER_PROTOCOL_NUMBER);

            /*
            std::cout << "\n";
            dsdvHeader.Print(std::cout);                
            std::cout << "\n";
            */ 
 
        ///////////////////////////////////////
        //  OLSR
        //////////////////////////////////////

        } else if(protocols[i] == OLSR_PACKET_HEADER_PROTOCOL_NUMBER){ 
    
            NS_LOG_FUNCTION(this << "OLSR_PACKET_HEADER detected!" << counter);
 
            std::string olsrHeaderText = plainText.substr (counter,counter + m_olsrPacketHeaderSize);
            const uint8_t* olsrBuffer = reinterpret_cast<const uint8_t*>(olsrHeaderText.c_str()); 

            Buffer olsrHeaderBuffer;
            olsrHeaderBuffer.Deserialize(olsrBuffer, m_olsrPacketHeaderSize);
 
            olsrPacketHeader.Deserialize(olsrHeaderBuffer.Begin ());   
 
            counter += m_olsrPacketHeaderSize;

            NS_LOG_FUNCTION(this << "OLSR_PACKET_HEADER decrypted");
  
            /*
            std::cout << "\n";
            olsrPacketHeader.Print(std::cout);                
            std::cout << "\n";
            */
            //delete[] olsrBuffer;

        } else if(protocols[i] == OLSR_MESSAGE_HEADER_PROTOCOL_NUMBER){ 
    
            NS_LOG_FUNCTION(this << "OLSR_MESSAGE_HEADER detected!" << counter <<  plainText.size() << plainText.size() - counter);

            //FIRST WE NEED TO FIGURE OUT THE LENGTH OF THIS HEADER
            //Therefore, we crop the QKDDelimiterHeader and read the length of OLSR Message Header

            std::string temp = plainText.substr(counter, m_qkdDHeaderSize); 
            QKDDelimiterHeader qkdDHeader = StringToQKDDelimiterHeader (temp);
            counter += m_qkdDHeaderSize;

            NS_LOG_FUNCTION (this << "OLSR_MESSAGE_HEADER size should be " << qkdDHeader.GetDelimiterSize());
 
            std::string olsrHeaderText = plainText.substr(counter, qkdDHeader.GetDelimiterSize());  
            uint32_t olsrheaderSize = olsrHeaderText.size();

            NS_LOG_FUNCTION (this << "Cropped temp is : " << olsrHeaderText); 
            NS_LOG_FUNCTION(this << "OLSR_MESSAGE_HEADER size:" << olsrheaderSize << temp.size() ); 

            const uint8_t* olsrBuffer = reinterpret_cast<const uint8_t*>(olsrHeaderText.c_str()); 

            Buffer olsrHeaderBuffer;
            olsrHeaderBuffer.Deserialize(olsrBuffer, olsrheaderSize);
  
            ns3::olsr::MessageHeader olsrMessageHeader; 
            olsrMessageHeader.Deserialize(olsrHeaderBuffer.Begin ()); 
 
            olsrMessageHeaders.push_back(olsrMessageHeader);
            counter += olsrheaderSize;
 
            NS_LOG_FUNCTION(this << "OLSR_MESSAGE_HEADER decrypted" << counter << olsrheaderSize);
            NS_LOG_FUNCTION(this << "OLSR_MESSAGE_HEADER type" << olsrMessageHeader.GetMessageType() );

            if(plainText.size() - counter > 0)
                protocols.push_back(OLSR_MESSAGE_HEADER_PROTOCOL_NUMBER);
            
            /*
            std::cout << "\n";
            olsrMessageHeader.Print(std::cout);                
            std::cout << "\n";
            */
            //delete[] olsrBuffer;
        
        ///////////////////////////////////////
        //  AODV
        //////////////////////////////////////
 
        } else if(protocols[i] == AODV_TYPE_HEADER_PROTOCOL_NUMBER){ 
          
            NS_LOG_FUNCTION(this << "aodv TypeHeader detected!" << counter);

            std::string aodvHeaderText = plainText.substr (counter,counter + m_aodvTypeHeaderSize);
            const uint8_t* aodvBuffer = reinterpret_cast<const uint8_t*>(aodvHeaderText.c_str()); 

            Buffer aodvHeaderBuffer;
            aodvHeaderBuffer.Deserialize(aodvBuffer, m_aodvTypeHeaderSize);

            aodvTypeHeader.Deserialize(aodvHeaderBuffer.Begin ());  

            counter += m_aodvTypeHeaderSize;

            NS_LOG_FUNCTION(this << "aodv TypeHeader decrypted");
            /*
            std::cout << "\n";
            aodvTypeHeader.Print(std::cout);                
            std::cout << "\n";
            */ 
            //delete[] aodvBuffer;

        } else if(protocols[i] == AODV_RREQ_HEADER_PROTOCOL_NUMBER){ 
          
            NS_LOG_FUNCTION(this << "aodv RreqHeader detected!" << counter);

            std::string aodvHeaderText = plainText.substr (counter,counter + m_aodvRreqHeaderSize);
            const uint8_t* aodvBuffer = reinterpret_cast<const uint8_t*>(aodvHeaderText.c_str()); 

            Buffer aodvHeaderBuffer;
            aodvHeaderBuffer.Deserialize(aodvBuffer, m_aodvRreqHeaderSize);

            aodvRreqHeader.Deserialize(aodvHeaderBuffer.Begin ());  

            counter += m_aodvRreqHeaderSize; 

            NS_LOG_FUNCTION(this << "aodv RreqHeader decrypted");
            /*
            std::cout << "\n";
            aodvRreqHeader.Print(std::cout);                
            std::cout << "\n";
            */
            //delete[] aodvBuffer;

        } else if(protocols[i] == AODV_RREP_HEADER_PROTOCOL_NUMBER){ 
          
            NS_LOG_FUNCTION(this << "aodv RrepHeader detected!" << counter);

            std::string aodvHeaderText = plainText.substr (counter,counter + m_aodvRrepHeaderSize);
            const uint8_t* aodvBuffer = reinterpret_cast<const uint8_t*>(aodvHeaderText.c_str()); 

            Buffer aodvHeaderBuffer;
            aodvHeaderBuffer.Deserialize(aodvBuffer, m_aodvRrepHeaderSize);

            aodvRrepHeader.Deserialize(aodvHeaderBuffer.Begin ());  

            counter += m_aodvRrepHeaderSize; 

            NS_LOG_FUNCTION(this << "aodv RrepHeader decrypted");
            /*
            std::cout << "\n";
            aodvRrepHeader.Print(std::cout);                
            std::cout << "\n";
            */ 
            //delete[] aodvBuffer;

        } else if(protocols[i] == AODV_RERR_HEADER_PROTOCOL_NUMBER){ 
          
            NS_LOG_FUNCTION(this << "aodv RrepHeader detected!" << counter);

            std::string aodvHeaderText = plainText.substr (counter,counter + m_aodvRerrHeaderSize);
            const uint8_t* aodvBuffer = reinterpret_cast<const uint8_t*>(aodvHeaderText.c_str()); 

            Buffer aodvHeaderBuffer;
            aodvHeaderBuffer.Deserialize(aodvBuffer, m_aodvRerrHeaderSize);

            aodvRerrHeader.Deserialize(aodvHeaderBuffer.Begin ());  

            counter += m_aodvRerrHeaderSize; 

            NS_LOG_FUNCTION(this << "aodv RrepHeader decrypted");
            /*
            std::cout << "\n";
            m_aodvRerrHeaderSize.Print(std::cout);                
            std::cout << "\n";
            */
            //delete[] aodvBuffer;
        
        } else if(protocols[i] == AODV_RREP_ACK_HEADER_PROTOCOL_NUMBER){ 
          
            NS_LOG_FUNCTION(this << "aodv RrepHeader detected!" << counter);

            std::string aodvHeaderText = plainText.substr (counter,counter + m_aodvRrepAckHeaderSize);
            const uint8_t* aodvBuffer = reinterpret_cast<const uint8_t*>(aodvHeaderText.c_str()); 

            Buffer aodvHeaderBuffer;
            aodvHeaderBuffer.Deserialize(aodvBuffer, m_aodvRrepAckHeaderSize);
            
            aodvRrepAckHeader.Deserialize(aodvHeaderBuffer.Begin ());  

            counter += m_aodvRrepAckHeaderSize; 

            NS_LOG_FUNCTION(this << "aodv RrepHeader decrypted");
            /*
            std::cout << "\n";
            m_aodvRrepAckHeaderSize.Print(std::cout);                
            std::cout << "\n";
            */
            //delete[] aodvBuffer;     

        ///////////////////////////////////////
        //  AODVQ
        //////////////////////////////////////
 
        } else if(protocols[i] == AODVQ_TYPE_HEADER_PROTOCOL_NUMBER){ 
          
            NS_LOG_FUNCTION(this << "aodvq TypeHeader detected!" << counter);

            std::string aodvqHeaderText = plainText.substr (counter,counter + m_aodvqTypeHeaderSize);
            const uint8_t* aodvqBuffer = reinterpret_cast<const uint8_t*>(aodvqHeaderText.c_str()); 

            Buffer aodvqHeaderBuffer;
            aodvqHeaderBuffer.Deserialize(aodvqBuffer, m_aodvqTypeHeaderSize);

            aodvqTypeHeader.Deserialize(aodvqHeaderBuffer.Begin ());  

            counter += m_aodvqTypeHeaderSize;

            NS_LOG_FUNCTION(this << "aodvq TypeHeader decrypted");
            /*
            std::cout << "\n";
            aodvqTypeHeader.Print(std::cout);                
            std::cout << "\n";
            */ 
            //delete[] aodvqBuffer;

        } else if(protocols[i] == AODVQ_RREQ_HEADER_PROTOCOL_NUMBER){ 
          
            NS_LOG_FUNCTION(this << "aodvq RreqHeader detected!" << counter);

            std::string aodvqHeaderText = plainText.substr (counter,counter + m_aodvqRreqHeaderSize);
            const uint8_t* aodvqBuffer = reinterpret_cast<const uint8_t*>(aodvqHeaderText.c_str()); 

            Buffer aodvqHeaderBuffer;
            aodvqHeaderBuffer.Deserialize(aodvqBuffer, m_aodvqRreqHeaderSize);

            aodvqRreqHeader.Deserialize(aodvqHeaderBuffer.Begin ());  

            counter += m_aodvqRreqHeaderSize;

            NS_LOG_FUNCTION(this << "aodvq RreqHeader decrypted");
            /*
            std::cout << "\n";
            aodvqRreqHeader.Print(std::cout);                
            std::cout << "\n";
            */
            //delete[] aodvqBuffer;

        } else if(protocols[i] == AODVQ_RREP_HEADER_PROTOCOL_NUMBER){ 
          
            NS_LOG_FUNCTION(this << "aodvq RrepHeader detected!" << counter);

            std::string aodvqHeaderText = plainText.substr (counter,counter + m_aodvqRrepHeaderSize);
            const uint8_t* aodvqBuffer = reinterpret_cast<const uint8_t*>(aodvqHeaderText.c_str()); 

            Buffer aodvqHeaderBuffer;
            aodvqHeaderBuffer.Deserialize(aodvqBuffer, m_aodvqRrepHeaderSize);

            aodvqRrepHeader.Deserialize(aodvqHeaderBuffer.Begin ());  

            counter += m_aodvqRrepHeaderSize;

            NS_LOG_FUNCTION(this << "aodvq RrepHeader decrypted");
            /*
            std::cout << "\n";
            aodvqRrepHeader.Print(std::cout);                
            std::cout << "\n";
            */ 
            //delete[] aodvqBuffer;

        } else if(protocols[i] == AODVQ_RERR_HEADER_PROTOCOL_NUMBER){ 
          
            NS_LOG_FUNCTION(this << "aodvq RrepHeader detected!" << counter);

            std::string aodvqHeaderText = plainText.substr (counter,counter + m_aodvqRerrHeaderSize);
            const uint8_t* aodvqBuffer = reinterpret_cast<const uint8_t*>(aodvqHeaderText.c_str()); 

            Buffer aodvqHeaderBuffer;
            aodvqHeaderBuffer.Deserialize(aodvqBuffer, m_aodvqRerrHeaderSize);

            aodvqRerrHeader.Deserialize(aodvqHeaderBuffer.Begin ());  

            counter += m_aodvqRerrHeaderSize; 

            NS_LOG_FUNCTION(this << "aodvq RrepHeader decrypted");
            /*
            std::cout << "\n";
            m_aodvqRerrHeaderSize.Print(std::cout);                
            std::cout << "\n";
            */
            //delete[] aodvqBuffer;
        
        } else if(protocols[i] == AODVQ_RREP_ACK_HEADER_PROTOCOL_NUMBER){ 
          
            NS_LOG_FUNCTION(this << "aodvq RrepHeader detected!" << counter);

            std::string aodvqHeaderText = plainText.substr (counter,counter + m_aodvqRrepAckHeaderSize);
            const uint8_t* aodvqBuffer = reinterpret_cast<const uint8_t*>(aodvqHeaderText.c_str()); 

            Buffer aodvqHeaderBuffer;
            aodvqHeaderBuffer.Deserialize(aodvqBuffer, m_aodvqRrepAckHeaderSize);
            
            aodvqRrepAckHeader.Deserialize(aodvqHeaderBuffer.Begin ());  

            counter += m_aodvqRrepAckHeaderSize; 

            NS_LOG_FUNCTION(this << "aodvq RrepHeader decrypted");
            /*
            std::cout << "\n";
            m_aodvqRrepAckHeaderSize.Print(std::cout);                
            std::cout << "\n";
            */
            //delete[] aodvqBuffer;
        }

       ++i;
    } 

    NS_LOG_FUNCTION (this << "HeaderSize" << counter);

    NS_LOG_FUNCTION(this << "Size of payload is: " << plainText.size() - counter);

    std::string packetPayloadText = plainText.substr (counter, plainText.size() - counter);

    Ptr<Packet> packet = Create<Packet> ((uint8_t*) packetPayloadText.c_str(), packetPayloadText.size());
    NS_LOG_FUNCTION(this << "Packet " << p->GetUid() << " >>>> GOES TO >>>> " << packet->GetUid()  );

    NS_LOG_FUNCTION(this << "Decryption completed!" << packet->GetUid() << packet->GetSize()  );

    ////////////////////////////////////
    //  ADD ALL HEADERS TO THE PACKET
    ////////////////////////////////////
 
    i = protocols.size();
    while(i > 0){   

        NS_LOG_FUNCTION(this << "ADDING PROTOCOL:" << protocols[i-1] <<  "TO THE PACKET!");

        switch (protocols[i-1]){

            /////////////////////////////////
            //  Ipv4
            /////////////////////////////////
            case 4:
                packet->AddHeader (ipv4Header);
                NS_LOG_FUNCTION(this << "IPv4 header added to packet!");
            break;


            /////////////////////////////////
            //  ICMPv4
            /////////////////////////////////
            case 1:
                packet->AddHeader (Icmpv4Header);
                NS_LOG_FUNCTION(this << "Icmpv4Header added to packet!");
            break;
            case Icmpv4Header::ICMPV4_ECHO:
                packet->AddHeader (Icmpv4EchoHeader);
                NS_LOG_FUNCTION(this << "Icmpv4Header::ICMPV4_ECHO header added to packet!");
            break;
            case Icmpv4Header::ICMPV4_ECHO_REPLY:
                packet->AddHeader (Icmpv4EchoHeader);
                NS_LOG_FUNCTION(this << "Icmpv4Header::ICMPV4_ECHO_REPLY header added to packet!");
            break;
            case Icmpv4Header::ICMPV4_DEST_UNREACH:
                packet->AddHeader (Icmpv4DestinationUnreachableHeader);
                NS_LOG_FUNCTION(this << "Icmpv4DestinationUnreachable Header added to packet!");
            break;
            case Icmpv4Header::ICMPV4_TIME_EXCEEDED:
                packet->AddHeader (Icmpv4TimeExceededHeader);
                NS_LOG_FUNCTION(this << "Icmpv4TimeExceeded Header added to packet!");
            break;
            


            /////////////////////////////////
            //  UDP
            /////////////////////////////////
            case 17:
                //udpHeader.InitializeChecksum(ipv4Header.GetSource(), ipv4Header.GetDestination(), ipv4Header.GetProtocol());
                packet->AddHeader (udpHeader);
                NS_LOG_FUNCTION(this << "UDP header added to packet!");
            break;

            /////////////////////////////////
            //  TCP
            /////////////////////////////////
            case 6:
                packet->AddHeader (tcpHeader);
                NS_LOG_FUNCTION(this << "TCP header added to packet!");
            break;
  
 
            /////////////////////////////////
            //  OLSR
            ///////////////////////////////// 
            case OLSR_PACKET_HEADER_PROTOCOL_NUMBER:
                packet->AddHeader (olsrPacketHeader);
                NS_LOG_FUNCTION(this << "olsr Packet Header added to packet!");
            break; 
            case OLSR_MESSAGE_HEADER_PROTOCOL_NUMBER:  
                packet->AddHeader ( olsrMessageHeaders.back() );
                olsrMessageHeaders.pop_back(); 
                NS_LOG_FUNCTION(this << "olsr Message Header added to packet!");
            break;
  
            /////////////////////////////////
            //  DSDVQ
            /////////////////////////////////
            case DSDVQ_PACKET_HEADER_PROTOCOL_NUMBER: 
                packet->AddHeader ( dsdvqHeaders.back() );
                dsdvqHeaders.pop_back();
                NS_LOG_FUNCTION(this << "DSDVQ header added to packet!");
            break;
  
            /////////////////////////////////
            //  DSDV
            /////////////////////////////////
            case DSDV_PACKET_HEADER_PROTOCOL_NUMBER: 
                packet->AddHeader ( dsdvHeaders.back() );
                dsdvHeaders.pop_back();
                NS_LOG_FUNCTION(this << "DSDV header added to packet!");
            break;


            /////////////////////////////////
            //  AODV
            /////////////////////////////////
            case AODV_TYPE_HEADER_PROTOCOL_NUMBER:
                packet->AddHeader (aodvTypeHeader);
                NS_LOG_FUNCTION(this << "aodvTypeHeaderadded to packet!");
            break;
            case AODV_RREQ_HEADER_PROTOCOL_NUMBER:
                packet->AddHeader (aodvRreqHeader);
                NS_LOG_FUNCTION(this << "aodvRreqHeader added to packet!");
            break;
            case AODV_RREP_HEADER_PROTOCOL_NUMBER:
                packet->AddHeader (aodvRrepHeader);
                NS_LOG_FUNCTION(this << "aodvRrepHeader added to packet!");
            break;
            case AODV_RREP_ACK_HEADER_PROTOCOL_NUMBER:
                packet->AddHeader (aodvRrepAckHeader);
                NS_LOG_FUNCTION(this << "aodvRrepAckHeader added to packet!");
            break; 
            case AODV_RERR_HEADER_PROTOCOL_NUMBER:
                packet->AddHeader (aodvRerrHeader);
                NS_LOG_FUNCTION(this << "aodvRerrHeader added to packet!");
            break; 


            /////////////////////////////////
            //  AODVQ
            /////////////////////////////////
            case AODVQ_TYPE_HEADER_PROTOCOL_NUMBER:
                packet->AddHeader (aodvqTypeHeader);
                NS_LOG_FUNCTION(this << "aodvqTypeHeaderadded to packet!");
            break;
            case AODVQ_RREQ_HEADER_PROTOCOL_NUMBER:
                packet->AddHeader (aodvqRreqHeader);
                NS_LOG_FUNCTION(this << "aodvqRreqHeader added to packet!");
            break;
            case AODVQ_RREP_HEADER_PROTOCOL_NUMBER:
                packet->AddHeader (aodvqRrepHeader);
                NS_LOG_FUNCTION(this << "aodvqRrepHeader added to packet!");
            break;
            case AODVQ_RREP_ACK_HEADER_PROTOCOL_NUMBER:
                packet->AddHeader (aodvqRrepAckHeader);
                NS_LOG_FUNCTION(this << "aodvqRrepAckHeader added to packet!");
            break; 
            case AODVQ_RERR_HEADER_PROTOCOL_NUMBER:
                packet->AddHeader (aodvqRerrHeader);
                NS_LOG_FUNCTION(this << "aodvqRerrHeader added to packet!");
            break; 

        }
        i--;
    } 
 
    NS_LOG_FUNCTION (this << "Output of DECRYPT function! PacketID: "  << packet->GetUid() << " PacketSize: " << packet->GetSize()  );

    QKDInternalTag internalTag; 
    internalTag.SetAuthenticateValue ( qkdHeader.GetAuthenticated() ); 
    internalTag.SetEncryptValue ( qkdHeader.GetEncrypted() );
    packet->AddPacketTag(internalTag); 
      
    /*
    packet->AddHeader(qkdCommandHeader);
    std::cout << "\n ..................RECEIVED plain....." << packet->GetUid() << "..." <<  packet->GetSize() << ".......  \n";
    packet->Print(std::cout);                
    std::cout << "\n ............................................  \n";
    packet->RemoveHeader(qkdCommandHeader);
    */

    m_decryptionTrace(packet);
    return packet; 
} 


/***************************************************************
*           CRYPTO++ CRYPTOGRAPHIC FUNCTIONS 
***************************************************************/

std::string
QKDCrypto::OTP (const std::string& data, Ptr<QKDKey> key)
{
    NS_LOG_FUNCTION  (this << data.size()); 
    if(!m_encryptionEnabled) return data;

    std::string encryptData = data; 
    std::string keyString = key->KeyToString();

    if(keyString.size() != encryptData.size()){
        NS_LOG_FUNCTION(this << "KEY IS NOT GOOD FOR OTP!");
        return data;
    }

    for (uint32_t i = 0; i < encryptData.length(); i++) {
        encryptData[i] ^= keyString[i];
    } 

    return encryptData;
}

std::string 
QKDCrypto::AESEncrypt (const std::string& data, Ptr<QKDKey> key)
{
    NS_LOG_FUNCTION  (this << data.size());  
    if(!m_encryptionEnabled) return data;

    std::string encryptData; 
    byte* Kkey = key->GetKey();

    // Encryption
    CryptoPP::CTR_Mode< CryptoPP::AES >::Encryption encryptor;
    encryptor.SetKeyWithIV(Kkey, key->GetSize(), m_iv);
    //encryptor.SetKeyWithIV( key, CryptoPP::AES::DEFAULT_KEYLENGTH, m_iv );
     
    CryptoPP::StreamTransformationFilter stf( encryptor, new CryptoPP::StringSink( encryptData ) );
    stf.Put( (byte*)data.c_str(), data.size() );
    stf.MessageEnd(); 
    delete[] Kkey;
     
    return encryptData;
}

std::string 
QKDCrypto::AESDecrypt (const std::string& data, Ptr<QKDKey> key)
{ 
    NS_LOG_FUNCTION  (this << data.size()); 
    if(!m_encryptionEnabled) return data;
 
    std::string decryptData;
    byte* Kkey = key->GetKey();
 
    // Decryption 
    CryptoPP::CTR_Mode< CryptoPP::AES >::Decryption decryptor;
    decryptor.SetKeyWithIV(Kkey, key->GetSize(), m_iv);
    //decryptor.SetKeyWithIV( key, CryptoPP::AES::DEFAULT_KEYLENGTH, m_iv );
     
    CryptoPP::StreamTransformationFilter stf( decryptor, new CryptoPP::StringSink( decryptData ) );
    stf.Put( (byte*)data.c_str(), data.size() );
    stf.MessageEnd();
    delete[] Kkey;

    return decryptData;
}

std::string 
QKDCrypto::HexEncode(const std::string& data)
{
    NS_LOG_FUNCTION  (this << data.size()); 
    if(!m_encryptionEnabled) return data;

    std::string encoded;
    CryptoPP::StringSource ss(
        (
            byte*)data.data(), 
            data.size(), 
            true, 
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)
        )
    );
    return encoded;
}

std::string 
QKDCrypto::HexDecode(const std::string& data)
{
    NS_LOG_FUNCTION  (this << data.size()); 
    if(!m_encryptionEnabled) return data;

    std::string decoded;
    CryptoPP::StringSource ss(
        (
            byte*)data.data(), 
            data.size(), 
            true, 
            new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)
        )
    );
    return decoded;
}

std::string
QKDCrypto::Authenticate (std::string& inputString, Ptr<QKDKey> key, uint8_t authenticationType)
{ 
    NS_LOG_FUNCTION (this << inputString.length()); 

    switch (authenticationType)
    {
        case QKDCRYPTO_AUTH_VMAC:  
            return VMAC(inputString, key); 
            break;
        case QKDCRYPTO_AUTH_MD5: 
            return MD5(inputString);
            break;
        case QKDCRYPTO_AUTH_SHA1: 
            return SHA1(inputString);
            break;
    }
    std::string temp;
    return temp;
}

Ptr<Packet>
QKDCrypto::CheckAuthentication(Ptr<Packet> p, Ptr<QKDKey> key, uint8_t authenticationType)
{   
    NS_LOG_FUNCTION  (this << p->GetUid() );   

    QKDHeader qkdHeader;
    p->PeekHeader(qkdHeader);
    //If no QKDheader is found, then just return the packet since the packet probabily is not authenticated! 
    if(!qkdHeader.IsValid () || qkdHeader.GetAuthenticated() <= 0){
        NS_LOG_FUNCTION(this << "Unauthenticated packet received!");
        return p;
    }

    Ptr<Packet> packet = p->Copy ();
    packet->RemoveHeader(qkdHeader);

    uint32_t packetSize = packet->GetSize();   
    uint8_t *buffer = new uint8_t[packetSize];
    packet->CopyData(buffer, packetSize);  
    std::string plaintext = std::string((char*)buffer, packetSize);   
    std::string hashTag;
    delete[] buffer;

    switch (authenticationType)
    {
        case QKDCRYPTO_AUTH_VMAC:  
            hashTag = VMAC(plaintext, key);
            break;
        case QKDCRYPTO_AUTH_MD5: 
            hashTag = MD5(plaintext);
            break;
        case QKDCRYPTO_AUTH_SHA1: 
            hashTag = SHA1(plaintext);
            break;
    }

    m_deauthenticationTrace(p, hashTag);
 
    if(hashTag != qkdHeader.GetAuthTag()){

        NS_LOG_FUNCTION (this << "1:" << hashTag << hashTag.length() );
        NS_LOG_FUNCTION (this << "2:" << qkdHeader.GetAuthTag() << qkdHeader.GetAuthTag().length()  );

        NS_LOG_FUNCTION(this << "\n\nMAC VERIFICATION FAILED!\n\n");
        return 0;
    }else{
        NS_LOG_FUNCTION(this << "\n\nMAC VERIFICATION SUCCESSFUL!\n\n");
    }
   
    return p;
}

std::string
QKDCrypto::VMAC (std::string& inputString, Ptr<QKDKey> key)
{ 
    NS_LOG_FUNCTION (this << inputString.length() << key->KeyToString() );  
    if(!m_encryptionEnabled) 
        return std::string( m_authenticationTagLengthInBits, '0'); 

    byte* Kkey = key->GetKey();
    byte digestBytes[key->GetSize()];  

    CryptoPP::VMAC<CryptoPP::AES> vmac;

    vmac.SetKeyWithIV(Kkey, key->GetSize(), m_iv, CryptoPP::AES::BLOCKSIZE);
    vmac.CalculateDigest(digestBytes, (byte *) inputString.c_str(), inputString.length());

    std::string outputString;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(outputString));
    encoder.Put(digestBytes, sizeof(digestBytes));
    encoder.MessageEnd();

    outputString = outputString.substr(0, m_authenticationTagLengthInBits);

    delete[] Kkey;
    return outputString; 
}

std::string 
QKDCrypto::MD5(std::string& inputString)
{   
    NS_LOG_FUNCTION (this << inputString.length() );   
    if(!m_encryptionEnabled) 
        return std::string( m_authenticationTagLengthInBits, '0'); 

    byte digestBytes[CryptoPP::Weak::MD5::DIGESTSIZE];

    CryptoPP::Weak1::MD5 md5;
    md5.CalculateDigest(digestBytes, (byte *) inputString.c_str(), inputString.length());

    std::string outputString;
    CryptoPP::HexEncoder encoder;

    encoder.Attach(new CryptoPP::StringSink(outputString));
    encoder.Put(digestBytes, sizeof(digestBytes));
    encoder.MessageEnd();

    outputString = outputString.substr(0, m_authenticationTagLengthInBits);
    return outputString;  
} 
 
std::string 
QKDCrypto::SHA1(std::string& inputString)
{   
    NS_LOG_FUNCTION (this << inputString.length() );   
    if(!m_encryptionEnabled) 
        return std::string( m_authenticationTagLengthInBits, '0'); 
  
    byte digestBytes[CryptoPP::SHA::DIGESTSIZE];

    CryptoPP::SHA1 sha1;
    sha1.CalculateDigest(digestBytes, (byte *) inputString.c_str(), inputString.length());

    std::string outputString;
    CryptoPP::HexEncoder encoder;

    encoder.Attach(new CryptoPP::StringSink(outputString));
    encoder.Put(digestBytes, sizeof(digestBytes));
    encoder.MessageEnd();

    outputString = outputString.substr(0, m_authenticationTagLengthInBits);
    return outputString;  
} 
 
std::string 
QKDCrypto::base64_encode(std::string& s) 
{
  NS_LOG_FUNCTION (this << s.length() ); 

  unsigned char const* bytes_to_encode = reinterpret_cast<const unsigned char*>(s.c_str());
  unsigned int in_len = s.length();

  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }
  delete[] bytes_to_encode;
  return ret;

}

std::string 
QKDCrypto::base64_decode(std::string const& encoded_string) 
{
    NS_LOG_FUNCTION (this << encoded_string.length() ); 

    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
    }

    if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}

std::string 
QKDCrypto::StringCompressEncode(const std::string &data)
{
    NS_LOG_FUNCTION (this << "INPUT:" << data.length()); 
    if(!m_compressionEnabled) return data;

    namespace bio = boost::iostreams; 

    std::stringstream compressed;
    std::stringstream origin(data);

    bio::filtering_streambuf<bio::input> out;
    out.push(bio::gzip_compressor(bio::gzip_params(bio::gzip::best_compression)));
    out.push(origin);
    bio::copy(out, compressed);

    //std::string output = base64_encode(compressed.str());
    std::string output = compressed.str();
    NS_LOG_FUNCTION (this << "OUTPUT:" << output.length()); 

    return output;
}

std::string 
QKDCrypto::StringDecompressDecode(const std::string &data)
{
    NS_LOG_FUNCTION (this << "INPUT:" << data.length());  
    if(!m_compressionEnabled) return data;

    namespace bio = boost::iostreams;
    //std::string temp = base64_decode(data);
    std::string temp = data;
    
    std::stringstream compressed(temp);
    std::stringstream decompressed;

    bio::filtering_streambuf<bio::input> out;
    out.push(bio::gzip_decompressor());
    out.push(compressed);
    bio::copy(out, decompressed);

    std::string output = decompressed.str();
    NS_LOG_FUNCTION (this << "OUTPUT:" << output.length()); 

    return output;
}


} // namespace ns3
