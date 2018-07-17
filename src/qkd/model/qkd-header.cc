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

#include "ns3/log.h" 
#include "ns3/object-vector.h"
#include "ns3/pointer.h"
#include "ns3/uinteger.h"
#include "qkd-header.h"

namespace ns3 {
 
NS_LOG_COMPONENT_DEFINE ("QKDHeader");

NS_OBJECT_ENSURE_REGISTERED (QKDCommandHeader);
 
QKDCommandHeader::QKDCommandHeader (){ 
    m_command = 'A';  
}

TypeId
QKDCommandHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::QKDCommandHeader")
    .SetParent<Header> ()
    .AddConstructor<QKDCommandHeader> ()
  ;
  return tid;
}

TypeId
QKDCommandHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
QKDCommandHeader::GetSerializedSize () const
{
  return sizeof(uint8_t) + sizeof(uint16_t);
}

void
QKDCommandHeader::Serialize (Buffer::Iterator i) const
{  
    i.WriteHtonU16 ((uint16_t) m_protocol);  
    i.WriteU8 ((uint8_t) m_command); 
}

uint32_t
QKDCommandHeader::Deserialize (Buffer::Iterator start)
{ 
    Buffer::Iterator i = start;  
    m_protocol = i.ReadNtohU16 ();  
    m_command = i.ReadU8 (); 
 
    NS_LOG_DEBUG ("Deserialize m_command: " << m_command  << " \n m_protocol: " << m_protocol);
   
    uint32_t dist = i.GetDistanceFrom (start);
    NS_ASSERT (dist == GetSerializedSize ());
    return dist;
}

void
QKDCommandHeader::Print (std::ostream &os) const
{  
    os << "Command: " << m_command << "\t"
       << "Protocol: " << (uint16_t) m_protocol << "\n";
}

bool
QKDCommandHeader::operator== (QKDCommandHeader const & o) const
{ 
    return (m_command == o.m_command);
}

std::ostream &
operator<< (std::ostream & os, QKDCommandHeader const & h)
{
    h.Print (os);
    return os;
} 


void 		
QKDCommandHeader::SetCommand (char value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_command = value;
}

char 	
QKDCommandHeader::GetCommand (void) const{

    NS_LOG_FUNCTION  (this << m_command); 
    return m_command;
}

void 		
QKDCommandHeader::SetProtocol (uint16_t value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_protocol = value;
}

uint16_t 	
QKDCommandHeader::GetProtocol (void) const{

    NS_LOG_FUNCTION  (this << m_protocol); 
    return m_protocol;
}


//////////////////////////////
//  QKD DELIMITER HEADER
///////////////////////////////




NS_OBJECT_ENSURE_REGISTERED (QKDDelimiterHeader);
 
QKDDelimiterHeader::QKDDelimiterHeader (){ 
    m_delimiter = 0;  
}

TypeId
QKDDelimiterHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::QKDDelimiterHeader")
    .SetParent<Header> ()
    .AddConstructor<QKDDelimiterHeader> ()
  ;
  return tid;
}

TypeId
QKDDelimiterHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
QKDDelimiterHeader::GetSerializedSize () const
{
  return sizeof(uint8_t);
}

void
QKDDelimiterHeader::Serialize (Buffer::Iterator i) const
{  
    i.WriteU8 ((uint8_t) m_delimiter);
}

uint32_t
QKDDelimiterHeader::Deserialize (Buffer::Iterator start)
{ 
    Buffer::Iterator i = start;  
    m_delimiter = i.ReadU8 ();   
 
    NS_LOG_DEBUG ("Deserialize m_delimiter: " << m_delimiter);
   
    uint32_t dist = i.GetDistanceFrom (start);
    NS_ASSERT (dist == GetSerializedSize ());
    return dist;
}

void
QKDDelimiterHeader::Print (std::ostream &os) const
{  
    os << "m_delimiter: " << (uint32_t) m_delimiter << "\n";
}

bool
QKDDelimiterHeader::operator== (QKDDelimiterHeader const & o) const
{ 
    return (m_delimiter == o.m_delimiter);
}

std::ostream &
operator<< (std::ostream & os, QKDDelimiterHeader const & h)
{
    h.Print (os);
    return os;
} 


void        
QKDDelimiterHeader::SetDelimiterSize (uint32_t value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_delimiter = value;
}

uint32_t    
QKDDelimiterHeader::GetDelimiterSize (void) const{

    NS_LOG_FUNCTION  (this << m_delimiter); 
    return (uint32_t) m_delimiter;
}
 

///////////////////////////////////
//  QKD HEADER
/////////////////////////////////



NS_OBJECT_ENSURE_REGISTERED (QKDHeader);
 
QKDHeader::QKDHeader ():m_valid (true)
{ 
    m_length = 0;
    m_messageId = 0;
    m_encryped = 0;
    m_authenticated = 0;
    m_zipped = 0;
    m_version = 2;
    m_reserved = 0; 
    m_channelId = 0; 
    m_encryptionKeyId = 0;
    m_authenticationKeyId = 0; 
}

TypeId
QKDHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::QKDHeader")
    .SetParent<Header> ()
    .AddConstructor<QKDHeader> ()
  ;
  return tid;
}

TypeId
QKDHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
QKDHeader::GetSerializedSize () const
{
  return 4  * sizeof(uint32_t) 
       + 1  * sizeof(uint16_t)
       + 5  * sizeof(uint8_t)
       + 33 * sizeof(uint8_t); //authTag 
}

void
QKDHeader::Serialize (Buffer::Iterator i) const
{
    i.WriteHtonU32 ((uint32_t) m_length);
    i.WriteHtonU32 ((uint32_t) m_messageId);

    i.WriteU8 ((uint8_t) m_encryped);
    i.WriteU8 ((uint8_t) m_authenticated);
    i.WriteU8 ((uint8_t) m_zipped);
    i.WriteU8 ((uint8_t) m_version);
    i.WriteU8 ((uint8_t) m_reserved);
    i.WriteHtonU16 ((uint16_t) m_channelId);  
  
    i.WriteHtonU32 ((uint32_t) m_encryptionKeyId);
    i.WriteHtonU32 ((uint32_t) m_authenticationKeyId);  
    
    char tmpBuffer [m_authTag.length() + 1];
    NS_LOG_FUNCTION( "AUTHTAG:" << sizeof(tmpBuffer)/sizeof(tmpBuffer[0]) << " ---- " << m_authTag.length()  );
    strcpy (tmpBuffer, m_authTag.c_str());
    i.Write ((uint8_t *)tmpBuffer, m_authTag.length() + 1);
}

uint32_t
QKDHeader::Deserialize (Buffer::Iterator start)
{

    Buffer::Iterator i = start; 
    m_valid = false;

    m_length = i.ReadNtohU32 (); 
    m_messageId = i.ReadNtohU32 ();

    m_encryped = i.ReadU8 ();
    m_authenticated = i.ReadU8 (); 
    m_zipped = i.ReadU8 ();
    m_version = i.ReadU8 (); 
    m_reserved = i.ReadU8 ();
    m_channelId = i.ReadNtohU16 (); 

    m_encryptionKeyId = i.ReadNtohU32 ();
    m_authenticationKeyId = i.ReadNtohU32 ();

    if(m_version == 2)
        m_valid = true;
     
    uint32_t len = 33;
    char tmpBuffer [len];
    i.Read ((uint8_t*)tmpBuffer, len);
    m_authTag = tmpBuffer;

    NS_LOG_DEBUG ("Deserialize m_length: " << (uint32_t) m_length 
                << " m_messageId: " << (uint32_t) m_messageId
                << " m_encryped: " << (uint32_t) m_encryped
                << " m_authenticated: " << (uint32_t) m_authenticated
                << " m_zipped: " << (uint32_t) m_zipped
                << " m_version: " << (uint32_t) m_version  
                << " m_reserved: " << m_reserved
                << " m_channelId: " << (uint32_t) m_channelId  
                << " m_encryptionKeyId: " << (uint32_t) m_encryptionKeyId
                << " m_authenticationKeyId: " << (uint32_t) m_authenticationKeyId 
                << " m_valid: " << (uint32_t) m_valid 
                << " m_authTag: " << m_authTag
    );
   
    uint32_t dist = i.GetDistanceFrom (start);
    NS_LOG_FUNCTION( this << dist << GetSerializedSize() );
    NS_ASSERT (dist == GetSerializedSize ());
    return dist;
}

void
QKDHeader::Print (std::ostream &os) const
{  
    os << "\n"
       << "MESSAGE ID: "    << (uint32_t) m_messageId << "\t"
       << "Length: "        << (uint32_t) m_length << "\t"

       << "Authenticated: " << (uint32_t) m_authenticated << "\t"
       << "Encrypted: "     << (uint32_t) m_encryped << "\t"
       << "Zipped: "        << (uint32_t) m_zipped << "\t"
       << "Version: "       << (uint32_t) m_version << "\t"
       << "Reserved: "       << (uint32_t) m_reserved << "\t"
       << "ChannelID: "     << (uint32_t) m_channelId << "\t" 

       << "EncryptKeyID: "  << (uint32_t) m_encryptionKeyId << "\t" 
       << "AuthKeyID: "     << (uint32_t) m_authenticationKeyId << "\t"  
       
       << "AuthTag: "       << m_authTag << "\t\n";
       
}

bool
QKDHeader::operator== (QKDHeader const & o) const
{ 
    return (m_messageId == o.m_messageId && m_authenticationKeyId == o.m_authenticationKeyId && m_authTag == o.m_authTag);
}

std::ostream &
operator<< (std::ostream & os, QKDHeader const & h)
{
    h.Print (os);
    return os;
} 
 

void 		
QKDHeader::SetLength (uint32_t value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_length = value;
}
uint32_t 	
QKDHeader::GetLength (void) const{

    NS_LOG_FUNCTION  (this << m_length); 
    return m_length;
}

void 		
QKDHeader::SetMessageId (uint32_t value){
    
    NS_LOG_FUNCTION  (this << value); 
    m_messageId = value;
}
uint32_t 	
QKDHeader::GetMessageId (void) const{
    
    NS_LOG_FUNCTION  (this << m_messageId); 
    return m_messageId;
}


void 		
QKDHeader::SetEncrypted (uint32_t value){
    
    NS_LOG_FUNCTION  (this << value); 
    m_encryped = value;
}
uint32_t 	
QKDHeader::GetEncrypted (void) const{

    NS_LOG_FUNCTION  (this << m_encryped); 
    return (uint32_t) m_encryped;
}


void 		
QKDHeader::SetAuthenticated (uint32_t value){

    NS_LOG_FUNCTION  (this << value);
    m_authenticated = value;
}
uint32_t 	
QKDHeader::GetAuthenticated (void) const{

    NS_LOG_FUNCTION  (this << m_authenticated); 
    return (uint32_t) m_authenticated;
}


void 		
QKDHeader::SetZipped (uint8_t value){

    NS_LOG_FUNCTION  (this << value); 
    m_zipped = value;
}
uint8_t 	
QKDHeader::GetZipped (void) const{

    NS_LOG_FUNCTION  (this << m_zipped); 
    return m_zipped;
}


void 		
QKDHeader::SetVersion (uint8_t value){

    NS_LOG_FUNCTION  (this << value); 
    m_version = value;
}
uint8_t 	    
QKDHeader::GetVersion (void) const{

    NS_LOG_FUNCTION  (this << m_version); 
    return m_version;
}

 
void 		
QKDHeader::SetChannelId (uint16_t value){

    NS_LOG_FUNCTION  (this << value); 
    m_channelId = value;
}
uint16_t 	
QKDHeader::GetChannelId (void) const{

    NS_LOG_FUNCTION  (this << m_channelId); 
    return m_channelId ; 
}


void 		
QKDHeader::SetEncryptionKeyId (uint32_t value){

    NS_LOG_FUNCTION  (this << value); 
    m_encryptionKeyId = value; 
}
uint32_t 	
QKDHeader::GetEncryptionKeyId (void) const{

    NS_LOG_FUNCTION  (this << m_encryptionKeyId); 
    return m_encryptionKeyId;
}


void 		
QKDHeader::SetAuthenticationKeyId (uint32_t value){

    NS_LOG_FUNCTION  (this << value);  
    m_authenticationKeyId = value; 
}
uint32_t 	
QKDHeader::GetAuthenticationKeyId (void) const{

    NS_LOG_FUNCTION  (this << m_authenticationKeyId); 
    return m_authenticationKeyId;
}


void 		
QKDHeader::SetAuthTag (std::string value){

    NS_LOG_FUNCTION  (this << value << value.size());
    m_authTag = value;
}
std::string
QKDHeader::GetAuthTag (void) const{

    NS_LOG_FUNCTION  (this << m_authTag << m_authTag.size());
    return m_authTag;
}
 

} // namespace ns3
