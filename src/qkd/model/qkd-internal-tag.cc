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
#include "qkd-internal-tag.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDInternalTag");

 
NS_OBJECT_ENSURE_REGISTERED (QKDCommandTag);
 
TypeId 
QKDCommandTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDCommandTag")
    .SetParent<Tag> ()
    .AddConstructor<QKDCommandTag> () 
  ;
  return tid;
}
TypeId 
QKDCommandTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}
uint32_t 
QKDCommandTag::GetSerializedSize (void) const
{
  return sizeof(uint8_t) + sizeof(uint32_t);
} 

void
QKDCommandTag::Serialize (TagBuffer i) const
{ 
    i.WriteU8 ((uint8_t) m_command);  
    i.WriteU32 ((uint32_t) m_routingProtocolNumber);
}

void
QKDCommandTag::Deserialize (TagBuffer i)
{  
    m_command = i.ReadU8 ();   
    m_routingProtocolNumber = i.ReadU32 ();   
    NS_LOG_DEBUG ("Deserialize m_command: " << m_command );
}

void
QKDCommandTag::Print (std::ostream &os) const
{  
    os << "Command: " << m_command << "\n";
    os << "m_routingProtocolNumber: " << m_routingProtocolNumber ;
}

void    
QKDCommandTag::SetCommand (char value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_command = value;
}

char  
QKDCommandTag::GetCommand (void) const{

    NS_LOG_FUNCTION  (this << m_command); 
    return m_command;
}

void    
QKDCommandTag::SetRoutingProtocolNumber (uint32_t value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_routingProtocolNumber = value;
}

uint32_t  
QKDCommandTag::GetRoutingProtocolNumber (void) const{

    NS_LOG_FUNCTION  (this << m_routingProtocolNumber); 
    return m_routingProtocolNumber;
}






 
NS_OBJECT_ENSURE_REGISTERED (QKDInternalTOSTag);


TypeId 
QKDInternalTOSTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDInternalTOSTag")
    .SetParent<Tag> ()
    .AddConstructor<QKDInternalTOSTag> () 
  ;
  return tid;
}
TypeId 
QKDInternalTOSTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}
uint32_t 
QKDInternalTOSTag::GetSerializedSize (void) const
{
  return sizeof(uint8_t); //+ 2 * sizeof(uint32_t)
}
void 
QKDInternalTOSTag::Serialize (TagBuffer i) const
{    
    i.WriteU8 (m_tos);

}
void 
QKDInternalTOSTag::Deserialize (TagBuffer i)
{   
    m_tos = i.ReadU8 ();
}
void 
QKDInternalTOSTag::Print (std::ostream &os) const
{
    NS_LOG_FUNCTION (this);     
    os << "m_tos=" << m_tos;
} 
void 
QKDInternalTOSTag::SetTos (uint8_t value)
{
    NS_LOG_FUNCTION (this << (uint32_t) value);
    m_tos = value;
}
uint8_t 
QKDInternalTOSTag::GetTos (void) const
{
    NS_LOG_FUNCTION (this << (uint32_t) m_tos);
    return m_tos;
} 


NS_OBJECT_ENSURE_REGISTERED (QKDInternalTag);


TypeId 
QKDInternalTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDInternalTag")
    .SetParent<Tag> ()
    .AddConstructor<QKDInternalTag> ()
    .AddAttribute ("Encrypt",
                   "Should Enrypt",
                   EmptyAttributeValue (),
                   MakeUintegerAccessor (&QKDInternalTag::GetEncryptValue),
                   MakeUintegerChecker<uint8_t> ())
    .AddAttribute ("Authenticate",
                   "Should Authenticate",
                   EmptyAttributeValue (),
                   MakeUintegerAccessor (&QKDInternalTag::GetAuthenticateValue),
                   MakeUintegerChecker<uint8_t> ())
  ;
  return tid;
}
TypeId 
QKDInternalTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}
uint32_t 
QKDInternalTag::GetSerializedSize (void) const
{
  return 2 * sizeof(uint8_t) + sizeof(uint32_t);
}
void 
QKDInternalTag::Serialize (TagBuffer i) const
{
  i.WriteU8 (m_encryptValue);
  i.WriteU8 (m_authenticateValue);
  i.WriteU32 (m_maxDelay);
}
void 
QKDInternalTag::Deserialize (TagBuffer i)
{
  m_encryptValue = i.ReadU8 ();
  m_authenticateValue = i.ReadU8 ();
  m_maxDelay = i.ReadU32 ();
}
void 
QKDInternalTag::Print (std::ostream &os) const
{
    NS_LOG_FUNCTION (this);
    os << "e=" << (uint32_t)m_encryptValue << "a=" << (uint32_t)m_authenticateValue;
}
void 
QKDInternalTag::SetAuthenticateValue (uint8_t value)
{
    NS_LOG_FUNCTION (this);
    m_authenticateValue = value;
}
uint8_t 
QKDInternalTag::GetAuthenticateValue (void) const
{
    NS_LOG_FUNCTION (this);
    return m_authenticateValue;
}
void 
QKDInternalTag::SetEncryptValue (uint8_t value)
{
    NS_LOG_FUNCTION (this);
    m_encryptValue = value;
}
uint8_t 
QKDInternalTag::GetEncryptValue (void) const
{
    NS_LOG_FUNCTION (this);
    return m_encryptValue;
} 

void 
QKDInternalTag::SetMaxDelayValue (uint32_t value)
{
    NS_LOG_FUNCTION (this);
    m_maxDelay = value;
}
uint32_t 
QKDInternalTag::GetMaxDelayValue (void) const
{
    NS_LOG_FUNCTION (this);
    return m_maxDelay;
} 


} // namespace ns3
