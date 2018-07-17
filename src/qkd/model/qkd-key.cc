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
#include "ns3/packet.h"
#include "ns3/assert.h"
#include "ns3/log.h" 
#include "qkd-key.h" 
#include <string>
#include <cstdarg>

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE ("QKDKey"); 

    NS_OBJECT_ENSURE_REGISTERED (QKDKey);

    TypeId 
    QKDKey::GetTypeId (void)
    {
        static TypeId tid = TypeId ("ns3::QKDKey")
            .SetParent<Object> () 
            ;
            return tid;
    }

    uint32_t QKDKey::m_globalUid = 0;
      
    Ptr<QKDKey> 
    QKDKey::Copy (void) const
    {
      // we need to invoke the copy constructor directly
      // rather than calling Create because the copy constructor
      // is private.
      return Ptr<QKDKey> (new QKDKey (*this), false);
    }

    QKDKey::QKDKey (uint32_t keyID, uint32_t size)
      : m_id (keyID),
        m_size (size)
    {
      NS_LOG_FUNCTION  (this << m_key << size ); 

      m_globalUid++;
      m_key = std::string( size, '0');
      m_timestamp = Simulator::Now ();
      NS_LOG_FUNCTION  (this << m_id << m_key  << m_timestamp.GetMilliSeconds() );     
    }

    uint32_t        
    QKDKey::GetKeyId (void) const
    {
        return m_id;
    }

    void            
    QKDKey::SetKeyId (uint32_t value)
    {
        m_id = value;
    }

    uint32_t 
    QKDKey::GetUid (void) const
    {
      NS_LOG_FUNCTION  (this << m_globalUid ); 
      return m_globalUid;
    }
        
    uint32_t 
    QKDKey::GetSize (void) const
    {
      NS_LOG_FUNCTION  (this << m_globalUid << m_size); 
      return m_size;
    }  
 
    void
    QKDKey::SetSize (uint32_t value)
    {
        NS_LOG_FUNCTION  (this << m_globalUid << value); 
        m_size = value;
    }

    std::string
    QKDKey::KeyToString (void) const
    {
        return m_key;
    }

    uint8_t *     
    QKDKey::GetKey(void) const
    {
        NS_LOG_FUNCTION  (this << m_globalUid << m_key.length() ); 
        uint8_t* temp = new uint8_t [m_key.length()];
        memcpy( temp, m_key.data(), m_key.length());
        return temp;
    }
 
} // namespace ns3
