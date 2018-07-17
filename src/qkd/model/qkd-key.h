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
#ifndef QKD_KEY_H
#define QKD_KEY_H

#include <stdint.h>  
#include <algorithm>
#include <stdint.h> 

#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/callback.h"
#include "ns3/assert.h"
#include "ns3/ptr.h"
#include "ns3/simulator.h"
#include <time.h>
#include "ns3/nstime.h"
#include "ns3/deprecated.h"
#include <string>
#include <iomanip>
#include <vector>
/*
#include <crypto++/iterhash.h>
#include <crypto++/secblock.h>
*/
namespace ns3 {

/**
 * \ingroup qkd
 * \brief The QKD key is an elementary class of QKDNetSim. It is used to describe 
 *  the key that is established in the QKD process. In QKD process, keys are stored as
 * blocks (blocks of 1024, 2048, 4096 bits or other). Later, some part of the block is 
 * taken and used for encryption, while other remains in the buffer. Operations regarding
 * QKD Key management (merge, split and other) are under construction.
 */

class QKDKey : public Object
{
    public:
        /**
        * \brief Get the TypeId
        *
        * \return The TypeId for this class
        */
        static TypeId GetTypeId (void);

        /**
        * \brief Create an empty QKD key with a new uid (as returned
        * by getUid).
        */
        QKDKey (uint32_t keyID, uint32_t keySize); 

        uint32_t        GetKeyId (void) const;
        void            SetKeyId (uint32_t);

        /**
        *   \brief Each QKD Key has its own unique ID.
        */
        uint32_t        GetUid (void) const;

        /**
        *   \brief Help function - Copy key
        *   @return Ptr<QKDKey>
        */
        Ptr<QKDKey>     Copy (void) const; 

        /**
        * Return key in byte* which is necessery for usage in QKDCrypto module for encryption or authentication
        * Convert key from std::String to byte*
        * @return byte*
        */  
        uint8_t *       GetKey (void) const; 

        /**
        *   \brief Get the size of the key
        *   @return uint32_t
        */
        uint32_t        GetSize(void) const;

        /**
        *   \brief Set the size of the key
        *   @param uint32_t
        */
        void            SetSize(uint32_t);

        /**
        *   \brief Return the raw key in std::string format
        *   @return std::string
        */
        std::string     KeyToString (void) const;

    private:
 
        uint32_t            m_id;       //<! QKDKeyID
        static uint32_t     m_globalUid; //<! Global static QKDKeyID
        uint32_t            m_size; //<! QKDKey size
        std::string         m_key;  //<! QKDKey raw value
        Time                m_timestamp; //<! QKDKey generation timestamp 
        
    };

} // namespace ns3

#endif /* QKD_KEY_H */
