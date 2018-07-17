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

#ifndef QKD_MANAGER_H
#define QKD_MANAGER_H

#include <queue>
#include "ns3/packet.h"
#include "ns3/tag.h"
#include "ns3/object.h"
#include "ns3/node.h"
#include "ns3/ipv4-header.h"
#include "ns3/net-device.h"
#include "ns3/traffic-control-layer.h"

#include "ns3/qkd-crypto.h"
#include "ns3/qkd-buffer.h"
#include "ns3/qkd-net-device.h"
#include "ns3/qkd-internal-tag.h"

#include "ns3/internet-module.h"
#include "ns3/ipv4-interface-address.h"

#include <vector> 
#include <map>

namespace ns3 {

    struct NeigborDetail{ 
      uint32_t    interface;
      Address     sourceAddress; //MAC address of source netDevice
      float       distance; //Geographical distance
      float       linkPerformance; //link performance (status)
    };

    class Node; 
    class QKDNetDevice; 

    /**
     * \ingroup qkd
     * \class QKDManager
     * \brief QKD manager is installed at each QKD node and it represents the backbone of QKDNetSim. It
     * contains a list of QKD Virtual NetDevices from the overlying network, a list of active sockets
     * in the underlying network, a list of IP addresses of interfaces in the overlying and underlying
     * network and a list of associated QKD buffers and QKD cryptos. Therefore, QKD manager serves
     * as a bond between the overlying NetDevices and sockets in the underlying network. Since the
     * QKD link is always realized in a point-to-point manner between exactly two nodes [30], QKD
     * manager stores information about NetDevices of the corresponding link and associated QKD
     * buffers. Using the MAC address of NetDevice, QKD manager unambiguously distinguishes
     * QKD crypto and QKD buffer which are utilized for packet processing. Finally, QKD manager
     * delivers the processed packet to the underlying network. Receiving and processing of incoming
     * packets follows identical procedure but in reverse order.
     *
     */
    class QKDManager : public Object {
    public:
 
        struct Connection
        {
            uint32_t                bufferId;
            Ptr<QKDNetDevice>       QKDNetDeviceSrc;
            Ptr<QKDNetDevice>       QKDNetDeviceDst;
            Ptr<NetDevice>          IPNetDeviceSrc;
            Ptr<NetDevice>          IPNetDeviceDst;
            Ptr<QKDBuffer>          buffer;
            Ptr<QKDCrypto>          crypto;
            Ptr<Socket>             socket;
            Ptr<Socket>             socketSink;
            std::string             socketType;
            uint32_t                underlayPortNumber; 
            Ipv4InterfaceAddress    IPQKDSrc; //QKD IP Src Address - overlay device
            Ipv4InterfaceAddress    IPQKDDst; //QKD IP Dst Address - overlay device
            Ipv4InterfaceAddress    IPSrc;  //IP Src Address - underlay device
            Ipv4InterfaceAddress    IPDst;  //IP Dst Address - underlay device
            bool                    isMaster; 
            bool                    shouldEncrypt;
            bool                    shouldAuthenticate;
            uint32_t                channelID;
            double                  publicChannelMetric;
            double                  quantumChannelMetric; 

            ~Connection()
            {
                QKDNetDeviceSrc = 0;
                QKDNetDeviceDst = 0;
                IPNetDeviceSrc = 0;
                IPNetDeviceDst = 0;
                buffer = 0;
                crypto = 0;
                socket = 0;
                socketSink = 0;
            }
        };

        struct addressGroup
        {
            Ptr<Node>       destinationNode;
            Ipv4Address     sourceAddress;
            Ipv4Address     destinationAddress;

            ~addressGroup()
            {
                destinationNode = 0; 
            }

        };
 
        /**
        * \brief Get the type ID.
        * \return the object TypeId
        */
        static TypeId GetTypeId (void);
       
        /**
        * \brief Constructor
        */
        QKDManager ();

        /**
        * \brief Destructor
        */
        virtual ~QKDManager ();
           
        /**
        *   \brief Return the number of buffers connected with QKD Manager of the node
        *   @return uint32_t 
        */
        uint32_t GetNBuffers (void) const;
         
        /**
        *   \brief Establish new QKD connection by adding new QKD link and record connection details
        *   This function is called from internet/helper/qkd-helper.cc
        *    @param     Ptr<QKDNetDevice>
        *    @param     Ptr<QKDNetDevice>
        *    @param     Ptr<NetDevice>
        *    @param     Ptr<NetDevice>
        *    @param     Ptr<QKDCrypto>
        *    @param     Ptr<Socket>
        *    @param     Ipv4InterfaceAddress
        *    @param     Ipv4InterfaceAddress
        *    @param     Ipv4InterfaceAddress
        *    @param     Ipv4InterfaceAddress
        *    @param     bool
        *    @param     bool
        *    @param     bool
        *    @param     uint32_t
        *    @param     uint32_t
        *    @param     uint32_t
        *    @param     uint32_t
        */
        void AddNewLink ( 
            Ptr<QKDNetDevice>       NetDeviceSrc,
            Ptr<QKDNetDevice>       NetDeviceDst,
            Ptr<NetDevice>          IPNetDeviceSrc,
            Ptr<NetDevice>          IPNetDeviceDst,
            Ptr<QKDCrypto>          Crypto,
            Ptr<Socket>             socket,
            Ptr<Socket>             socketSink,
            std::string             socketType,
            uint32_t                underlayPortNumber, 
            Ipv4InterfaceAddress    IPQKDSrc, //QKD IP Src Address - overlay device
            Ipv4InterfaceAddress    IPQKDDst, //QKD IP Dst Address - overlay device 
            Ipv4InterfaceAddress    IPSrc,  //IP Src Address - underlay device
            Ipv4InterfaceAddress    IPDst,  //IP Dst Address - underlay device 
            bool                    isMaster,  
            uint32_t                Mmin, 
            uint32_t                Mthr, 
            uint32_t                Mmax, 
            uint32_t                Mcurrent,
            uint32_t                channelID
        ); 

        /**
        * \brief Called from QKDManager::VirtualReceive
        * This function is used to decrypt the packet after receiving from the underlay network
        * @param Ptr<NetDevice> src
        */
        std::vector<Ptr<Packet> > ProcessIncomingRequest (Ptr<NetDevice> src, Ptr<Packet> p);

        /**
        * \brief Called from QKDManager::VirtualSend
        * This function is used to encrypt the packet prior sending to the underlay network
        * @param Ptr<NetDevice> src
        */  
        std::vector<Ptr<Packet> > ProcessOutgoingRequest (Ptr<NetDevice> src, Ptr<Packet> p); 
        
        /**
        *   \brief Get destination node where destination ndoe is pointing to. 
        *   The information is obtained from connection details of the link
        *   Currently not in use anywhere!
        *   @param Ipv4Address
        *   @return Ptr<Node>
        */
        Ptr<Node> GetDestinationNode (const Address dst);
 
        /**
        *   \brief Add new key material to the corresponding QKD Buffer. 
        *   Returns true if success, false otherwise.
        *   @param Ptr<NetDevice>
        *   @param uint32_t&
        *   @return bool        
        */
        bool AddNewKeyMaterial (const Address sourceAddress, uint32_t& newKey);
     
        /**
        * \brief Called from traffic-control/module/qkd-pfifo-fast-queue-disc
        * This function needs to check the status of QKDBuffer. 
        * According to the information obtained, packet from corresponding queue will be served
        * @param Ptr<NetDevice> QKDNetDevice
        */
        uint8_t FetchStatusForDestinationBuffer(Ptr<NetDevice> src);

        /**
        * \brief Help Function (not used)
        * @param Ipv4Address
        * \return uint32_t
        */
        uint32_t FetchMaxNumberOfRecordedKeyChargingTimePeriods (Ipv4Address nextHop);
    
        /**
        *   \brief Forward packet from underlay network through the socket to the QKDNetDevice
        *   Note: USED ONLY IN OVERLAY NETWORK
        *   @param Ptr<Socket> 
        */
        void VirtualReceive  (Ptr<Socket> socket);
                
        /**
        *   \brief Forward packet from device to the underlay network through the socket.
        *   Thus, this is L2 of Overlay network
        *   @param Ptr<Packet>
        *   @param Address
        *   @param Address
        *   @param uint16_t
        *   @return bool
        */
        bool VirtualSendOverlay (
            Ptr<Packet> packet, 
            const Address& source, 
            const Address& dest, 
            uint16_t protocolNumber
        );

        /**
        *   \brief Forward packet from device to the underlay network through the socket
        *   Thus, this is L2 of Overlay network.
        *   Also, used in single TCP/IP network and it is called 
        *   from QKDL2SingleTCPIPPfifoFastQueueDisc::TransmitL2. 
        *   Since sometimes device queue can be closed but packet was forwarded to processing 
        *   it is necessery to forward TxQueueIndex and check queue status.
        *   For overlay network this is not the case, since packet in overlay network is
        *   forwarded to underlying interface. Therefore, TxQueueIndex is set to 0.
        *
        *   @param Ptr<Packet>
        *   @param Address
        *   @param Address
        *   @param uint16_t
        *   @uint8_t TxQueueIndex
        *   @return bool
        */
        bool VirtualSend (
            Ptr<Packet> packet, 
            const Address& source, 
            const Address& dest, 
            uint16_t protocolNumber,
            uint8_t TxQueueIndex
        );
    
        /**
        *   \brief Deliver the processed packet to the underlying socket
        *
        *   @param Ptr<Packet>
        *   @param Ptr<Packet>
        *   @param Address
        *   @param Address
        *   @param uint16_t
        *   @uint8_t TxQueueIndex
        */
        bool
        ForwardToSocket(
            Ptr<Packet> originalPacket,
            Ptr<Packet> packet, 
            const Address& source, 
            const Address& dst,
            uint16_t protocolNumber,
            uint8_t TxQueueIndex
        );

        /**
        *   \brief Help function used to call determine TOSband and call original
        *   CheckForResourcesToProcessThePacket with all params
        *   @param Ptr<Packet>
        *   @param Ipv4Address
        *   @return bool
        */
        bool
        CheckForResourcesToProcessThePacket(
            Ptr<Packet> p,
            const Address sourceAddress
        );
         
        /**
        *   \brief Used to chech whether there are enough resources to encrypt/decrypt the packet.
        *   Function calls QKDCrypto to which QKDBuffer is forwarded as parameter. QKDCrypto is in 
        *   charge to analyze the packet's requirements and QKDBuffer status.
        *   @param Ptr<Packet>
        *   @param Ipv4Address
        *   @uint32_t 
        *   @return bool
        */
        bool
        CheckForResourcesToProcessThePacket(
            Ptr<Packet> p,
            const Address sourceAddress,
            const uint32_t& TOSband 
        );

        /**
        *   \brief Help function that returns QKDBuffer Position in m_buffers on the basis of source IPv4Address
        *   @Ipv4Address
        *   @return uint32_t
        */
        uint32_t GetBufferPosition (const Address& sourceAddress);

        /**
        *   \brief Return QKDBuffer by the buffer position. Usually called from QKDGraphManager
        *   @param uint32_t bufferId
        *   @return Ptr<QKDBuffer>
        */
        Ptr<QKDBuffer> GetBufferByBufferPosition (const uint32_t& index);

        /**
        *   \brief Return QKDBuffer Position in m_buffers on the basis of source IPv4Address
        *   @param  Address
        *   @return Ptr<QKDBuffer>
        */
        Ptr<QKDBuffer> GetBufferBySourceAddress (const Address& sourceAddress);

        /**
        *   \brief Get connection details based on destination IPv4Address
        *   @param Ipv4Address
        *   @return QKDManager::Connection
        */
        QKDManager::Connection GetConnectionDetails (const uint32_t& bufferId);

        /**
        *   \brief Return QKDBufferID on the basis of destination IPv4Address
        *   @Ipv4Address
        *   @return uint32_t
        */
        QKDManager::Connection GetConnectionDetails (const Address sourceAddress);

        /**
        *   \brief Mark packet to be authenticated only! 
        *   @param Ptr<Packet> 
        *   @return Ptr<Packet>
        */
        Ptr<Packet> MarkAuthenticate (Ptr<Packet> p);

        /**
        *   \brief Mark packet to be encrypted and authenticated
        *   Note: All encrypted packets MUST be authenticated as well!
        *   @param Ptr<Packet> 
        *   @return Ptr<Packet>
        */
        Ptr<Packet> MarkEncrypt (Ptr<Packet> p);

        /**
        *   \brief Mark packet to be encrypted and authenticated
        *   Note: All encrypted packets MUST be authenticated as well!
        *   @param  Ptr<Packet> 
        *   @param  uint_8_t    encryptionType
        *   @param  uint_8_t    authenticationType
        *   @return Ptr<Packet>
        */
        Ptr<Packet> MarkEncrypt (Ptr<Packet> p, uint8_t encryptionType, uint8_t authneticationType);

        /**
        *   \brief Mark maxDelay of packet to be tolerated (in miliseconds)
        *   @param Ptr<Packet> 
        *   @return Ptr<Packet>
        */
        Ptr<Packet> MarkMaxDelay(Ptr<Packet> p, uint32_t delay);

        /**
        *   \brief Check whether packet is marked to be encrypted
        *   @param Ptr<Packet> 
        *   @return bool
        */
        bool IsMarkedAsEncrypt (Ptr<Packet> p);
 
        /**
        * \brief Indicates that the TCP connection for socket in param is established
        * @param Ptr<Socket>
        */
        void ConnectionSucceeded (Ptr<Socket> socket);

        /**
        * \brief Indicates that the TCP connection for socket in param failed to establish
        * @param Ptr<Socket>
        */
        void ConnectionFailed (Ptr<Socket> socket);
        
        /**
        * \brief Handle an incoming connection
        * \param socket the incoming connection socket
        * \param from the address the connection is from
        */
        void HandleAccept (Ptr<Socket> socket, const Address& from);
        
        /**
        * \brief Do we use real storages (save QKDKey on hard-drive)?
        */
        void UseRealStorages (const bool& useRealStorages);

        /**
        *   \brief Process packet (Decrypt and authentication check) after receiving at 
        *   NetDevice, and forward it to upper layer. USED ONLY IN SINGLE TCP/IP NETWORK!
        *   @param Ptr<NetDevice>   device
        */
        void VirtualReceiveSimpleNetwork (Ptr<NetDevice> device, Ptr<const Packet> p,
                        uint16_t protocol, const Address &from,
                        const Address &to, NetDevice::PacketType packetType
        );
 
        /**
        *   \brief Help function called from routing protocol to count the number of neighbors
        *   @return uint32_t
        */
        uint32_t GetNumberOfDestinations();
 
        /**
        *   \brief Help function called from routing protocol to fetch the map of source 
        *   and destination addresses. Used in HELLO process to determin which nodes are neighbors
        *   @return std::map<Ipv4Address, Ipv4Address>
        */
        std::vector<QKDManager::addressGroup > GetMapOfSourceDestinationAddresses();

        /**
        *   \brief Help function
        *   @return uint32_t
        */
        uint32_t    FetchLinkThresholdHelpValue(); 
        
        /**
        *   \brief Help function
        */
        void        CalculateLinkThresholdHelpValue();

        /**
        *   \brief Help function
        *   @return uint32_t
        */
        uint32_t GetLinkThresholdValue(const Address sourceAddress );

        /**
        *   \brief Help function
        */
        void SetLinkThresholdValue( const uint32_t& proposedLaValue, const Address sourceAddress );

        /**
        *   \brief Help function
        */
        Ipv4Address PopulateLinkStatusesForNeighbors( 
            Ptr<Packet> p, 
            std::map<Ipv4Address, NeigborDetail> distancesToDestination,
            uint8_t tos,
            uint32_t& outputInterface 
        );

        /**
        *   \brief Help function used to fetch TOS value from the packet
        *   @param Ptr<Packet> p
        *   @return uint32_t
        */
        uint32_t    FetchPacketTos(Ptr<Packet> p);

        /**
        *   \brief Help function used to convert TOS value to TOS band 
        *   which is used for determing the priority of the delivery
        *   @param uint32_t
        *   @return uint32_t
        */
        uint32_t    TosToBand(const uint32_t& tos);

        /**
        *   \brief Help function used to detect netDevice by using MAC address when the packet is encrypted
        *   @param  const Address address
        *   @return Ptr<NetDevice>
        */
        Ptr<NetDevice>  GetSourceNetDevice (const Address address);

        /**
        *   \brief Help function
        */
        std::map<Address, QKDManager::Connection >::iterator FetchConnection(const Address sourceAddress);

        /**
        *   \brief Fetch performances of the public channel. 
        */
        double  FetchPublicChannelPerformance (Ipv4Address nextHop);
 
    protected: 
      /**
       * The dispose method. Subclasses must override this method
       * and must chain up to it by calling Node::DoDispose at the
       * end of their own DoDispose method.
       */
      virtual void DoDispose (void);

        /**
        *   \briefInitialization function
        */
        virtual void DoInitialize (void);

    private:  
  
        /**
        *   \brief Help function
        */
        void UpdateQuantumChannelMetric(const Address sourceAddress);

        /**
        *   \brief Help function
        */
        void UpdatePublicChannelMetric (const Address sourceAddress);

        uint32_t    m_linksThresholdHelpValue; //<! Help value, not used for now

        bool    m_useRealStorages;  //<! do we use real storages (store QKDKey on HDD)?

    	std::map<Address, Connection> m_destinations; //<! map of QKD destinations including buffers

        std::vector<Ptr<QKDBuffer> > m_buffers; //<!  Buffers associated to this QKD manager
 
    }; 
}  
// namespace ns3

#endif /* PriorityQueue */
