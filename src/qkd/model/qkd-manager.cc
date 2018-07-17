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

//#define NS_LOG_APPEND_CONTEXT                                   \
//  if (GetObject<Node> ()) { std::clog << "[node " << GetObject<Node> ()->GetId () << "] "; }
 */

#include "ns3/log.h" 
#include "ns3/qkd-crypto.h"
#include "ns3/object-vector.h"
#include "ns3/qkd-internal-tag.h"
#include "ns3/qkd-manager.h"
#include "ns3/qkd-packet-filter.h"
#include "ns3/net-device-queue-interface.h"
#include "ns3/pointer.h"
#include "ns3/uinteger.h" 
#include <math.h>       /* exp */
#include <cmath>


namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDManager");

NS_OBJECT_ENSURE_REGISTERED (QKDManager);

TypeId QKDManager::GetTypeId (void) 
{
  static TypeId tid = TypeId ("ns3::QKDManager")
    .SetParent<Object> ()
    .AddConstructor<QKDManager> ()
    .AddAttribute ("BufferList", "The list of buffers associated to this Manager.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&QKDManager::m_buffers),
                   MakeObjectVectorChecker<QKDManager> ())
    ;
  return tid;
} 
QKDManager::QKDManager () 
{ 
    NS_LOG_FUNCTION (this);   
    m_linksThresholdHelpValue = 0; 
}
 
QKDManager::~QKDManager ()
{
}
 
void 
QKDManager::DoInitialize (void)
{
    NS_LOG_FUNCTION (this); 
    Object::DoInitialize ();
}
 
void 
QKDManager::DoDispose ()
{
    NS_LOG_FUNCTION (this); 
    for (std::vector<Ptr<QKDBuffer> >::iterator i = m_buffers.begin ();
       i != m_buffers.end (); i++)
    {
      Ptr<QKDBuffer> device = *i;
      device->Dispose ();
      *i = 0;
    }
    m_buffers.clear (); 

    std::map<Address, QKDManager::Connection >::iterator j; 
    for (j = m_destinations.begin (); !(j == m_destinations.end ()); j++){ 
        j->second.QKDNetDeviceSrc = 0;
        j->second.QKDNetDeviceDst = 0;
        j->second.IPNetDeviceSrc = 0;
        j->second.IPNetDeviceDst = 0;
        j->second.buffer = 0;
        j->second.crypto = 0;
        j->second.socket = 0;
        j->second.socketSink = 0;   
    }
    
    Object::DoDispose ();
}

void
QKDManager::UseRealStorages(const bool& useRealStorages){
    m_useRealStorages = useRealStorages;
}

void
QKDManager::AddNewLink (  
    Ptr<QKDNetDevice>       QKDNetDeviceSrc,
    Ptr<QKDNetDevice>       QKDNetDeviceDst,
    Ptr<NetDevice>          IPNetDeviceSrc,
    Ptr<NetDevice>          IPNetDeviceDst,
    Ptr<QKDCrypto>          Crypto,
    Ptr<Socket>             socket,
    Ptr<Socket>             socketSink,
    std::string             socketType,
    uint32_t                underlayPortNumber, 
    Ipv4InterfaceAddress    IPQKDSrc,   //QKD IP Src Address - overlay device
    Ipv4InterfaceAddress    IPQKDDst,   //QKD IP Dst Address - overlay device 
    Ipv4InterfaceAddress    IPSrc,      //IP Src Address - underlay device
    Ipv4InterfaceAddress    IPDst,      //IP Dst Address - underlay device 
    bool                    isMaster,  
    uint32_t                Mmin, 
    uint32_t                Mthr, 
    uint32_t                Mmax, 
    uint32_t                Mcurrent,
    uint32_t                channelID
)
{  
    NS_LOG_FUNCTION (this); 
 
    NS_ASSERT (IPQKDSrc.GetMask () == IPQKDDst.GetMask ());

    Ptr<Node> a = IPNetDeviceSrc->GetNode();
    Ptr<Node> b = IPNetDeviceDst->GetNode();
    
    struct QKDManager::Connection newConnection; 

    newConnection.QKDNetDeviceSrc = QKDNetDeviceSrc;
    newConnection.QKDNetDeviceDst = QKDNetDeviceDst;
    newConnection.IPNetDeviceSrc  = IPNetDeviceSrc;
    newConnection.IPNetDeviceDst  = IPNetDeviceDst;



    newConnection.isMaster = isMaster;
    newConnection.crypto = Crypto;
    newConnection.socket = socket;
    newConnection.socketSink = socketSink;
    newConnection.socketType = socketType; 
    newConnection.underlayPortNumber = underlayPortNumber; 
    newConnection.channelID = channelID;

    newConnection.IPQKDSrc = IPQKDSrc;
    newConnection.IPQKDDst = IPQKDDst;
    newConnection.IPSrc = IPSrc;
    newConnection.IPDst = IPDst; 

    newConnection.publicChannelMetric = 0;
    newConnection.quantumChannelMetric = 0;
 
    
    // Only one buffer can exist per connection between two nodes!
    // It is possible to implement multiple number of links,
    // but if the source and the destination of the link is the same, 
    // these links belong to the same connection and they sohuld use the same buffer.
    /*
    std::map<Address, QKDManager::Connection >::iterator i = FetchConnection ( IPNetDeviceSrc.GetAddress() );
    if (i != m_destinations.end ()){
        bufferExist = true;
        newConnection.buffer = i->second.buffer; 
        newConnection.bufferId = i->second.bufferId;
        NS_LOG_FUNCTION (this << "BUFFER ALREADY EXISTS!");
    }
    */

    NS_LOG_FUNCTION (this << "CREATE NEW BUFFER!");
    newConnection.buffer = CreateObject<QKDBuffer> (a->GetId(), b->GetId(), m_useRealStorages );
    newConnection.buffer->SetAttribute ("Minimal",     UintegerValue (Mmin));
    newConnection.buffer->SetAttribute ("Maximal",     UintegerValue (Mmax));
    newConnection.buffer->SetAttribute ("Threshold",   UintegerValue (Mthr));
    newConnection.buffer->SetAttribute ("Current",     UintegerValue (Mcurrent));   
    m_buffers.push_back(newConnection.buffer); 
    newConnection.bufferId = newConnection.buffer->m_bufferID;

    NS_LOG_FUNCTION(this << "BUFFERID:" << newConnection.buffer->m_bufferID);  

    NS_LOG_FUNCTION(this << "QKDNetDeviceSrc:" << newConnection.QKDNetDeviceSrc);
    if(newConnection.QKDNetDeviceSrc != 0){
        NS_LOG_FUNCTION(this << "QKDNetDeviceSrc address:" << newConnection.QKDNetDeviceSrc->GetAddress() );
    }

    NS_LOG_FUNCTION(this << "QKDNetDeviceDst:" << newConnection.QKDNetDeviceDst);
    if(newConnection.QKDNetDeviceDst != 0){
        NS_LOG_FUNCTION(this << "QKDNetDeviceDst address:" << newConnection.QKDNetDeviceDst->GetAddress() );
    }

    NS_LOG_FUNCTION(this << "IPNetDeviceSrc:" << newConnection.IPNetDeviceSrc);
    if(newConnection.IPNetDeviceSrc != 0){
        NS_LOG_FUNCTION(this << "IPNetDeviceSrc address:" << newConnection.IPNetDeviceSrc->GetAddress() );
    }
    
    NS_LOG_FUNCTION(this << "IPNetDeviceDst:" << newConnection.IPNetDeviceDst);
    if(newConnection.IPNetDeviceDst != 0){
        NS_LOG_FUNCTION(this << "IPNetDeviceDst address:" << newConnection.IPNetDeviceDst->GetAddress() );
    }
    
    m_destinations.insert (std::make_pair (IPNetDeviceSrc->GetAddress (), newConnection));  
}
 

uint32_t 
QKDManager::GetNumberOfDestinations(){
    return m_destinations.size();
}

std::vector<QKDManager::addressGroup> 
QKDManager::GetMapOfSourceDestinationAddresses(){

    NS_LOG_FUNCTION (this);

    std::vector<addressGroup> m_links;

    std::map<Address, Connection >::const_iterator j; 

    for (j = m_destinations.begin (); !(j == m_destinations.end ()); j++){ 

        struct QKDManager::addressGroup detail;  

        //If only underlay network
        if( j->second.QKDNetDeviceSrc == 0){ 

            NS_LOG_FUNCTION (this << "\t Destination address found:" << j->second.IPSrc.GetLocal() );
        
            detail.destinationNode = j->second.IPNetDeviceDst->GetNode();
            detail.sourceAddress = j->second.IPSrc.GetLocal();
            detail.destinationAddress = j->second.IPDst.GetLocal();
            m_links.push_back(detail);

        //If overlay network
        }else{ 

            NS_LOG_FUNCTION (this << "\t Destination address found:" << j->second.IPQKDDst.GetLocal() );

            detail.destinationNode = j->second.QKDNetDeviceDst->GetNode();
            detail.sourceAddress = j->second.IPQKDSrc.GetLocal();
            detail.destinationAddress = j->second.IPQKDDst.GetLocal();
            m_links.push_back(detail);

        }

    }
    return m_links;
}

Ipv4Address
QKDManager::PopulateLinkStatusesForNeighbors(
    Ptr<Packet> p, 
    std::map<Ipv4Address, NeigborDetail> distancesToDestination,
    uint8_t tos,
    uint32_t& outputInterface
){
    NS_LOG_DEBUG (this << p << distancesToDestination.size() << (uint32_t) tos);

    Ipv4Address bestOutput;     
    return bestOutput;
}

uint32_t
QKDManager::FetchLinkThresholdHelpValue(){
    
    NS_LOG_FUNCTION(this << m_linksThresholdHelpValue);
    return m_linksThresholdHelpValue;
}

void        
QKDManager::CalculateLinkThresholdHelpValue(){

    NS_LOG_FUNCTION(this << m_linksThresholdHelpValue);
}

void
QKDManager::SetLinkThresholdValue( const uint32_t& proposedLaValue, const Address sourceAddress ){

    NS_LOG_FUNCTION (this << proposedLaValue << sourceAddress);
}

uint32_t
QKDManager::GetLinkThresholdValue(const Address sourceAddress ){

    NS_LOG_FUNCTION (this << sourceAddress);
    return 0;
}

std::map<Address, QKDManager::Connection >::iterator
QKDManager::FetchConnection(const Address sourceAddress){

    NS_LOG_FUNCTION (this << sourceAddress << m_destinations.size() );

    std::map<Address, QKDManager::Connection >::iterator i = m_destinations.find (sourceAddress);
    if (i == m_destinations.end ()){
        std::map<Address, QKDManager::Connection >::iterator j;
        for (j = m_destinations.begin (); !(j == m_destinations.end ()); j++){ 
            if (
                 (j->second.IPNetDeviceSrc != 0 && j->second.IPNetDeviceSrc->GetAddress() == sourceAddress) || 
                 (j->second.QKDNetDeviceSrc != 0 && j->second.QKDNetDeviceSrc->GetAddress() == sourceAddress)
             ) {
                return j;
            }
        }
    }
    return i;
}



Ptr<NetDevice>
QKDManager::GetSourceNetDevice (const Address address){
    
    NS_LOG_FUNCTION (this << "\t" << address);

    std::map<Address, Connection >::const_iterator j;
    for (j = m_destinations.begin (); !(j == m_destinations.end ()); j++){ 

        //if only underlay network
        if( j->second.QKDNetDeviceSrc == 0 && j->second.IPNetDeviceSrc->GetAddress() == address){ 
            NS_LOG_FUNCTION (this << "\t Destination address found:" << j->second.IPNetDeviceSrc->GetAddress() );
            NS_LOG_FUNCTION (this << "Src" << j->second.IPSrc.GetLocal() << "Dst" << j->second.IPDst.GetLocal() );
            return j->second.IPNetDeviceSrc;

        //if overlay network
        }else if( j->second.QKDNetDeviceSrc != 0 && j->second.QKDNetDeviceSrc->GetAddress() == address){ 
            NS_LOG_FUNCTION (this << "\t Destination address found:" << j->second.QKDNetDeviceSrc->GetAddress() ); 
            NS_LOG_FUNCTION (this << "Src" << j->second.IPQKDSrc.GetLocal() << "Dst" << j->second.IPQKDDst.GetLocal() );
            return j->second.QKDNetDeviceSrc;
        }
    }
    return 0;
}

bool
QKDManager::VirtualSendOverlay (Ptr<Packet> p, const Address& source, const Address& dst, uint16_t protocolNumber)
{
    return VirtualSend (p, source, dst, protocolNumber, 0);
}

bool
QKDManager::VirtualSend (
    Ptr<Packet> p, 
    const Address& source, 
    const Address& destination, 
    uint16_t protocolNumber, 
    uint8_t TxQueueIndex
){
    NS_LOG_FUNCTION ( this << "\t" << p->GetUid() << "\t" << p->GetSize() );
    NS_LOG_FUNCTION ( this << p );

    // packetCopy is unencrypted packet that is used for sniffing in netDevices (to create .pcap records that are readble)
    Ptr<Packet> packetCopy = p->Copy ();
  
    /*
    std::cout << "--------QKDManager::VirtualSend-----------\n";   
    std::cout << p->GetUid() << "\t" << p->GetSize() << "\n";
    p->Print(std::cout);
    std::cout << "\n\n";
    std::cout << "--------End of QKDManager::VirtualSend-----------\n";
    */

    //PERFORM ENCRYPTION and AUTHENTICATION
    Ptr<NetDevice> SourceDevice = GetSourceNetDevice(source);
    std::vector<Ptr<Packet> > processedPackets = ProcessOutgoingRequest (SourceDevice, p);


    NS_LOG_DEBUG(this << "****** processedPackets size ****** " << processedPackets.size() );

    if(processedPackets.size() > 0 ){
        typename std::vector<Ptr<Packet> >::iterator it = processedPackets.begin();
        for( ; it != processedPackets.end(); ++it){

            Ptr<Packet> packet = *it;
            if(packet == 0) 
                continue;
            else {
                
                NS_LOG_DEBUG (this << "\t" 
                    << packet->GetUid() 
                    << packet->GetSize() << "\t" 
                    << source <<  "\t" 
                    << destination <<  "\t"
                );  
                 
                return ForwardToSocket (packetCopy, packet, source, destination, protocolNumber, TxQueueIndex);
            }
        } 
    }else{
        
        NS_LOG_DEBUG (this << "\t" 
            << p->GetUid() 
            << p->GetSize() << "\t" 
            << source <<  "\t" 
            << destination
        );

    }
    NS_LOG_DEBUG(this << "****** WE DO NOT KNOW WHERE TO FORWARD THIS PACKET ******" << p << source << destination);
    return false; 
}

bool
QKDManager::ForwardToSocket (
    Ptr<Packet> originalPacket,
    Ptr<Packet> packet, 
    const Address& source, 
    const Address& destination,      
    uint16_t protocolNumber,
    uint8_t TxQueueIndex
){

    NS_LOG_FUNCTION (this << "\t" 
        << originalPacket->GetUid() 
        << originalPacket->GetSize() << "\t" 
        << packet->GetUid() 
        << packet->GetSize() << "\t" 
    );  

    //if unicast delivery
    std::map<Address, QKDManager::Connection >::iterator i = FetchConnection (source);
    if (i != m_destinations.end ()){

        /**
        *   Since some routing protocols might not be aware of QKDbuffers and QKD materials in these buffers, 
        *   we need to analyze the status of QKD buffers priori processing of packet. If there is enough key material
        *   packet is processed. Otherwise, packet is silently discarded
        */
        if(CheckForResourcesToProcessThePacket(packet, source) == false){
            NS_LOG_DEBUG (this << "WE DO NOT HAVE ENOUGH KEY MATERIAL TO PROCESS THIS PACKET!\n Discarding this path!" << "\n");
            return false;
        }
 
        //if only underlay network
        if( i->second.QKDNetDeviceSrc == 0){


            NS_LOG_DEBUG (this 
                << "Sending UNICAST to socket\t" << i->second.socket << "\t"  
                << "IPQKDSrc:\t" << i->second.IPQKDSrc.GetLocal() << "\t" 
                << "IPQKDDst:\t" << i->second.IPQKDDst.GetLocal() << "\t" 
                << "IPNetDeviceSrc:\t" << i->second.IPNetDeviceSrc->GetAddress() << "\t" 
                << "IPNetDeviceDst:\t" << i->second.IPNetDeviceDst->GetAddress() << "\t" 
                << "IPSrc:\t" << i->second.IPSrc.GetLocal() << "\t" 
                << "IPDst:\t" << i->second.IPDst.GetLocal() << "\t" 
                << "PORT:\t" << i->second.underlayPortNumber << "\t"
                << "PacketID:\t" << packet->GetUid() << "\t"
                << "From:\t" << source << "\t"
                << "To:\t" << destination << "\t"
            );


            NS_LOG_DEBUG (this << "SINGLE TCP/IP Network" << i->second.QKDNetDeviceSrc);

            Ptr<NetDeviceQueueInterface> m_devQueueIface = i->second.IPNetDeviceSrc->GetObject<NetDeviceQueueInterface> ();
            if ( m_devQueueIface!= 0 &&  m_devQueueIface->GetTxQueue (TxQueueIndex)->IsStopped ())
            { 
                NS_LOG_DEBUG (this << "NetDevice " << i->second.IPNetDeviceSrc << " queue is stopped! Aborting!");             
                return false;
                
            }else{ 

                i->second.IPNetDeviceSrc->SniffPacket(originalPacket);
                i->second.IPNetDeviceSrc->Send (
                    packet,
                    i->second.IPNetDeviceDst->GetAddress (),
                    protocolNumber
                );

                NS_LOG_DEBUG(this << "******PACKET LEFT SINGLE TCP/IP NETWORK (UNICAST)******");

            }
            
            return true;

        //if overlay network
        }else{

            NS_LOG_INFO (this 
                << "Sending UNICAST to socket\t" << i->second.socket << "\t"  
                << "IPQKDSrc:\t" << i->second.IPQKDSrc.GetLocal() << "\t" 
                << "IPQKDDst:\t" << i->second.IPQKDDst.GetLocal() << "\t" 
                << "IPSrc:\t" << i->second.IPSrc.GetLocal() << "\t" 
                << "IPDst:\t" << i->second.IPDst.GetLocal() << "\t" 
                << "PORT:\t" << i->second.underlayPortNumber << "\t"
                << "PacketID:\t" << packet->GetUid() << "\t"
                << "From:\t" << source << "\t"
                << "To:\t" << destination << "\t"
            );

            NS_LOG_FUNCTION (this << "OVERLAY Network" << i->second.QKDNetDeviceSrc);
            NS_LOG_FUNCTION (this << "SocketType:" << i->second.socketType);

            if(i->second.socketType == "ns3::TcpSocketFactory"){
                i->second.socket->Send (packet);

            }else if(i->second.socketType == "ns3::UdpSocketFactory"){
                i->second.socket->SendTo (
                    packet, 
                    0, 
                    InetSocketAddress (
                        i->second.IPDst.GetLocal(),
                        i->second.underlayPortNumber
                    )
                );    
            }

            NS_LOG_FUNCTION (this << "socketType:" << i->second.socketType);
            NS_LOG_FUNCTION (this << "******PACKET LEFT OVERLAY NETWORK (UNICAST) ******"); 

            return true;
        }

    } else{
        NS_LOG_INFO(this << "--------- We do not have QKD link to desired destination! ------------");
    }
 
    return false;
}

void 
QKDManager::VirtualReceiveSimpleNetwork (Ptr<NetDevice> device, Ptr<const Packet> packet,
                              uint16_t protocol, const Address &from, const Address &to,
                              NetDevice::PacketType packetType
            )
{
    
    NS_LOG_DEBUG (this << device << packet->GetUid() << packet->GetSize() << protocol << from << to << packetType);    

    std::map<Address, QKDManager::Connection >::iterator i = FetchConnection (device->GetAddress());

    if (i != m_destinations.end ()){        

        if(i->second.IPNetDeviceSrc == device){

            //PERFORM DECRYPTION and AUTHENTICATION-CHECK
            Ptr<Packet> packetCopy = packet->Copy ();
            std::vector<Ptr<Packet> > processedPackets;

            //It is possible that routing protocol uses LoopbackRoute. In that case, there is no need to perform
            //decryption/authentication operations
            if(from == to){ 
                NS_LOG_DEBUG ( this << "#### ROUTING TO MY SELF from " << from << " to " << to);
                processedPackets.push_back(packetCopy);
            }else{
                processedPackets = ProcessIncomingRequest (i->second.IPNetDeviceSrc, packetCopy);
            }

            NS_LOG_DEBUG ( this << "We have in total " << processedPackets.size() << " decrypted packets!" );
            
            //ForwardUP
            typename std::vector<Ptr<Packet> >::iterator it = processedPackets.begin();
            for( ; it != processedPackets.end(); ++it){

                Ptr<const Packet> p = *it;
                if(p != 0){

                    NS_LOG_DEBUG (this << "Starting forward up process for packet:" << p << " pid " << p->GetUid() << " of size " << p->GetSize());
                    /*
                    std::cout << "--------QKDManager::VirtualReceiveSimpleNetwork-----------\n";   
                    std::cout << p->GetUid() << "\t" << p->GetSize() << "\n";
                    p->Print(std::cout);
                    std::cout << "\n\n";
                    std::cout << "--------End of QKDManager::VirtualReceiveSimpleNetwork-----------\n";
                    */
                    Ptr<Node> node = device->GetNode();
                    NS_ASSERT (node != 0);

                    Ptr<TrafficControlLayer> tc = node->GetObject<TrafficControlLayer> ();
                    NS_ASSERT (tc != 0);
 
                    device->SniffPacket(p);
                    tc->Receive(device, p, protocol, from, to, packetType);

                }else{
                    NS_LOG_FUNCTION(this << "Packet is EMPTY!" << p);
                }
            }
        }
    }
}
 
void 
QKDManager::VirtualReceive (Ptr<Socket> socket)
{       
    NS_LOG_FUNCTION(this << socket);

    std::map<Address, Connection >::const_iterator i; 
    for (i = m_destinations.begin (); !(i == m_destinations.end ()); i++){        
        Ptr<NetDevice> sNetDevice = socket->GetBoundNetDevice();
        Ptr<NetDevice> sSinkNetDevice = i->second.socketSink->GetBoundNetDevice();                
        if( sNetDevice != 0 && sSinkNetDevice != 0 && sNetDevice->GetAddress() == sSinkNetDevice->GetAddress() ){
            NS_LOG_FUNCTION (this << "QKDNetDevice Found!");
            break;
        } 
    }

    if( i != m_destinations.end () ){

        NS_LOG_FUNCTION(this << i->second.socketType);

        /////////////////////////////////TCP SOCKET//////////////////////////////////////////
        if(i->second.socketType == "ns3::TcpSocketFactory"){
            NS_LOG_FUNCTION (this << "It is TCP underlay socket!");

            Ptr<Packet> packet;
            Address from;
            while ((packet = socket->RecvFrom (from)))
            {
                if (packet->GetSize () == 0)
                { //EOF
                    break;
                }

                NS_LOG_FUNCTION(this << packet->GetUid() << packet->GetSize() );
                
                //PERFORM DECRYPTION and AUTHENTICATION-CHECK
                std::vector<Ptr<Packet> > processedPackets = ProcessIncomingRequest (i->second.QKDNetDeviceSrc, packet);

                typename std::vector<Ptr<Packet> >::iterator it = processedPackets.begin();
                for( ; it != processedPackets.end(); ++it){

                    Ptr<Packet> p = *it;
                    if (p != 0){
                        i->second.QKDNetDeviceSrc->Receive (
                            p, 
                            0x0800, 
                            i->second.QKDNetDeviceDst->GetAddress (), //who is sending packet
                            i->second.QKDNetDeviceSrc->GetAddress (), //who is receiving packet
                            NetDevice::PACKET_HOST
                        );
                     
                        if (InetSocketAddress::IsMatchingType (from))
                        {
                          NS_LOG_FUNCTION (this << "\nAt time " << Simulator::Now ().GetSeconds ()
                                       << "s packet sink received "
                                       << p->GetSize () << " bytes from "
                                       << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                                       << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
                                       << " size " << p->GetSize () << " bytes");
                        }
                        NS_LOG_FUNCTION (this << " Received packet : " << p->GetUid()  << " of size " << p->GetSize() << " on socket " << socket);
                    }
                    NS_LOG_FUNCTION (this << p);  
                    

                }   

            }

        //////////////////////////////////UDP SOCKET/////////////////////////////////////////
        } else if(i->second.socketType == "ns3::UdpSocketFactory"){
            
            NS_LOG_FUNCTION (this << "It is UDP underlay socket!");

            Ptr<Packet> packet = socket->Recv (65535, 0); 

            //PERFORM DECRYPTION and AUTHENTICATION-CHECK
            std::vector<Ptr<Packet> > processedPackets = ProcessIncomingRequest (i->second.QKDNetDeviceSrc, packet);

            typename std::vector<Ptr<Packet> >::iterator it = processedPackets.begin();
            for( ; it != processedPackets.end(); ++it){

                Ptr<Packet> p = *it;

                NS_LOG_FUNCTION (this << "Delivering packet " << p << " to " << i->second.QKDNetDeviceSrc);

                if(p != 0){
                    i->second.QKDNetDeviceSrc->Receive (
                        p, 
                        0x0800, 
                        i->second.QKDNetDeviceDst->GetAddress (), //who is sending packet
                        i->second.QKDNetDeviceSrc->GetAddress (), //who is receiving packet
                        NetDevice::PACKET_HOST
                    );
                    NS_LOG_FUNCTION (this << " Received packet : " << p->GetUid()  << " of size " << p->GetSize() << " on socket " << socket);
                }

                NS_LOG_FUNCTION (this << p);

            }

        }
    }

    /*
    std::cout << "--------QKDManager::VirtualReceive-----------\n";   
    std::cout << packet->GetUid() << "\t" << packet->GetSize() << "\n";
    packet->Print(std::cout);
    std::cout << "\n\n";
    std::cout << "--------End of QKDManager::VirtualReceive-----------\n";   
    */ 
}
 
void 
QKDManager::HandleAccept (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&QKDManager::VirtualReceive, this)); 
}

void 
QKDManager::ConnectionSucceeded (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDManager Connection succeeded");
//    m_connected = true; 
}

void 
QKDManager::ConnectionFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDManager, Connection Failed");
}

Ptr<Node> 
QKDManager::GetDestinationNode (const Address sourceAddress) 
{
    NS_LOG_FUNCTION (this << sourceAddress);
    std::map<Address, QKDManager::Connection >::iterator i = FetchConnection (sourceAddress);
    if (i != m_destinations.end ())
        return i->second.IPNetDeviceDst->GetNode (); 
    return 0;
}

QKDManager::Connection
QKDManager::GetConnectionDetails (const Address sourceAddress)
{
    NS_LOG_FUNCTION (this << sourceAddress);
    std::map<Address, QKDManager::Connection >::iterator i = FetchConnection (sourceAddress);
    if (i != m_destinations.end ())
        return i->second;

    struct QKDManager::Connection newConnection; 
    return newConnection;
}

QKDManager::Connection
QKDManager::GetConnectionDetails (const uint32_t& bufferId)
{
    NS_LOG_FUNCTION (this << bufferId);
    std::map<Address, Connection >::const_iterator i; 
    for (i = m_destinations.begin (); !(i == m_destinations.end ()); i++){
        if( i->second.bufferId == bufferId )
            return i->second;
    }

    struct QKDManager::Connection newConnection; 
    return newConnection;
}


uint32_t 
QKDManager::GetBufferPosition (const Address& sourceAddress)
{
    NS_LOG_FUNCTION (this << sourceAddress);

    Ptr<QKDBuffer> tempBuffer;  
    
    std::map<Address, QKDManager::Connection >::iterator i = FetchConnection (sourceAddress);
    if (i != m_destinations.end ()){ 
        tempBuffer = i->second.buffer;
        uint32_t a = 0;
        for (std::vector<Ptr<QKDBuffer> >::iterator i = m_buffers.begin (); !(i == m_buffers.end ()); i++){
            if( **i == *tempBuffer ){
                return a;
            } 
            a++;
        } 
    } 

    return 0;
}


Ptr<QKDBuffer>
QKDManager::GetBufferBySourceAddress (const Address& sourceAddress)
{
    NS_LOG_FUNCTION (this << sourceAddress); 
  
    std::map<Address, QKDManager::Connection >::iterator i = FetchConnection (sourceAddress);
    if (i != m_destinations.end ())
        return i->second.buffer;

    return 0;
}

Ptr<QKDBuffer>
QKDManager::GetBufferByBufferPosition (const uint32_t& bufferPosition)
{
    NS_LOG_FUNCTION (this << bufferPosition << m_buffers.size());
    
    if(bufferPosition < m_buffers.size())  
        return m_buffers[bufferPosition]; 

    return 0;
}

uint32_t 
QKDManager::GetNBuffers (void) const
{
    NS_LOG_FUNCTION (this);
    return m_buffers.size ();
}

uint8_t 
QKDManager::FetchStatusForDestinationBuffer(Ptr<NetDevice> dev)
{   
    NS_LOG_FUNCTION (this  << dev );

    if(dev == 0) 
        return 0;

    Ptr<Node> node = dev->GetNode();
    if(node != 0)
        NS_LOG_FUNCTION (this  << node->GetId() << dev );    

    std::map<Address, Connection >::const_iterator i; 
    for (i = m_destinations.begin (); !(i == m_destinations.end ()); i++){

        //if simple single TCP/IP network OR if overlay network
        if( (i->second.QKDNetDeviceSrc == 0 && i->second.IPNetDeviceSrc == dev) ||
            i->second.QKDNetDeviceSrc == dev
        ){  
            uint32_t output = i->second.buffer->FetchState();
            NS_LOG_FUNCTION (this  << "status is " << (uint32_t) output );
            return output;
        }
    }
    NS_LOG_FUNCTION (this  << "status is 0" );
    return 0;
}

std::vector<Ptr<Packet> >
QKDManager::ProcessIncomingRequest (Ptr<NetDevice> dev, Ptr<Packet> p)
{
    NS_LOG_FUNCTION (this << dev->GetNode()->GetId() << dev << p->GetUid() << p->GetSize() << p ); 
 
    QKDInternalTag tag;
    std::vector<Ptr<Packet> > packetOutput;

    if(p->PeekPacketTag(tag)) {
        //This packet is already processed
        NS_LOG_FUNCTION(this << "Packet " << p->GetUid() << " was already decrypted/deauthenticated!" << p->GetUid() << p);
        return packetOutput;
    }

    NS_LOG_FUNCTION(this << "Packet " << p->GetUid() << " is ready to be decrypted/deauthenticated!" << p->GetUid() << p); 

    Ptr<Packet> packet = p->Copy ();

    std::map<Address, Connection >::const_iterator i; 
    for (i = m_destinations.begin (); !(i == m_destinations.end ()); i++){

        //if simple single TCP/IP network OR if overlay network
        if( (i->second.QKDNetDeviceSrc == 0 && i->second.IPNetDeviceSrc == dev) ||
            i->second.QKDNetDeviceSrc == dev
        ){  

            if(i->second.crypto == 0)
                continue;

            packetOutput = i->second.crypto->ProcessIncomingPacket(
                packet, 
                i->second.buffer,
                i->second.channelID
            );  
            UpdatePublicChannelMetric (i->first);
            UpdateQuantumChannelMetric(i->first);
            break;
        }
    } 

    NS_LOG_FUNCTION(this << "Size of packet output:" << packetOutput.size() );
    return packetOutput;
}

std::vector<Ptr<Packet> >
QKDManager::ProcessOutgoingRequest (Ptr<NetDevice> dev, Ptr<Packet> p)
{
    NS_LOG_FUNCTION (this << dev << p->GetUid() << p->GetSize() << p );  
 
    std::vector<Ptr<Packet> > processedPackets;
    QKDInternalTag tag;
    if(p->PeekPacketTag(tag)) {
        //p->RemovePacketTag(tag);
    } else { 
        NS_LOG_FUNCTION ( 
            this << "No QKDInternalTag detected!" 
            << "No encryption/authentication needed (no MarkEncryt or MarkAuthenticated called before)" 
        );
        tag.SetAuthenticateValue ( 0 ); 
        tag.SetEncryptValue ( 0 );
        tag.SetMaxDelayValue ( 10 );
        p->AddPacketTag(tag); 
    }
    
    /*
    std::cout << "\n###################################################\n";
    p->Print(std::cout);
    std::cout << "\n###################################################\n";
    */

    NS_LOG_FUNCTION(this << "Packet is ready to be ecrypted/authenticated!" << p->GetUid() << p);  
    NS_LOG_FUNCTION(this << "Packet to be encrypted:"      << (uint32_t) tag.GetEncryptValue() ); 
    NS_LOG_FUNCTION(this << "Packet to be authenticated:"  << (uint32_t) tag.GetAuthenticateValue() ); 
    NS_LOG_FUNCTION(this << "Packet (maxDelay):"  << (uint32_t) tag.GetMaxDelayValue() ); 
    
    Ptr<Packet> packet = p->Copy ();
    std::map<Address, Connection >::const_iterator i; 
    for (i = m_destinations.begin (); !(i == m_destinations.end ()); i++){


        //if simple single TCP/IP network OR if overlay network
        if( (i->second.QKDNetDeviceSrc == 0 && i->second.IPNetDeviceSrc == dev) ||
            i->second.QKDNetDeviceSrc == dev
        ){ 

            NS_LOG_FUNCTION (this 
                << "Sending from " 
                << i->second.IPQKDSrc  
                << " to " 
                << i->second.IPQKDDst 
                << " using buffer: " 
                << i->second.buffer->m_bufferID
            );

            if(i->second.crypto == 0)
                continue;

            processedPackets = i->second.crypto->ProcessOutgoingPacket(
                packet, 
                i->second.buffer,
                i->second.channelID
            );                
            NS_LOG_FUNCTION(this << "Encryption/Authentication completed!" 
                << "PacketID:"
                << packet->GetUid()
                << "PacketSize:"
                << packet->GetSize()
            );    
            UpdatePublicChannelMetric (i->first);
            UpdateQuantumChannelMetric(i->first);
            break;
        }
    }
    return processedPackets;
}

double
QKDManager::FetchPublicChannelPerformance (Ipv4Address nextHop){

    NS_LOG_FUNCTION (this << nextHop);
    return 0;
}
  
uint32_t
QKDManager::FetchMaxNumberOfRecordedKeyChargingTimePeriods (Ipv4Address nextHop){

    NS_LOG_FUNCTION (this << nextHop);
    return 0;
}




//UPDATE PUBLIC CHANNEL METRIC OF THIS CHANNEL
void
QKDManager::UpdatePublicChannelMetric(const Address sourceAddress){
  
    NS_LOG_FUNCTION (this << sourceAddress);
}


//UPDATE QUANTUM CHANNEL METRIC OF THIS CHANNEL
void
QKDManager::UpdateQuantumChannelMetric(const Address sourceAddress){

    NS_LOG_FUNCTION (this << sourceAddress);
}

bool
QKDManager::AddNewKeyMaterial (const Address sourceAddress, uint32_t& newKey)
{
    NS_LOG_FUNCTION (this << sourceAddress << newKey);

    std::map<Address, QKDManager::Connection >::iterator i = FetchConnection ( sourceAddress );
    if (i != m_destinations.end ()){

        NS_LOG_DEBUG ( this << "\t" << "sourceAddress: \t" << i->first );
        NS_LOG_DEBUG (this << "Adding new key to the buffer! \t" << "keySize:\t" << newKey << "\n" );

        bool response = i->second.buffer->AddNewContent(newKey); 
        UpdatePublicChannelMetric (i->first);
        UpdateQuantumChannelMetric(i->first);
        CalculateLinkThresholdHelpValue();
        return response;
    
    }
    return false;
}
   
bool
QKDManager::IsMarkedAsEncrypt (Ptr<Packet> p)
{
    NS_LOG_FUNCTION (this << p->GetUid());
     
    QKDInternalTag tag;
    if(p->PeekPacketTag(tag)){ 
       NS_LOG_FUNCTION (this << tag.GetEncryptValue());
       return (tag.GetEncryptValue() > 0);
    } 
    NS_LOG_FUNCTION (this << false);
    return false; 
}

Ptr<Packet> 
QKDManager::MarkEncrypt (Ptr<Packet> p)
{
    NS_LOG_FUNCTION (this << p->GetUid() << p->GetSize() ); 

    //default values are OTP and VMAC
    return MarkEncrypt(p, QKDCRYPTO_OTP, QKDCRYPTO_AUTH_VMAC);  
}

Ptr<Packet> 
QKDManager::MarkMaxDelay (Ptr<Packet> p,uint32_t delay)
{
    NS_LOG_FUNCTION (this << p->GetUid() << p->GetSize() << delay );  
    
    QKDInternalTag tag;
    if(p->PeekPacketTag(tag)){
        p->RemovePacketTag(tag);
    } 
    tag.SetMaxDelayValue ( delay ); 
    p->AddPacketTag(tag);
    return p; 
} 

Ptr<Packet> 
QKDManager::MarkAuthenticate (Ptr<Packet> p)
{
    NS_LOG_FUNCTION (this << p->GetUid() << p->GetSize() ); 
    return MarkEncrypt(p, 0, QKDCRYPTO_AUTH_VMAC);  
}

Ptr<Packet> 
QKDManager::MarkEncrypt (Ptr<Packet> p, uint8_t encryptionType, uint8_t authneticationType)
{
    NS_LOG_FUNCTION (this << p->GetUid() << p->GetSize() << (uint32_t) encryptionType <<  (uint32_t) authneticationType); 

    QKDInternalTag tag;
    if(p->PeekPacketTag(tag)){
        p->RemovePacketTag(tag);
    } 
    tag.SetEncryptValue ( encryptionType );
    tag.SetAuthenticateValue ( authneticationType );
    p->AddPacketTag(tag);
    return p; 
}

bool
QKDManager::CheckForResourcesToProcessThePacket(
    Ptr<Packet> p,
    const Address sourceAddress
){

    NS_LOG_WARN(this << "\t" << p->GetUid() << "\t" << p->GetSize() << "\t" << sourceAddress);
    
    uint32_t tos = FetchPacketTos(p);
    uint32_t TOSband = TosToBand(tos);

    NS_LOG_WARN(this << "\t" << p << "\t" << sourceAddress << "\t" << TOSband);

    return CheckForResourcesToProcessThePacket(
        p,
        sourceAddress,
        TOSband
    );
}

bool
QKDManager::CheckForResourcesToProcessThePacket(
    Ptr<Packet> p,
    const Address sourceAddress,
    const uint32_t& TOSband 
){

    NS_LOG_WARN(this << "\tp:" << p << "\tsourceAddress:" << sourceAddress << "\tTOSband: " << TOSband); 

    std::map<Address, QKDManager::Connection >::iterator i = FetchConnection (sourceAddress);  
    if (i != m_destinations.end ()){
        NS_LOG_WARN (this << "\t Destination found!");
        NS_LOG_WARN (this << "\t first:\t" << i->first);
        NS_LOG_WARN (this << "\t IPNetDeviceSrc:\t" << i->second.IPNetDeviceSrc);
        NS_LOG_WARN (this << "\t IPNetDeviceDst:\t" << i->second.IPNetDeviceDst);
        NS_LOG_WARN (this << "\t BufferID:\t" << i->second.bufferId);

        NS_ASSERT (i->second.buffer != 0);
        NS_ASSERT (i->second.crypto != 0);

        NS_LOG_WARN (this << "\t BufferID:\t" << i->second.buffer);
        NS_LOG_WARN (this << "\t BufferID:\t" << i->second.buffer->m_bufferID);

        return i->second.crypto->CheckForResourcesToProcessThePacket(
            p,
            TOSband,
            i->second.buffer
        );
    }
    return false;
}

uint32_t
QKDManager::FetchPacketTos(Ptr<Packet> p){

    NS_LOG_FUNCTION(this << p );
    NS_LOG_FUNCTION(this << "\t" << p->GetUid() << "\t" << p->GetSize() );

    uint8_t tos = 0;

    SocketIpTosTag ipTosTag;
    QKDInternalTOSTag temp_qkdNextHopTag; 
 
    if ( p->PeekPacketTag (ipTosTag) )
    {
        tos = ipTosTag.GetTos ();
        NS_LOG_WARN(this << "\t" << "Found TOS tag using SocketIpTosTag; value:" << "\t" << (uint32_t) tos);

    }else if( p->PeekPacketTag(temp_qkdNextHopTag) ){ 

        tos = temp_qkdNextHopTag.GetTos();
        NS_LOG_WARN(this << "\t" << "Found TOS tag using QKDInternalTOSTag; value:" << "\t" << (uint32_t) tos);

    }

    NS_LOG_FUNCTION( this << "\t packet:" << p << "\t tos:" << (uint32_t) tos );
    return tos;
}

uint32_t
QKDManager::TosToBand(const uint32_t& tos){

    NS_LOG_FUNCTION( this << "\t" << tos );

    Ptr<PfifoFastQKDPacketFilter> filter = CreateObject<PfifoFastQKDPacketFilter> ();
    uint32_t priority = filter->TosToBand(Socket::IpTos2Priority (tos));

    NS_LOG_WARN( this << "\t tos:" << tos << "\t priority:" << (uint32_t) Socket::IpTos2Priority(tos) << "\t band:" << filter->TosToBand(Socket::IpTos2Priority (tos)) );

    /*   

        for (uint32_t i = 0; i <= 30; i++){
            std::cout << "tos (decimal):" << i << " - priority:" << (uint32_t) Socket::IpTos2Priority(i) << " - band:" << filter->TosToBand(Socket::IpTos2Priority (i)) <<  "\n";
        } 

        enum SocketPriority {
            NS3_PRIO_BESTEFFORT = 0,
            NS3_PRIO_FILLER = 1,
            NS3_PRIO_BULK = 2,
            NS3_PRIO_INTERACTIVE_BULK = 4,
            NS3_PRIO_INTERACTIVE = 6,
            NS3_PRIO_CONTROL = 7
        };

        tos (decimal):0 - priority:0 - band:1
        tos (decimal):1 - priority:0 - band:1
        tos (decimal):2 - priority:0 - band:1
        tos (decimal):3 - priority:0 - band:1
        tos (decimal):4 - priority:0 - band:1
        tos (decimal):5 - priority:0 - band:1
        tos (decimal):6 - priority:0 - band:1
        tos (decimal):7 - priority:0 - band:1
        tos (decimal):8 - priority:2 - band:2
        tos (decimal):9 - priority:2 - band:2
        tos (decimal):10 - priority:2 - band:2
        tos (decimal):11 - priority:2 - band:2
        tos (decimal):12 - priority:2 - band:2
        tos (decimal):13 - priority:2 - band:2
        tos (decimal):14 - priority:2 - band:2
        tos (decimal):15 - priority:2 - band:2
        tos (decimal):16 - priority:6 - band:0
        tos (decimal):17 - priority:6 - band:0
        tos (decimal):18 - priority:6 - band:0
        tos (decimal):19 - priority:6 - band:0
        tos (decimal):20 - priority:6 - band:0
        tos (decimal):21 - priority:6 - band:0
        tos (decimal):22 - priority:6 - band:0
        tos (decimal):23 - priority:6 - band:0
        tos (decimal):24 - priority:4 - band:1
        tos (decimal):25 - priority:4 - band:1
        tos (decimal):26 - priority:4 - band:1
        tos (decimal):27 - priority:4 - band:1
        tos (decimal):28 - priority:4 - band:1
        tos (decimal):29 - priority:4 - band:1
        tos (decimal):30 - priority:4 - band:1 
    */

    /*
     * PfifoFastQKDPacketFilter is the filter to be added to the PfifoFast
     * queue disc to simulate the behavior of the pfifo_fast Linux queue disc.
     * 
     * Two modes of operation are provided. In PF_MODE_TOS mode, packets are
     * classified based on the TOS byte (originally defined by RFC 1349:
     * http://www.ietf.org/rfc/rfc1349.txt)
     *
     *               0     1     2     3     4     5     6     7
     *           +-----+-----+-----+-----+-----+-----+-----+-----+
     *           |   PRECEDENCE    |          TOS          | MBZ |
     *           +-----+-----+-----+-----+-----+-----+-----+-----+
     *
     * where MBZ stands for 'must be zero'.
     *
     * In the eight-bit legacy TOS byte, there were five lower bits for TOS
     * and three upper bits for Precedence.  Bit 7 was never used.  Bits 6-7
     * are now repurposed for ECN.  The below TOS values correspond to
     * bits 3-7 in the TOS byte (i.e. including MBZ), omitting the precedence
     * bits 0-2.
     *
     * TOS  | TOS Decimal | Bits | Means                   | Linux Priority | Band
     * -----|-------------|------|-------------------------|----------------|-----
     * 0x0  |     0-7     | 0    |  Normal Service         | 0 Best Effort  |  1  
     * 0x8  |     8-15    | 4    |  Real-time service      | 2 Bulk         |  2 
     * 0x10 |     16-23   | 8    |  PREMIUM Service        | 6 Interactive  |  0 
     * 0x18 |     24-30   | 12   |  Normal service         | 4 Int. Bulk    |  1
     */
    return priority;
}


 
} // namespace ns3
