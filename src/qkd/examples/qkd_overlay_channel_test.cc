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


// Network topology
//
//       n0 ---p2p-- n1 --p2p-- n2
//        |---------qkd---------|
//
// - udp flows from n0 to n2

#include <fstream>
#include "ns3/core-module.h" 
#include "ns3/qkd-helper.h" 
#include "ns3/qkd-app-charging-helper.h"
#include "ns3/qkd-graph-manager.h" 
#include "ns3/applications-module.h"
#include "ns3/internet-module.h" 
#include "ns3/flow-monitor-module.h" 
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/gnuplot.h" 
#include "ns3/qkd-send.h"

#include "ns3/aodv-module.h"
#include "ns3/olsr-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"

#include "ns3/aodvq-module.h" 
#include "ns3/dsdvq-module.h"  

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("QKD_CHANNEL_TEST");
  

uint32_t m_bytes_total = 0; 
uint32_t m_bytes_received = 0; 
uint32_t m_bytes_sent = 0; 
uint32_t m_packets_received = 0; 
double m_time = 0;
 
void
SentPacket(std::string context, Ptr<const Packet> p){
     
    m_bytes_sent += p->GetSize();  
}

void
ReceivedPacket(std::string context, Ptr<const Packet> p, const Address& addr){
     
    m_bytes_received += p->GetSize(); 
    m_bytes_total += p->GetSize(); 
    m_packets_received++;

}

void
Ratio(uint32_t m_bytes_sent, uint32_t m_packets_sent ){
    std::cout << "Sent (bytes):\t" <<  m_bytes_sent
    << "\tReceived (bytes):\t" << m_bytes_received 
    << "\nSent (Packets):\t" <<  m_packets_sent
    << "\tReceived (Packets):\t" << m_packets_received 
    
    << "\nRatio (bytes):\t" << (float)m_bytes_received/(float)m_bytes_sent
    << "\tRatio (packets):\t" << (float)m_packets_received/(float)m_packets_sent << "\n";
}
int main (int argc, char *argv[])
{
    Packet::EnablePrinting(); 
    PacketMetadata::Enable ();
    //
    // Explicitly create the nodes required by the topology (shown above).
    //
    NS_LOG_INFO ("Create nodes.");
    NodeContainer n;
    n.Create (5); 

    NodeContainer n0n1 = NodeContainer (n.Get(0), n.Get (1));
    NodeContainer n1n2 = NodeContainer (n.Get(1), n.Get (2));
    NodeContainer n2n3 = NodeContainer (n.Get(2), n.Get (3));
    NodeContainer n3n4 = NodeContainer (n.Get(3), n.Get (4)); 
    NodeContainer qkdNodes = NodeContainer (
        n.Get (0), 
        n.Get (2),
        n.Get (4)
    );

    //Underlay network - set routing protocol (if any)

    //Enable OLSR
    //OlsrHelper routingProtocol;
    //DsdvHelper routingProtocol; 

    InternetStackHelper internet;
    //internet.SetRoutingHelper (routingProtocol);
    internet.Install (n);

    // Set Mobility for all nodes
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject <ListPositionAllocator>();
    positionAlloc ->Add(Vector(0, 200, 0)); // node0 
    positionAlloc ->Add(Vector(200, 200, 0)); // node1
    positionAlloc ->Add(Vector(400, 200, 0)); // node2 
    positionAlloc ->Add(Vector(600, 200, 0)); // node3 
    positionAlloc ->Add(Vector(800, 200, 0)); // node4 

    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(n);
       
    // We create the channels first without any IP addressing information
    NS_LOG_INFO ("Create channels.");
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("1Gbps"));
    //p2p.SetChannelAttribute ("Delay", StringValue ("100ps")); 

    NetDeviceContainer d0d1 = p2p.Install (n0n1); 
    NetDeviceContainer d1d2 = p2p.Install (n1n2);
    NetDeviceContainer d2d3 = p2p.Install (n2n3);
    NetDeviceContainer d3d4 = p2p.Install (n3n4);

    //
    // We've got the "hardware" in place.  Now we need to add IP addresses.
    // 
    NS_LOG_INFO ("Assign IP Addresses.");
    Ipv4AddressHelper ipv4;

    ipv4.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer i0i1 = ipv4.Assign (d0d1);

    ipv4.SetBase ("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer i1i2 = ipv4.Assign (d1d2);

    ipv4.SetBase ("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer i2i3 = ipv4.Assign (d2d3);

    ipv4.SetBase ("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer i3i4 = ipv4.Assign (d3d4);

    // Create router nodes, initialize routing database and set up the routing
    // tables in the nodes.
    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
 
    //Overlay network - set routing protocol

    //Enable Overlay Routing
    //AodvqHelper routingOverlayProtocol; 
    DsdvqHelper routingOverlayProtocol; 

    //
    // Explicitly create the channels required by the topology (shown above).
    //
    QKDHelper QHelper;  

    //install QKD Managers on the nodes
    QHelper.SetRoutingHelper (routingOverlayProtocol);
    QHelper.InstallQKDManager (qkdNodes); 
        
    //Create QKDNetDevices and create QKDbuffers
    Ipv4InterfaceAddress va02_0 (Ipv4Address ("11.0.0.1"), Ipv4Mask ("255.255.255.0"));
    Ipv4InterfaceAddress va02_2 (Ipv4Address ("11.0.0.2"), Ipv4Mask ("255.255.255.0"));

    Ipv4InterfaceAddress va24_2 (Ipv4Address ("11.0.0.3"), Ipv4Mask ("255.255.255.0"));
    Ipv4InterfaceAddress va24_4 (Ipv4Address ("11.0.0.4"), Ipv4Mask ("255.255.255.0"));
    
    //create QKD connection between nodes 0 and 2
    NetDeviceContainer qkdNetDevices02 = QHelper.InstallOverlayQKD (
        d0d1.Get(0), d1d2.Get(1), 
        va02_0, va02_2,  
        108576,     //min
        0,          //thr - will be set automatically
        1085760,    //max
        1085760     //current    //20485770
    );
    //Create graph to monitor buffer changes
    QHelper.AddGraph(qkdNodes.Get(0), d1d2.Get (0), "myGraph02"); //srcNode, destinationAddress, BufferTitle

    //create QKD connection between nodes 0 and 2
    NetDeviceContainer qkdNetDevices24 = QHelper.InstallOverlayQKD (
        d2d3.Get(0), d3d4.Get(1), 
        va24_2, va24_4,  
        108576,     //min
        0,          //thr - will be set automatically
        1085760,    //max
        1085760     //current    //88576
    );
    //Create graph to monitor buffer changes
    QHelper.AddGraph(qkdNodes.Get(1), d3d4.Get (0), "myGraph24"); //srcNode, destinationAddress, BufferTitle
 
    NS_LOG_INFO ("Create Applications."); 

    /* QKD APPs for charing */
    //Config::SetDefault ("ns3::TcpSocket::SegmentSize", UintegerValue (2536)); 
    
    QKDAppChargingHelper qkdChargingApp02("ns3::VirtualTcpSocketFactory", va02_0.GetLocal (), va02_2.GetLocal (), 200000);
    ApplicationContainer qkdChrgApps02 = qkdChargingApp02.Install ( qkdNetDevices02.Get (0), qkdNetDevices02.Get (1) );
    qkdChrgApps02.Start (Seconds (10.));
    qkdChrgApps02.Stop (Seconds (120.));

    QKDAppChargingHelper qkdChargingApp24("ns3::VirtualTcpSocketFactory", va24_2.GetLocal (), va24_4.GetLocal (), 200000);
    ApplicationContainer qkdChrgApps24 = qkdChargingApp24.Install ( qkdNetDevices24.Get (0), qkdNetDevices24.Get (1) );
    qkdChrgApps24.Start (Seconds (10.));
    qkdChrgApps24.Stop (Seconds (120.));
    

    /* Create user's traffic between v0 and v1 */
    /* Create sink app */
    uint16_t sinkPort = 8080;
    QKDSinkAppHelper packetSinkHelper ("ns3::VirtualUdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort));
    ApplicationContainer sinkApps = packetSinkHelper.Install (qkdNodes.Get (2));
    sinkApps.Start (Seconds (25.));
    sinkApps.Stop (Seconds (170.));
    
    /* Create source app  */
    Address sinkAddress (InetSocketAddress (va24_4.GetLocal (), sinkPort));
    Address sourceAddress (InetSocketAddress (va02_0.GetLocal (), sinkPort));
    Ptr<Socket> overlaySocket = Socket::CreateSocket (qkdNodes.Get (0), VirtualUdpSocketFactory::GetTypeId ());
 
    Ptr<QKDSend> app = CreateObject<QKDSend> ();
    app->Setup (overlaySocket, sourceAddress, sinkAddress, 1040, 0, DataRate ("5kbps"));
    qkdNodes.Get (0)->AddApplication (app);
    app->SetStartTime (Seconds (25.));
    app->SetStopTime (Seconds (170.)); 
        
    //////////////////////////////////////
    ////         STATISTICS
    //////////////////////////////////////

    //if we need we can create pcap files
    p2p.EnablePcapAll ("QKD_vnet_test"); 
    QHelper.EnablePcapAll ("QKD_overlay_vnet_test");

    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDSend/Tx", MakeCallback(&SentPacket));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDSink/Rx", MakeCallback(&ReceivedPacket));
 
    Simulator::Stop ( Seconds (30) );
    Simulator::Run ();

    Ratio(app->sendDataStats(), app->sendPacketStats());

    //Finally print the graphs
    QHelper.PrintGraphs();
    Simulator::Destroy ();
}
