/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
 *
 * Author: Miralem Mehic <miralem.mehic@ieee.org>
 */

// Network topology
//
//                    ------- n2 ---------                       
//                    |                  |   
//        n0 ------- n1 ----- n3 ------ n5 ------ n6
//                    |                  |   
//                    ------- n4 ---------
//
//
//
// - All links are wired point-to-point  
// - UDP flow from n0 to n6

#include <fstream>
#include "ns3/core-module.h" 
#include "ns3/applications-module.h"
#include "ns3/internet-module.h" 
#include "ns3/flow-monitor-module.h" 
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h" 
  
#include "ns3/aodv-module.h" 
#include "ns3/olsr-module.h"
#include "ns3/dsdv-module.h" 
 
#include "ns3/network-module.h"
#include "ns3/fd-net-device-module.h"
#include "ns3/internet-apps-module.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
    
using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("SIMPLENET_3");
  
uint32_t m_bytes_total = 0; 
uint32_t m_bytes_received = 0; 
uint32_t m_bytes_sent = 0; 
uint32_t m_packets_received = 0; 
uint32_t m_packets_sent = 0;
double m_time = 0;

void
SentPacket(std::string context, Ptr<const Packet> p){
    
    m_bytes_sent += p->GetSize(); 
    m_packets_sent++; 
}

void
ReceivedPacket(std::string context, Ptr<const Packet> p, const Address& addr){
    
    m_bytes_received += p->GetSize(); 
    m_bytes_total += p->GetSize(); 
    m_packets_received++;

}

static void
DisableChannel(uint32_t m_channelId){

    std::cout << "setting delay for channelID" << m_channelId << "\n";

    std::ostringstream temp; 
    temp << "/ChannelList/" << m_channelId << "/$ns3::PointToPointChannel/Delay";        
    std::string query(temp.str());
    Config::Set (query, StringValue ("20000000ms"));

}

void
Ratio(){

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

    bool enableFlowMonitor = false;  
    bool enableApplication = true;
    double simulationTime = 100; 
    bool useSeparetedIPAddresses = true;
    uint32_t routingProtocolType = 0;
    std::string lat = "2ms";
    std::string rate = "10Mb/s"; // P2P link

    CommandLine cmd;
    cmd.AddValue ("EnableMonitor", "Enable Flow Monitor", enableFlowMonitor);
    cmd.AddValue ("simulationTime", "simulationTime", simulationTime);
    cmd.AddValue ("enableApplication", "enableApplication", enableApplication);
    cmd.AddValue ("routingProtocol", "routingProtocol", routingProtocolType);
    cmd.AddValue ("useSeparetedIPAddresses", "useSeparetedIPAddresses", useSeparetedIPAddresses);
    cmd.Parse (argc, argv);
 
    //
    // Explicitly create the nodes required by the topology (shown above).
    //

    NS_LOG_INFO ("Create nodes.");
    NodeContainer nodes; // ALL Nodes
    nodes.Create(7); 

    //Enable OLSR
    InternetStackHelper internet;
    if(routingProtocolType == 0){
        std::cout << "DSDV routing protocol" << "\n";
        DsdvHelper routingProtocol;
        internet.SetRoutingHelper (routingProtocol);

    }else if(routingProtocolType == 1){
        std::cout << "AODV routing protocol" << "\n";
        AodvHelper routingProtocol;
        internet.SetRoutingHelper (routingProtocol);

    }else if(routingProtocolType == 2){
        std::cout << "OLSR routing protocol" << "\n";
        OlsrHelper routingProtocol;
        internet.SetRoutingHelper (routingProtocol);

    } 
    
    //
    // Install Internet Stack
    //
    internet.Install (nodes);

    // Set up Addresses
    NS_LOG_INFO ("Create channels.");
    NS_LOG_INFO ("Assign IP Addresses.");

    Ipv4AddressHelper ipv4;
    uint32_t channelID = 0;

    //
    // Explicitly create the channels required by the topology (shown above).
    // 
    PointToPointHelper p2p;  
    p2p.SetDeviceAttribute ("DataRate", StringValue (rate));
    p2p.SetChannelAttribute ("Delay", StringValue (lat));

    //Nodes 0 & 1
    NodeContainer link_0_1;
    link_0_1.Add(nodes.Get(0));
    link_0_1.Add(nodes.Get(1));
  
    NetDeviceContainer devices_0_1 = p2p.Install (link_0_1);         
    ipv4.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifconf_0_1 = ipv4.Assign (devices_0_1);
    channelID++;

    //Nodes 1 & 2
    NodeContainer link_1_2;
    link_1_2.Add(nodes.Get(1));
    link_1_2.Add(nodes.Get(2));
  
    NetDeviceContainer devices_1_2 = p2p.Install (link_1_2); 
    if(useSeparetedIPAddresses) ipv4.SetBase ("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer ifconf_1_2 = ipv4.Assign (devices_1_2); 
    //Simulator::Schedule(Seconds( 50 ), &DisableChannel, channelID) ;
    channelID++;

    //Nodes 1 & 3
    NodeContainer link_1_3;
    link_1_3.Add(nodes.Get(1));
    link_1_3.Add(nodes.Get(3));
  
    NetDeviceContainer devices_1_3 = p2p.Install (link_1_3); 
    if(useSeparetedIPAddresses) ipv4.SetBase ("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer ifconf_1_3 = ipv4.Assign (devices_1_3); 
    //Simulator::Schedule(Seconds( 50 ), &DisableChannel, channelID) ;
    channelID++;
 
    //Nodes 1_4
    NodeContainer link_1_4;
    link_1_4.Add(nodes.Get(1));
    link_1_4.Add(nodes.Get(4));

    NetDeviceContainer devices_1_4 = p2p.Install (link_1_4); 
    if(useSeparetedIPAddresses) ipv4.SetBase ("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer ifconf_1_4 = ipv4.Assign (devices_1_4); 
    Simulator::Schedule(Seconds( 50 ), &DisableChannel, channelID) ;
    channelID++;

    //Nodes 2_5
    NodeContainer link_2_5;
    link_2_5.Add(nodes.Get(2));
    link_2_5.Add(nodes.Get(5));

    NetDeviceContainer devices_2_5 = p2p.Install (link_2_5); 
    if(useSeparetedIPAddresses) ipv4.SetBase ("10.1.5.0", "255.255.255.0");
    Ipv4InterfaceContainer ifconf_2_5 = ipv4.Assign (devices_2_5); 
    //Simulator::Schedule(Seconds( 50 ), &DisableChannel, channelID) ;
    channelID++;

    //Nodes 3_5
    NodeContainer link_3_5;
    link_3_5.Add(nodes.Get(3));
    link_3_5.Add(nodes.Get(5));

    NetDeviceContainer devices_3_5 = p2p.Install (link_3_5); 
    if(useSeparetedIPAddresses) ipv4.SetBase ("10.1.6.0", "255.255.255.0");
    Ipv4InterfaceContainer ifconf_3_5 = ipv4.Assign (devices_3_5); 
    //Simulator::Schedule(Seconds( 50 ), &DisableChannel, channelID) ;
    channelID++;

    //Nodes 4_5
    NodeContainer link_4_5;
    link_4_5.Add(nodes.Get(4));
    link_4_5.Add(nodes.Get(5));

    NetDeviceContainer devices_4_5 = p2p.Install (link_4_5); 
    if(useSeparetedIPAddresses) ipv4.SetBase ("10.1.7.0", "255.255.255.0");
    Ipv4InterfaceContainer ifconf_4_5 = ipv4.Assign (devices_4_5); 
    Simulator::Schedule(Seconds( 50 ), &DisableChannel, channelID) ;
    channelID++;

    //Nodes 5_6
    NodeContainer link_5_6;
    link_5_6.Add(nodes.Get(5));
    link_5_6.Add(nodes.Get(6));

    NetDeviceContainer devices_5_6 = p2p.Install (link_5_6); 
    if(useSeparetedIPAddresses) ipv4.SetBase ("10.1.8.0", "255.255.255.0");
    Ipv4InterfaceContainer ifconf_5_6 = ipv4.Assign (devices_5_6); 
    //Simulator::Schedule(Seconds( 50 ), &DisableChannel, channelID) ;
    channelID++;
 
    // Set Mobility for all nodes
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject <ListPositionAllocator>();
    positionAlloc ->Add(Vector(0, 200, 0)); // node0 
    positionAlloc ->Add(Vector(200, 200, 0)); // node1
    positionAlloc ->Add(Vector(400, 350, 0)); // node2
    positionAlloc ->Add(Vector(400, 200, 0)); // node3
    positionAlloc ->Add(Vector(400, 50, 0)); // node4
    positionAlloc ->Add(Vector(600, 200, 0)); // node5
    positionAlloc ->Add(Vector(800, 200, 0)); // node6

    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);
      
    NS_LOG_INFO ("Create Applications."); 

    std::cout << "Source IP address: " << ifconf_0_1.GetAddress(0) << std::endl;
    std::cout << "Destination IP address: " << ifconf_5_6.GetAddress(1) << std::endl;
  
    if(enableApplication){ 

      // Create the OnOff application to send UDP datagrams of size
      // 210 bytes at a rate of 448 Kb/s
      NS_LOG_INFO ("Create Applications.");
      uint16_t port = 9;   // Discard port (RFC 863)
      OnOffHelper onoff ("ns3::UdpSocketFactory", Address (InetSocketAddress (ifconf_5_6.GetAddress (1), port)));
      onoff.SetConstantRate (DataRate ("448kb/s"));
      ApplicationContainer apps = onoff.Install (nodes.Get (0));
      apps.Start (Seconds (15.0));
      apps.Stop (Seconds (300.0));

      // Create a packet sink to receive these packets
      PacketSinkHelper sink ("ns3::UdpSocketFactory", Address (InetSocketAddress (Ipv4Address::GetAny (), port)));
      apps = sink.Install (nodes.Get (6));
      apps.Start (Seconds (15.0));
      apps.Stop (Seconds (300.0)); 

    }
    //////////////////////////////////////
    ////         STATISTICS
    //////////////////////////////////////

    //if we need we can create pcap files
    p2p.EnablePcapAll ("my_netsim_test");  
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback(&ReceivedPacket));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::OnOffApplication/Tx", MakeCallback(&SentPacket));

    //
    // Now, do the actual simulation.
    //
    NS_LOG_INFO ("Run Simulation."); 

    //AnimationInterface anim("secoqc_olsr_wifi.xml");
    Simulator::Stop (Seconds(simulationTime));
    Simulator::Run (); 

    if(enableApplication)
        Ratio();

    Simulator::Destroy ();
}