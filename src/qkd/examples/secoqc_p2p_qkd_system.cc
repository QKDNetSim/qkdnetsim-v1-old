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
 * Author: Miralem Mehic <miralem.mehic@ieee.org>
 */

// Network topology
// Simulation of SECOQC QKD Network
//
//                                       2Mbps                15Mbps
//                            n3(SIE) -- 2kbps -- n4(ERD) --- 17kbps n5(FRM)
//                              |                   |
//                              5.7kbps (5.5Mbps) 8kbps (7.2Mbps)
//                              |                   |
//        n0(STP) --0.5kbps-- n1(BRT) --1kbps --- n2(GUD)
//                  1Mbps               1Mbps
//
// - All links are wired point-to-point  
// - TCP flow from n0 to n5

#include <fstream>
#include "ns3/core-module.h" 
#include "ns3/applications-module.h"
#include "ns3/internet-module.h" 
#include "ns3/flow-monitor-module.h" 
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/gnuplot.h" 

#include "ns3/qkd-helper.h" 
#include "ns3/qkd-app-charging-helper.h"
#include "ns3/qkd-send.h"

#include "ns3/aodv-module.h" 
#include "ns3/olsr-module.h"
#include "ns3/dsdv-module.h" 
 
#include "ns3/network-module.h" 
#include "ns3/internet-apps-module.h"
 

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
 

NS_LOG_COMPONENT_DEFINE ("SECOQC");

using namespace ns3;
  
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

    bool enableFlowMonitor = false;  
    bool enableApplication = true;
    double simulationTime = 300; 
    bool useSeparetedIPAddresses = false;
    std::string lat = "2ms";
    std::string rate = "10Mb/s"; // P2P link

    CommandLine cmd;
    cmd.AddValue ("EnableMonitor", "Enable Flow Monitor", enableFlowMonitor);
    cmd.AddValue ("simulationTime", "simulationTime", simulationTime);
    cmd.AddValue ("enableApplication", "enableApplication", enableApplication);
    cmd.Parse (argc, argv);

    NS_LOG_INFO ("Create QKD system.");

    //
    // Explicitly create the nodes required by the topology (shown above).
    //

    NS_LOG_INFO ("Create nodes.");
    NodeContainer nodes; // ALL Nodes
    nodes.Create(6); 

    //Enable OLSR
    //OlsrHelper routingProtocol;
    //AodvHelper routingProtocol; 
    DsdvHelper routingProtocol; 

    //
    // Install Internet Stack
    //

    InternetStackHelper internet;
    internet.SetRoutingHelper (routingProtocol);
    internet.Install (nodes);

    // Set up Addresses
    NS_LOG_INFO ("Create channels.");
    NS_LOG_INFO ("Assign IP Addresses.");
    Ipv4AddressHelper ipv4;

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

    //Nodes 1 & 2
    NodeContainer link_1_2;
    link_1_2.Add(nodes.Get(1));
    link_1_2.Add(nodes.Get(2));
  
    NetDeviceContainer devices_1_2 = p2p.Install (link_1_2); 

    if(useSeparetedIPAddresses)
        ipv4.SetBase ("10.1.2.0", "255.255.255.0");

    Ipv4InterfaceContainer ifconf_1_2 = ipv4.Assign (devices_1_2);

    //Nodes 1 & 2
    NodeContainer link_1_3;
    link_1_3.Add(nodes.Get(1));
    link_1_3.Add(nodes.Get(3));
  
    NetDeviceContainer devices_1_3 = p2p.Install (link_1_3); 

    if(useSeparetedIPAddresses)
        ipv4.SetBase ("10.1.3.0", "255.255.255.0");

    Ipv4InterfaceContainer ifconf_1_3 = ipv4.Assign (devices_1_3);

    //Nodes 3 & 4
    NodeContainer link_3_4;
    link_3_4.Add(nodes.Get(3));
    link_3_4.Add(nodes.Get(4));
  
    NetDeviceContainer devices_3_4 = p2p.Install (link_3_4); 

    if(useSeparetedIPAddresses)
        ipv4.SetBase ("10.1.4.0", "255.255.255.0");

    Ipv4InterfaceContainer ifconf_3_4 = ipv4.Assign (devices_3_4);

    //Nodes 2 & 4
    NodeContainer link_2_4;
    link_2_4.Add(nodes.Get(2));
    link_2_4.Add(nodes.Get(4));
  
    NetDeviceContainer devices_2_4 = p2p.Install (link_2_4); 

    if(useSeparetedIPAddresses)
        ipv4.SetBase ("10.1.5.0", "255.255.255.0");

    Ipv4InterfaceContainer ifconf_2_4 = ipv4.Assign (devices_2_4);

    //Nodes 4 & 5
    NodeContainer link_4_5;
    link_4_5.Add(nodes.Get(4));
    link_4_5.Add(nodes.Get(5));
  
    NetDeviceContainer devices_4_5 = p2p.Install (link_4_5); 

    if(useSeparetedIPAddresses)
        ipv4.SetBase ("10.1.6.0", "255.255.255.0");

    Ipv4InterfaceContainer ifconf_4_5 = ipv4.Assign (devices_4_5);

    // Create router nodes, initialize routing database and set up the routing
    // tables in the nodes.
    //Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
    //routingProtocol.Set ("LocationServiceName", StringValue ("GOD"));
    //routingProtocol.Install (); 

    //
    // Explicitly create the channels required by the topology (shown above).
    //
    //  install QKD Managers on the nodes 
    QKDHelper QHelper;  
    QHelper.InstallQKDManager (nodes); 

    //create QKD connection between nodes 0 and 1
    NetDeviceContainer qkdNetDevices_0_1 = QHelper.InstallQKD (
        devices_0_1.Get(0), devices_0_1.Get(1),  
        1048576,    //min
        11324620, //thr
        52428800,   //max
        52428800     //current    //20485770
    ); 
    //Create graph to monitor buffer changes
    QHelper.AddGraph(nodes.Get(0), devices_0_1.Get(0)); //srcNode, destinationAddress, BufferTitle
 
    //create QKD connection between nodes 0 and 1
    NetDeviceContainer qkdNetDevices_1_2 = QHelper.InstallQKD (
        devices_1_2.Get(0), devices_1_2.Get(1),  
        1548576,    //min
        11324620, //thr
        52428800,   //max
        52428800     //current    //20485770
    ); 
    //Create graph to monitor buffer changes
    QHelper.AddGraph(nodes.Get(1), devices_1_2.Get(1)); //srcNode, destinationAddress, BufferTitle
 
    //create QKD connection between nodes 0 and 1
    NetDeviceContainer qkdNetDevices_2_4 = QHelper.InstallQKD (
        devices_2_4.Get(0), devices_2_4.Get(1),  
        1048576,    //min
        11324620, //thr
        52428800,   //max
        10485760     //current    //10485760
    ); 
    //Create graph to monitor buffer changes
    QHelper.AddGraph(nodes.Get(2), devices_2_4.Get(1)); //srcNode, destinationAddress, BufferTitle
 
    //create QKD connection between nodes 0 and 1
    NetDeviceContainer qkdNetDevices_1_3 = QHelper.InstallQKD (
        devices_1_3.Get(0), devices_1_3.Get(1),  
        1048576,    //min
        11324620, //thr
        52428800,   //max
        52428800     //current    //20485770
    ); 
    //Create graph to monitor buffer changes
    QHelper.AddGraph(nodes.Get(1), devices_1_3.Get(1)); //srcNode, destihnationAddress, BufferTitle
 
    //create QKD connection between nodes 0 and 1
    NetDeviceContainer qkdNetDevices_3_4 = QHelper.InstallQKD (
        devices_3_4.Get(0), devices_3_4.Get(1),  
        1048576,    //min
        11324620, //thr
        52428800,   //max
        12485760     //current    //12485760
    ); 
    //Create graph to monitor buffer changes
    QHelper.AddGraph(nodes.Get(3), devices_3_4.Get(1)); //srcNode, destinationAddress, BufferTitle
 
    //create QKD connection between nodes 0 and 1
    NetDeviceContainer qkdNetDevices_4_5 = QHelper.InstallQKD (
        devices_4_5.Get(0), devices_4_5.Get(1),  
        1048576,    //min
        11324620, //thr
        52428800,   //max
        52428800     //current    //20485770
    ); 
    //Create graph to monitor buffer changes
    QHelper.AddGraph(nodes.Get(4), devices_4_5.Get(1)); //srcNode, destinationAddress, BufferTitle
 
    // Set Mobility for all nodes
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject <ListPositionAllocator>();
    positionAlloc ->Add(Vector(0, 200, 0)); // node0 
    positionAlloc ->Add(Vector(200, 200, 0)); // node1
    positionAlloc ->Add(Vector(400, 60, 0)); // node2
    positionAlloc ->Add(Vector(400, 350, 0)); // node3
    positionAlloc ->Add(Vector(600, 200, 0)); // node4
    positionAlloc ->Add(Vector(700, 200, 0)); // node5
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);
      
    NS_LOG_INFO ("Create Applications."); 

    std::cout << "Source IP address: " << ifconf_0_1.GetAddress(0) << std::endl;
    std::cout << "Destination IP address: " << ifconf_4_5.GetAddress(1) << std::endl;

    /* QKD APPs for charing */
    //QKD LINK 0_1 
    QKDAppChargingHelper qkdChargingApp_0_1("ns3::TcpSocketFactory", ifconf_0_1.GetAddress(0),  ifconf_0_1.GetAddress(1), 3072000); //102400 * 30seconds
    ApplicationContainer qkdChrgApps_0_1 = qkdChargingApp_0_1.Install ( devices_0_1.Get(0), devices_0_1.Get(1) );
    qkdChrgApps_0_1.Start (Seconds (5.));
    qkdChrgApps_0_1.Stop (Seconds (500.)); 
     
    //QKD LINK 1_2
    QKDAppChargingHelper qkdChargingApp_1_2("ns3::TcpSocketFactory", ifconf_1_2.GetAddress(0),  ifconf_1_2.GetAddress(1), 3072000); //102400 * 30seconds
    ApplicationContainer qkdChrgApps_1_2 = qkdChargingApp_1_2.Install ( devices_1_2.Get(0), devices_1_2.Get(1) );
    qkdChrgApps_1_2.Start (Seconds (5.));
    qkdChrgApps_1_2.Stop (Seconds (500.)); 
   
    //QKD LINK 2_4
    QKDAppChargingHelper qkdChargingApp_2_4("ns3::TcpSocketFactory", ifconf_2_4.GetAddress(0),  ifconf_2_4.GetAddress(1), 3072000); //102400 * 30seconds
    ApplicationContainer qkdChrgApps_2_4 = qkdChargingApp_2_4.Install ( devices_2_4.Get(0), devices_2_4.Get(1) );
    qkdChrgApps_2_4.Start (Seconds (5.));
    qkdChrgApps_2_4.Stop (Seconds (500.)); 

    //QKD LINK 1_3 
    QKDAppChargingHelper qkdChargingApp_1_3("ns3::TcpSocketFactory", ifconf_1_3.GetAddress(0),  ifconf_1_3.GetAddress(1), 3072000); //102400 * 30seconds
    ApplicationContainer qkdChrgApps_1_3 = qkdChargingApp_1_3.Install ( devices_1_3.Get(0), devices_1_3.Get(1) );
    qkdChrgApps_1_3.Start (Seconds (5.));
    qkdChrgApps_1_3.Stop (Seconds (500.)); 

    //QKD LINK 3_4
    QKDAppChargingHelper qkdChargingApp_3_4("ns3::TcpSocketFactory", ifconf_3_4.GetAddress(0),  ifconf_3_4.GetAddress(1), 3072000); //102400 * 30seconds
    ApplicationContainer qkdChrgApps_3_4 = qkdChargingApp_3_4.Install ( devices_3_4.Get(0), devices_3_4.Get(1) );
    qkdChrgApps_3_4.Start (Seconds (5.));
    qkdChrgApps_3_4.Stop (Seconds (500.)); 

    //QKD LINK 4_5
    QKDAppChargingHelper qkdChargingApp_4_5("ns3::TcpSocketFactory", ifconf_4_5.GetAddress(0),  ifconf_4_5.GetAddress(1), 3072000); //102400 * 30seconds
    ApplicationContainer qkdChrgApps_4_5 = qkdChargingApp_4_5.Install ( devices_4_5.Get(0), devices_4_5.Get(1) );
    qkdChrgApps_4_5.Start (Seconds (5.));
    qkdChrgApps_4_5.Stop (Seconds (500.)); 
    

    Ptr<QKDSend> app = CreateObject<QKDSend> ();
    if(enableApplication){
        /* Create user's traffic between v0 and v1 */
        /* Create sink app */
        uint16_t sinkPort = 8080;
        QKDSinkAppHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort));
        ApplicationContainer sinkApps = packetSinkHelper.Install (nodes.Get (5));
        sinkApps.Start (Seconds (15.));
        sinkApps.Stop (Seconds (500.));

        /* Create source app */
        Address sinkAddress (InetSocketAddress (ifconf_4_5.GetAddress(1), sinkPort));
        Address sourceAddress (InetSocketAddress (ifconf_0_1.GetAddress(0), sinkPort));
        Ptr<Socket> socket = Socket::CreateSocket (nodes.Get (0), UdpSocketFactory::GetTypeId ());

        app->Setup (socket, sourceAddress, sinkAddress, 512, 0, DataRate ("160kbps"));
        nodes.Get (0)->AddApplication (app);
        app->SetStartTime (Seconds (15.));
        app->SetStopTime (Seconds (500.));  
    }
    //////////////////////////////////////
    ////         STATISTICS
    //////////////////////////////////////

    //if we need we can create pcap files
    p2p.EnablePcapAll ("QKD_netsim_test"); 
    //QHelper.EnablePcapAll ("QKD_netsim_test_Qhelper"); 

    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDSink/Rx", MakeCallback(&ReceivedPacket));

    //
    // Now, do the actual simulation.
    //
    NS_LOG_INFO ("Run Simulation."); 

    //AnimationInterface anim("secoqc_olsr_wifi.xml");
    Simulator::Stop (Seconds(simulationTime));
    Simulator::Run (); 

    if(enableApplication)
        Ratio(app->sendDataStats(), app->sendPacketStats());

    //Finally print the graphs
    QHelper.PrintGraphs();
    Simulator::Destroy ();
}