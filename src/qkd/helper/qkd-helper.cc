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

#include "ns3/abort.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/queue.h"
#include "ns3/config.h"
#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/names.h"
#include "ns3/mpi-interface.h"
#include "ns3/mpi-receiver.h"
#include "ns3/qkd-net-device.h" 
#include "ns3/qkd-manager.h" 
#include "ns3/internet-module.h"
#include "ns3/random-variable-stream.h"
#include "ns3/trace-helper.h" 
#include "ns3/qkd-l4-traffic-control-layer.h"
#include "ns3/traffic-control-module.h"
#include "ns3/virtual-ipv4-l3-protocol.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/virtual-tcp-l4-protocol.h"
#include "ns3/qkd-graph-manager.h" 
#include "qkd-helper.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDHelper");

QKDHelper::QKDHelper ()
{ 
    m_deviceFactory.SetTypeId ("ns3::QKDNetDevice"); 
    m_tcpFactory.SetTypeId ("ns3::VirtualTcpL4Protocol");

    m_useRealStorages = false;
    m_portOverlayNumber = 667; 
    m_channelID = 0; 
    m_routing = 0; 
    m_counter = 0;
    m_QCrypto = CreateObject<QKDCrypto> (); 
    m_supportQKDL4 = 1;
}  

void 
QKDHelper::SetDeviceAttribute (std::string n1, const AttributeValue &v1)
{
    m_deviceFactory.Set (n1, v1);
}

/**
*   Enable Pcap recording
*/
void 
QKDHelper::EnablePcapInternal (std::string prefix, Ptr<NetDevice> nd, bool promiscuous, bool explicitFilename)
{
     
    //
    // All of the Pcap enable functions vector through here including the ones
    // that are wandering through all of devices on perhaps all of the nodes in
    // the system.  We can only deal with devices of type QKDNetDevice.
    //
    Ptr<QKDNetDevice> device = nd->GetObject<QKDNetDevice> ();
    if (device == 0 || device->GetNode()->GetObject<QKDManager> () == 0)
    {
      NS_LOG_INFO ("QKDHelper::EnablePcapInternal(): Device " << device << " is not related with QKD TCP/IP stack");
      return;
    }

    PcapHelper pcapHelper;

    std::string filename;
    if (explicitFilename)
    {
      filename = prefix;
    }
    else
    {
      filename = pcapHelper.GetFilenameFromDevice (prefix, device);
    }

    Ptr<PcapFileWrapper> file = pcapHelper.CreateFile (filename, std::ios::out, 
                                                     PcapHelper::DLT_RAW  );
    pcapHelper.HookDefaultSink<QKDNetDevice> (device, "PromiscSniffer", file);  
}

/**
*   Enable ASCII recording
*/
void 
QKDHelper::EnableAsciiInternal (
  Ptr<OutputStreamWrapper> stream, 
  std::string prefix, 
  Ptr<NetDevice> nd,
  bool explicitFilename)
{
     
    //
    // All of the ascii enable functions vector through here including the ones
    // that are wandering through all of devices on perhaps all of the nodes in
    // the system.  We can only deal with devices of type QKDNetDevice.
    //
    Ptr<QKDNetDevice> device = nd->GetObject<QKDNetDevice> ();
    if (device == 0)
    {
      NS_LOG_INFO ("QKDHelper::EnableAsciiInternal(): Device " << device << 
                   " not of type ns3::QKDNetDevice");
      return;
    }

    //
    // Our default trace sinks are going to use packet printing, so we have to 
    // make sure that is turned on.
    //
    Packet::EnablePrinting ();

    //
    // If we are not provided an OutputStreamWrapper, we are expected to create 
    // one using the usual trace filename conventions and do a Hook*WithoutContext
    // since there will be one file per context and therefore the context would
    // be redundant.
    //
    if (stream == 0)
    {
      //
      // Set up an output stream object to deal with private ofstream copy 
      // constructor and lifetime issues.  Let the helper decide the actual
      // name of the file given the prefix.
      //
      AsciiTraceHelper asciiTraceHelper;

      std::string filename;
      if (explicitFilename)
        {
          filename = prefix;
        }
      else
        {
          filename = asciiTraceHelper.GetFilenameFromDevice (prefix, device);
        }

      Ptr<OutputStreamWrapper> theStream = asciiTraceHelper.CreateFileStream (filename);

      //
      // The MacRx trace source provides our "r" event.
      //
      asciiTraceHelper.HookDefaultReceiveSinkWithoutContext<QKDNetDevice> (device, "MacRx", theStream);

      //
      // The "+", '-', and 'd' events are driven by trace sources actually in the
      // transmit queue.
      // 
      Ptr<Queue<Packet> > queue = device->GetQueue ();
      asciiTraceHelper.HookDefaultEnqueueSinkWithoutContext<Queue<Packet> > (queue, "Enqueue", theStream);
      asciiTraceHelper.HookDefaultDropSinkWithoutContext<Queue<Packet> > (queue, "Drop", theStream);
      asciiTraceHelper.HookDefaultDequeueSinkWithoutContext<Queue<Packet> > (queue, "Dequeue", theStream);

      // PhyRxDrop trace source for "d" event
      asciiTraceHelper.HookDefaultDropSinkWithoutContext<QKDNetDevice> (device, "PhyRxDrop", theStream);

      return;
    }

    //
    // If we are provided an OutputStreamWrapper, we are expected to use it, and
    // to providd a context.  We are free to come up with our own context if we
    // want, and use the AsciiTraceHelper Hook*WithContext functions, but for 
    // compatibility and simplicity, we just use Config::Connect and let it deal
    // with the context.
    //
    // Note that we are going to use the default trace sinks provided by the 
    // ascii trace helper.  There is actually no AsciiTraceHelper in sight here,
    // but the default trace sinks are actually publicly available static 
    // functions that are always there waiting for just such a case.
    //
    uint32_t nodeid = nd->GetNode ()->GetId ();
    uint32_t deviceid = nd->GetIfIndex ();
    std::ostringstream oss;

    oss << "/NodeList/" << nd->GetNode ()->GetId () << "/DeviceList/" << deviceid << "/$ns3::QKDNetDevice/MacRx";
    Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultReceiveSinkWithContext, stream));

    oss.str ("");
    oss << "/NodeList/" << nodeid << "/DeviceList/" << deviceid << "/$ns3::QKDNetDevice/TxQueue/Enqueue";
    Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultEnqueueSinkWithContext, stream));

    oss.str ("");
    oss << "/NodeList/" << nodeid << "/DeviceList/" << deviceid << "/$ns3::QKDNetDevice/TxQueue/Dequeue";
    Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultDequeueSinkWithContext, stream));

    oss.str ("");
    oss << "/NodeList/" << nodeid << "/DeviceList/" << deviceid << "/$ns3::QKDNetDevice/TxQueue/Drop";
    Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultDropSinkWithContext, stream));

    oss.str ("");
    oss << "/NodeList/" << nodeid << "/DeviceList/" << deviceid << "/$ns3::QKDNetDevice/PhyRxDrop";
    Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultDropSinkWithContext, stream));
}

/**
*   ADD QKDGraph
*   @param  Ptr<Node>       sourceNode
*   @param  Ipv4Address     destinationAddress
*/
void 
QKDHelper::AddGraph(Ptr<Node> node, Ptr<NetDevice> device)
{
    AddGraph(node, device, "", "png");
}

/**
*   ADD QKDGraph
*   @param  Ptr<Node>       sourceNode
*   @param  Ipv4Address     destinationAddress
*   @param  std::string     graphName    
*/
void 
QKDHelper::AddGraph(Ptr<Node> node, Ptr<NetDevice> device, std::string graphName)
{
    AddGraph(node, device, graphName, "png");
}
/**
*   ADD QKDGraph
*   @param  Ptr<Node>       sourceNode
*   @param  Ipv4Address     sourceAddress
*   @param  std::string     graphName    
*   @param  std::string     graphType    
*/
void 
QKDHelper::AddGraph(Ptr<Node> node, Ptr<NetDevice> device, std::string graphName, std::string graphType)
{   

    NS_ASSERT (node != 0);
    NS_ASSERT (device != 0);

    uint32_t bufferPosition = node->GetObject<QKDManager> ()->GetBufferPosition ( device->GetAddress() ); 
    NS_LOG_FUNCTION(this << node->GetId() << bufferPosition << device ); 

    Ptr<QKDBuffer> buffer = node->GetObject<QKDManager> ()->GetBufferByBufferPosition (bufferPosition); 
    NS_ASSERT (buffer != 0);

    NS_LOG_FUNCTION(this << buffer << buffer->FetchState() << node->GetObject<QKDManager> ()->GetNBuffers() );

    QKDGraphManager *QKDGraphManager = QKDGraphManager::getInstance();
    QKDGraphManager->AddBuffer(node->GetId(), bufferPosition, graphName, graphType);
}

/**
*   Print QKDGraphs
*/
void 
QKDHelper::PrintGraphs()
{    
    QKDGraphManager *QKDGraphManager = QKDGraphManager::getInstance();
    QKDGraphManager->PrintGraphs();
}

/**
*   Install QKDManager on the node
*   @param  NodeContainer&  n
*/ 
void
QKDHelper::InstallQKDManager (NodeContainer& n)
{   
    ObjectFactory factory;    
    factory.SetTypeId ("ns3::QKDManager");
 
    for(uint16_t i=0; i< n.GetN(); i++)
    {   
        if(n.Get(i)->GetObject<QKDManager> () == 0){
            Ptr<Object> manager = factory.Create <Object> ();
            n.Get(i)->AggregateObject (manager);  
            n.Get(i)->GetObject<QKDManager> ()->UseRealStorages(m_useRealStorages);
        } 
    }
}

/**
*   Set routing protocol to be used in overlay QKDNetwork
*   @param  Ipv4RoutingHelper&  routing       
*/
void 
QKDHelper::SetRoutingHelper (const Ipv4RoutingHelper &routing)
{
  delete m_routing;
  m_routing = routing.Copy ();
}

/**
*   Help function used to aggregate protocols to the node such as virtual-tcp, virtual-udp, virtual-ipv4-l3
*   @param  Ptr<Node>           node
*   @param  const std::string   typeID
*/
void
QKDHelper::CreateAndAggregateObjectFromTypeId (Ptr<Node> node, const std::string typeId)
{
    ObjectFactory factory;
    factory.SetTypeId (typeId);
    Ptr<Object> protocol = factory.Create <Object> ();
    node->AggregateObject (protocol);
}

/**
*   Help function used to install and set overlay QKD network using default settings
*   and random values for QKDBuffers in single TCP/IP network. Usefull for testing
*   @param  Ptr<NetDevice>  a
*   @param  Ptr<NetDevice>  b
*/ 
NetDeviceContainer 
QKDHelper::InstallQKD (
    Ptr<NetDevice> a, 
    Ptr<NetDevice> b
)
{ 
    //################################
    //  SINGLE TCP/IP NETWORK
    //################################

    Ptr<UniformRandomVariable> random = CreateObject<UniformRandomVariable> (); 
    return InstallQKD (
        a, 
        b,  
        1000000,    //1 Megabit
        0, 
        100000000, //1000 Megabit
        random->GetValue ( 1000000, 100000000)
    ); 
}


/**
*   Help function used to install and set overlay QKD network using default settings
*   and random values for QKDBuffers in OVERLAY NETWORK. Usefull for testing
*   @param  Ptr<NetDevice>  a
*   @param  Ptr<NetDevice>  b
*/ 
NetDeviceContainer 
QKDHelper::InstallOverlayQKD (
    Ptr<NetDevice> a, 
    Ptr<NetDevice> b
)
{
    //################################
    //  OVERLAY NETWORK
    //################################
 
    std::string address;

    address = "11.0.0." + (++m_counter); 
    Ipv4InterfaceAddress da (Ipv4Address (address.c_str()), Ipv4Mask ("255.255.255.0"));

    address = "11.0.0." + (++m_counter);
    Ipv4InterfaceAddress db (Ipv4Address (address.c_str()), Ipv4Mask ("255.255.255.0"));
    
    Ptr<UniformRandomVariable> random = CreateObject<UniformRandomVariable> ();

    return InstallOverlayQKD (
        a, 
        b, 
        da, 
        db, 
        1000000,    //1 Megabit
        0, 
        1000000000, //1000 Megabit
        random->GetValue ( 1000000, 1000000000)
    ); 
}


 
/**
*   Install and setup OVERLAY QKD link between the nodes
*   @param  Ptr<NetDevice>          IPa
*   @param  Ptr<NetDevice>          IPb
*   @param  Ipv4InterfaceAddress    IPQKDaddressA
*   @param  Ipv4InterfaceAddress    IPQKDaddressB
*   @param  uint32_t                Mmin
*   @param  uint32_t                Mthr
*   @param  uint32_t                Mmmax
*   @param  uint32_t                Mcurrent
*/
NetDeviceContainer
QKDHelper::InstallOverlayQKD(
    Ptr<NetDevice>          IPa, //IP Net device of underlay network on node A
    Ptr<NetDevice>          IPb, //IP Net device of underlay network on node B
    Ipv4InterfaceAddress    IPQKDaddressA,  //IP address of overlay network on node A
    Ipv4InterfaceAddress    IPQKDaddressB,  //IP address of overlay network on node B  
    uint32_t                Mmin, //Buffer details
    uint32_t                Mthr, //Buffer details
    uint32_t                Mmax, //Buffer details
    uint32_t                Mcurrent //Buffer details
){
    return InstallOverlayQKD(
        IPa, //IP Net device of underlay network on node A
        IPb, //IP Net device of underlay network on node B
        IPQKDaddressA,  //IP address of overlay network on node A
        IPQKDaddressB,  //IP address of overlay network on node B  
        Mmin, //Buffer details
        Mthr, //Buffer details
        Mmax, //Buffer details
        Mcurrent, //Buffer details
        "ns3::UdpSocketFactory"
    );
}
 
/**
*   Install and setup OVERLAY QKD link between the nodes
*   @param  Ptr<NetDevice>          IPa
*   @param  Ptr<NetDevice>          IPb
*   @param  Ipv4InterfaceAddress    IPQKDaddressA
*   @param  Ipv4InterfaceAddress    IPQKDaddressB
*   @param  uint32_t                Mmin
*   @param  uint32_t                Mthr
*   @param  uint32_t                Mmmax
*   @param  uint32_t                Mcurrent
*   @param  std::string             Underlying protocol type
*/
NetDeviceContainer
QKDHelper::InstallOverlayQKD(
    Ptr<NetDevice>          IPa,            //IP Net device of underlay network on node A
    Ptr<NetDevice>          IPb,            //IP Net device of underlay network on node B
    Ipv4InterfaceAddress    IPQKDaddressA,  //IP address of overlay network on node A
    Ipv4InterfaceAddress    IPQKDaddressB,  //IP address of overlay network on node B  
    uint32_t                Mmin,           //Buffer details
    uint32_t                Mthr,           //Buffer details
    uint32_t                Mmax,           //Buffer details
    uint32_t                Mcurrent,       //Buffer details
    const std::string       typeId         //Protocol which is used in the underlying network for connection
)
{
    //################################
    //  OVERLAY NETWORK
    //################################
 
    /////////////////////////////////
    // Virtual IPv4L3 Protocol
    /////////////////////////////////

    Ptr<Node> a = IPa->GetNode();    
    Ptr<Node> b = IPb->GetNode();

    NS_LOG_FUNCTION(this << a->GetId() << b->GetId());

    // Set virtual IPv4L3 on A     
    if (a->GetObject<VirtualIpv4L3Protocol> () == 0){
        CreateAndAggregateObjectFromTypeId (a, "ns3::VirtualIpv4L3Protocol");  
  
        //Install Routing Protocol
        Ptr<VirtualIpv4L3Protocol> Virtualipv4a_temp = a->GetObject<VirtualIpv4L3Protocol> ();
        Ptr<Ipv4RoutingProtocol> ipv4Routinga_temp = m_routing->Create (a);
        Virtualipv4a_temp->SetRoutingProtocol (ipv4Routinga_temp);
    } 

    if( m_supportQKDL4 && a->GetObject<QKDL4TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (a, "ns3::QKDL4TrafficControlLayer");

    if( a->GetObject<TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (a, "ns3::TrafficControlLayer");

    //Install UDPL4 and TCPL4 
    if( a->GetObject<VirtualUdpL4Protocol> () == 0){ 
        CreateAndAggregateObjectFromTypeId (a, "ns3::VirtualUdpL4Protocol"); 
        a->AggregateObject (m_tcpFactory.Create<Object> ()); 
    }

    NS_ASSERT (a->GetObject<VirtualIpv4L3Protocol> () != 0);


    /////////////////////////////////
    //          NODE A
    /////////////////////////////////

    //install new QKDNetDevice on node A
    Ptr<QKDNetDevice> devA = m_deviceFactory.Create<QKDNetDevice> (); 
    devA->SetAddress (Mac48Address::Allocate ()); 
    devA->SetSendCallback (MakeCallback (&QKDManager::VirtualSendOverlay, a->GetObject<QKDManager> () ));
    a->AddDevice (devA);

    //Setup QKD NetDevice and interface    
    Ptr<VirtualIpv4L3Protocol> Virtualipv4a = a->GetObject<VirtualIpv4L3Protocol> ();  
    uint32_t i = Virtualipv4a->AddInterface (devA); 
    Virtualipv4a->AddAddress (i, IPQKDaddressA);
    Virtualipv4a->SetUp (i);

    //Get address of classical device which is used for connection on the lower layer
    Ptr<Ipv4> ipv4a = a->GetObject<Ipv4L3Protocol> ();
    uint32_t interfaceOfClassicalDeviceOnNodeA = ipv4a->GetInterfaceForDevice(IPa);
    Ipv4InterfaceAddress netA = ipv4a->GetAddress (interfaceOfClassicalDeviceOnNodeA, 0);

 
    /////////////////////////////////
    //          NODE B
    /////////////////////////////////

    // Set virtual IPv4L3 on B
    if (b->GetObject<VirtualIpv4L3Protocol> () == 0){
        CreateAndAggregateObjectFromTypeId (b, "ns3::VirtualIpv4L3Protocol");
        //Install Routing Protocol
        Ptr<VirtualIpv4L3Protocol> Virtualipv4b_temp = b->GetObject<VirtualIpv4L3Protocol> ();
        Ptr<Ipv4RoutingProtocol> ipv4Routingb_temp = m_routing->Create (b);
        Virtualipv4b_temp->SetRoutingProtocol (ipv4Routingb_temp); 
    }
         
    if( m_supportQKDL4 && b->GetObject<QKDL4TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (b, "ns3::QKDL4TrafficControlLayer");
    
    if( b->GetObject<TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (b, "ns3::TrafficControlLayer");

    //Install UDPL4 and TCPL4 
    if( b->GetObject<VirtualUdpL4Protocol> () == 0){
        CreateAndAggregateObjectFromTypeId (b, "ns3::VirtualUdpL4Protocol");  
        b->AggregateObject (m_tcpFactory.Create<Object> ()); 
    }
    NS_ASSERT (b->GetObject<VirtualIpv4L3Protocol> () != 0); 

    //install new QKDNetDevice on node B 
    Ptr<QKDNetDevice> devB = m_deviceFactory.Create<QKDNetDevice> ();
    devB->SetAddress (Mac48Address::Allocate ()); 
    devB->SetSendCallback (MakeCallback (&QKDManager::VirtualSendOverlay, b->GetObject<QKDManager> () ));
    b->AddDevice (devB);

    //Setup QKD NetDevice and interface 
    Ptr<VirtualIpv4L3Protocol> Virtualipv4b = b->GetObject<VirtualIpv4L3Protocol> ();
    uint32_t j = Virtualipv4b->AddInterface (devB);
    Virtualipv4b->AddAddress (j, IPQKDaddressB);
    Virtualipv4b->SetUp (j); 

    //Get address of classical device which is used for connection of QKDNetDevice on lower layer
    Ptr<Ipv4> ipv4b = b->GetObject<Ipv4L3Protocol> ();
    uint32_t interfaceOfClassicalDeviceOnNodeB = ipv4b->GetInterfaceForDevice(IPb);
    Ipv4InterfaceAddress netB = ipv4b->GetAddress (interfaceOfClassicalDeviceOnNodeB, 0);    
    
    Ptr<Socket> m_socketA;
    Ptr<Socket> m_socketB;
    Ptr<Socket> m_socketA_sink;
    Ptr<Socket> m_socketB_sink;


    /////////////////////////////////
    // QKD Traffic Control  - queues on QKD Netdevices (L2)
    // Optional usage, that is the reason why the length of the queue is only 1
    /////////////////////////////////
    
    //TCH for net devices on overlay L2
    NetDeviceContainer qkdNetDevices;
    qkdNetDevices.Add(devA);
    qkdNetDevices.Add(devB);
     
    //TCH for net devices on underlay L2
    NetDeviceContainer UnderlayNetDevices;
    UnderlayNetDevices.Add(IPa);
    UnderlayNetDevices.Add(IPb);

    TrafficControlHelper tchUnderlay;
    tchUnderlay.Uninstall(UnderlayNetDevices);
    uint16_t handleUnderlay = tchUnderlay.SetRootQueueDisc ("ns3::QKDL2PfifoFastQueueDisc");
    tchUnderlay.AddInternalQueues (handleUnderlay, 3, "ns3::DropTailQueue<QueueDiscItem>", "MaxSize", StringValue ("1000p"));
    //tchUnderlay.AddPacketFilter (handleUnderlay, "ns3::PfifoFastIpv4PacketFilter");
    QueueDiscContainer qdiscsUnderlay = tchUnderlay.Install (UnderlayNetDevices);  
    


    /*
        In NS3, TCP is not bidirectional. Therefore, we need to create separate sockets for listening and sending
    */
    if(typeId == "ns3::TcpSocketFactory"){

        Address inetAddrA (InetSocketAddress (ipv4a->GetAddress (interfaceOfClassicalDeviceOnNodeA, 0).GetLocal (), m_portOverlayNumber) ); 
        Address inetAddrB (InetSocketAddress (ipv4b->GetAddress (interfaceOfClassicalDeviceOnNodeB, 0).GetLocal (), m_portOverlayNumber) );
        
        // SINK SOCKETS
     
        //create TCP Sink socket on A
        m_socketA_sink = Socket::CreateSocket (a, TypeId::LookupByName ("ns3::TcpSocketFactory"));
        m_socketA_sink->Bind ( inetAddrA ); 
        m_socketA_sink->BindToNetDevice ( IPa );
        m_socketA_sink->Listen ();
        m_socketA_sink->ShutdownSend ();   
        m_socketA_sink->SetRecvCallback (MakeCallback (&QKDManager::VirtualReceive, a->GetObject<QKDManager> () ));
        m_socketA_sink->SetAcceptCallback (
            MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
            MakeCallback (&QKDManager::HandleAccept, a->GetObject<QKDManager> () )
        );

        
        //create TCP Sink socket on B
        m_socketB_sink = Socket::CreateSocket (b, TypeId::LookupByName ("ns3::TcpSocketFactory"));
        m_socketB_sink->Bind ( inetAddrB ); 
        m_socketB_sink->BindToNetDevice ( IPb );
        m_socketB_sink->Listen ();
        m_socketB_sink->ShutdownSend ();  
        m_socketB_sink->SetRecvCallback (MakeCallback (&QKDManager::VirtualReceive, b->GetObject<QKDManager> () ));
        m_socketB_sink->SetAcceptCallback (
            MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
            MakeCallback (&QKDManager::HandleAccept, b->GetObject<QKDManager> () )
        );

        // SEND SOCKETS
        
        //create TCP Send socket 
        m_socketA = Socket::CreateSocket (a, TypeId::LookupByName ("ns3::TcpSocketFactory"));
        m_socketA->Bind ();  
        m_socketA->SetConnectCallback (
            MakeCallback (&QKDManager::ConnectionSucceeded, a->GetObject<QKDManager> () ),
            MakeCallback (&QKDManager::ConnectionFailed,    a->GetObject<QKDManager> () )); 
        m_socketA->Connect ( inetAddrB ); 
        m_socketA->ShutdownRecv ();

        //create TCP Send socket 
        m_socketB = Socket::CreateSocket (b, TypeId::LookupByName ("ns3::TcpSocketFactory"));
        m_socketB->Bind ();  
        m_socketB->SetConnectCallback (
            MakeCallback (&QKDManager::ConnectionSucceeded, b->GetObject<QKDManager> () ),
            MakeCallback (&QKDManager::ConnectionFailed,    b->GetObject<QKDManager> () )); 
        m_socketB->Connect ( inetAddrA ); 
        m_socketB->ShutdownRecv (); 
 
    } else {

        //create UDP socket
        InetSocketAddress inetAddrA (ipv4a->GetAddress (interfaceOfClassicalDeviceOnNodeA, 0).GetLocal (), m_portOverlayNumber);
        m_socketA = Socket::CreateSocket (a, TypeId::LookupByName ("ns3::UdpSocketFactory"));
        m_socketA->Bind ( inetAddrA );
        m_socketA->BindToNetDevice ( IPa );
        m_socketA->SetRecvCallback (MakeCallback (&QKDManager::VirtualReceive, a->GetObject<QKDManager> () )); 

        //create UDP socket
        InetSocketAddress inetAddrB (ipv4b->GetAddress (interfaceOfClassicalDeviceOnNodeB, 0).GetLocal (), m_portOverlayNumber);
        m_socketB = Socket::CreateSocket (b, TypeId::LookupByName ("ns3::UdpSocketFactory"));
        m_socketB->Bind ( inetAddrB ); 
        m_socketB->BindToNetDevice ( IPb );
        m_socketB->SetRecvCallback (MakeCallback (&QKDManager::VirtualReceive, b->GetObject<QKDManager> () ));
         
        m_socketA_sink = m_socketA;
        m_socketB_sink = m_socketB;
    }

    /////////////////////////////////
    // UDP AND TCP SetDownTarget to QKD Priority Queues which sit between L3 and L4
    /////////////////////////////////

    //------------------------------------------
    // Forward from TCP/UDP L4 to QKD Queues
    //------------------------------------------
    if( m_supportQKDL4 ){

        QKDL4TrafficControlHelper qkdTch;
        uint16_t QKDhandle = qkdTch.SetRootQueueDisc ("ns3::QKDL4PfifoFastQueueDisc");
        qkdTch.AddInternalQueues (QKDhandle, 3, "ns3::DropTailQueue<QueueDiscItem>", "MaxSize", StringValue ("1000p"));
        //qkdTch.AddPacketFilter (QKDhandle, "ns3::PfifoFastQKDPacketFilter");
        QueueDiscContainer QKDqdiscsA = qkdTch.Install (a);
        QueueDiscContainer QKDqdiscsB = qkdTch.Install (b);

        //NODE A
        //Forward UDP communication from L4 to QKD Queues
        Ptr<VirtualUdpL4Protocol> udpA = a->GetObject<VirtualUdpL4Protocol> (); 
        udpA->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, a->GetObject<QKDL4TrafficControlLayer> ()));

        //Forward TCP communication from L4 to QKD Queues
        Ptr<VirtualTcpL4Protocol> tcpA = a->GetObject<VirtualTcpL4Protocol> (); 
        tcpA->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, a->GetObject<QKDL4TrafficControlLayer> ()));

        //NODE B
        //Forward UDP communication from L4 to QKD Queues
        Ptr<VirtualUdpL4Protocol> udpB = b->GetObject<VirtualUdpL4Protocol> (); 
        udpB->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, b->GetObject<QKDL4TrafficControlLayer> () ));

        //Forward TCP communication from L4 to QKD Queues
        Ptr<VirtualTcpL4Protocol> tcpB = b->GetObject<VirtualTcpL4Protocol> (); 
        tcpB->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, b->GetObject<QKDL4TrafficControlLayer> ()));
        
        //------------------------------------------
        // Forward from QKD Queues to Virtual IPv4 L3
        //------------------------------------------

        //Forward TCP communication from L4 to Virtual L3
        Ptr<QKDL4TrafficControlLayer> QKDTCLa = a->GetObject<QKDL4TrafficControlLayer> (); 
        QKDTCLa->SetDownTarget (MakeCallback (&VirtualIpv4L3Protocol::Send, a->GetObject<VirtualIpv4L3Protocol> ()));

        //Forward TCP communication from L4 to Virtual L3
        Ptr<QKDL4TrafficControlLayer> QKDTCLb = b->GetObject<QKDL4TrafficControlLayer> (); 
        QKDTCLb->SetDownTarget (MakeCallback (&VirtualIpv4L3Protocol::Send, b->GetObject<VirtualIpv4L3Protocol> ()));

    }

    /////////////////////////////////
    // Store details in QKD Managers
    // which are in charge to create QKD buffers  
    /////////////////////////////////
 
    //MASTER on node A
    if(a->GetObject<QKDManager> () != 0){
        a->GetObject<QKDManager> ()->AddNewLink( 
            devA, //QKDNetDevice on node A
            devB, //QKDNetDevice on node B
            IPa,  //IPNetDevice on node A
            IPb,  //IPNetDevice on node B
            m_QCrypto,
            m_socketA,
            m_socketA_sink,
            typeId,
            m_portOverlayNumber, 
            IPQKDaddressA, //QKD IP Src Address - overlay device
            IPQKDaddressB, //QKD IP Dst Address - overlay device 
            netA,  //IP Src Address - underlay device
            netB,  //IP Dst Address - underlay device 
            true,  
            Mmin, 
            Mthr, 
            Mmax, 
            Mcurrent,
            m_channelID
        ); 
    }
    
    //SLAVE on node B
    if(b->GetObject<QKDManager> () != 0){
        b->GetObject<QKDManager> ()->AddNewLink( 
            devB, //QKDNetDevice on node B
            devA, //QKDNetDevice on node A
            IPb,  //IPNetDevice on node B
            IPa,  //IPNetDevice on node A
            m_QCrypto,
            m_socketB,
            m_socketB_sink,
            typeId,
            m_portOverlayNumber, 
            IPQKDaddressB, //QKD IP Dst Address - overlay device 
            IPQKDaddressA, //QKD IP Src Address - overlay device
            netB,  //IP Dst Address - underlay device 
            netA,  //IP Src Address - underlay device
            false,              
            Mmin, 
            Mthr, 
            Mmax, 
            Mcurrent,
            m_channelID++
        ); 
    } 

    /**
    *   Initial load in QKD Buffers
    *   @ToDo: Currently buffers do not whole real data due to reduction of simlation time and computation complexity.
    *           Instead, they only keep the number of current amount of key material, but not the real key material in memory
    */
    if(m_useRealStorages){ 
        Ptr<QKDBuffer> bufferA = a->GetObject<QKDManager> ()->GetBufferBySourceAddress(IPQKDaddressA.GetLocal ()); 
        Ptr<QKDBuffer> bufferB = b->GetObject<QKDManager> ()->GetBufferBySourceAddress(IPQKDaddressB.GetLocal ());

        NS_LOG_FUNCTION(this << "!!!!!!!!!!!!!!" << bufferA->GetBufferId() << bufferB->GetBufferId() );

        uint32_t packetSize = 32;
        for(uint32_t i = 0; i < Mcurrent; i++ )
        {
            bufferA->AddNewContent(packetSize);
            bufferB->AddNewContent(packetSize);
        }
    }

    
    if(typeId == "ns3::TcpSocketFactory")
        m_portOverlayNumber++;

    return qkdNetDevices;
}

/**
*   Install and setup SINGLE TCP/IP QKD link between the nodes
*   @param  Ptr<NetDevice>          IPa
*   @param  Ptr<NetDevice>          IPb 
*   @param  uint32_t                Mmin
*   @param  uint32_t                Mthr
*   @param  uint32_t                Mmmax
*   @param  uint32_t                Mcurrent 
*/
NetDeviceContainer
QKDHelper::InstallQKD(
    Ptr<NetDevice>          IPa,            //IP Net device of underlay network on node A
    Ptr<NetDevice>          IPb,            //IP Net device of underlay network on node B
    uint32_t                Mmin,           //Buffer details
    uint32_t                Mthr,           //Buffer details
    uint32_t                Mmax,           //Buffer details
    uint32_t                Mcurrent        //Buffer details
)
{
    //################################
    //  SINGLE TCP/IP NETWORK
    //################################ 

    IPa->SetSniffPacketFromDevice(false);
    IPb->SetSniffPacketFromDevice(false);

    /////////////////////////////////
    // IPv4L3 Protocol and QKDL2 Traffic controller
    /////////////////////////////////

    Ptr<Node> a = IPa->GetNode();    
    Ptr<Node> b = IPb->GetNode();

    NS_LOG_FUNCTION(this << a->GetId() << b->GetId());

    /////////////////////////////////
    //          NODE A
    /////////////////////////////////

    if( m_supportQKDL4 && a->GetObject<QKDL4TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (a, "ns3::QKDL4TrafficControlLayer");

    if( a->GetObject<TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (a, "ns3::TrafficControlLayer");

    //Get address of classical device which is used for connection on the lower layer
    Ptr<Ipv4> ipv4a = a->GetObject<Ipv4L3Protocol> ();
    uint32_t interfaceOfClassicalDeviceOnNodeA = ipv4a->GetInterfaceForDevice(IPa);
    Ipv4InterfaceAddress netA = ipv4a->GetAddress (interfaceOfClassicalDeviceOnNodeA, 0);
      
    /////////////////////////////////
    //          NODE B
    /////////////////////////////////
   
    if( m_supportQKDL4 && b->GetObject<QKDL4TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (b, "ns3::QKDL4TrafficControlLayer");
    
    if( b->GetObject<TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (b, "ns3::TrafficControlLayer");

    //Get address of classical device which is used for connection of QKDNetDevice on lower layer
    Ptr<Ipv4> ipv4b = b->GetObject<Ipv4L3Protocol> ();
    uint32_t interfaceOfClassicalDeviceOnNodeB = ipv4b->GetInterfaceForDevice(IPb);
    Ipv4InterfaceAddress netB = ipv4b->GetAddress (interfaceOfClassicalDeviceOnNodeB, 0);    
    
    Ptr<Socket> m_socketA;
    Ptr<Socket> m_socketB;
    Ptr<Socket> m_socketA_sink;
    Ptr<Socket> m_socketB_sink;

    /////////////////////////////////
    // UDP AND TCP SetDownTarget to QKD Priority Queues which sit between L3 and L4
    /////////////////////////////////

    //------------------------------------------
    // Forward from TCP/UDP L4 to QKD Queues
    //------------------------------------------

    if (m_supportQKDL4) {

        QKDL4TrafficControlHelper qkdTch;
        uint16_t QKDhandle = qkdTch.SetRootQueueDisc ("ns3::QKDL4PfifoFastQueueDisc");
        qkdTch.AddInternalQueues (QKDhandle, 3, "ns3::DropTailQueue<QueueDiscItem>", "MaxSize", StringValue ("1000p"));
        //qkdTch.AddPacketFilter (QKDhandle, "ns3::PfifoFastQKDPacketFilter");
        QueueDiscContainer QKDqdiscsA = qkdTch.Install (a);
        QueueDiscContainer QKDqdiscsB = qkdTch.Install (b);


        //------------------------------------------
        // Forward from QKD Queues to IPv4 L3
        //------------------------------------------

       //Forward L4 communication to IPv4 L3
        Ptr<QKDL4TrafficControlLayer> QKDTCLa = a->GetObject<QKDL4TrafficControlLayer> (); 
        IpL4Protocol::DownTargetCallback qkdl4DownTarget_a = QKDTCLa->GetDownTarget();

        //Set it only once, otherwise we will finish in infinite loop
        if(qkdl4DownTarget_a.IsNull()){
        
            //Node A
            Ptr<UdpL4Protocol> udpA = a->GetObject<UdpL4Protocol> (); 
            Ptr<TcpL4Protocol> tcpA = a->GetObject<TcpL4Protocol> (); 

            IpL4Protocol::DownTargetCallback udpA_L4_downTarget = udpA->GetDownTarget ();
            IpL4Protocol::DownTargetCallback tcpA_L4_downTarget = tcpA->GetDownTarget ();

            if(!udpA_L4_downTarget.IsNull ())
                QKDTCLa->SetDownTarget (udpA_L4_downTarget);
            else if(!tcpA_L4_downTarget.IsNull ())
                QKDTCLa->SetDownTarget (tcpA_L4_downTarget);
            else
                NS_ASSERT (!udpA_L4_downTarget.IsNull ());
            //QKDTCLa->SetDownTarget (MakeCallback (&Ipv4L3Protocol::Send, a->GetObject<Ipv4L3Protocol> ()));

            //NODE A
            //Forward UDP communication from L4 to QKD Queues
            udpA->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, a->GetObject<QKDL4TrafficControlLayer> ()));
            //Forward TCP communication from L4 to QKD Queues
            tcpA->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, a->GetObject<QKDL4TrafficControlLayer> ()));

        }



        Ptr<QKDL4TrafficControlLayer> QKDTCLb = b->GetObject<QKDL4TrafficControlLayer> (); 
        IpL4Protocol::DownTargetCallback qkdl4DownTarget_b = QKDTCLb->GetDownTarget();
        
        //Set it only once, otherwise we will finish in infinite loop
        if(qkdl4DownTarget_b.IsNull()){

            //Node B
            Ptr<UdpL4Protocol> udpB = b->GetObject<UdpL4Protocol> (); 
            Ptr<TcpL4Protocol> tcpB = b->GetObject<TcpL4Protocol> (); 

            //Forward L4 communication to IPv4 L3
            IpL4Protocol::DownTargetCallback udpB_L4_downTarget = udpB->GetDownTarget ();
            IpL4Protocol::DownTargetCallback tcpB_L4_downTarget = tcpB->GetDownTarget ();

            if(!udpB_L4_downTarget.IsNull ())
                QKDTCLb->SetDownTarget (udpB_L4_downTarget);
            else if(!tcpB_L4_downTarget.IsNull ())
                QKDTCLb->SetDownTarget (tcpB_L4_downTarget);
            else
                NS_ASSERT (!udpB_L4_downTarget.IsNull ());
            //QKDTCLb->SetDownTarget (MakeCallback (&Ipv4L3Protocol::Send, b->GetObject<Ipv4L3Protocol> ()));
     
            //NODE B
            //Forward UDP communication from L4 to QKD Queues
            udpB->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, b->GetObject<QKDL4TrafficControlLayer> () ));
            //Forward TCP communication from L4 to QKD Queues
            tcpB->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, b->GetObject<QKDL4TrafficControlLayer> ()));
            
        }

    } 

    /////////////////////////////////
    // QKD Traffic Control  - queues on QKD Netdevices (L2)
    // Optional usage
    /////////////////////////////////

    NetDeviceContainer qkdNetDevices;
    qkdNetDevices.Add(IPa);
    qkdNetDevices.Add(IPb);

    TrafficControlHelper tch;
    tch.Uninstall(qkdNetDevices); 
    uint16_t handle = tch.SetRootQueueDisc ("ns3::QKDL2SingleTCPIPPfifoFastQueueDisc");
    tch.AddInternalQueues (handle, 3, "ns3::DropTailQueue<QueueDiscItem>", "MaxSize", StringValue ("1000p"));
    //tch.AddPacketFilter (handle, "ns3::PfifoFastIpv4PacketFilter");
    QueueDiscContainer qdiscs = tch.Install (qkdNetDevices);     
    
    ///ONLY FOR SINGLE TCP/IP STACK NETWORK (not overlay)
    //Forward packet from NETDevice to QKDManager to be processed (decrypted and authentication check);

    Ptr<TrafficControlLayer> tc_a = a->GetObject<TrafficControlLayer> ();
    NS_ASSERT (tc_a != 0);

    Ptr<TrafficControlLayer> tc_b = b->GetObject<TrafficControlLayer> ();
    NS_ASSERT (tc_b != 0);
 
    /**
    *   QKDManager sits between NetDevice and TrafficControlLayer
    *   Therefore, we need unregister existing callbacks and create new callbakcs to QKDManager  
    */
    a->UnregisterProtocolHandler (MakeCallback (&TrafficControlLayer::Receive, tc_a ));//One for IP
    a->UnregisterProtocolHandler (MakeCallback (&TrafficControlLayer::Receive, tc_a ));//One for ARP
 
    //a->UnregisterProtocolHandler (MakeCallback (&QKDManager::VirtualReceiveSimpleNetwork, a->GetObject<QKDManager> () ));
    //a->UnregisterProtocolHandler (MakeCallback (&QKDManager::VirtualReceiveSimpleNetwork, a->GetObject<QKDManager> () ));
    
    a->RegisterProtocolHandler (MakeCallback (&QKDManager::VirtualReceiveSimpleNetwork, a->GetObject<QKDManager> ()),
                                   Ipv4L3Protocol::PROT_NUMBER, IPa);
    a->RegisterProtocolHandler (MakeCallback (&QKDManager::VirtualReceiveSimpleNetwork, a->GetObject<QKDManager> ()),
                                   ArpL3Protocol::PROT_NUMBER, IPa);
      
    /**
    *   QKDManager sits between NetDevice and TrafficControlLayer
    *   Therefore, we need unregister existing callbacks and create new callbakcs to QKDManager 
    */
    b->UnregisterProtocolHandler (MakeCallback (&TrafficControlLayer::Receive, tc_b ));//One for IP
    b->UnregisterProtocolHandler (MakeCallback (&TrafficControlLayer::Receive, tc_b ));//One for ARP
 
    //b->UnregisterProtocolHandler (MakeCallback (&QKDManager::VirtualReceiveSimpleNetwork, b->GetObject<QKDManager> () ));
    //b->UnregisterProtocolHandler (MakeCallback (&QKDManager::VirtualReceiveSimpleNetwork, b->GetObject<QKDManager> () ));

    b->RegisterProtocolHandler (MakeCallback (&QKDManager::VirtualReceiveSimpleNetwork, b->GetObject<QKDManager> ()),
                                   Ipv4L3Protocol::PROT_NUMBER, IPb);
    b->RegisterProtocolHandler (MakeCallback (&QKDManager::VirtualReceiveSimpleNetwork, b->GetObject<QKDManager> ()),
                                   ArpL3Protocol::PROT_NUMBER, IPb);
 
    /////////////////////////////////
    // Store details in QKD Managers
    // which are in charge to create QKD buffers  
    /////////////////////////////////
 
    //MASTER on node A
    if(a->GetObject<QKDManager> () != 0){
        a->GetObject<QKDManager> ()->AddNewLink( 
            0, //QKDNetDevice on node A
            0, //QKDNetDevice on node B
            IPa,  //IPNetDevice on node A
            IPb,  //IPNetDevice on node B
            m_QCrypto,
            0, //m_socketA = 0
            0, //m_socketA_sink = 0
            "", //sockettypeID
            m_portOverlayNumber, 
            netA, //QKD IP Src Address - overlay device - same as underlay
            netB, //QKD IP Dst Address - overlay device - same as underlay
            netA,  //IP Src Address - underlay device
            netB,  //IP Dst Address - underlay device 
            true,  
            Mmin, 
            Mthr, 
            Mmax, 
            Mcurrent,
            m_channelID
        ); 
    }
    
    //SLAVE on node B
    if(b->GetObject<QKDManager> () != 0){
        b->GetObject<QKDManager> ()->AddNewLink( 
            0, //QKDNetDevice on node B
            0, //QKDNetDevice on node A
            IPb,  //IPNetDevice on node B
            IPa,  //IPNetDevice on node A
            m_QCrypto,
            0, //m_socketB = 0
            0, //m_socketB_sink = 0
            "", //sockettypeID
            m_portOverlayNumber, 
            netB, //QKD IP Dst Address - overlay device - same as underlay
            netA, //QKD IP Src Address - overlay device - same as underlay
            netB,  //IP Dst Address - underlay device 
            netA,  //IP Src Address - underlay device
            false,              
            Mmin, 
            Mthr, 
            Mmax, 
            Mcurrent,
            m_channelID++
        ); 
    }  

    /**
    *   Initial load in QKD Buffers
    *   @ToDo: Currently buffers do not whole real data due to reduction of simlation time and computation complexity.
    *           Instead, they only keep the number of current amount of key material, but not the real key material in memory
    */
    if(m_useRealStorages){

        //Get buffer on node A which is pointed from netA 
        Ptr<QKDBuffer> bufferA = a->GetObject<QKDManager> ()->GetBufferBySourceAddress(netA.GetLocal ());

        //Get buffer on node B which is pointed from netB 
        Ptr<QKDBuffer> bufferB = b->GetObject<QKDManager> ()->GetBufferBySourceAddress(netB.GetLocal ()); 

        NS_LOG_FUNCTION(this << "!!!!!!!!!!!!!!" << bufferA->GetBufferId() << bufferB->GetBufferId() );

        uint32_t packetSize = 32;
        for(uint32_t i = 0; i < Mcurrent; i++ )
        {
            bufferA->AddNewContent(packetSize);
            bufferB->AddNewContent(packetSize);
        }
    }

    return qkdNetDevices;

    }
} // namespace ns3
