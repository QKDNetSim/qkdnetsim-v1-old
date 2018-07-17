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
#include "ns3/address.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/virtual-tcp-socket-factory.h"
#include "ns3/qkd-manager.h"
#include "qkd-charging-application.h"
#include <iostream>
#include <fstream> 
#include <string>


NS_LOG_COMPONENT_DEFINE ("QKDChargingApplication");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (QKDChargingApplication);

TypeId
QKDChargingApplication::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDChargingApplication")
    .SetParent<Application> ()
    .AddConstructor<QKDChargingApplication> () 
    //send params
    .AddAttribute ("ThrPeriod", "The period for exchange of Threshold packets.",
                   UintegerValue (15),
                   MakeUintegerAccessor (&QKDChargingApplication::m_thresholdPeriodExchange),
                   MakeUintegerChecker<uint32_t> (1))
    .AddAttribute ("KeyRate", "The amount of data to be added to QKD Buffer (in bits).",
                   UintegerValue (100000),
                   MakeUintegerAccessor (&QKDChargingApplication::m_keyRate),
                   MakeUintegerChecker<uint32_t> (1))
    .AddAttribute ("DataRate", "The average data rate of communication.",
                   DataRateValue (DataRate ("650kbps")), //3.3Mbps //10kbps
                   MakeDataRateAccessor (&QKDChargingApplication::m_cbrRate),
                   MakeDataRateChecker ())
    .AddAttribute ("PacketSize", "The size of packets sent in post-processing state",
                   UintegerValue (320), //280
                   MakeUintegerAccessor (&QKDChargingApplication::m_pktSize),
                   MakeUintegerChecker<uint32_t> (1))  
    .AddAttribute ("MaxPackets", "The size of packets sent in post-processing state",
                   UintegerValue (1270), //93000
                   MakeUintegerAccessor (&QKDChargingApplication::m_maxPackets),
                   MakeUintegerChecker<uint32_t> (1))  
    .AddAttribute ("MaxAuthPackets", "The size of packets sent in auth state",
                   UintegerValue (540), //4
                   MakeUintegerAccessor (&QKDChargingApplication::m_maxPackets_auth),
                   MakeUintegerChecker<uint32_t> (1))  
    .AddAttribute ("MaxSiftingPackets", "The size of packets sent in sifting state",
                   UintegerValue (330), ///190
                   MakeUintegerAccessor (&QKDChargingApplication::m_maxPackets_sifting),
                   MakeUintegerChecker<uint32_t> (1))  
    .AddAttribute ("MaxTemp1Packets", "The size of packets sent in temp1 state",
                   UintegerValue (200), ///190
                   MakeUintegerAccessor (&QKDChargingApplication::m_maxPackets_temp1),
                   MakeUintegerChecker<uint32_t> (1))  
    .AddAttribute ("MaxTemp2Packets", "The size of packets sent in temp2 state",
                   UintegerValue (190), ///190
                   MakeUintegerAccessor (&QKDChargingApplication::m_maxPackets_temp2),
                   MakeUintegerChecker<uint32_t> (1))  

    .AddAttribute ("MaxTemp3Packets", "The size of packets sent in temp2 state",
                   UintegerValue (190), ///190
                   MakeUintegerAccessor (&QKDChargingApplication::m_maxPackets_temp3),
                   MakeUintegerChecker<uint32_t> (1))  

    .AddAttribute ("MaxTemp4Packets", "The size of packets sent in temp2 state",
                   UintegerValue (190), ///190
                   MakeUintegerAccessor (&QKDChargingApplication::m_maxPackets_temp4),
                   MakeUintegerChecker<uint32_t> (1))  

    .AddAttribute ("MaxTemp5Packets", "The size of packets sent in temp2 state",
                   UintegerValue (18), ///190
                   MakeUintegerAccessor (&QKDChargingApplication::m_maxPackets_temp5),
                   MakeUintegerChecker<uint32_t> (1))  

    .AddAttribute ("MaxTemp6Packets", "The size of packets sent in temp2 state",
                   UintegerValue (1), ///190
                   MakeUintegerAccessor (&QKDChargingApplication::m_maxPackets_temp6),
                   MakeUintegerChecker<uint32_t> (1))  

    .AddAttribute ("MaxTemp7Packets", "The size of packets sent in temp2 state",
                   UintegerValue (8), ///190
                   MakeUintegerAccessor (&QKDChargingApplication::m_maxPackets_temp7),
                   MakeUintegerChecker<uint32_t> (1))  

    .AddAttribute ("MaxTemp8Packets", "The size of packets sent in temp2 state",
                   UintegerValue (1), ///190
                   MakeUintegerAccessor (&QKDChargingApplication::m_maxPackets_temp8),
                   MakeUintegerChecker<uint32_t> (1))  

    .AddAttribute ("Protocol", "The type of protocol to use.",
                   TypeIdValue (VirtualTcpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&QKDChargingApplication::m_tid),
                   MakeTypeIdChecker ()) 

    .AddAttribute ("Remote", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_peer),
                   MakeAddressChecker ())
   .AddAttribute ("Local", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_local),
                   MakeAddressChecker ()) 
 
    .AddAttribute ("Remote_Sifting", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_peer_sifting),
                   MakeAddressChecker ())
   .AddAttribute ("Local_Sifting", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_local_sifting),
                   MakeAddressChecker ()) 

    .AddAttribute ("Remote_Auth", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_peer_auth),
                   MakeAddressChecker ())
   .AddAttribute ("Local_Auth", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_local_auth),
                   MakeAddressChecker ()) 

    .AddAttribute ("Remote_Mthreshold", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_peer_mthreshold),
                   MakeAddressChecker ())
   .AddAttribute ("Local_Mthreshold", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_local_mthreshold),
                   MakeAddressChecker ())  

    .AddAttribute ("Remote_Temp1", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_peer_temp1),
                   MakeAddressChecker ())
   .AddAttribute ("Local_Temp1", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_local_temp1),
                   MakeAddressChecker ())  

    .AddAttribute ("Remote_Temp2", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_peer_temp2),
                   MakeAddressChecker ())
   .AddAttribute ("Local_Temp2", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_local_temp2),
                   MakeAddressChecker ())   

    .AddAttribute ("Remote_Temp3", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_peer_temp3),
                   MakeAddressChecker ())
   .AddAttribute ("Local_Temp3", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_local_temp3),
                   MakeAddressChecker ())   

    .AddAttribute ("Remote_Temp4", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_peer_temp4),
                   MakeAddressChecker ())
   .AddAttribute ("Local_Temp4", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_local_temp4),
                   MakeAddressChecker ())   

    .AddAttribute ("Remote_Temp5", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_peer_temp5),
                   MakeAddressChecker ())
   .AddAttribute ("Local_Temp5", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_local_temp5),
                   MakeAddressChecker ())   

    .AddAttribute ("Remote_Temp6", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_peer_temp6),
                   MakeAddressChecker ())
   .AddAttribute ("Local_Temp6", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_local_temp6),
                   MakeAddressChecker ())   

    .AddAttribute ("Remote_Temp7", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_peer_temp7),
                   MakeAddressChecker ())
   .AddAttribute ("Local_Temp7", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_local_temp7),
                   MakeAddressChecker ())   

    .AddAttribute ("Remote_Temp8", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_peer_temp8),
                   MakeAddressChecker ())
   .AddAttribute ("Local_Temp8", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&QKDChargingApplication::m_local_temp8),
                   MakeAddressChecker ())   

   .AddTraceSource ("Tx", "A new packet is created and is sent",
                   MakeTraceSourceAccessor (&QKDChargingApplication::m_txTrace),
                   "ns3::QKDChargingApplication::Tx")
   .AddTraceSource ("Rx", "A packet has been received",
                   MakeTraceSourceAccessor (&QKDChargingApplication::m_rxTrace),
                   "ns3::QKDChargingApplication::Rx")
  ;
  return tid;
}


QKDChargingApplication::QKDChargingApplication ()
{     
  m_connected = false;
  m_packetNumber= 0; 
  m_totalRx= 0;
  m_sendKeyRateMessage= 0;
  m_qkdPacketNumber= 0;
  m_qkdTotalTime= 0;
  m_status= 0;
  m_packetNumber_auth= 0; 
  m_packetNumber_sifting= 0; 
  m_packetNumber_temp1= 0; 
  m_packetNumber_temp2= 0; 
  m_packetNumber_temp3= 0; 
  m_packetNumber_temp4= 0; 
  m_packetNumber_temp5= 0; 
  m_packetNumber_temp6= 0; 
  m_packetNumber_temp7= 0; 
  m_packetNumber_temp8= 0; 
}

QKDChargingApplication::~QKDChargingApplication ()
{
  NS_LOG_FUNCTION (this);
}


uint32_t QKDChargingApplication::GetTotalRx () const
{
  NS_LOG_FUNCTION (this);
  return m_totalRx;
}


std::list<Ptr<Socket> >
QKDChargingApplication::GetAcceptedSockets (void) const
{
  NS_LOG_FUNCTION (this);
  return m_sinkSocketList;
}

Ptr<Socket>
QKDChargingApplication::GetSinkSocket (void) const
{
  NS_LOG_FUNCTION (this);
  return m_sinkSocket;
}

 
Ptr<Socket>
QKDChargingApplication::GetSendSocket (void) const
{
  NS_LOG_FUNCTION (this);
  return m_sendSocket;
}

void
QKDChargingApplication::SetSocket (std::string type, Ptr<Socket> socket, Ptr<NetDevice> device, bool isMaster)
{
    NS_LOG_FUNCTION (this << type << socket << device << isMaster);

    if(type == "send"){//send app
      m_sendSocket = socket;
      m_sendDevice = device;
    }else{ // sink app
      m_sinkSocket = socket;
      m_sinkDevice = device;
    } 
    m_master = isMaster;
}

void
QKDChargingApplication::SetAuthSocket (std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << type << socket);

  if(type == "send"){//send app
    m_sendSocket_auth = socket; 
  }else{ // sink app
    m_sinkSocket_auth = socket; 
  } 
}

void
QKDChargingApplication::SetSiftingSocket (std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << type << socket);

  if(type == "send"){//send app
    m_sendSocket_sifting = socket; 
  }else{ // sink app
    m_sinkSocket_sifting = socket; 
  } 
}

void
QKDChargingApplication::SetTemp1Socket (std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << type << socket);

  if(type == "send"){//send app
    m_tempSendSocket_1 = socket; 
  }else{ // sink app
    m_tempSinkSocket_1 = socket; 
  } 
}

void
QKDChargingApplication::SetTemp2Socket (std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << type << socket);

  if(type == "send"){//send app
    m_tempSendSocket_2 = socket; 
  }else{ // sink app
    m_tempSinkSocket_2 = socket; 
  } 
}

void
QKDChargingApplication::SetTemp3Socket (std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << type << socket);

  if(type == "send"){//send app
    m_tempSendSocket_3 = socket; 
  }else{ // sink app
    m_tempSinkSocket_3 = socket; 
  } 
}

void
QKDChargingApplication::SetTemp4Socket (std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << type << socket);

  if(type == "send"){//send app
    m_tempSendSocket_4 = socket; 
  }else{ // sink app
    m_tempSinkSocket_4 = socket; 
  } 
}

void
QKDChargingApplication::SetTemp5Socket (std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << type << socket);

  if(type == "send"){//send app
    m_tempSendSocket_5 = socket; 
  }else{ // sink app
    m_tempSinkSocket_5 = socket; 
  } 
}

void
QKDChargingApplication::SetTemp6Socket (std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << type << socket);

  if(type == "send"){//send app
    m_tempSendSocket_6 = socket; 
  }else{ // sink app
    m_tempSinkSocket_6 = socket; 
  } 
}

void
QKDChargingApplication::SetTemp7Socket (std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << type << socket);

  if(type == "send"){//send app
    m_tempSendSocket_7 = socket; 
  }else{ // sink app
    m_tempSinkSocket_7 = socket; 
  } 
}

void
QKDChargingApplication::SetTemp8Socket (std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << type << socket);

  if(type == "send"){//send app
    m_tempSendSocket_8 = socket; 
  }else{ // sink app
    m_tempSinkSocket_8 = socket; 
  } 
}



void
QKDChargingApplication::DoDispose (void)
{
  NS_LOG_FUNCTION (this);

  m_sendSocket = 0;
  m_sinkSocket = 0;
  m_sendSocket_sifting = 0;
  m_sinkSocket_sifting = 0;
  m_sendSocket_mthreshold = 0;
  m_sinkSocket_mthreshold = 0;
  m_sendSocket_auth = 0;
  m_sinkSocket_auth = 0;
  m_tempSendSocket_1 = 0;
  m_tempSinkSocket_1 = 0;
  m_tempSendSocket_2 = 0;
  m_tempSinkSocket_2 = 0;
  m_tempSendSocket_3 = 0;
  m_tempSinkSocket_3 = 0;
  m_tempSendSocket_4 = 0;
  m_tempSinkSocket_4 = 0;
  m_tempSendSocket_5 = 0;
  m_tempSinkSocket_5 = 0;
  m_tempSendSocket_6 = 0;
  m_tempSinkSocket_6 = 0;
  m_tempSendSocket_7 = 0;
  m_tempSinkSocket_7 = 0;
  m_tempSendSocket_8 = 0;
  m_tempSinkSocket_8 = 0;

  m_sinkSocketList.clear ();
  Simulator::Cancel (m_sendEvent);
  // chain up
  Application::DoDispose ();
}

// Application Methods
void QKDChargingApplication::StartApplication (void) // Called at time specified by Start
{
  NS_LOG_FUNCTION (this);

  m_random = CreateObject<UniformRandomVariable> ();
  //m_maxPackets = m_random->GetValue (m_maxPackets * 0.5, m_maxPackets * 1.5);
  
  //   SINK socket settings
  // Create the socket if not already
  if (!m_sinkSocket)
    m_sinkSocket = Socket::CreateSocket (GetNode (), m_tid);
  m_sinkSocket->SetIpTos(16); 
  m_sinkSocket->SetIpRecvTos(true);
  m_sinkSocket->Bind (m_local);
  m_sinkSocket->BindToNetDevice(m_sinkDevice);
  m_sinkSocket->Listen ();
  m_sinkSocket->ShutdownSend ();
  m_sinkSocket->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleRead, this));
  m_sinkSocket->SetAcceptCallback (
      MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
      MakeCallback (&QKDChargingApplication::HandleAccept, this));
  m_sinkSocket->SetCloseCallbacks (
      MakeCallback (&QKDChargingApplication::HandlePeerClose, this),
      MakeCallback (&QKDChargingApplication::HandlePeerError, this)); 

  // SEND socket settings
  // Create the socket if not already
  if (!m_sendSocket)
      m_sendSocket = Socket::CreateSocket (GetNode (), m_tid);
  m_sendSocket->SetIpTos(16); 
  m_sendSocket->SetIpRecvTos(true); 
  m_sendSocket->BindToNetDevice(m_sendDevice);
  //initate TCP-threehand shaking
  m_sendSocket->Connect (m_peer); 
  //disable receiving any data on this socket
  m_sendSocket->ShutdownRecv ();
  m_sendSocket->SetConnectCallback (
      MakeCallback (&QKDChargingApplication::ConnectionSucceeded, this),
      MakeCallback (&QKDChargingApplication::ConnectionFailed, this)); 
  m_sendSocket->SetDataSentCallback (
      MakeCallback (&QKDChargingApplication::DataSend, this)); 

  m_sendSocket->TraceConnectWithoutContext ("RTT", MakeCallback (&QKDChargingApplication::RegisterAckTime, this)); 
  

  //---------------------------------------------------------------------
  //   mthreshold socket settings
  //----------------------------------------------------------------------
  
  //   mthreshold SINK socket settings
  // Create the socket if not already
  if (!m_sinkSocket_mthreshold)
    m_sinkSocket_mthreshold = Socket::CreateSocket (GetNode (), m_tid);
  m_sinkSocket_mthreshold->SetIpTos(16);  
  m_sinkSocket_mthreshold->SetIpTtl (30); 
  m_sinkSocket_mthreshold->SetIpRecvTos(true);
  m_sinkSocket_mthreshold->SetIpRecvTtl(true); 
  m_sinkSocket_mthreshold->Bind (m_local_mthreshold);
  m_sinkSocket_mthreshold->BindToNetDevice(m_sinkDevice);
  m_sinkSocket_mthreshold->Listen ();
  m_sinkSocket_mthreshold->ShutdownSend ();      
  m_sinkSocket_mthreshold->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadMthreshold, this));
  m_sinkSocket_mthreshold->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDChargingApplication::HandleAcceptMthreshold, this));

  m_sinkSocket_mthreshold->SetCloseCallbacks (
    MakeCallback (&QKDChargingApplication::HandlePeerClose, this),
    MakeCallback (&QKDChargingApplication::HandlePeerError, this)); 

  // mthreshold SEND socket settings
  // Create the socket if not already
  if (!m_sendSocket_mthreshold)
    m_sendSocket_mthreshold = Socket::CreateSocket (GetNode (), m_tid);
  m_sendSocket_mthreshold->SetIpTos(16);
  m_sendSocket_mthreshold->SetIpTtl (30);
  m_sendSocket_mthreshold->SetIpRecvTos(true);
  m_sendSocket_mthreshold->SetIpRecvTtl(true); 
  //m_sendSocket_mthreshold->Bind (m_local); 
  m_sendSocket_mthreshold->BindToNetDevice(m_sendDevice);
  //initate TCP-threehand shaking
  m_sendSocket_mthreshold->Connect (m_peer_mthreshold);
  //m_sendSocket_mthreshold->SetIpTtl (0);
  //disable receiving any data on this socket
  m_sendSocket_mthreshold->ShutdownRecv ();
  m_sendSocket_mthreshold->SetConnectCallback (
    MakeCallback (&QKDChargingApplication::ConnectionSucceededMthreshold, this),
    MakeCallback (&QKDChargingApplication::ConnectionFailedMthreshold, this)); 

  m_sendSocket_mthreshold->SetDataSentCallback (
    MakeCallback (&QKDChargingApplication::DataSend, this)); 
 
  //---------------------------------------------------------------------
  //  AUTH socket settings
  //----------------------------------------------------------------------
   
  //   AUTH SINK socket settings
  // Create the socket if not already
  if (!m_sinkSocket_auth)
    m_sinkSocket_auth = Socket::CreateSocket (GetNode (), m_tid);
  m_sinkSocket_auth->SetIpTos(16); 
  m_sinkSocket_auth->SetIpRecvTos(true);
  m_sinkSocket_auth->Bind (m_local_auth);
  m_sinkSocket_auth->BindToNetDevice(m_sinkDevice);
  m_sinkSocket_auth->Listen ();
  m_sinkSocket_auth->ShutdownSend ();      
  m_sinkSocket_auth->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadAuth, this));
  m_sinkSocket_auth->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDChargingApplication::HandleAcceptAuth, this));

  m_sinkSocket_auth->SetCloseCallbacks (
    MakeCallback (&QKDChargingApplication::HandlePeerClose, this),
    MakeCallback (&QKDChargingApplication::HandlePeerError, this)); 

  // AUTH SEND socket settings
  // Create the socket if not already
  if (!m_sendSocket_auth)
    m_sendSocket_auth = Socket::CreateSocket (GetNode (), m_tid);
  m_sendSocket_auth->SetIpTos(16); 
  m_sendSocket_auth->SetIpRecvTos(true);
  m_sendSocket_auth->BindToNetDevice(m_sendDevice);
  m_sendSocket_auth->Connect (m_peer_auth);
  m_sendSocket_auth->ShutdownRecv ();
  m_sendSocket_auth->SetConnectCallback (
    MakeCallback (&QKDChargingApplication::ConnectionSucceededAuth, this),
    MakeCallback (&QKDChargingApplication::ConnectionFailedAuth, this)); 
  m_sendSocket_auth->SetDataSentCallback (
    MakeCallback (&QKDChargingApplication::DataSend, this)); 


  //---------------------------------------------------------------------
  //  SIFTING socket settings
  //----------------------------------------------------------------------
  
  //   SIFTING SINK socket settings
  // Create the socket if not already
  if (!m_sinkSocket_sifting  )
    m_sinkSocket_sifting = Socket::CreateSocket (GetNode (), m_tid);
  m_sinkSocket_sifting->SetIpTos(16); 
  m_sinkSocket_sifting->SetIpRecvTos(true);
  m_sinkSocket_sifting->Bind (m_local_sifting);
  m_sinkSocket_sifting->BindToNetDevice(m_sinkDevice);
  m_sinkSocket_sifting->Listen ();
  m_sinkSocket_sifting->ShutdownSend ();      
  m_sinkSocket_sifting->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadSifting, this));
  m_sinkSocket_sifting->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDChargingApplication::HandleAcceptSifting, this));
  m_sinkSocket_sifting->SetCloseCallbacks (
    MakeCallback (&QKDChargingApplication::HandlePeerClose, this),
    MakeCallback (&QKDChargingApplication::HandlePeerError, this)); 

  
  //   SIFTING SEND socket settings
  // Create the socket if not already
  if (!m_sendSocket_sifting)
    m_sendSocket_sifting = Socket::CreateSocket (GetNode (), m_tid);
  m_sendSocket_sifting->SetIpTos(16); 
  m_sendSocket_sifting->SetIpRecvTos(true);
  //m_sendSocket_sifting->Bind (m_local); 
  m_sendSocket_sifting->BindToNetDevice(m_sendDevice);
  m_sendSocket_sifting->Connect (m_peer_sifting);
  m_sendSocket_sifting->ShutdownRecv ();
  m_sendSocket_sifting->SetConnectCallback (
    MakeCallback (&QKDChargingApplication::ConnectionSucceededSifting, this),
    MakeCallback (&QKDChargingApplication::ConnectionFailedSifting, this)); 
  m_sendSocket_sifting->SetDataSentCallback (
    MakeCallback (&QKDChargingApplication::DataSend, this));  
 

  //---------------------------------------------------------------------
  //   temp1 socket settings
  //----------------------------------------------------------------------
  
  //   temp1 SINK socket settings
  // Create the socket if not already
  if (!m_tempSinkSocket_1){
    NS_LOG_FUNCTION(this << "CREATE TEMP1 SINK SOCKET!");
    m_tempSinkSocket_1 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSinkSocket_1->SetIpTos(16); 
  m_tempSinkSocket_1->SetIpRecvTos(true);
  m_tempSinkSocket_1->Bind (m_local_temp1);
  m_tempSinkSocket_1->BindToNetDevice(m_sinkDevice);
  m_tempSinkSocket_1->Listen ();
  m_tempSinkSocket_1->ShutdownSend ();      
  m_tempSinkSocket_1->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp1, this));
  m_tempSinkSocket_1->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDChargingApplication::HandleAcceptTemp1, this));
  m_tempSinkSocket_1->SetCloseCallbacks (
    MakeCallback (&QKDChargingApplication::HandlePeerClose, this),
    MakeCallback (&QKDChargingApplication::HandlePeerError, this)); 

  // temp1 SEND socket settings
  // Create the socket if not already
  if (!m_tempSendSocket_1){
    NS_LOG_FUNCTION(this << "CREATE TEMP1 SEND SOCKET!");
    m_tempSendSocket_1 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSendSocket_1->SetIpTos(16); 
  m_tempSendSocket_1->SetIpRecvTos(true); 
  m_tempSendSocket_1->BindToNetDevice(m_sendDevice); 
  m_tempSendSocket_1->Connect (m_peer_temp1); 
  m_tempSendSocket_1->ShutdownRecv ();
  m_tempSendSocket_1->SetConnectCallback (
    MakeCallback (&QKDChargingApplication::ConnectionSucceededtemp1, this),
    MakeCallback (&QKDChargingApplication::ConnectionFailedtemp1, this)); 
  m_tempSendSocket_1->SetDataSentCallback (
    MakeCallback (&QKDChargingApplication::DataSend, this)); 


  //---------------------------------------------------------------------
  //   temp2 socket settings
  //----------------------------------------------------------------------
  
  //   temp2 SINK socket settings
  // Create the socket if not already
  if (!m_tempSinkSocket_2){
    NS_LOG_FUNCTION(this << "CREATE TEMP2 SINK SOCKET!");
    m_tempSinkSocket_2 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSinkSocket_2->SetIpTos(16); 
  m_tempSinkSocket_2->SetIpRecvTos(true);
  m_tempSinkSocket_2->Bind (m_local_temp2);
  m_tempSinkSocket_2->BindToNetDevice(m_sinkDevice);
  m_tempSinkSocket_2->Listen ();
  m_tempSinkSocket_2->ShutdownSend ();      
  m_tempSinkSocket_2->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp2, this));
  m_tempSinkSocket_2->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDChargingApplication::HandleAcceptTemp2, this));

  m_tempSinkSocket_2->SetCloseCallbacks (
    MakeCallback (&QKDChargingApplication::HandlePeerClose, this),
    MakeCallback (&QKDChargingApplication::HandlePeerError, this)); 

  
  // temp2 SEND socket settings
  // Create the socket if not already
  if (!m_tempSendSocket_2){
    NS_LOG_FUNCTION(this << "CREATE TEMP2 SEND SOCKET!");
    m_tempSendSocket_2 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSendSocket_2->SetIpTos(16); 
  m_tempSendSocket_2->SetIpRecvTos(true);
  //m_tempSendSocket_2->Bind (m_local); 
  m_tempSendSocket_2->BindToNetDevice(m_sendDevice);
  //initate TCP-threehand shaking
  m_tempSendSocket_2->Connect (m_peer_temp2);
  //m_tempSendSocket_2->SetIpTtl (0);
  //disable receiving any data on this socket
  m_tempSendSocket_2->ShutdownRecv ();
  m_tempSendSocket_2->SetConnectCallback (
    MakeCallback (&QKDChargingApplication::ConnectionSucceededtemp2, this),
    MakeCallback (&QKDChargingApplication::ConnectionFailedtemp2, this)); 
  m_tempSendSocket_2->SetDataSentCallback (
    MakeCallback (&QKDChargingApplication::DataSend, this)); 




  //---------------------------------------------------------------------
  //   temp3 socket settings
  //----------------------------------------------------------------------
  
  //   temp3 SINK socket settings
  // Create the socket if not already
  if (!m_tempSinkSocket_3){
    NS_LOG_FUNCTION(this << "CREATE TEMP3 SINK SOCKET!");
    m_tempSinkSocket_3 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSinkSocket_3->SetIpTos(16); 
  m_tempSinkSocket_3->SetIpRecvTos(true);
  m_tempSinkSocket_3->Bind (m_local_temp3);
  m_tempSinkSocket_3->BindToNetDevice(m_sinkDevice);
  m_tempSinkSocket_3->Listen ();
  m_tempSinkSocket_3->ShutdownSend ();      
  m_tempSinkSocket_3->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp3, this));
  m_tempSinkSocket_3->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDChargingApplication::HandleAcceptTemp3, this));

  m_tempSinkSocket_3->SetCloseCallbacks (
    MakeCallback (&QKDChargingApplication::HandlePeerClose, this),
    MakeCallback (&QKDChargingApplication::HandlePeerError, this)); 

  
  // temp3 SEND socket settings
  // Create the socket if not already
  if (!m_tempSendSocket_3){
    NS_LOG_FUNCTION(this << "CREATE TEMP3 SEND SOCKET!");
    m_tempSendSocket_3 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSendSocket_3->SetIpTos(16); 
  m_tempSendSocket_3->SetIpRecvTos(true);
  //m_tempSendSocket_3->Bind (m_local); 
  m_tempSendSocket_3->BindToNetDevice(m_sendDevice);
  //initate TCP-threehand shaking
  m_tempSendSocket_3->Connect (m_peer_temp3);
  //m_tempSendSocket_3->SetIpTtl (0);
  //disable receiving any data on this socket
  m_tempSendSocket_3->ShutdownRecv ();
  m_tempSendSocket_3->SetConnectCallback (
    MakeCallback (&QKDChargingApplication::ConnectionSucceededtemp3, this),
    MakeCallback (&QKDChargingApplication::ConnectionFailedtemp3, this)); 
  m_tempSendSocket_3->SetDataSentCallback (
    MakeCallback (&QKDChargingApplication::DataSend, this)); 


  //---------------------------------------------------------------------
  //  temp4 socket settings
  //----------------------------------------------------------------------
  
  //   temp4 SINK socket settings
  // Create the socket if not already
  if (!m_tempSinkSocket_4){
    NS_LOG_FUNCTION(this << "CREATE TEMP4 SINK SOCKET!");
    m_tempSinkSocket_4 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSinkSocket_4->SetIpTos(16); 
  m_tempSinkSocket_4->SetIpRecvTos(true);
  m_tempSinkSocket_4->Bind (m_local_temp4);
  m_tempSinkSocket_4->BindToNetDevice(m_sinkDevice);
  m_tempSinkSocket_4->Listen ();
  m_tempSinkSocket_4->ShutdownSend ();      
  m_tempSinkSocket_4->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp4, this));
  m_tempSinkSocket_4->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDChargingApplication::HandleAcceptTemp4, this));

  m_tempSinkSocket_4->SetCloseCallbacks (
    MakeCallback (&QKDChargingApplication::HandlePeerClose, this),
    MakeCallback (&QKDChargingApplication::HandlePeerError, this)); 


  // temp4 SEND socket settings
  // Create the socket if not already
  if (!m_tempSendSocket_4){
    NS_LOG_FUNCTION(this << "CREATE TEMP4 SEND SOCKET!");
    m_tempSendSocket_4 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSendSocket_4->SetIpTos(16); 
  m_tempSendSocket_4->SetIpRecvTos(true);
  //m_tempSendSocket_4->Bind (m_local); 
  m_tempSendSocket_4->BindToNetDevice(m_sendDevice);
  //initate TCP-threehand shaking
  m_tempSendSocket_4->Connect (m_peer_temp4);
  //m_tempSendSocket_4->SetIpTtl (0);
  //disable receiving any data on this socket
  m_tempSendSocket_4->ShutdownRecv ();
  m_tempSendSocket_4->SetConnectCallback (
    MakeCallback (&QKDChargingApplication::ConnectionSucceededtemp4, this),
    MakeCallback (&QKDChargingApplication::ConnectionFailedtemp4, this)); 
  m_tempSendSocket_4->SetDataSentCallback (
    MakeCallback (&QKDChargingApplication::DataSend, this)); 


  //---------------------------------------------------------------------
  //   temp5 socket settings
  //----------------------------------------------------------------------
  
  //   temp5 SINK socket settings
  // Create the socket if not already
  if (!m_tempSinkSocket_5){
    NS_LOG_FUNCTION(this << "CREATE TEMP5 SINK SOCKET!");
    m_tempSinkSocket_5 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSinkSocket_5->SetIpTos(16); 
  m_tempSinkSocket_5->SetIpRecvTos(true);
  m_tempSinkSocket_5->Bind (m_local_temp5);
  m_tempSinkSocket_5->BindToNetDevice(m_sinkDevice);
  m_tempSinkSocket_5->Listen ();
  m_tempSinkSocket_5->ShutdownSend ();      
  m_tempSinkSocket_5->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp5, this));
  m_tempSinkSocket_5->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDChargingApplication::HandleAcceptTemp5, this));

  m_tempSinkSocket_5->SetCloseCallbacks (
    MakeCallback (&QKDChargingApplication::HandlePeerClose, this),
    MakeCallback (&QKDChargingApplication::HandlePeerError, this)); 

  
  // temp5 SEND socket settings
  // Create the socket if not already
  if (!m_tempSendSocket_5){
    NS_LOG_FUNCTION(this << "CREATE TEMP5 SEND SOCKET!");
    m_tempSendSocket_5 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSendSocket_5->SetIpTos(16); 
  m_tempSendSocket_5->SetIpRecvTos(true);
  //m_tempSendSocket_5->Bind (m_local); 
  m_tempSendSocket_5->BindToNetDevice(m_sendDevice);
  //initate TCP-threehand shaking
  m_tempSendSocket_5->Connect (m_peer_temp5);
  //m_tempSendSocket_5->SetIpTtl (0);
  //disable receiving any data on this socket
  m_tempSendSocket_5->ShutdownRecv ();
  m_tempSendSocket_5->SetConnectCallback (
    MakeCallback (&QKDChargingApplication::ConnectionSucceededtemp5, this),
    MakeCallback (&QKDChargingApplication::ConnectionFailedtemp5, this)); 
  m_tempSendSocket_5->SetDataSentCallback (
    MakeCallback (&QKDChargingApplication::DataSend, this)); 


  //---------------------------------------------------------------------
  //   temp6 socket settings
  //----------------------------------------------------------------------
  
  //   temp6 SINK socket settings
  // Create the socket if not already
  if (!m_tempSinkSocket_6){
    NS_LOG_FUNCTION(this << "CREATE TEMP6 SINK SOCKET!");
    m_tempSinkSocket_6 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSinkSocket_6->SetIpTos(16); 
  m_tempSinkSocket_6->SetIpRecvTos(true);
  m_tempSinkSocket_6->Bind (m_local_temp6);
  m_tempSinkSocket_6->BindToNetDevice(m_sinkDevice);
  m_tempSinkSocket_6->Listen ();
  m_tempSinkSocket_6->ShutdownSend ();      
  m_tempSinkSocket_6->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp6, this));
  m_tempSinkSocket_6->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDChargingApplication::HandleAcceptTemp6, this));

  m_tempSinkSocket_6->SetCloseCallbacks (
    MakeCallback (&QKDChargingApplication::HandlePeerClose, this),
    MakeCallback (&QKDChargingApplication::HandlePeerError, this)); 

  // temp6 SEND socket settings
  // Create the socket if not already
  if (!m_tempSendSocket_6){
    NS_LOG_FUNCTION(this << "CREATE TEMP6 SEND SOCKET!");
    m_tempSendSocket_6 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSendSocket_6->SetIpTos(16); 
  m_tempSendSocket_6->SetIpRecvTos(true);
  //m_tempSendSocket_6->Bind (m_local); 
  m_tempSendSocket_6->BindToNetDevice(m_sendDevice);
  //initate TCP-threehand shaking
  m_tempSendSocket_6->Connect (m_peer_temp6);
  //m_tempSendSocket_6->SetIpTtl (0);
  //disable receiving any data on this socket
  m_tempSendSocket_6->ShutdownRecv ();
  m_tempSendSocket_6->SetConnectCallback (
    MakeCallback (&QKDChargingApplication::ConnectionSucceededtemp6, this),
    MakeCallback (&QKDChargingApplication::ConnectionFailedtemp6, this)); 
  m_tempSendSocket_6->SetDataSentCallback (
    MakeCallback (&QKDChargingApplication::DataSend, this)); 

  //---------------------------------------------------------------------
  //   temp7 socket settings
  //----------------------------------------------------------------------
  
  //   temp7 SINK socket settings
  // Create the socket if not already
  if (!m_tempSinkSocket_7){
    NS_LOG_FUNCTION(this << "CREATE TEMP7 SINK SOCKET!");
    m_tempSinkSocket_7 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSinkSocket_7->SetIpTos(16); 
  m_tempSinkSocket_7->SetIpRecvTos(true);
  m_tempSinkSocket_7->Bind (m_local_temp7);
  m_tempSinkSocket_7->BindToNetDevice(m_sinkDevice);
  m_tempSinkSocket_7->Listen ();
  m_tempSinkSocket_7->ShutdownSend ();      
  m_tempSinkSocket_7->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp7, this));
  m_tempSinkSocket_7->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDChargingApplication::HandleAcceptTemp7, this));

  m_tempSinkSocket_7->SetCloseCallbacks (
    MakeCallback (&QKDChargingApplication::HandlePeerClose, this),
    MakeCallback (&QKDChargingApplication::HandlePeerError, this)); 

  // temp7 SEND socket settings
  // Create the socket if not already
  if (!m_tempSendSocket_7){
    NS_LOG_FUNCTION(this << "CREATE TEMP7 SEND SOCKET!");
    m_tempSendSocket_7 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSendSocket_7->SetIpTos(16); 
  m_tempSendSocket_7->SetIpRecvTos(true);
  //m_tempSendSocket_7->Bind (m_local); 
  m_tempSendSocket_7->BindToNetDevice(m_sendDevice);
  //initate TCP-threehand shaking
  m_tempSendSocket_7->Connect (m_peer_temp7);
  //m_tempSendSocket_7->SetIpTtl (0);
  //disable receiving any data on this socket
  m_tempSendSocket_7->ShutdownRecv ();
  m_tempSendSocket_7->SetConnectCallback (
    MakeCallback (&QKDChargingApplication::ConnectionSucceededtemp7, this),
    MakeCallback (&QKDChargingApplication::ConnectionFailedtemp7, this)); 
  m_tempSendSocket_7->SetDataSentCallback (
    MakeCallback (&QKDChargingApplication::DataSend, this)); 

  //---------------------------------------------------------------------
  //   temp8 socket settings
  //----------------------------------------------------------------------
  
  //   temp8 SINK socket settings
  // Create the socket if not already
  if (!m_tempSinkSocket_8){
    NS_LOG_FUNCTION(this << "CREATE TEMP8 SINK SOCKET!");
    m_tempSinkSocket_8 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSinkSocket_8->SetIpTos(16); 
  m_tempSinkSocket_8->SetIpRecvTos(true);
  m_tempSinkSocket_8->Bind (m_local_temp8);
  m_tempSinkSocket_8->BindToNetDevice(m_sinkDevice);
  m_tempSinkSocket_8->Listen ();
  m_tempSinkSocket_8->ShutdownSend ();      
  m_tempSinkSocket_8->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp8, this));
  m_tempSinkSocket_8->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDChargingApplication::HandleAcceptTemp8, this));

  m_tempSinkSocket_8->SetCloseCallbacks (
    MakeCallback (&QKDChargingApplication::HandlePeerClose, this),
    MakeCallback (&QKDChargingApplication::HandlePeerError, this)); 

  // temp8 SEND socket settings
  // Create the socket if not already
  if (!m_tempSendSocket_8){
    NS_LOG_FUNCTION(this << "CREATE TEMP8 SEND SOCKET!");
    m_tempSendSocket_8 = Socket::CreateSocket (GetNode (), m_tid);
  }
  m_tempSendSocket_8->SetIpTos(16); 
  m_tempSendSocket_8->SetIpRecvTos(true);
  //m_tempSendSocket_8->Bind (m_local); 
  m_tempSendSocket_8->BindToNetDevice(m_sendDevice);
  //initate TCP-threehand shaking
  m_tempSendSocket_8->Connect (m_peer_temp8);
  //m_tempSendSocket_8->SetIpTtl (0);
  //disable receiving any data on this socket
  m_tempSendSocket_8->ShutdownRecv ();
  m_tempSendSocket_8->SetConnectCallback (
    MakeCallback (&QKDChargingApplication::ConnectionSucceededtemp8, this),
    MakeCallback (&QKDChargingApplication::ConnectionFailedtemp8, this)); 
  m_tempSendSocket_8->SetDataSentCallback (
    MakeCallback (&QKDChargingApplication::DataSend, this)); 
   
  /******************
  *   PLEASE START
  ******************/
  if(m_master){   
    
    //SendSiftingPacket ();
 
    //SendData(); 
    //SendMthresholdPacket();

    //SendSiftingPacket();
    //SendDataTemp3 ();
    //SendDataTemp4 ();
  }
}

void QKDChargingApplication::StopApplication (void) // Called at time specified by Stop
{
  NS_LOG_FUNCTION (this);

  if (m_sendSocket != 0)
    {
      m_sendSocket->Close ();
    }
  else
    {
      NS_LOG_WARN ("QKDChargingApplication found null socket to close in StopApplication");
    }
 
    NS_LOG_FUNCTION (this);
    while(!m_sinkSocketList.empty ()) //these are accepted sockets, close them
    {
      Ptr<Socket> acceptedSocket = m_sinkSocketList.front ();
      m_sinkSocketList.pop_front ();
      acceptedSocket->Close ();
    }
    if (m_sinkSocket != 0) 
    {
      m_sinkSocket->Close ();
      m_sinkSocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    }

  m_connected = false; 
  Simulator::Cancel (m_sendEvent);//
}


 
void QKDChargingApplication::SendData (void)
{
  NS_LOG_FUNCTION (this);
 
  if(m_master == true)
    NS_LOG_FUNCTION(this << "********************** MASTER **********************");      
  else
    NS_LOG_FUNCTION(this << "********************** SLAVE **********************");      

  NS_LOG_FUNCTION(this << "####################### POST-PROCESSING STATE #######################");

  NS_LOG_DEBUG(this << "\tSendData!\t" << m_sendDevice->GetAddress() << "\t" << m_sinkDevice->GetAddress() );
  NS_LOG_DEBUG (this << "\t Sending packet " << m_packetNumber << " of maximal " << m_maxPackets);

  if(m_packetNumber >= m_maxPackets)
  {
    m_sendKeyRateMessage = true;
    m_packetNumber = 0;
    m_qkdPacketNumber = 0;
  }

  if(m_master == true && m_sendKeyRateMessage == true)
    PrepareOutput("ADDKEY", m_keyRate); 
  else
    PrepareOutput("QKDPPS", m_packetNumber);
}

void QKDChargingApplication::PrepareOutput (std::string key, uint32_t value)
{    
    NS_LOG_DEBUG (this <<  Simulator::Now () << key << value);     
 
    std::ostringstream msg; 
    msg << key << ":" << value << ";";

    //playing with packet size to introduce some randomness 
    msg << std::string( m_random->GetValue (m_pktSize, m_pktSize*1.5), '0');
    msg << '\0';

    //NS_LOG_FUNCTION (this << msg.str() );

    Ptr<Packet> packet = Create<Packet> ((uint8_t*) msg.str().c_str(), msg.str().length());

    if(key== "ADDKEY:"){
      if( GetNode()->GetObject<QKDManager> () != 0 )
        packet = GetNode()->GetObject<QKDManager> ()->MarkEncrypt (packet);
    }

    NS_LOG_DEBUG(this << "\t PACKET SIZE:" << packet->GetSize());
    
    uint32_t bits = packet->GetSize() * 8;
    NS_LOG_LOGIC (this << "bits = " << bits);

    Time nextTime (Seconds (bits / static_cast<double>(m_cbrRate.GetBitRate ()))); // Time till next packet
    NS_LOG_FUNCTION(this << "CALCULATED NEXTTIME:" << bits / m_cbrRate.GetBitRate ());

    NS_LOG_LOGIC ("nextTime = " << nextTime);
    m_sendEvent = Simulator::Schedule (nextTime, &QKDChargingApplication::SendPacket, this, packet);
}

void QKDChargingApplication::SendPacket (Ptr<Packet> packet){

    NS_LOG_DEBUG (this << "\t" << packet << "PACKETID: " << packet->GetUid() << packet->GetSize() );
    if(m_connected){ 
      m_txTrace (packet);
      m_sendSocket->Send (packet); 
    }
}

void QKDChargingApplication::SendSiftingPacket(){

  NS_LOG_FUNCTION (this);    
  
  uint32_t tempValue = 800 + m_random->GetValue (100, 300);
  NS_LOG_FUNCTION (this << "Sending SIFTING packet of size" << tempValue);
  Ptr<Packet> packet = Create<Packet> (tempValue); 
  m_sendSocket_sifting->Send (packet);
  NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

  m_packetNumber_sifting++;

  if(m_packetNumber_sifting < m_maxPackets_sifting){
    Simulator::Schedule (MicroSeconds(400), &QKDChargingApplication::SendSiftingPacket, this);
  }else {
    SendAuthPacket();
    SendDataTemp1 ();
    SendDataTemp2 ();
    SendDataTemp5 ();
    SendDataTemp6 ();
    SendDataTemp7 ();
    m_packetNumber_sifting = 0;
    Simulator::Schedule (Seconds(32), &QKDChargingApplication::SendSiftingPacket, this);
  }

}

void QKDChargingApplication::SendAuthPacket(){

  NS_LOG_FUNCTION (this);     
  Ptr<Packet> packet = Create<Packet> (m_random->GetValue (400, 700)); 
  m_sendSocket_auth->Send (packet);

  NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() ); 

  m_packetNumber_auth++;

  if(m_packetNumber_auth < m_maxPackets_auth){
    Simulator::Schedule (MicroSeconds(18000), &QKDChargingApplication::SendAuthPacket, this);
  }else { 
    m_packetNumber_auth = 0; 
  }
}


void QKDChargingApplication::SendDataTemp1 (void)
{
    NS_LOG_FUNCTION (this);
 
    Ptr<Packet> packet = Create<Packet> (m_random->GetValue (30, 100)); 

    m_tempSendSocket_1->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

    m_packetNumber_temp1++;

    if(m_packetNumber_temp1 < m_maxPackets_temp1){
      Simulator::Schedule (MicroSeconds(8100), &QKDChargingApplication::SendDataTemp1, this);
    }else { 
      m_packetNumber_temp1 = 0; 
    }


}

void QKDChargingApplication::SendDataTemp2 (void)
{
    NS_LOG_FUNCTION (this);
 
    Ptr<Packet> packet = Create<Packet> (m_random->GetValue (400, 600)); 

    m_tempSendSocket_2->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

    m_packetNumber_temp2++;

    if(m_packetNumber_temp2 < m_maxPackets_temp2){
      Simulator::Schedule (MicroSeconds(13500), &QKDChargingApplication::SendDataTemp2, this);
    }else { 
      m_packetNumber_temp2 = 0; 
    }
}

void QKDChargingApplication::SendDataTemp3 (void)
{
    NS_LOG_FUNCTION (this);
 
    Ptr<Packet> packet = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_3->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );
 
    Ptr<Packet> packet2 = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_3->Send (packet2);
    NS_LOG_FUNCTION (this << packet2 << "PACKETID: " << packet2->GetUid() << " of size: " << packet2->GetSize() );
 
    Ptr<Packet> packet3 = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_3->Send (packet3);
    NS_LOG_FUNCTION (this << packet3 << "PACKETID: " << packet3->GetUid() << " of size: " << packet3->GetSize() );
 
    Ptr<Packet> packet4 = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_3->Send (packet4);
    NS_LOG_FUNCTION (this << packet4 << "PACKETID: " << packet4->GetUid() << " of size: " << packet4->GetSize() );

    Ptr<Packet> packet5 = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_3->Send (packet5);
    NS_LOG_FUNCTION (this << packet5 << "PACKETID: " << packet5->GetUid() << " of size: " << packet5->GetSize() );

    Ptr<Packet> packet6 = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_3->Send (packet6);
    NS_LOG_FUNCTION (this << packet6 << "PACKETID: " << packet6->GetUid() << " of size: " << packet6->GetSize() );

    Ptr<Packet> packet7 = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_3->Send (packet7);
    NS_LOG_FUNCTION (this << packet7 << "PACKETID: " << packet7->GetUid() << " of size: " << packet7->GetSize() );

    Ptr<Packet> packet8 = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_3->Send (packet8);
    NS_LOG_FUNCTION (this << packet8 << "PACKETID: " << packet8->GetUid() << " of size: " << packet8->GetSize() );

    Ptr<Packet> packet9 = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_3->Send (packet9);
    NS_LOG_FUNCTION (this << packet9 << "PACKETID: " << packet9->GetUid() << " of size: " << packet9->GetSize() );

    Ptr<Packet> packet10 = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_3->Send (packet10);
    NS_LOG_FUNCTION (this << packet10 << "PACKETID: " << packet10->GetUid() << " of size: " << packet10->GetSize() );

    Simulator::Schedule (MicroSeconds(600000), &QKDChargingApplication::SendDataTemp3, this);
     
}

void QKDChargingApplication::SendDataTemp4 (void)
{
    NS_LOG_FUNCTION (this);
 
    Ptr<Packet> packet = Create<Packet> (m_random->GetValue (30, 100)); 
    m_tempSendSocket_4->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );
 
    Simulator::Schedule (MicroSeconds(700000), &QKDChargingApplication::SendDataTemp4, this);
    
}

void QKDChargingApplication::SendDataTemp5 (void)
{
    NS_LOG_FUNCTION (this);
 
    Ptr<Packet> packet;

    packet = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_5->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

    packet = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_5->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

    packet = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_5->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

    packet = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_5->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

    packet = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_5->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

    packet = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_5->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

    packet = Create<Packet> (m_random->GetValue (700,1000)); 
    m_tempSendSocket_5->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

    packet = Create<Packet> (m_random->GetValue (700, 1000)); 
    m_tempSendSocket_5->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

    m_packetNumber_temp5++;

    if(m_packetNumber_temp5 < m_maxPackets_temp5){
      Simulator::Schedule (MicroSeconds(600000), &QKDChargingApplication::SendDataTemp5, this);
    }else { 
      m_packetNumber_temp5 = 0; 
    }
}

void QKDChargingApplication::SendDataTemp6 (void)
{
    NS_LOG_FUNCTION (this);
 
    Ptr<Packet> packet;
    for (uint32_t i=0; i < 12; i++){
      packet = Create<Packet> (m_random->GetValue (800, 1000)); 
      m_tempSendSocket_6->Send (packet);
      NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );
    }

    if(m_packetNumber_temp6 < m_maxPackets_temp6){
      Simulator::Schedule (Seconds(19), &QKDChargingApplication::SendDataTemp6, this);
      m_packetNumber_temp6++;
    }else { 
      m_packetNumber_temp6 = 0; 
    }
}

void QKDChargingApplication::SendDataTemp7 (void)
{
    NS_LOG_FUNCTION (this);
 
    Ptr<Packet> packet;
    for (uint32_t i=0; i < 26; i++){
      packet = Create<Packet> (m_random->GetValue (700, 1000)); 
      m_tempSendSocket_7->Send (packet);
      NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );
    }

    if(m_packetNumber_temp7 < m_maxPackets_temp7){
      Simulator::Schedule (Seconds(3.3 + m_random->GetValue (0, 0.7)), &QKDChargingApplication::SendDataTemp7, this);
      m_packetNumber_temp7++;
    }else { 
      m_packetNumber_temp7 = 0; 
    }
}

void QKDChargingApplication::SendDataTemp8 (void)
{
    NS_LOG_FUNCTION (this);
 
    Ptr<Packet> packet;
    for (uint32_t i=0; i < 11; i++){
      packet = Create<Packet> (m_random->GetValue (700,1000)); 
      m_tempSendSocket_8->Send (packet);
      NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );
    }

    if(m_packetNumber_temp8 < m_maxPackets_temp8){
      Simulator::Schedule (Seconds(19), &QKDChargingApplication::SendDataTemp8, this);
      m_packetNumber_temp8++;
    }else { 
      m_packetNumber_temp8 = 0; 
    }
}
 
  
void QKDChargingApplication::HandleRead (Ptr<Socket> socket)
{

  NS_LOG_FUNCTION (this << socket);

  if(m_master == true)
    NS_LOG_FUNCTION(this << "***MASTER***");
  else
    NS_LOG_FUNCTION(this << "!!!SLAVE!!!");
 
  Ptr<Packet> packet;
  Address from;     
  while ((packet = socket->RecvFrom (from)))
  {
      if (packet->GetSize () == 0)
      { //EOF
        break;
      }

      NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

      m_totalRx += packet->GetSize ();
      if (InetSocketAddress::IsMatchingType (from))
        {
          
          NS_LOG_FUNCTION (this << "At time " << Simulator::Now ().GetSeconds ()
                       << "s packet sink received "
                       <<  packet->GetSize () << " bytes from "
                       << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                       << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
                       << " total Rx " << m_totalRx << " bytes");
          
        } 

        ProcessIncomingPacket(packet, socket);
        m_rxTrace (packet, from); 
  }
}

void QKDChargingApplication::HandleReadSifting (Ptr<Socket> socket)
{

  NS_LOG_FUNCTION (this << socket);

  if(m_master == true)
    NS_LOG_FUNCTION(this << "***MASTER***" );
  else
    NS_LOG_FUNCTION(this << "!!!SLAVE!!!");

  Ptr<Packet> packet; 
  Address from;      
  
  NS_LOG_FUNCTION (this << "IT is UDP sifting socket!");
  packet = socket->Recv (65535, 0);  
}

void QKDChargingApplication::SendMthresholdPacket(){

  NS_LOG_FUNCTION (this << Simulator::Now ());
 
}

void QKDChargingApplication::HandleReadMthreshold (Ptr<Socket> socket)
{
 
}
  
void QKDChargingApplication::HandleReadAuth (Ptr<Socket> socket)
{

  NS_LOG_FUNCTION (this << socket);

  if(m_master == true)
    NS_LOG_FUNCTION(this << "***MASTER***" );
  else
    NS_LOG_FUNCTION(this << "!!!SLAVE!!!");

  Ptr<Packet> packet; 
  Address from;      
    while ((packet = socket->RecvFrom (from)))
    {
        if (packet->GetSize () == 0)
        { //EOF
          break;
        }
        NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

        m_totalRx += packet->GetSize ();
        if (InetSocketAddress::IsMatchingType (from))
        {
            
            NS_LOG_FUNCTION (this << "At time " << Simulator::Now ().GetSeconds ()
                         << "s packet sink received "
                         <<  packet->GetSize () << " bytes from "
                         << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                         << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
                         << " total Rx " << m_totalRx << " bytes");
            
        } 
    }
}
  
void QKDChargingApplication::HandleReadTemp1 (Ptr<Socket> socket)
{

  NS_LOG_FUNCTION (this << socket);

  if(m_master == true)
    NS_LOG_FUNCTION(this << "***MASTER***" );
  else
    NS_LOG_FUNCTION(this << "!!!SLAVE!!!");

  Ptr<Packet> packet; 
  Address from;    

  NS_LOG_FUNCTION (this << "IT is UDP sifting socket!");
  packet = socket->Recv (65535, 0);  
}

void QKDChargingApplication::HandleReadTemp2 (Ptr<Socket> socket)
{

  NS_LOG_FUNCTION (this << socket);

  if(m_master == true)
    NS_LOG_FUNCTION(this << "***MASTER***" );
  else
    NS_LOG_FUNCTION(this << "!!!SLAVE!!!");
  
  Ptr<Packet> packet; 
  Address from;      

  NS_LOG_FUNCTION (this << "IT is UDP sifting socket!");
  packet = socket->Recv (65535, 0);  
}

void QKDChargingApplication::HandleReadTemp3 (Ptr<Socket> socket)
{

  NS_LOG_FUNCTION (this << socket);

  if(m_master == true)
    NS_LOG_FUNCTION(this << "***MASTER***" );
  else
    NS_LOG_FUNCTION(this << "!!!SLAVE!!!");
  
  Ptr<Packet> packet; 
  Address from;      

  NS_LOG_FUNCTION (this << "IT is UDP sifting socket!");
  packet = socket->Recv (65535, 0);  
}

void QKDChargingApplication::HandleReadTemp4 (Ptr<Socket> socket)
{

  NS_LOG_FUNCTION (this << socket);

  if(m_master == true)
    NS_LOG_FUNCTION(this << "***MASTER***" );
  else
    NS_LOG_FUNCTION(this << "!!!SLAVE!!!");
  
  Ptr<Packet> packet; 
  Address from;      

  NS_LOG_FUNCTION (this << "IT is UDP sifting socket!");
  packet = socket->Recv (65535, 0);  
}

void QKDChargingApplication::HandleReadTemp5 (Ptr<Socket> socket)
{

  NS_LOG_FUNCTION (this << socket);

  if(m_master == true)
    NS_LOG_FUNCTION(this << "***MASTER***" );
  else
    NS_LOG_FUNCTION(this << "!!!SLAVE!!!");
  
  Ptr<Packet> packet; 
  Address from;      

  NS_LOG_FUNCTION (this << "IT is UDP sifting socket!");
  packet = socket->Recv (65535, 0);  
}
void QKDChargingApplication::HandleReadTemp6 (Ptr<Socket> socket)
{

  NS_LOG_FUNCTION (this << socket);

  if(m_master == true)
    NS_LOG_FUNCTION(this << "***MASTER***" );
  else
    NS_LOG_FUNCTION(this << "!!!SLAVE!!!");
  
  Ptr<Packet> packet; 
  Address from;      

  NS_LOG_FUNCTION (this << "IT is UDP sifting socket!");
  packet = socket->Recv (65535, 0);  
}
void QKDChargingApplication::HandleReadTemp7 (Ptr<Socket> socket)
{

  NS_LOG_FUNCTION (this << socket);

  if(m_master == true)
    NS_LOG_FUNCTION(this << "***MASTER***" );
  else
    NS_LOG_FUNCTION(this << "!!!SLAVE!!!");
  
  Ptr<Packet> packet; 
  Address from;      

  NS_LOG_FUNCTION (this << "IT is UDP sifting socket!");
  packet = socket->Recv (65535, 0);  
}

void QKDChargingApplication::HandleReadTemp8 (Ptr<Socket> socket)
{

  NS_LOG_FUNCTION (this << socket);

  if(m_master == true)
    NS_LOG_FUNCTION(this << "***MASTER***" );
  else
    NS_LOG_FUNCTION(this << "!!!SLAVE!!!");
  
  Ptr<Packet> packet; 
  Address from;      

  NS_LOG_FUNCTION (this << "IT is UDP sifting socket!");
  packet = socket->Recv (65535, 0);  
}

void QKDChargingApplication::ProcessIncomingPacket(Ptr<Packet> packet, Ptr<Socket> socket){

    NS_LOG_DEBUG(this << "\nProcessIncomingPacket!\t" << m_sendDevice->GetAddress() << "\t" << m_sinkDevice->GetAddress() );
 
    NS_LOG_DEBUG (this << packet << "\tPACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );
    m_packetNumber++;

    /**
    *  POST PROCESSING
    */    
    uint8_t *buffer = new uint8_t[packet->GetSize ()];
    packet->CopyData(buffer, packet->GetSize ());
    std::string s = std::string((char*)buffer);
    delete[] buffer;  

    uint32_t packetValue;  
    if(s.size() > 5){

      char labelChar[6];
      sscanf(s.c_str(), "%6[^;]:%d;", labelChar, &packetValue);
      std::string label (labelChar); 

      NS_LOG_DEBUG (this << "\tLABEL:\t" <<  label << "\tPACKETVALUE:\t" << packetValue);

      if(label == "ADDKEY"){
        m_packetNumber = 0;
        m_sendKeyRateMessage = false;

        //add key to buffer
        if(GetNode ()->GetObject<QKDManager> () != 0){

            /*
            std::cout << Simulator::Now ().GetSeconds () 
            << "\t" << m_sendDevice->GetAddress() 
            << "\t" << m_sinkDevice->GetAddress()  
            << "\tLABEL:\t" <<  label 
            << "\tPACKETVALUE:\t" << packetValue << "\n";
            */
            
            NS_LOG_DEBUG(this << "\t" << m_sendDevice->GetAddress() << "\t" << m_sinkDevice->GetAddress() );
            GetNode ()->GetObject<QKDManager> ()->AddNewKeyMaterial(m_sendDevice->GetAddress(), packetValue);
            //m_maxPackets = m_random->GetValue (m_maxPackets * 0.8, m_maxPackets * 1.2);
        }

        //prepare response            
        if(m_master == false){ 
            SendMthresholdPacket();
            PrepareOutput(label, packetValue); 
        }else{  
            SendData(); 
        }                 

        //Reset QKDPacketNumber
        m_qkdPacketNumber = 0; 
        return;
      }
    }

    if(packetValue < m_maxPackets){
      m_packetNumber = packetValue + 1; 
    }

    SendData();

}

void QKDChargingApplication::HandlePeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}
 
void QKDChargingApplication::HandlePeerError (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void QKDChargingApplication::HandleAccept (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from); 
  s->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleRead, this));
  m_sinkSocketList.push_back (s);
}

void QKDChargingApplication::HandleAcceptAuth (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadAuth, this));
  m_sinkSocketList.push_back (s);
}

void QKDChargingApplication::HandleAcceptSifting (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadSifting, this));
  m_sinkSocketList.push_back (s);
}

void QKDChargingApplication::HandleAcceptMthreshold (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadMthreshold, this));
  m_sinkSocketList.push_back (s);
}

void QKDChargingApplication::HandleAcceptTemp1 (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp1, this));
  m_sinkSocketList.push_back (s);
}

void QKDChargingApplication::HandleAcceptTemp2 (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp2, this));
  m_sinkSocketList.push_back (s);
}

void QKDChargingApplication::HandleAcceptTemp3 (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp3, this));
  m_sinkSocketList.push_back (s);
}
void QKDChargingApplication::HandleAcceptTemp4 (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp4, this));
  m_sinkSocketList.push_back (s);
}
void QKDChargingApplication::HandleAcceptTemp5 (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp5, this));
  m_sinkSocketList.push_back (s);
}
void QKDChargingApplication::HandleAcceptTemp6 (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp6, this));
  m_sinkSocketList.push_back (s);
}
void QKDChargingApplication::HandleAcceptTemp7 (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp7, this));
  m_sinkSocketList.push_back (s);
}
void QKDChargingApplication::HandleAcceptTemp8 (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&QKDChargingApplication::HandleReadTemp8, this));
  m_sinkSocketList.push_back (s);
}
 
void QKDChargingApplication::ConnectionSucceeded (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDChargingApplication Connection succeeded");

    if (m_sendSocket == socket || m_sinkSocket == socket){
      m_connected = true;  
    }
    
    if(m_master) SendData();
}

void QKDChargingApplication::ConnectionSucceededMthreshold (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDChargingApplication AUTH Connection succeeded");

    if(m_master)
      SendMthresholdPacket();
    /*
    if (m_connected && m_master && m_sendSocket_mthreshold == socket)     
     SendData ();
    */
}

void QKDChargingApplication::ConnectionSucceededAuth (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDChargingApplication AUTH Connection succeeded");
    /*
    if (m_connected && m_master && m_sendSocket_auth == socket)     
     SendData ();
    */
}

void QKDChargingApplication::ConnectionSucceededSifting (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDChargingApplication SIFTING Connection succeeded");
}

void QKDChargingApplication::ConnectionSucceededtemp1 (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDChargingApplication TEMP1 Connection succeeded");
}

void QKDChargingApplication::ConnectionSucceededtemp2 (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDChargingApplication TEMP2 Connection succeeded");
}

void QKDChargingApplication::ConnectionSucceededtemp3 (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDChargingApplication TEMP3 Connection succeeded");

    if (m_master)     
      SendDataTemp3();
}

void QKDChargingApplication::ConnectionSucceededtemp4 (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDChargingApplication TEMP4 Connection succeeded");

    if (m_master)     
      SendDataTemp4();
}

void QKDChargingApplication::ConnectionSucceededtemp5 (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDChargingApplication TEMP5 Connection succeeded");
}

void QKDChargingApplication::ConnectionSucceededtemp6 (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDChargingApplication TEMP6 Connection succeeded");
}

void QKDChargingApplication::ConnectionSucceededtemp7 (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDChargingApplication TEMP7 Connection succeeded");
}

void QKDChargingApplication::ConnectionSucceededtemp8 (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDChargingApplication TEMP8 Connection succeeded");
}


void QKDChargingApplication::ConnectionFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDChargingApplication, Connection Failed");
}

void QKDChargingApplication::ConnectionFailedMthreshold (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDChargingApplication, Connection Failed");
}

void QKDChargingApplication::ConnectionFailedAuth (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDChargingApplication, Connection Failed");
}

void QKDChargingApplication::ConnectionFailedSifting (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDChargingApplication, Connection Failed");
}

void QKDChargingApplication::ConnectionFailedtemp1 (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDChargingApplication, Connection Failed");
}

void QKDChargingApplication::ConnectionFailedtemp2 (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDChargingApplication, Connection Failed");
}

void QKDChargingApplication::ConnectionFailedtemp3 (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDChargingApplication, Connection Failed");
}

void QKDChargingApplication::ConnectionFailedtemp4 (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDChargingApplication, Connection Failed");
}

void QKDChargingApplication::ConnectionFailedtemp5 (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDChargingApplication, Connection Failed");
}

void QKDChargingApplication::ConnectionFailedtemp6 (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDChargingApplication, Connection Failed");
}

void QKDChargingApplication::ConnectionFailedtemp7 (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDChargingApplication, Connection Failed");
}

void QKDChargingApplication::ConnectionFailedtemp8 (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDChargingApplication, Connection Failed");
}






void QKDChargingApplication::DataSend (Ptr<Socket>, uint32_t)
{
    NS_LOG_FUNCTION (this);
}

void QKDChargingApplication::RegisterAckTime (Time oldRtt, Time newRtt)
{
  NS_LOG_FUNCTION (this << oldRtt << newRtt);
  m_lastAck = Simulator::Now ();
}

Time QKDChargingApplication::GetLastAckTime ()
{
  NS_LOG_FUNCTION (this);
  return m_lastAck;
}

} // Namespace ns3
