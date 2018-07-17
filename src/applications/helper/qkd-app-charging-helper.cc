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

#include "ns3/core-module.h" 
#include "qkd-app-charging-helper.h"
#include "ns3/qkd-charging-application.h"
#include "ns3/inet-socket-address.h"
#include "ns3/packet-socket-address.h"
#include "ns3/virtual-udp-socket-factory.h"
#include "ns3/virtual-tcp-socket-factory.h"
#include "ns3/socket.h"
#include "ns3/string.h"
#include "ns3/names.h" 
#include "ns3/uinteger.h" 
#include "ns3/qkd-manager.h"

namespace ns3 {

uint32_t QKDAppChargingHelper::appCounter = 0;

QKDAppChargingHelper::QKDAppChargingHelper (std::string protocol, Ipv4Address master, Ipv4Address slave, uint32_t keyRate)
{
    SetSettings(protocol, master, slave, keyRate);
}

void 
QKDAppChargingHelper::SetSettings ( std::string protocol, Ipv4Address master, Ipv4Address slave, uint32_t keyRate)
{
    uint16_t port;

    /*************************
    //      MASTER
    **************************/

    port = 8000 + appCounter++; 
    Address sinkAddress (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress (InetSocketAddress (slave, port));
    m_factory_master_app.SetTypeId ("ns3::QKDChargingApplication");
    m_factory_master_app.Set ("Protocol", StringValue (protocol));
    m_factory_master_app.Set ("KeyRate", UintegerValue (keyRate)); 
    m_factory_master_app.Set ("Local", AddressValue (sinkAddress)); 
    m_factory_master_app.Set ("Remote", AddressValue (slaveAppRemoteAddress));

    //Sifting
    port = 8000 + appCounter++; 
    Address sinkAddress_sifting (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress_sifting (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress_sifting (InetSocketAddress (slave, port));
    m_factory_master_app.Set ("Local_Sifting", AddressValue (sinkAddress_sifting)); 
    m_factory_master_app.Set ("Remote_Sifting", AddressValue (slaveAppRemoteAddress_sifting));
   
    //Auth
    port = 8000 + appCounter++; 
    Address sinkAddress_auth (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress_auth (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress_auth (InetSocketAddress (slave, port));
    m_factory_master_app.Set ("Local_Auth", AddressValue (sinkAddress_auth)); 
    m_factory_master_app.Set ("Remote_Auth", AddressValue (slaveAppRemoteAddress_auth));
    
    //Threshold
    port = 8000 + appCounter++; 
    Address sinkAddress_mthreshold (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress_mthreshold (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress_mthreshold (InetSocketAddress (slave, port));
    m_factory_master_app.Set ("Local_Mthreshold", AddressValue (sinkAddress_mthreshold)); 
    m_factory_master_app.Set ("Remote_Mthreshold", AddressValue (slaveAppRemoteAddress_mthreshold));
    
     //Temp1
    port = 8000 + appCounter++; 
    Address sinkAddress_temp1 (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress_temp1 (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress_temp1 (InetSocketAddress (slave, port));
    m_factory_master_app.Set ("Local_Temp1", AddressValue (sinkAddress_temp1)); 
    m_factory_master_app.Set ("Remote_Temp1", AddressValue (slaveAppRemoteAddress_temp1));
    
    //Temp2
    port = 8000 + appCounter++; 
    Address sinkAddress_temp2 (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress_temp2 (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress_temp2 (InetSocketAddress (slave, port));
    m_factory_master_app.Set ("Local_Temp2", AddressValue (sinkAddress_temp2)); 
    m_factory_master_app.Set ("Remote_Temp2", AddressValue (slaveAppRemoteAddress_temp2));

    //Temp3
    port = 8000 + appCounter++; 
    Address sinkAddress_temp3 (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress_temp3 (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress_temp3 (InetSocketAddress (slave, port));
    m_factory_master_app.Set ("Local_Temp3", AddressValue (sinkAddress_temp3)); 
    m_factory_master_app.Set ("Remote_Temp3", AddressValue (slaveAppRemoteAddress_temp3));

    //Temp4
    port = 8000 + appCounter++; 
    Address sinkAddress_temp4 (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress_temp4 (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress_temp4 (InetSocketAddress (slave, port));
    m_factory_master_app.Set ("Local_Temp4", AddressValue (sinkAddress_temp4)); 
    m_factory_master_app.Set ("Remote_Temp4", AddressValue (slaveAppRemoteAddress_temp4));

    //Temp5
    port = 8000 + appCounter++; 
    Address sinkAddress_temp5 (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress_temp5 (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress_temp5 (InetSocketAddress (slave, port));
    m_factory_master_app.Set ("Local_Temp5", AddressValue (sinkAddress_temp5)); 
    m_factory_master_app.Set ("Remote_Temp5", AddressValue (slaveAppRemoteAddress_temp5));

    //Temp6
    port = 8000 + appCounter++; 
    Address sinkAddress_temp6 (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress_temp6 (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress_temp6 (InetSocketAddress (slave, port));
    m_factory_master_app.Set ("Local_Temp6", AddressValue (sinkAddress_temp6)); 
    m_factory_master_app.Set ("Remote_Temp6", AddressValue (slaveAppRemoteAddress_temp6));
     
    //Temp7
    port = 8000 + appCounter++; 
    Address sinkAddress_temp7 (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress_temp7 (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress_temp7 (InetSocketAddress (slave, port));
    m_factory_master_app.Set ("Local_Temp7", AddressValue (sinkAddress_temp7)); 
    m_factory_master_app.Set ("Remote_Temp7", AddressValue (slaveAppRemoteAddress_temp7));

    //Temp8
    port = 8000 + appCounter++; 
    Address sinkAddress_temp8 (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress_temp8 (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress_temp8 (InetSocketAddress (slave, port));
    m_factory_master_app.Set ("Local_Temp8", AddressValue (sinkAddress_temp8)); 
    m_factory_master_app.Set ("Remote_Temp8", AddressValue (slaveAppRemoteAddress_temp8));

    /*************************
    //      SLAVE
    **************************/
    m_factory_slave_app.SetTypeId ("ns3::QKDChargingApplication");
    m_factory_slave_app.Set ("Protocol", StringValue (protocol));
    m_factory_slave_app.Set ("KeyRate", UintegerValue (keyRate)); 
    m_factory_slave_app.Set ("Local", AddressValue (sinkAddress));
    m_factory_slave_app.Set ("Remote", AddressValue (masterAppRemoteAddress));

    m_factory_slave_app.Set ("Local_Sifting", AddressValue (sinkAddress_sifting)); 
    m_factory_slave_app.Set ("Remote_Sifting", AddressValue (masterAppRemoteAddress_sifting));

    m_factory_slave_app.Set ("Local_Auth", AddressValue (sinkAddress_auth)); 
    m_factory_slave_app.Set ("Remote_Auth", AddressValue (masterAppRemoteAddress_auth));

    m_factory_slave_app.Set ("Local_Mthreshold", AddressValue (sinkAddress_mthreshold)); 
    m_factory_slave_app.Set ("Remote_Mthreshold", AddressValue (masterAppRemoteAddress_mthreshold));

    m_factory_slave_app.Set ("Local_Temp1", AddressValue (sinkAddress_temp1)); 
    m_factory_slave_app.Set ("Remote_Temp1", AddressValue (masterAppRemoteAddress_temp1));

    m_factory_slave_app.Set ("Local_Temp2", AddressValue (sinkAddress_temp2)); 
    m_factory_slave_app.Set ("Remote_Temp2", AddressValue (masterAppRemoteAddress_temp2));

    m_factory_slave_app.Set ("Local_Temp3", AddressValue (sinkAddress_temp3)); 
    m_factory_slave_app.Set ("Remote_Temp3", AddressValue (masterAppRemoteAddress_temp3));

    m_factory_slave_app.Set ("Local_Temp4", AddressValue (sinkAddress_temp4)); 
    m_factory_slave_app.Set ("Remote_Temp4", AddressValue (masterAppRemoteAddress_temp4));

    m_factory_slave_app.Set ("Local_Temp5", AddressValue (sinkAddress_temp5)); 
    m_factory_slave_app.Set ("Remote_Temp5", AddressValue (masterAppRemoteAddress_temp5));

    m_factory_slave_app.Set ("Local_Temp6", AddressValue (sinkAddress_temp6)); 
    m_factory_slave_app.Set ("Remote_Temp6", AddressValue (masterAppRemoteAddress_temp6));

    m_factory_slave_app.Set ("Local_Temp7", AddressValue (sinkAddress_temp7)); 
    m_factory_slave_app.Set ("Remote_Temp7", AddressValue (masterAppRemoteAddress_temp7));

    m_factory_slave_app.Set ("Local_Temp8", AddressValue (sinkAddress_temp8)); 
    m_factory_slave_app.Set ("Remote_Temp8", AddressValue (masterAppRemoteAddress_temp8));

    m_protocol = protocol;

}


void
QKDAppChargingHelper::SetAttribute ( std::string mFactoryName, std::string name, const AttributeValue &value)
{ 
    if(mFactoryName == "master") 
        m_factory_master_app.Set (name, value); 
    else if(mFactoryName == "slave") 
        m_factory_slave_app.Set (name, value);  
}
 
ApplicationContainer
QKDAppChargingHelper::Install (Ptr<NetDevice> n1, Ptr<NetDevice> n2) const
{
  return InstallPriv (n1, n2);
}

ApplicationContainer
QKDAppChargingHelper::InstallPriv (Ptr<NetDevice> net1, Ptr<NetDevice> net2) const
{
    Ptr<Node> node1 = net1->GetNode();
    Ptr<Node> node2 = net2->GetNode();

    TypeId m_tid = TypeId::LookupByName (m_protocol); 

    /**
    *   UDP Protocol is used for sifting (implementation detail)
    */
    std::string udpProtocol;
    if( node1->GetObject<VirtualUdpL4Protocol> () == 0){
        udpProtocol = "ns3::UdpSocketFactory";
    }else{
        udpProtocol = "ns3::VirtualUdpSocketFactory";
    }
    TypeId udp_tid = TypeId::LookupByName (udpProtocol); 
 
    /**************
    //MASTER
    ***************/
    Ptr<Application> appMaster = m_factory_master_app.Create<Application> (); 
    node1->AddApplication (appMaster);
    //POST-processing sockets
    Ptr<Socket> sckt1 = Socket::CreateSocket (node1, m_tid);
    Ptr<Socket> sckt2 = Socket::CreateSocket (node1, m_tid);
    DynamicCast<QKDChargingApplication> (appMaster)->SetSocket ("send", sckt1, net1, true);
    DynamicCast<QKDChargingApplication> (appMaster)->SetSocket ("sink", sckt2, net1, true);
    //SIFTING
    Ptr<Socket> sckt1_sifting = Socket::CreateSocket (node1, udp_tid);
    Ptr<Socket> sckt2_sifting = Socket::CreateSocket (node1, udp_tid);   
    DynamicCast<QKDChargingApplication> (appMaster)->SetSiftingSocket ("send", sckt1_sifting);
    DynamicCast<QKDChargingApplication> (appMaster)->SetSiftingSocket ("sink", sckt2_sifting);
    //TEMP1
    Ptr<Socket> sckt1_temp1 = Socket::CreateSocket (node1, udp_tid);
    Ptr<Socket> sckt2_temp1 = Socket::CreateSocket (node1, udp_tid);   
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp1Socket ("send", sckt1_temp1);
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp1Socket ("sink", sckt2_temp1);
    //TEMP2
    Ptr<Socket> sckt1_temp2 = Socket::CreateSocket (node1, udp_tid);
    Ptr<Socket> sckt2_temp2 = Socket::CreateSocket (node1, udp_tid);   
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp2Socket ("send", sckt1_temp2);
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp2Socket ("sink", sckt2_temp2);
    //TEMP3
    Ptr<Socket> sckt1_temp3 = Socket::CreateSocket (node1, udp_tid);
    Ptr<Socket> sckt2_temp3 = Socket::CreateSocket (node1, udp_tid);   
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp3Socket ("send", sckt1_temp3);
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp3Socket ("sink", sckt2_temp3);
    //TEMP4
    Ptr<Socket> sckt1_temp4 = Socket::CreateSocket (node1, udp_tid);
    Ptr<Socket> sckt2_temp4 = Socket::CreateSocket (node1, udp_tid);   
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp4Socket ("send", sckt1_temp4);
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp4Socket ("sink", sckt2_temp4);
    //TEMP5
    Ptr<Socket> sckt1_temp5 = Socket::CreateSocket (node1, udp_tid);
    Ptr<Socket> sckt2_temp5 = Socket::CreateSocket (node1, udp_tid);   
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp5Socket ("send", sckt1_temp5);
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp5Socket ("sink", sckt2_temp5);
    //TEMP6
    Ptr<Socket> sckt1_temp6 = Socket::CreateSocket (node1, udp_tid);
    Ptr<Socket> sckt2_temp6 = Socket::CreateSocket (node1, udp_tid);   
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp6Socket ("send", sckt1_temp6);
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp6Socket ("sink", sckt2_temp6);
    //TEMP7
    Ptr<Socket> sckt1_temp7 = Socket::CreateSocket (node1, udp_tid);
    Ptr<Socket> sckt2_temp7 = Socket::CreateSocket (node1, udp_tid);   
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp7Socket ("send", sckt1_temp7);
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp7Socket ("sink", sckt2_temp7);
    //TEMP8
    Ptr<Socket> sckt1_temp8 = Socket::CreateSocket (node1, udp_tid);
    Ptr<Socket> sckt2_temp8 = Socket::CreateSocket (node1, udp_tid);   
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp8Socket ("send", sckt1_temp8);
    DynamicCast<QKDChargingApplication> (appMaster)->SetTemp8Socket ("sink", sckt2_temp8);
 








    /**************
    //SLAVE
    ***************/
    Ptr<Application> appSlave = m_factory_slave_app.Create<Application> (); 
    node2->AddApplication (appSlave);
    //POST-processing sockets
    Ptr<Socket> sckt3 = Socket::CreateSocket (node2, m_tid);
    Ptr<Socket> sckt4 = Socket::CreateSocket (node2, m_tid);
    DynamicCast<QKDChargingApplication> (appSlave)->SetSocket ("send", sckt3, net2, false);
    DynamicCast<QKDChargingApplication> (appSlave)->SetSocket ("sink", sckt4, net2, false);
    //SIFTING
    Ptr<Socket> sckt3_sifting = Socket::CreateSocket (node2, udp_tid);
    Ptr<Socket> sckt4_sifting = Socket::CreateSocket (node2, udp_tid);   
    DynamicCast<QKDChargingApplication> (appSlave)->SetSiftingSocket ("send", sckt3_sifting);
    DynamicCast<QKDChargingApplication> (appSlave)->SetSiftingSocket ("sink", sckt4_sifting);
    //TEMP1
    Ptr<Socket> sckt1_temp1B = Socket::CreateSocket (node2, udp_tid);
    Ptr<Socket> sckt2_temp1B = Socket::CreateSocket (node2, udp_tid);   
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp1Socket ("send", sckt1_temp1B);
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp1Socket ("sink", sckt2_temp1B);
    //TEMP2
    Ptr<Socket> sckt1_temp2B = Socket::CreateSocket (node2, udp_tid);
    Ptr<Socket> sckt2_temp2B = Socket::CreateSocket (node2, udp_tid);   
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp2Socket ("send", sckt1_temp2B);
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp2Socket ("sink", sckt2_temp2B);
    //TEMP3
    Ptr<Socket> sckt1_temp3B = Socket::CreateSocket (node2, udp_tid);
    Ptr<Socket> sckt2_temp3B = Socket::CreateSocket (node2, udp_tid);   
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp3Socket ("send", sckt1_temp3B);
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp3Socket ("sink", sckt2_temp3B);
    //TEMP4
    Ptr<Socket> sckt1_temp4B = Socket::CreateSocket (node2, udp_tid);
    Ptr<Socket> sckt2_temp4B = Socket::CreateSocket (node2, udp_tid);   
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp4Socket ("send", sckt1_temp4B);
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp4Socket ("sink", sckt2_temp4B);
    //TEMP5
    Ptr<Socket> sckt1_temp5B = Socket::CreateSocket (node2, udp_tid);
    Ptr<Socket> sckt2_temp5B = Socket::CreateSocket (node2, udp_tid);   
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp5Socket ("send", sckt1_temp5B);
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp5Socket ("sink", sckt2_temp5B);
    //TEMP6
    Ptr<Socket> sckt1_temp6B = Socket::CreateSocket (node2, udp_tid);
    Ptr<Socket> sckt2_temp6B = Socket::CreateSocket (node2, udp_tid);   
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp6Socket ("send", sckt1_temp6B);
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp6Socket ("sink", sckt2_temp6B);
    //TEMP7
    Ptr<Socket> sckt1_temp7B = Socket::CreateSocket (node2, udp_tid);
    Ptr<Socket> sckt2_temp7B = Socket::CreateSocket (node2, udp_tid);   
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp7Socket ("send", sckt1_temp7B);
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp7Socket ("sink", sckt2_temp7B);
    //TEMP8
    Ptr<Socket> sckt1_temp8B = Socket::CreateSocket (node2, udp_tid);
    Ptr<Socket> sckt2_temp8B = Socket::CreateSocket (node2, udp_tid);   
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp8Socket ("send", sckt1_temp8B);
    DynamicCast<QKDChargingApplication> (appSlave)->SetTemp8Socket ("sink", sckt2_temp8B); 





    ApplicationContainer apps;
    apps.Add(appMaster);
    apps.Add(appSlave); 
    
    
    std::string tcpProtocol;

    if(m_protocol == "ns3::VirtualTcpSocketFactory")
        tcpProtocol = "$ns3::VirtualTcpL4Protocol";

    else if(m_protocol == "ns3::TcpSocketFactory")
        tcpProtocol = "$ns3::TcpL4Protocol";
    

    std::ostringstream pathNode1;
    pathNode1 << "/NodeList/" << node1 << "/" << tcpProtocol << "/SocketType";
    std::string query1(pathNode1.str());
 
    std::ostringstream pathNode2;
    pathNode2 << "/NodeList/" << node2 << "/" << tcpProtocol << "/SocketType";
    std::string query2(pathNode2.str());
 
    TypeId tidNewReno = TypeId::LookupByName ("ns3::TcpNewReno"); 
 
    Config::Set (query1, TypeIdValue (tidNewReno)); 
    Config::Set (query2, TypeIdValue (tidNewReno));
    

    return apps;
}
} // namespace ns3

