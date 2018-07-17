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

#ifndef QKD_CHARGING_APPLICATION_H
#define QKD_CHARGING_APPLICATION_H

#include "ns3/address.h"
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/data-rate.h"
#include "ns3/traced-callback.h"
#include "ns3/random-variable-stream.h"

namespace ns3 {

class Address;
class Socket;

/**
 * \ingroup applications
 * \defgroup qkdsend QKDChargingApplication
 *
 * This traffic generator simply sends data
 * as fast as possible up to MaxBytes or until
 * the appplication is stopped if MaxBytes is
 * zero. Once the lower layer send buffer is
 * filled, it waits until space is free to
 * send more data, essentially keeping a
 * constant flow of data. 
 */
class QKDChargingApplication : public Application
{
public:
  static TypeId GetTypeId (void);

  QKDChargingApplication ();

  virtual ~QKDChargingApplication ();
 
  /**
   * \return pointer to associated socket
   */
  Ptr<Socket> GetSendSocket (void) const;
  Ptr<Socket> GetSinkSocket (void) const;

 void PrepareOutput (std::string key, uint32_t value);
 

  /**
   * \param socket pointer to socket to be set
   */
  void SetSocket (std::string type, Ptr<Socket> socket, Ptr<NetDevice> dev, bool isMaster);

  /**
   * \param socket pointer to socket to be set
   */
  void SetAuthSocket (std::string type, Ptr<Socket> socket);

  /**
   * \param socket pointer to socket to be set
   */
  void SetSiftingSocket (std::string type, Ptr<Socket> socket);

  /**
   * \param socket pointer to socket to be set
   */
  void SetTemp1Socket (std::string type, Ptr<Socket> socket);

  /**
   * \param socket pointer to socket to be set
   */
  void SetTemp2Socket (std::string type, Ptr<Socket> socket);

  /**
   * \param socket pointer to socket to be set
   */
  void SetTemp3Socket (std::string type, Ptr<Socket> socket);

  /**
   * \param socket pointer to socket to be set
   */
  void SetTemp4Socket (std::string type, Ptr<Socket> socket);

  /**
   * \param socket pointer to socket to be set
   */
  void SetTemp5Socket (std::string type, Ptr<Socket> socket);

  /**
   * \param socket pointer to socket to be set
   */
  void SetTemp6Socket (std::string type, Ptr<Socket> socket);


  /**
   * \param socket pointer to socket to be set
   */
  void SetTemp7Socket (std::string type, Ptr<Socket> socket);


  /**
   * \param socket pointer to socket to be set
   */
  void SetTemp8Socket (std::string type, Ptr<Socket> socket);


  /**
   * \return the total bytes received in this sink app
   */
  uint32_t GetTotalRx () const;

  /**
   * \return pointer to listening socket
   */
  Ptr<Socket> GetListeningSocket (void) const;

  /**
   * \return list of pointers to accepted sockets
   */
  std::list<Ptr<Socket> > GetAcceptedSockets (void) const;
 
  Time GetLastAckTime ();
  
protected:
  virtual void DoDispose (void);
private:

  void ProcessIncomingPacket(Ptr<Packet> packet, Ptr<Socket> socket);

  // inherited from Application base class.
  void StartApplication (void);    // Called at time specified by Start

  void StopApplication (void);     // Called at time specified by Stop

  /**
   * \brief Send packet to the socket
   * \param Packet to be sent
   */
  void SendPacket (Ptr<Packet> packet);

  /**
   * \brief Send AUTH packet to the socket
   * \param Packet to be sent
   */
  void SendAuthPacket (void);

  /**
   * \brief Send Mthreshold packet to the socket
   * \param Packet to be sent
   */
  void SendMthresholdPacket (void);

  /**
   * \brief Send SIFTING packet to the socket
   * \param Packet to be sent
   */
  void SendSiftingPacket (void);

  /**
   * \brief Handle a packet received by the application
   * \param socket the receiving socket
   */
  void HandleRead (Ptr<Socket> socket);

  /**
   * \brief Handle a packet received by the application
   * \param socket the receiving socket
   */
  void HandleReadSifting (Ptr<Socket> socket);

  /**
   * \brief Handle a packet received by the application
   * \param socket the receiving socket
   */
  void HandleReadMthreshold (Ptr<Socket> socket);

  /**
   * \brief Handle a packet received by the application
   * \param socket the receiving socket
   */
  void HandleReadAuth (Ptr<Socket> socket);
 
  void HandleReadTemp1 (Ptr<Socket> socket);

  void HandleReadTemp2(Ptr<Socket> socket);

  void HandleReadTemp3(Ptr<Socket> socket);

  void HandleReadTemp4(Ptr<Socket> socket);

  void HandleReadTemp5(Ptr<Socket> socket);

  void HandleReadTemp6(Ptr<Socket> socket);

  void HandleReadTemp7(Ptr<Socket> socket);

  void HandleReadTemp8(Ptr<Socket> socket);

  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAccept (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAcceptAuth (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAcceptSifting (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAcceptMthreshold (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAcceptTemp1 (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAcceptTemp2 (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAcceptTemp3 (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAcceptTemp4 (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAcceptTemp5 (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAcceptTemp6 (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAcceptTemp7 (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAcceptTemp8 (Ptr<Socket> socket, const Address& from);
  
  /**
   * \brief Handle an connection close
   * \param socket the connected socket
   */
  void HandlePeerClose (Ptr<Socket> socket);
  /**
   * \brief Handle an connection error
   * \param socket the connected socket
   */
  void HandlePeerError (Ptr<Socket> socket);

  void SendData ();

  void SendDataTemp1 ();

  void SendDataTemp2 ();

  void SendDataTemp3 ();

  void SendDataTemp4 ();

  void SendDataTemp5 ();

  void SendDataTemp6 ();

  void SendDataTemp7 ();

  void SendDataTemp8 ();


  Ptr<NetDevice>  m_sendDevice; 
  Ptr<NetDevice>  m_sinkDevice;  

  /**
  * IMITATE post-processing traffic (CASCADE, PRIVACY AMPLIFICATION and etc. )
  */
  Ptr<Socket>     m_sendSocket;       // Associated socket
  Ptr<Socket>     m_sinkSocket;       // Associated socket
  /**
  * Sockets used for SIFTING
  */
  Ptr<Socket>     m_sendSocket_sifting;       // Associated socket
  Ptr<Socket>     m_sinkSocket_sifting;       // Associated socket 
  /**
  * Sockets used for mthreshold value exchange
  */
  Ptr<Socket>     m_sendSocket_mthreshold;       // Associated socket
  Ptr<Socket>     m_sinkSocket_mthreshold;       // Associated socket  
  /**
  * Sockets used for authentication
  */
  Ptr<Socket>     m_sendSocket_auth;       // Associated socket
  Ptr<Socket>     m_sinkSocket_auth;       // Associated socket  

  Ptr<Socket>     m_tempSendSocket_1;
  Ptr<Socket>     m_tempSinkSocket_1;

  Ptr<Socket>     m_tempSendSocket_2;
  Ptr<Socket>     m_tempSinkSocket_2; 

  Ptr<Socket>     m_tempSendSocket_3;
  Ptr<Socket>     m_tempSinkSocket_3; 

  Ptr<Socket>     m_tempSendSocket_4;
  Ptr<Socket>     m_tempSinkSocket_4; 

  Ptr<Socket>     m_tempSendSocket_5;
  Ptr<Socket>     m_tempSinkSocket_5; 

  Ptr<Socket>     m_tempSendSocket_6;
  Ptr<Socket>     m_tempSinkSocket_6; 

  Ptr<Socket>     m_tempSendSocket_7;
  Ptr<Socket>     m_tempSinkSocket_7; 

  Ptr<Socket>     m_tempSendSocket_8;
  Ptr<Socket>     m_tempSinkSocket_8; 

  Address         m_peer;         // Peer address
  Address         m_local;        //!< Local address to bind to

  Address         m_peer_sifting;         // Peer address
  Address         m_local_sifting;        //!< Local address to bind to

  Address         m_peer_mthreshold;         // Peer address
  Address         m_local_mthreshold;        //!< Local address to bind to

  Address         m_peer_auth;         // Peer address
  Address         m_local_auth;        //!< Local address to bind to

  Address         m_peer_temp1;         // Peer address
  Address         m_local_temp1;        //!< Local address to bind to

  Address         m_peer_temp2;         // Peer address
  Address         m_local_temp2;        //!< Local address to bind to

  Address         m_peer_temp3;         // Peer address
  Address         m_local_temp3;        //!< Local address to bind to

  Address         m_peer_temp4;         // Peer address
  Address         m_local_temp4;        //!< Local address to bind to

  Address         m_peer_temp5;         // Peer address
  Address         m_local_temp5;        //!< Local address to bind to

  Address         m_peer_temp6;         // Peer address
  Address         m_local_temp6;        //!< Local address to bind to

  Address         m_peer_temp7;         // Peer address
  Address         m_local_temp7;        //!< Local address to bind to

  Address         m_peer_temp8;         // Peer address
  Address         m_local_temp8;        //!< Local address to bind to

  bool            m_odd;

  uint32_t        m_thresholdPeriodExchange;

  uint32_t        m_keyRate;     // KeyRate of QKDlink
  bool            m_connected;    // True if connected
  bool            m_master;       // True if master  
  uint32_t        m_maxPackets;     // Limit total number of packets sent
  uint32_t        m_packetNumber;     // Total number of packets received so far 
  uint32_t        m_totalRx;      //!< Total bytes received 
  bool            m_sendKeyRateMessage;
  Time            m_lastAck;     // Time of last ACK received

  std::list<Ptr<Socket> > m_sinkSocketList; //!< the accepted sockets
  EventId         m_sendEvent;    //!< Event id of pending "send packet" event

  uint64_t        m_totBytes;     //!< Total bytes sent so far
  DataRate        m_cbrRate;      //!< Rate that data is generatedm_pktSize
  uint32_t        m_pktSize;      //!< Size of packets
  TypeId          m_tid; 

  double          m_qkdPacketNumber;     // Time of establishment of QKDMessage
  double          m_qkdTotalTime;        // Time of establishment of QKDMessage

  /// Traced Callback: received packets, source address.
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTrace;
  TracedCallback<Ptr<const Packet> > m_txTrace;

  uint32_t        m_status; //0-sifting; 1-post-processing; 2-mthreshold exchange; 3-authentication;

  uint32_t        m_packetNumber_sifting;
  uint32_t        m_maxPackets_sifting;

  uint32_t        m_packetNumber_auth;
  uint32_t        m_maxPackets_auth;
 
  uint32_t        m_packetNumber_temp1;
  uint32_t        m_maxPackets_temp1;

  uint32_t        m_packetNumber_temp2;
  uint32_t        m_maxPackets_temp2;

  uint32_t        m_packetNumber_temp3;
  uint32_t        m_maxPackets_temp3;

  uint32_t        m_packetNumber_temp4;
  uint32_t        m_maxPackets_temp4;

  uint32_t        m_packetNumber_temp5;
  uint32_t        m_maxPackets_temp5;

  uint32_t        m_packetNumber_temp6;
  uint32_t        m_maxPackets_temp6;

  uint32_t        m_packetNumber_temp7;
  uint32_t        m_maxPackets_temp7;

  uint32_t        m_packetNumber_temp8;
  uint32_t        m_maxPackets_temp8;


private:

  void ConnectionSucceeded (Ptr<Socket> socket);
  void ConnectionFailed (Ptr<Socket> socket);

  void ConnectionSucceededAuth (Ptr<Socket> socket);
  void ConnectionFailedAuth (Ptr<Socket> socket);

  void ConnectionSucceededMthreshold (Ptr<Socket> socket);
  void ConnectionFailedMthreshold (Ptr<Socket> socket);

  void ConnectionSucceededSifting (Ptr<Socket> socket);
  void ConnectionFailedSifting (Ptr<Socket> socket);

  void ConnectionSucceededtemp1 (Ptr<Socket> socket);
  void ConnectionFailedtemp1 (Ptr<Socket> socket);

  void ConnectionSucceededtemp2 (Ptr<Socket> socket);
  void ConnectionFailedtemp2 (Ptr<Socket> socket);

  void ConnectionSucceededtemp3 (Ptr<Socket> socket);
  void ConnectionFailedtemp3 (Ptr<Socket> socket);

  void ConnectionSucceededtemp4 (Ptr<Socket> socket);
  void ConnectionFailedtemp4 (Ptr<Socket> socket);

  void ConnectionSucceededtemp5 (Ptr<Socket> socket);
  void ConnectionFailedtemp5 (Ptr<Socket> socket);

  void ConnectionSucceededtemp6 (Ptr<Socket> socket);
  void ConnectionFailedtemp6 (Ptr<Socket> socket);

  void ConnectionSucceededtemp7 (Ptr<Socket> socket);
  void ConnectionFailedtemp7 (Ptr<Socket> socket);

  void ConnectionSucceededtemp8 (Ptr<Socket> socket);
  void ConnectionFailedtemp8 (Ptr<Socket> socket);

  void DataSend (Ptr<Socket>, uint32_t); // for socket's SetSendCallback 
  void Ignore (Ptr<Socket> socket);
  void RegisterAckTime (Time oldRtt, Time newRtt);
  
  Ptr<UniformRandomVariable> m_random;
};

} // namespace ns3

#endif /* QKD_APPLICATION_H */

