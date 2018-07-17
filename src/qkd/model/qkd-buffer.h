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

#ifndef QKD_BUFFER_H
#define QKD_BUFFER_H

#include <queue>
#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/ipv4-header.h" 
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/event-id.h"
#include "ns3/qkd-key.h"
#include <vector>
#include <map>
 
namespace ns3 {

/**
 * \defgroup qkd Quantum Key Distribution (QKD)
 * This section documents the API of the ns-3 QKD Network Simulation Module (QKDNetSim). 
 *
 * Be sure to read the manual BEFORE going down to the API.
 */

/**
 * \ingroup qkd
 * \class QKDBuffer
 * \brief QKD buffer (storage) that keeps QKD keys. QKDBuffer is assigned for each link using
 *  QKDManager on each side of the link (each node). That is, two QKDBuffers for one link. 
 *
 *  \note Due to the limited key rate, the links are organized in the following way: both
 *  endpoints of the corresponding link have key storages (QKD buffers) with limited capacity
 *  which are gradually filled with the new key material, which is subsequently used for
 *  the encryption/decryption of the data flow. The QKD devices constantly generate keys
 *  at their maximum key rate until the key storages are filled. The type of the used
 *  encryption algorithm and the amount of network traffic to be encrypted determines the
 *  speed of emptying the key storage, often referred as the key consumption rate, while the
 *  key rate of the link determines the key charging rate. If there is no enough of
 *  the stored key material, the encryption of the data flow cannot be performed and the
 *  link can be characterized as “currently unavailable”. QKD buffer can be in one of the following states:
 *  READY, WARNING, CHARGING, EMTPY.
 *  The states of QKD buffer do not directly affect the communication, but it can be used for 
 *  easier prioritization of traffic depending on the state of the buffer. For example, in EMPTY state, 
 *  QKD post-processing application used to establish a new key material should have the highest 
 *  priority in traffic processing.
 * 
 */
class QKDBuffer : public Object
{
public:
    
    static const uint32_t  QKDSTATUS_READY        = 0;  //!< QKDStatus READY
    static const uint32_t  QKDSTATUS_WARNING      = 1;  //!< QKDStatus WARNING
    static const uint32_t  QKDSTATUS_CHARGING     = 2;  //!< QKDStatus CHARGING
    static const uint32_t  QKDSTATUS_EMPTY        = 3;  //!< QKDStatus EMPTY
    
    struct data{
        uint32_t value;
        uint32_t position;
    };
    
    /**
    * \brief Get the TypeId
    *
    * \return The TypeId for this class
    */
    static TypeId GetTypeId (void);

    /**
    * \brief Create a QKDBuffer
    *
    * By default, you get an empty QKD storage
    */
    QKDBuffer (uint32_t srcNodeId, uint32_t dstNodeId, bool useRealStorages);

    /**
    * Destroy a QKDBuffer
    *
    * This is the destructor for the QKDBuffer.
    */
    virtual ~QKDBuffer ();
    
    /**
    * Initialize a QKDBuffer
    *
    * This is the initialize function of the new QKDBuffer.
    */
    void Init(void);

    /**
    * Destroy a QKDBuffer
    *
    * This is the pre-destructor function of the QKDBuffer.
    */
    void Dispose(void);
    
    /**
    * Check whether there is enough key material to send the package to destination
    *
    * \param keySize uint32_t size of the requested key
    * \return Ptr<QKDKey> if there is enough key material; 0 otherwise
    */
    Ptr<QKDKey> ProcessOutgoingRequest(const uint32_t& keySize);

    /**
    * Check whether there is enough key material to decrypt the incoming package
    *
    * \param keyID uint32_t ID of incoming key request
    * \param keySize uint32_t size of the requested key
    * \return Ptr<QKDKey> if there is enough key material; 0 otherwise
    */
    Ptr<QKDKey> ProcessIncomingRequest(const uint32_t& keyID, const uint32_t& keySize);
    
    /**
    * Add new key material to the storage after post-processing is completed
    * 
    * \param keySize uint32_t size of the new key material
    * \return True if the key material can be added to the storage; False otherwise
    */
    bool AddNewContent(const uint32_t& keySize);

    /**
    *   Fetch the current state of the QKD buffer
    *
    *   QKD buffer can be in one of the following states:
    *   – READY—when Mcur (t) ≥ Mthr ,
    *   – WARNING—when Mthr > Mcur (t) > Mmin and the previous state was READY,
    *   – CHARGING—when Mthr > Mcur (t) and the previous state was EMPTY,
    *   – EMTPY—when Mmin ≥ Mcur (t) and the previous state was WARNING or CHARGING
    */
    uint32_t FetchState(void);

    /**
    *   Fetch the previous state of the QKD buffer. Help function used for ploting graphs
    *
    *   \return int32_t integer representation of QKD Storage state
    */
    uint32_t FetchPreviousState(void);
  
    /**
    *   Help function used for ploting graphs
    */
    void CalculateAverageAmountOfTheKeyInTheBuffer();

    /**
    *   Update the state after some changes on the buffer
    */
    void CheckState(void);

    /**
    *   Help function used for ploting graphs
    */
    void KeyCalculation();

    /*
    *   Return time difference between the current time and time at which 
    *   last key charging process finished
    *
    *   \return int64_t deltaTime
    */
    int64_t FetchDeltaTime();

    /**
    *   Return time value about the time duration of last key charging process
    *
    *   \return int64_t lastKeyChargingTimeDuration
    */
    int64_t FetchLastKeyChargingTimeDuration();

    /**
    *   Return average duration of key charging process in the long run
    *   
    *   \return double average duration of key charging period
    */
    double FetchAverageKeyChargingTimePeriod();

    /**
    *   Return the maximal number of values which are used for stored 
    *   for calculation of average key charging time period
    *
    *   \return int32_t maximal number of recorded key charging time periods; default value 5
    */
    uint32_t FetchMaxNumberOfRecordedKeyChargingTimePeriods();

    /**
    *   Help function used for ploting graphs; Previous - before latest change
    *
    *   \return int32_t integer representation of the previous QKD storage key material;
    */
    uint32_t GetMCurrentPrevious (void) const; 

    /**
    *   Get the current amount of key material in QKD storage
    *
    *   \return int32_t integer representation of the current QKD storage key material
    */
    uint32_t GetMcurrent (void) const;

    /**
    *   Get the threshold value of QKD storage
    *   The threshold value Mthr (t) at the time of measurement t is used to indicate the
    *   state of QKD buffer where it holds that Mthr (t) ≤ Mmax .
    *
    *   \return int32_t integer representation of the threshold value of the QKD storage
    */
    uint32_t GetMthr (void) const;

    /**
    *   Set the threshold value of QKD storage
    *
    *   \param int32_t integer set the threshold value of the QKD storage
    */
    void SetMthr (uint32_t thr);

    /**
    *   Get the maximal amount of key material that can be stored in QKD storage
    * 
    *   \return int32_t integer representation of the QKD storage capacity
    */
    uint32_t GetMmax (void) const;

    /**
    *   Get the minimal amount of key material that can be stored in QKD storage
    *   
    *   \return int32_t integer representation of the min value of QKD storage
    */
    uint32_t GetMmin (void) const; 

    /**
    *   Help function for total graph ploting
    */
    void    InitTotalGraph() const;

    /**
    *   Get the QKD Storage/Buffer ID
    *   
    *   \return int32_t buffer unique ID
    */
    uint32_t GetBufferId (void) const;

    /**
    *   Assign operator
    *  
    *   \param o Other QKDBuffer
    *   \return True if buffers are identical; False otherwise
    */
    bool    operator== (QKDBuffer const & o) const;
 
    uint32_t            m_SrcNodeId;    //!< source node ID

    uint32_t            m_DstNodeId;    //!< destination node ID

    uint32_t            m_bufferID;     //!< unique buffer ID

    static uint32_t     nBuffers;       //!< number of created buffers - static value
 
private:

    /**
    *   Check whether key exists in the buffer
    *  
    *   \param uint32_t keyID
    *   \return Ptr to the key
    */
    Ptr<QKDKey>     FetchKeyByID (const uint32_t& keyID);

    /**
    *   Find the key of required size to be used for encryption
    *   UNDER CONSTRUCTION!
    *   THIS FUNCTION NEEDS TO PERFORM MERGE, SPLIT OF KEYS AND TO PROVIDE FINAL KEY OF REQUIRED SIZE
    *
    *   \param uint32_t keySize in bits! 
    *   \return Ptr to the key
    */
    Ptr<QKDKey>     FetchKeyOfSize (const uint32_t& keySize);

    /**
    *   Whether to use real storages or virtual buffers
    *   UNDER CONSTRUCTION! Currently only virtual buffers supported
    */
    bool        m_useRealStorages;

    /**
    *   ID of the next key to be generated
    */
    uint32_t    m_nextKeyID;

    /**
    *   map of ID-Ptr<QKDKey>
    */
	std::map<uint32_t, Ptr<QKDKey> > m_keys;

    /**
    *   Help value used for graph ploting
    */
    uint32_t    m_noEntry;
    
    /**
    *   Help value used for graph ploting
    */
    uint32_t    m_period; 

    /**
    *   Help value used for graph ploting
    */
    uint32_t    m_noAddNewValue;

    /**
    *   Help value used for graph ploting and calculation of average
    *   post-processing duration
    */
    uint32_t    m_bitsChargedInTimePeriod;
    
    /**
    *   Help value used for detection of average key usage
    */
    uint32_t    m_bitsUsedInTimePeriod;

    /**
    *   The period of time (in seconds) to calculate average amount of the key in the buffer
    *   Default value 5 - used in routing protocols for detection of information freshness
    */
    uint32_t    m_recalculateTimePeriod;

    /**
    *   Help vector used for graph ploting
    */
    std::vector<struct QKDBuffer::data> m_previousValues;
  
    double      m_c; //!< average amount of key in the buffer during the recalculate time period

    bool        m_isRisingCurve; //!< whether curve on graph is rising or not

    /**
    *   Holds previous status; important for deciding about further status that can be selected
    */
    uint32_t    m_previousStatus;

    /**
    * The minimal amount of key material in QKD key storage
    */
    uint32_t       m_Mmin;

    /**
    * The maximal amount of key material in QKD key storage
    */
    uint32_t       m_Mmax;

    /**
    * The threshold amount of key material in QKD key storage
    */
    uint32_t       m_Mthr; 

    TracedCallback<uint32_t > m_MthrChangeTrace;
    TracedCallback<uint32_t > m_MthrIncreaseTrace;
    TracedCallback<uint32_t > m_MthrDecreaseTrace;

    /**
    * The current amount of key material in QKD key storage
    */
    uint32_t       m_Mcurrent;

    /**
    * The previous value of current amount of key material in QKD key storage
    */
    uint32_t       m_McurrentPrevious;

    /**
    * The timestamp of last key charging (when the new key material was added)
    */
    int64_t         m_lastKeyChargingTimeStamp;
    
    /**
    * The timestamp of last key usage
    */
    int64_t         m_lastKeyChargingTimeDuration;
    
    /**
    *   The maximal number of values which are used for stored for calculation 
    *   of average key charging time period
    */
    uint32_t        m_maxNumberOfRecordedKeyChargingTimePeriods;

    /**
    *   Vector of durations of several last charging time periods
    */
    std::vector<int64_t > m_chargingTimePeriods;

    /**
    * The state of the Net Device transmit state machine.
    */
    uint32_t        m_Status;
    
    /**
    *   The average duration of key charging time period
    */
    double          m_AverageKeyChargingTimePeriod;

    EventId         m_calculateRoutingMetric;

    TracedCallback<uint32_t > m_McurrentChangeTrace;
    TracedCallback<uint32_t > m_McurrentIncreaseTrace;
    TracedCallback<uint32_t > m_McurrentDecreaseTrace;
    TracedCallback<uint32_t > m_StatusChangeTrace;   
    TracedCallback<double   > m_CMetricChangeTrace;   
    TracedCallback<double  > m_AverageKeyChargingTimePeriodTrace;    
};
}

#endif /* QKD_BUFFER_H */
