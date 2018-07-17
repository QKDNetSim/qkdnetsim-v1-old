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
 

#include <algorithm>                                                      
#include <numeric>    
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/log.h" 
  
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/uinteger.h" 

#include "qkd-buffer.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDBuffer");

NS_OBJECT_ENSURE_REGISTERED (QKDBuffer);

TypeId 
QKDBuffer::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDBuffer")
    .SetParent<Object> () 
    .AddAttribute ("Minimal", 
                   "The minimal amount of key material in QKD storage",
                   UintegerValue (1000000), //1Mb 
                   MakeUintegerAccessor (&QKDBuffer::m_Mmin),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Maximal", 
                   "The maximal amount of key material in QKD storage",
                   UintegerValue (1000000000), //1Gb
                   MakeUintegerAccessor (&QKDBuffer::m_Mmax),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Threshold", 
                   "The threshold amount of key material in QKD storage",
                   UintegerValue (2000000), //2Mb
                   MakeUintegerAccessor (&QKDBuffer::m_Mthr),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("Current", 
                   "The current amount of key material in QKD storage",
                   UintegerValue (5000000), //5Mb
                   MakeUintegerAccessor (&QKDBuffer::m_Mcurrent),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("CalculationTimePeriod", 
                   "The period of time (in seconds) to calculate average amount of the key in the buffer",
                   UintegerValue (5), // in seconds
                   MakeUintegerAccessor (&QKDBuffer::m_recalculateTimePeriod),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("MaxNumberOfRecordedKeyCharingTimePeriods", 
                   "The maximal number of values which are used for stored for calculation of average key charging time period",
                   UintegerValue (5), 
                   MakeUintegerAccessor (&QKDBuffer::m_maxNumberOfRecordedKeyChargingTimePeriods),
                   MakeUintegerChecker<uint32_t> ()) 

    .AddTraceSource ("ThresholdChange",
                     "The change trace for threshold amount of key material in QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_MthrChangeTrace),
                     "ns3::QKDBuffer::ThresholdChange") 

    .AddTraceSource ("ThresholdIncrease",
                     "The increase trace for threshold amount of key material in QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_MthrIncreaseTrace),
                     "ns3::QKDBuffer::ThresholdIncrease") 

    .AddTraceSource ("ThresholdDecrease",
                     "The decrease trace for threshold amount of key material in QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_MthrDecreaseTrace),
                     "ns3::QKDBuffer::ThresholdDecrease") 

    .AddTraceSource ("CurrentChange",
                    "The change trace for current amount of key material in QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_McurrentChangeTrace),
                     "ns3::QKDBuffer::CurrentChange")

    .AddTraceSource ("CurrentIncrease",
                    "The increase trace for current amount of key material in QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_McurrentIncreaseTrace),
                     "ns3::QKDBuffer::CurrentIncrease")

    .AddTraceSource ("CurrentDecrease",
                    "The decrease trace for current amount of key material in QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_McurrentDecreaseTrace),
                     "ns3::QKDBuffer::CurrentDecrease")

    .AddTraceSource ("StatusChange",
                    "The change trace for current status of QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_StatusChangeTrace),
                     "ns3::QKDBuffer::StatusChange")
    .AddTraceSource ("CMetricChange",
                    "The change trace for current status of QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_CMetricChangeTrace),
                     "ns3::QKDBuffer::CMetricChange")
    .AddTraceSource ("AverageKeyChargingTimePeriod",
                    "The change trace for current status of QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_AverageKeyChargingTimePeriodTrace),
                     "ns3::QKDBuffer::AverageKeyChargingTimePeriod")
    ; 
  return tid;
}

QKDBuffer::QKDBuffer(uint32_t srcNodeId, uint32_t dstNodeId, bool useRealStorages)
{
    NS_LOG_FUNCTION(this << srcNodeId << dstNodeId); 
    m_SrcNodeId = srcNodeId;  
    m_DstNodeId = dstNodeId;  
    m_nextKeyID = 0;
    m_useRealStorages = useRealStorages;
    Init();
}

uint32_t QKDBuffer::nBuffers = 0;

void
QKDBuffer::Init(){

    NS_LOG_FUNCTION  (this);

    m_bufferID = ++nBuffers;
    m_McurrentPrevious = 0;  
    m_noEntry = 0; 
    m_period = 5;
    m_noAddNewValue = 0;
    m_lastKeyChargingTimeDuration = 0;
    
    m_bitsChargedInTimePeriod = 0;
    m_bitsUsedInTimePeriod = 0;
    m_c = 0;
    m_lastKeyChargingTimeStamp = 0;
 
    this->CalculateAverageAmountOfTheKeyInTheBuffer();
}

QKDBuffer::~QKDBuffer ()
{
  NS_LOG_FUNCTION  (this);
}
 
void 
QKDBuffer::Dispose ()
{ 
    NS_LOG_FUNCTION  (this);
    Simulator::Cancel (m_calculateRoutingMetric); 
}

void
QKDBuffer::CalculateAverageAmountOfTheKeyInTheBuffer(){
      
    NS_LOG_FUNCTION  (this);
    m_c = (m_Mcurrent - m_Mthr) + (m_bitsChargedInTimePeriod - m_bitsUsedInTimePeriod);
    m_CMetricChangeTrace(m_c); 

    NS_LOG_FUNCTION  (this << m_c);

    m_bitsChargedInTimePeriod = 0;
    m_bitsUsedInTimePeriod = 0;
     
    m_calculateRoutingMetric = Simulator::Schedule(
        Seconds( m_recalculateTimePeriod ), 
        &QKDBuffer::CalculateAverageAmountOfTheKeyInTheBuffer, 
        this
    );
}

bool compareByData(const QKDBuffer::data &a, const QKDBuffer::data &b)
{
    return a.value > b.value;
}

void
QKDBuffer::KeyCalculation()
{   
    NS_LOG_FUNCTION  (this);
    m_McurrentPrevious = m_Mcurrent;
    
    struct QKDBuffer::data q;
    q.value = m_Mcurrent;
    q.position = m_noEntry;
   
    while( m_previousValues.size () > m_period ) 
        m_previousValues.pop_back();

    m_previousValues.insert( m_previousValues.begin() ,q);
       
    //sort elements in descending order, first element has the maximum value
    std::sort(m_previousValues.begin(), m_previousValues.end(), compareByData);

    /*
    *   Check state of the function for current period
    */ 
   /* if( m_noAddNewValue == m_noEntry || 
      ( (m_noEntry > m_noAddNewValue + m_period) && (m_period > 0 
        //&& m_noEntry % m_period == 0
        ) ) 
    ){ */
        /*
        *   If maximal value is on the current location then it means that the current value is the highest in the period => function is rising
        *   Otherwise, function is going down
        */
        m_isRisingCurve = (m_previousValues[0].position == m_noEntry);
        CheckState();
    //}
    m_noEntry++;
}


/**
*   Add new content to buffer
*   @param uint32_t keySize in bits
*   Used when node receives information that new key material was establieshed
*/
bool
QKDBuffer::AddNewContent(const uint32_t& keySize)
{
    NS_LOG_FUNCTION  (this << keySize);

    if(m_Mcurrent + keySize >= m_Mmax){

        NS_LOG_FUNCTION(this << "Buffer is full! Not able to add new " 
            << keySize << "since the current is " 
            << m_Mcurrent << " and max is " << m_Mmax
        );
        
        m_McurrentChangeTrace (m_Mcurrent);
        m_McurrentIncreaseTrace (0);

    }else{

        if(m_useRealStorages){
          Ptr<QKDKey> key = CreateObject<QKDKey> (m_nextKeyID, keySize);
          m_nextKeyID++;
          m_keys.insert( std::make_pair(  key->GetUid() ,  key) );
          NS_LOG_FUNCTION (this << "New Key In USE:" << key->GetUid() << m_keys.size() ); 
        }
     
        m_Mcurrent = m_Mcurrent + keySize;
        m_McurrentChangeTrace (m_Mcurrent);
        m_McurrentIncreaseTrace (keySize);
    }

    /*
    * First CALCULATE AVERAGE TIME PERIOD OF KEY CHARGING VALUE
    */

    //calculate average value of periods in vector
    if(m_chargingTimePeriods.size())
        m_AverageKeyChargingTimePeriod = accumulate( m_chargingTimePeriods.begin(), m_chargingTimePeriods.end(), 0.0 ) / m_chargingTimePeriods.size() ;
    else
        m_AverageKeyChargingTimePeriod = 0;

    m_AverageKeyChargingTimePeriodTrace (m_AverageKeyChargingTimePeriod);

    NS_LOG_DEBUG(this << " m_AverageKeyChargingTimePeriod: " << m_AverageKeyChargingTimePeriod );
    NS_LOG_DEBUG(this << " m_chargingTimePeriods.size(): " << m_chargingTimePeriods.size() );

    /**
    * Second, add new value to vector of previous values
    */
    while( m_chargingTimePeriods.size () > m_maxNumberOfRecordedKeyChargingTimePeriods ){
        m_chargingTimePeriods.pop_back();
    }

    int64_t currentTime = Simulator::Now ().GetMilliSeconds();
    int64_t tempPeriod = currentTime - m_lastKeyChargingTimeStamp; 
    m_chargingTimePeriods.insert( m_chargingTimePeriods.begin(), tempPeriod );
    m_lastKeyChargingTimeDuration = tempPeriod;
    m_lastKeyChargingTimeStamp = currentTime;

    NS_LOG_DEBUG (this << " m_lastKeyChargingTimeStamp: " << m_lastKeyChargingTimeStamp );
    NS_LOG_DEBUG (this << " m_lastKeyChargingTimeDuration: " << m_lastKeyChargingTimeDuration );
    
    //////////////////////////////////////////////////////////////////////////////////

    m_period = m_noEntry - m_noAddNewValue;
    m_noAddNewValue = m_noEntry;

    m_bitsChargedInTimePeriod += keySize;

    NS_LOG_FUNCTION  (this << "New key material added");

    KeyCalculation();
    return true;
}

uint32_t 
QKDBuffer::FetchMaxNumberOfRecordedKeyChargingTimePeriods(){
    return m_maxNumberOfRecordedKeyChargingTimePeriods;
}

/**
*   Process Outgoing Request
*   Used when node wants to send encrypted packet to other node 
*   @param  keySize in bits!
*/
Ptr<QKDKey>
QKDBuffer::ProcessOutgoingRequest(const uint32_t& keySize)
{    
    NS_LOG_FUNCTION  (this << keySize << m_Mcurrent); 

    if(m_Mcurrent <= keySize)
        return 0;

    Ptr<QKDKey> key = FetchKeyOfSize(keySize);

    m_Mcurrent = m_Mcurrent - keySize;
    m_McurrentChangeTrace(m_Mcurrent);
    m_McurrentDecreaseTrace (keySize);

    m_bitsUsedInTimePeriod -= keySize;

    KeyCalculation(); 
    return key;
}

/**
*   Process Incoming Request
*   Used when node receives encrypted packet from other node so he needs to use key to decrypt it
*   @todo Perform decryption of the packet and 
*          analyze encryption metadata (keyID and authID)
*/
Ptr<QKDKey>
QKDBuffer::ProcessIncomingRequest(const uint32_t& akeyID, const uint32_t& akeySize)
{
    NS_LOG_FUNCTION  (this << akeyID ); 

    uint32_t keySize; 
    Ptr<QKDKey> key;

    //If realKeys are NOT used then fetch some key of required size
    if(m_useRealStorages == false){
      key = FetchKeyOfSize(akeySize);
      if(key == 0) 
        return 0;
      
    }else{
    //Otherwise, find the requested key by keyID
      key = FetchKeyByID(akeyID);
      if(key == 0) 
        return 0;
    }
    keySize = key->GetSize();

    NS_LOG_FUNCTION  (this << keySize << m_Mcurrent); 

    if(m_Mcurrent <= keySize)
        return 0;
 
    m_Mcurrent = m_Mcurrent - keySize;
    m_McurrentChangeTrace(m_Mcurrent);
    m_McurrentDecreaseTrace(keySize);

    m_bitsUsedInTimePeriod -= keySize;

    KeyCalculation(); 
    return key;
}

/**
*   Find the key of required size to be used for encryption
*   UNDER CONSTRUCTION!
*   THIS FUNCTION NEEDS TO PERFORM MERGE, SPLIT OF KEYS AND TO PROVIDE FINAL KEY OF REQUIRED SIZE
*   @param  keySize in bits!
*/
Ptr<QKDKey>
QKDBuffer::FetchKeyOfSize (const uint32_t& keySize)
{
    NS_LOG_FUNCTION  (this << keySize); 

    Ptr<QKDKey> key = CreateObject<QKDKey> (m_nextKeyID, keySize); //in BITS
    m_nextKeyID++;
    //m_keys.insert( std::make_pair(  key->GetUid() ,  key) );
    NS_LOG_FUNCTION (this << "New Key In USE:" << key->GetUid() << m_keys.size() ); 
    return key;
}

Ptr<QKDKey>
QKDBuffer::FetchKeyByID (const uint32_t& keyID)
{
    NS_LOG_FUNCTION  (this << keyID); 

    std::map<uint32_t, Ptr<QKDKey> >::iterator a = m_keys.find (keyID);
    if (a != m_keys.end () && a->first == keyID)
    {
       NS_LOG_FUNCTION (this << "KeyID is valid!" << m_keys.size() ); 
    }else{
      NS_LOG_FUNCTION (this << "KeyID is NOT valid!" << m_keys.size() ); 
      return 0;
    }
    return a->second;
}


void 
QKDBuffer::CheckState(void)
{
    NS_LOG_FUNCTION  (this << m_Mmin << m_Mcurrent << m_McurrentPrevious << m_Mthr << m_Mmax << m_Status << m_previousStatus );

	if(m_Mcurrent >= m_Mthr){ 
         NS_LOG_FUNCTION  ("case 1");
		 m_Status = QKDBuffer::QKDSTATUS_READY;

	}else if(m_Mcurrent < m_Mthr && m_Mcurrent > m_Mmin && 
        ((m_isRisingCurve == true && m_previousStatus != QKDBuffer::QKDSTATUS_READY) || m_previousStatus == QKDBuffer::QKDSTATUS_EMPTY )
    ){
         NS_LOG_FUNCTION  ("case 2");
		 m_Status = QKDBuffer::QKDSTATUS_CHARGING;

	}else if(m_Mcurrent < m_Mthr && m_Mcurrent > m_Mmin && 
        (m_previousStatus != QKDBuffer::QKDSTATUS_CHARGING)
    ){ 
         NS_LOG_FUNCTION  ("case 3");
		 m_Status = QKDBuffer::QKDSTATUS_WARNING;

	}else if(m_Mcurrent <= m_Mmin){ 
        NS_LOG_FUNCTION  ("case 4");
		 m_Status  = QKDBuffer::QKDSTATUS_EMPTY; 
	}else{ 
         NS_LOG_FUNCTION  ("case UNDEFINED"     << m_Mmin << m_Mcurrent << m_McurrentPrevious << m_Mthr << m_Mmax << m_Status << m_previousStatus ); 
    } 

    if(m_previousStatus != m_Status){
        NS_LOG_FUNCTION  (this << "STATUS IS NOT EQUAL TO PREVIOUS STATUS" << m_previousStatus << m_Status);
        NS_LOG_FUNCTION  (this << m_Mmin << m_Mcurrent << m_McurrentPrevious << m_Mthr << m_Mmax << m_Status << m_previousStatus );
 
        m_StatusChangeTrace(m_previousStatus);
        m_StatusChangeTrace(m_Status);
        m_previousStatus = m_Status;
    } 
}

bool
QKDBuffer::operator== (QKDBuffer const & o) const
{ 
    return (this->m_bufferID == o.m_bufferID);
}

uint32_t
QKDBuffer::GetBufferId() const{
    NS_LOG_FUNCTION  (this << this->m_bufferID); 
    return this->m_bufferID ;
}

void
QKDBuffer::InitTotalGraph() const{

  NS_LOG_FUNCTION  (this);  

  m_McurrentIncreaseTrace (m_Mcurrent);
  m_MthrIncreaseTrace(m_Mthr); 
  
}

/**
*   Return time value about the time duration of last key charging process
*/
int64_t
QKDBuffer::FetchLastKeyChargingTimeDuration(){

  NS_LOG_FUNCTION  (this);
  return m_lastKeyChargingTimeDuration;
}

/*
*   Return time difference between the current time and time at which 
*   last key charging process finished
*/
int64_t
QKDBuffer::FetchDeltaTime(){

  NS_LOG_FUNCTION  (this); 
  int64_t currentTime = Simulator::Now ().GetMilliSeconds();
  return currentTime - m_lastKeyChargingTimeStamp; 
}

double
QKDBuffer::FetchAverageKeyChargingTimePeriod(){
  NS_LOG_FUNCTION  (this << m_AverageKeyChargingTimePeriod); 
  return m_AverageKeyChargingTimePeriod;
}

uint32_t
QKDBuffer::FetchState(void)
{
    NS_LOG_FUNCTION  (this << m_Status); 
    return m_Status;
}

uint32_t
QKDBuffer::FetchPreviousState(void)
{
    NS_LOG_FUNCTION  (this << m_previousStatus); 
    return m_previousStatus;
}


uint32_t 
QKDBuffer::GetMcurrent (void) const
{
    NS_LOG_FUNCTION  (this << m_Mcurrent); 
    return m_Mcurrent;
}

uint32_t 
QKDBuffer::GetMCurrentPrevious (void) const
{
    NS_LOG_FUNCTION  (this << m_McurrentPrevious); 
    return m_McurrentPrevious;
}

uint32_t 
QKDBuffer::GetMthr (void) const
{
    NS_LOG_FUNCTION  (this << m_Mthr); 
    return m_Mthr;
}
void
QKDBuffer::SetMthr (uint32_t thr)
{
    NS_LOG_FUNCTION  (this << thr); 

    if(thr > m_Mthr){
      m_MthrIncreaseTrace (thr - m_Mthr);
    }else{
      m_MthrDecreaseTrace (m_Mthr - thr);
    }

    m_Mthr = thr;
    m_MthrChangeTrace(m_Mthr);
}

uint32_t 
QKDBuffer::GetMmax (void) const
{
    NS_LOG_FUNCTION  (this << m_Mmax); 
    return m_Mmax;
}

uint32_t 
QKDBuffer::GetMmin (void) const
{
    NS_LOG_FUNCTION  (this << m_Mmin); 
    return m_Mmin;
} 

} // namespace ns3
