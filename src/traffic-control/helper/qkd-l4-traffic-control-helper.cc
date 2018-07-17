/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 Universita' degli Studi di Napoli Federico II
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
 * Author: Stefano Avallone <stavallo@unina.it>
 * Modified by: Miralem Mehic <miralem.mehic@ieee.org>
 */

#include "ns3/log.h"
#include "ns3/abort.h"
#include "ns3/queue-disc.h"
#include "ns3/uinteger.h"
#include "ns3/pointer.h"
#include "ns3/qkd-l4-traffic-control-layer.h"
#include "qkd-l4-traffic-control-helper.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDL4TrafficControlHelper"); 

QKDL4TrafficControlHelper::QKDL4TrafficControlHelper ()
{
}

QKDL4TrafficControlHelper
QKDL4TrafficControlHelper::Default (void)
{
  QKDL4TrafficControlHelper helper;
  uint16_t handle = helper.SetRootQueueDisc ("ns3::QKDL4PfifoFastQueueDisc");
  helper.AddInternalQueues (handle, 3, "ns3::DropTailQueue", "MaxPackets", UintegerValue (1000));
  helper.AddPacketFilter (handle, "ns3::PfifoFastQKDPacketFilter");
  return helper;
}

uint16_t
QKDL4TrafficControlHelper::SetRootQueueDisc (std::string type,
                                        std::string n01, const AttributeValue& v01,
                                        std::string n02, const AttributeValue& v02,
                                        std::string n03, const AttributeValue& v03,
                                        std::string n04, const AttributeValue& v04,
                                        std::string n05, const AttributeValue& v05,
                                        std::string n06, const AttributeValue& v06,
                                        std::string n07, const AttributeValue& v07,
                                        std::string n08, const AttributeValue& v08,
                                        std::string n09, const AttributeValue& v09,
                                        std::string n10, const AttributeValue& v10,
                                        std::string n11, const AttributeValue& v11,
                                        std::string n12, const AttributeValue& v12,
                                        std::string n13, const AttributeValue& v13,
                                        std::string n14, const AttributeValue& v14,
                                        std::string n15, const AttributeValue& v15)
{
  NS_ABORT_MSG_UNLESS (m_queueDiscFactory.empty (), "A root queue disc has been already added to this factory");

  ObjectFactory factory;
  factory.SetTypeId (type);
  factory.Set (n01, v01);
  factory.Set (n02, v02);
  factory.Set (n03, v03);
  factory.Set (n04, v04);
  factory.Set (n05, v05);
  factory.Set (n06, v06);
  factory.Set (n07, v07);
  factory.Set (n08, v08);
  factory.Set (n09, v09);
  factory.Set (n10, v10);
  factory.Set (n11, v11);
  factory.Set (n12, v12);
  factory.Set (n13, v13);
  factory.Set (n14, v14);
  factory.Set (n15, v15);

  m_queueDiscFactory.push_back (QueueDiscFactory (factory));
  return 0;
}

void
QKDL4TrafficControlHelper::AddInternalQueues (uint16_t handle, uint16_t count, std::string type,
                                         std::string n01, const AttributeValue& v01,
                                         std::string n02, const AttributeValue& v02,
                                         std::string n03, const AttributeValue& v03,
                                         std::string n04, const AttributeValue& v04,
                                         std::string n05, const AttributeValue& v05,
                                         std::string n06, const AttributeValue& v06,
                                         std::string n07, const AttributeValue& v07,
                                         std::string n08, const AttributeValue& v08)
{
  NS_ABORT_MSG_IF (handle >= m_queueDiscFactory.size (), "A queue disc with handle "
                   << handle << " does not exist");
 

  ObjectFactory factory;
  factory.SetTypeId (type);
  factory.Set (n01, v01);
  factory.Set (n02, v02);
  factory.Set (n03, v03);
  factory.Set (n04, v04);
  factory.Set (n05, v05);
  factory.Set (n06, v06);
  factory.Set (n07, v07);
  factory.Set (n08, v08);

  for (int i = 0; i < count; i++)
    {
      m_queueDiscFactory[handle].AddInternalQueue (factory);
    }
}

void
QKDL4TrafficControlHelper::AddPacketFilter (uint16_t handle, std::string type,
                                       std::string n01, const AttributeValue& v01,
                                       std::string n02, const AttributeValue& v02,
                                       std::string n03, const AttributeValue& v03,
                                       std::string n04, const AttributeValue& v04,
                                       std::string n05, const AttributeValue& v05,
                                       std::string n06, const AttributeValue& v06,
                                       std::string n07, const AttributeValue& v07,
                                       std::string n08, const AttributeValue& v08)
{
  NS_ABORT_MSG_IF (handle >= m_queueDiscFactory.size (), "A queue disc with handle "
                   << handle << " does not exist");

  ObjectFactory factory;
  factory.SetTypeId (type);
  factory.Set (n01, v01);
  factory.Set (n02, v02);
  factory.Set (n03, v03);
  factory.Set (n04, v04);
  factory.Set (n05, v05);
  factory.Set (n06, v06);
  factory.Set (n07, v07);
  factory.Set (n08, v08);

  m_queueDiscFactory[handle].AddPacketFilter (factory);
}

QKDL4TrafficControlHelper::ClassIdList
QKDL4TrafficControlHelper::AddQueueDiscClasses (uint16_t handle, uint16_t count, std::string type,
                                           std::string n01, const AttributeValue& v01,
                                           std::string n02, const AttributeValue& v02,
                                           std::string n03, const AttributeValue& v03,
                                           std::string n04, const AttributeValue& v04,
                                           std::string n05, const AttributeValue& v05,
                                           std::string n06, const AttributeValue& v06,
                                           std::string n07, const AttributeValue& v07,
                                           std::string n08, const AttributeValue& v08)
{
  NS_ABORT_MSG_IF (handle >= m_queueDiscFactory.size (), "A queue disc with handle "
                   << handle << " does not exist");

  ObjectFactory factory;
  factory.SetTypeId (type);
  factory.Set (n01, v01);
  factory.Set (n02, v02);
  factory.Set (n03, v03);
  factory.Set (n04, v04);
  factory.Set (n05, v05);
  factory.Set (n06, v06);
  factory.Set (n07, v07);
  factory.Set (n08, v08);

  ClassIdList list;
  uint16_t classId;

  for (int i = 0; i < count; i++)
    {
      classId = m_queueDiscFactory[handle].AddQueueDiscClass (factory);
      list.push_back (classId);
    }
  return list;
}

uint16_t
QKDL4TrafficControlHelper::AddChildQueueDisc (uint16_t handle, uint16_t classId, std::string type,
                                         std::string n01, const AttributeValue& v01,
                                         std::string n02, const AttributeValue& v02,
                                         std::string n03, const AttributeValue& v03,
                                         std::string n04, const AttributeValue& v04,
                                         std::string n05, const AttributeValue& v05,
                                         std::string n06, const AttributeValue& v06,
                                         std::string n07, const AttributeValue& v07,
                                         std::string n08, const AttributeValue& v08,
                                         std::string n09, const AttributeValue& v09,
                                         std::string n10, const AttributeValue& v10,
                                         std::string n11, const AttributeValue& v11,
                                         std::string n12, const AttributeValue& v12,
                                         std::string n13, const AttributeValue& v13,
                                         std::string n14, const AttributeValue& v14,
                                         std::string n15, const AttributeValue& v15)
{
  NS_ABORT_MSG_IF (handle >= m_queueDiscFactory.size (), "A queue disc with handle "
                   << handle << " does not exist");

  ObjectFactory factory;
  factory.SetTypeId (type);
  factory.Set (n01, v01);
  factory.Set (n02, v02);
  factory.Set (n03, v03);
  factory.Set (n04, v04);
  factory.Set (n05, v05);
  factory.Set (n06, v06);
  factory.Set (n07, v07);
  factory.Set (n08, v08);
  factory.Set (n09, v09);
  factory.Set (n10, v10);
  factory.Set (n11, v11);
  factory.Set (n12, v12);
  factory.Set (n13, v13);
  factory.Set (n14, v14);
  factory.Set (n15, v15);

  uint16_t childHandle = m_queueDiscFactory.size ();
  m_queueDiscFactory.push_back (QueueDiscFactory (factory));
  m_queueDiscFactory[handle].SetChildQueueDisc (classId, childHandle);

  return childHandle;
}

QKDL4TrafficControlHelper::HandleList
QKDL4TrafficControlHelper::AddChildQueueDiscs (uint16_t handle, const QKDL4TrafficControlHelper::ClassIdList &classes,
                                          std::string type,
                                          std::string n01, const AttributeValue& v01,
                                          std::string n02, const AttributeValue& v02,
                                          std::string n03, const AttributeValue& v03,
                                          std::string n04, const AttributeValue& v04,
                                          std::string n05, const AttributeValue& v05,
                                          std::string n06, const AttributeValue& v06,
                                          std::string n07, const AttributeValue& v07,
                                          std::string n08, const AttributeValue& v08,
                                          std::string n09, const AttributeValue& v09,
                                          std::string n10, const AttributeValue& v10,
                                          std::string n11, const AttributeValue& v11,
                                          std::string n12, const AttributeValue& v12,
                                          std::string n13, const AttributeValue& v13,
                                          std::string n14, const AttributeValue& v14,
                                          std::string n15, const AttributeValue& v15)
{
  HandleList list;
  for (ClassIdList::const_iterator c = classes.begin (); c != classes.end (); c++)
    {
      uint16_t childHandle = AddChildQueueDisc (handle, *c, type, n01, v01, n02, v02, n03, v03,
                                                n04, v04, n05, v05, n06, v06, n07, v07, n08, v08, n09, v09,
                                                n10, v10, n11, v11, n12, v12, n13, v13, n14, v14, n15, v15);
      list.push_back (childHandle);
    }
  return list;
}

void
QKDL4TrafficControlHelper::SetQueueLimits (std::string type,
                                      std::string n01, const AttributeValue& v01,
                                      std::string n02, const AttributeValue& v02,
                                      std::string n03, const AttributeValue& v03,
                                      std::string n04, const AttributeValue& v04,
                                      std::string n05, const AttributeValue& v05,
                                      std::string n06, const AttributeValue& v06,
                                      std::string n07, const AttributeValue& v07,
                                      std::string n08, const AttributeValue& v08)
{
  m_queueLimitsFactory.SetTypeId (type);
  m_queueLimitsFactory.Set (n01, v01);
  m_queueLimitsFactory.Set (n02, v02);
  m_queueLimitsFactory.Set (n03, v03);
  m_queueLimitsFactory.Set (n04, v04);
  m_queueLimitsFactory.Set (n05, v05);
  m_queueLimitsFactory.Set (n06, v06);
  m_queueLimitsFactory.Set (n07, v07);
  m_queueLimitsFactory.Set (n08, v08);
}

QueueDiscContainer
QKDL4TrafficControlHelper::Install (Ptr<Node> node)
{
  NS_LOG_FUNCTION(this << node->GetId());

  QueueDiscContainer container;

  // A QKDL4TrafficControlLayer object is aggregated by the InternetStackHelper, but check
  // anyway because a queue disc has no effect without a QKDL4TrafficControlLayer object
  Ptr<QKDL4TrafficControlLayer> tc = node->GetObject<QKDL4TrafficControlLayer> ();
  NS_ASSERT (tc != 0);

  // Start from an empty vector of queue discs
  m_queueDiscs.clear ();
  m_queueDiscs.resize (m_queueDiscFactory.size ());

  // Create queue discs (from leaves to root)
  for (int i = m_queueDiscFactory.size () - 1; i >= 0; i--)
    {
      Ptr<QueueDisc> q = m_queueDiscFactory[i].CreateQueueDisc (m_queueDiscs);
      m_queueDiscs[i] = q;
      container.Add (q);
    }

  // Set the root queue disc (if any has been created) on the device
  if (!m_queueDiscs.empty () && m_queueDiscs[0])
    {
      tc->SetRootQueueDisc (m_queueDiscs[0]);
    }
 
  return container;
}
 

void
QKDL4TrafficControlHelper::Uninstall (Ptr<Node> node)
{
  Ptr<QKDL4TrafficControlLayer> tc = node->GetObject<QKDL4TrafficControlLayer> ();
  NS_ASSERT (tc != 0);

  tc->DeleteRootQueueDisc (); 
}
 

} // namespace ns3
