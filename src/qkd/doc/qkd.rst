Quantum Key Distribution Network Simulation Module
----------------------------

This model implements the base specification of the Quantum Key Distribution (QKD) network module including QKD key, QKD Buffer (storage), QKD NetDevices, QKD Header, QKD Post-processing applications. It has been developed at the VSB Technical University of Ostrava (Czech Republic) by Miralem Mehic (miralem.mehic@ieee.org) and it is maintained by Department of Telecommunications of the University of Sarajevo, Bosnia and Herzegovina and LIPTEL team of VSB Technical University of Ostrava, Czech Republic. 

The implementation of QKD Buffer, QKD Header and QKD Key is based on Austrian Institute of Technology (AIT) R10 post-processing software (https://sqt.ait.ac.at/software/projects/qkd). More details can be found in our article which is listed in the reference section.

.. include:: replace.txt
.. highlight:: cpp

.. heading hierarchy:
   ------------- Chapter
   ************* Section (#.#)
   ============= Subsection (#.#.#)
   ############# Paragraph (no number)
 

Prerequisite
*****************
Quantum Key Distribution Network Simulation Module (QKDNetSim) includes QKDCrypto class that relies on cryptographic algorithms and schemes from Crypto++ open-source C++ class cryptographic library. Currently, QKD crypto supports several crypto- graphic algorithms and cryptographic hashes including One-Time Pad (OTP) cipher, Advanced Encryption Standard (AES) block cipher, VMAC message authentication code (MAC) algorithm and others. Also, QKD crypto implements functions for seri- alization and deserialization of the packet into a byte array which is used as the input in cryptographic algorithms and schemes. 

Installing crypto++ (libcryptopp) on Ubuntu:

::

 $ sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils

On distributions which use yum (such as Fedora):

::

 $ yum install cryptopp cryptopp-devel

In your scripts simple include required libraries using:

::

 $ #include <crypto++/aes.h>;
 $ #include <crypto++/modes.h>;
 $ #include <crypto++/filters.h>;

Wscript is already updated to support crypto++ while installation details can be found on `this URL <http://www.mehic.info/2016/04/installing-and-crypto-libcryptopp-with-ns3/>`_

Model Description
*****************

The source code for the new module lives in the directory ``src/qkd``. Due to realization of overlay QKD link and network, additional "virtual" TCP, UDP and IP classes are implemented in ``src/internet``. QKD Queue discs are placed ``src/traffic-control`` while QKD post-processing applications live in ``src/applications``. 

QKD network module organization
======

.. _module_organization:
 
.. figure:: figures/module_organization.*
   :align: center

   QKDNetSim module organization with a single TCP/IP stack

QKD Key
#############

QKD key is an elementary class of QKDNetSim. It is used to describe the key that is established in QKD process. QKD key is characterized by several meta-key parameters, of which the most important are the following:


* key identification (ID) 
* key size
* key value in ``std::string`` or ``byte`` format
* key generation timestamp

QKD Buffer
#############

QKD keys are stored in QKD buffers which are characterized by following parameters:
 
* QKD is also known as Quantum Key Growing since it needs a small amount of key material pre-shared between parties to establish a larger amount of the secret key material. The pre-shared secret key serves to guarantee the integrity of the protocol in the first transaction and it should not be used for any other purposes except to establish a new key material. The amount of pre-shared key material for that purpose is denoted with Mmin, 

* The key material storage depth Mmax, used to denote the maximal amount of keys that can be stored in QKD buffer, 

* The current value Mcur(t), representing the amount of key material in QKD buffer at the time of measurement ``t``, where it holds that Mcur(t)<=Mmax,

* The threshold value Mthr(t) at the time of measurement ``t`` is used to indicate the state of QKD buffer where it holds that Mthr(t)<=Mmax. During the simulation, Mthr(t) can be static or variable depending on the state of the network. However, algorithms for calculation of Mthr are out of the scope of this document.
 
.. qkd_buffer:
 
.. figure:: figures/qkd_buffer.*
   :align: center

   Fig.1 Graphical representation of QKD buffer status generated using the QKD Graph

As shown in Fig.1, QKD buffer can be in one of the following states:
 
* READY - when Mcur(t)>=thr,
* WARNING - when Mthr>Mcur(t)>Mmin and the previous state was READY,
* CHARGING - when Mthr>Mcur(t) and the previous state was EMPTY,
* EMTPY - when Mmin >= Mcur(t) and the previous state was WARNING or CHARGING.
 
The states of QKD buffer do not directly affect the communication, but it can be used for easier prioritization of traffic depending on the state of the buffer. For example, in EMPTY state, QKD post-processing application used to establish a new key material should have the highest priority in traffic processing. QKD post-processing applications are discussed in section~\ref{sec:QKDPostProcessingApplication}.

Without loss of generality, QKDNetSim allows storage of the ``virtual`` key material in QKD buffers instead of the actual occupation of memory by establishing and storing the symmetrical key material in QKD buffers. Simply put, key material is not generated, nor it takes up computer memory, it is only represented by a number that indicates the amount of key material in QKD buffer. In network simulators, such operations are common since they reduce the duration of simulation and save computational resources. For example, instead of generating packets with real or random information in packet payload field, network simulators often generate empty packets. 

QKD Crypto 
#############

QKD crypto is a class used to perform encryption, decryption, authentication, atuhentication-check operations and reassembly of previously fragmented packets. QKD crypto uses cryptographic algorithms and schemes from ``Crypto++`` open-source C++ class cryptographic library. Currently, QKD crypto supports several cryptographic algorithms and cryptographic hashes including One-Time Pad (OTP) cipher, Advanced Encryption Standard (AES) block cipher, VMAC message authentication code (MAC) algorithm and other.

Also, QKD crypto implements functions for serialization and deserialization of the packet into a byte array which is used as the input in cryptographic algorithms and schemes. 

QKD Virtual Network Device
#############

To facilitate the ease of operation of the overlay routing protocol, encryption, and authentication of the incoming frame is performed on the data link layer prior leaving QKD network device (NetDevice). QKD NetDevice implements a sniffer trace source which allows recording of the overlay traffic in ``pcap`` trace files. Also, QKD NetDevices allows fine tuning of the MAC-level Maximum Transmission Unit (MTU) parameter which limits the size of the frame in the overlying network. 

In practice, in overlay network, these devices are usually registered as Virtual QKD NetDevice since in the overlay network they do not add MAC header to the frame. Instead, MAC header is replaced with a QKD header which contains authentication tag and information about used encryption. In QKDNetSim, bond with QKD crypto is realized via QKD manager. Packets leaving QKD NetDevice are passed to QKD manager which is in charge of control of the cryptographic process. Similarly, the reception packet is processed (authentication check and/or decryption) before passing into the QKD NetDevice. Such implementation allows the use of other types of devices instead of QKD NetDevices, that is, use of different network technologies such as Point-to-Point, WiFi, WiMAX, LTE, UAN and other.

In the case of the network with a single TCP/IP stack, QKD manager is called from Traffic Control Layer that sits between NetDevice (L2) and IP protocol (L3). Placing connection to QKD manager in the same layer with waiting queues of Traffic Control Layer allows simple usage of various types of NetDevices and it follows previous work on encryption of the packet content above OSI data link layer.

QKD Manager
#############

QKD manager is installed at each QKD node and it represents the backbone of QKDNetSim. It contains a list of QKD Virtual NetDevices from the overlying network, a list of active sockets in the underlying network, a list of IP addresses of interfaces in the overlying and underlying network and a list of associated QKD buffers and QKD cryptos. Therefore, QKD manager serves as a bond between the overlying NetDevices and sockets in the underlying network. 
Since the QKD link is always realized in a point-to-point manner between exactly two nodes, QKD manager stores information about NetDevices of the corresponding link and associated QKD buffers. Using the MAC address of NetDevice, QKD manager unambiguously distinguishes QKD crypto and QKD buffer which are utilized for packet processing. Finally, QKD manager delivers the processed packet to the underlying network. Receiving and processing of incoming packets follows identical procedure but in reverse order.

QKD Post-processing Application
#############

Key material establishment process is an inevitable part of the QKD network. It is performed using QKD protocols to provide a key to the participant of symmetric system transmission in a safe manner. 
%Generally speaking, QKD protocols can be roughly distinguished into three broad categories: Discrete variable protocols (BB84, B92, E91, SARG04), Continuous variable protocols and Distributed phase reference coding (COW, DPS).
Although there are several types of QKD protocols, they consist of nearly identical steps at a high level, but differ, among others, in the way the quantum particles or photons are prepared and transmitted over quantum channel. Communication via the public channel is referred as ``post-processing`` and it used for extraction of the secret key from the raw key which is generated over the quantum channel.
Although there are differences in implementations, almost every post-processing application needs to implement following steps: extraction of the raw key, error rate estimation, key reconciliation, privacy amplification and authentication. 
Given that the focus of the QKDNetSim is placed on network traffic and considering that there are different variations of post-processing applications, QKDNetSim provides a simple application which seeks to imitate traffic that is generated by the real-world post-processing applications such as AIT R10 QKD software. The goal was to build an application that credibly imitates traffic from existing post-processing applications to reduce the simulation time and computational resources.

It is important to emphasize that the impact of post-processing applications cannot be ignored in QKD network. Considering that node in a QKD network constantly generate keys at their maximum rate until their key storages are filled, in some cases, the traffic generated by the post-processing application can have a significant impact on the quality of communication over the public channel, especially when it comes to public channels of weaker network performance. 

QKD Graph
#############

QKD graphs are implemented to allow easier access to the state of QKD buffers and easier monitoring of key material consumption. QKD graph is associated with QKD buffer which allows plotting of graphs on each node with associated QKD link and QKD buffer. QKD Graph creates separate PLT and DAT files which are suitable for plotting using popular ``Gnuplot`` tool in PNG, SVG or EPSLATEX format. QKDNetSim supports plotting of QKD Total Graph which is used to show the overall consumption of key material in QKD Network. QKD Total Graph is updated each time when key material is generated or consumed on a network link. Fig.1 is plotted using QKDGraph.

QKD Helper
#############

QKDNetSim comes with a helper class (QKD helper) which provides easier installation of QKD managers at network nodes, setting the parameters of QKD links and QKD buffers, and drawing of QKD graphs. Given that cryptographic operations are called from QKD managers, QKD module can be easily used in overlay networks with two TCP/IP stacks or in simple networks with a single TCP/IP stack. In the case of usage of the overlay network, it is necessary for applications to use ``virtual-TCP-L4`` or ``virtual-UDP-L4`` protocols which pass the packet to virtual-ipv4-l3 protocol. The packet is further passed to corresponding NetDevice and QKD manager. After performing cryptographic operations, the packet is finally delivered to the underlying network. In the case of a simple network when a single TCP/IP stack is used, standard ``tcp-l4``, ``udp-l4`` and ``ipv4-l3`` protocols are utilized, while QKD helper sets sending and receiving callback from NetDevice to QKD manager to perform cryptographic operations. QKDHelper is realized to facilitate the procedure for the establishment of these configurations.


QKD Overlay network module organization
======
 
QKDNetSim allows realization of overlay network which can be used for various purposes regardless of QKD network. To ensure the independence of the underlying network, each QKD node implements an overlay TCP/IP stack with an independent overlay routing protocol. During the development of QKDNetSim, we aimed to minimize changes to the existing core code of NS-3 simulator. But, still, to provide independent overlay networking, QKDNetSim implements following classes in the ``internet`` module of NS-3 simulator:

* virtual-ipv4-protocol
* virtual-tcp-l4-protocol
* virtual-tcp-socket-base
* virtual-tcp-socket-factory
* virtual-tcp-socket-factory-impl
* virtual-udp-l4-protocol
* virtual-udp-socket
* virtual-udp-socket-factory
* virtual-udp-socket-factory-impl
* virtual-udp-socket-impl

Class ``ipv4-protocol`` keeps a list of all IPv4 address associated with IPv4 interfaces. Thus, to distinguish IP addresses of underlying and overlying network ``virtual-ipv4-protocol`` class is introduced. This implies the implementation of independent overlay TCP and UDP L4 protocol classes which pass packets to ``virtual-ipv4-protocol`` instead of original ``ipv4-protocol``. Additionally, realization of independent TCP and UDP L4 protocol classes allows simple modification of overlying L4 communication without affecting the underlying TCP/IP stack.

.. overlay_module_organization:
 
.. figure:: figures/overlay_module_organization.*
   :align: center

   Fig.2 QKDNetSim module organization with overlay TCP/IP stack

.. traffic_flow:
 
.. figure:: figures/traffic_flow.*
   :align: center

   Fig.3 QKDNetSim traffic flow


QKDNetSim UML Class Diagram
=====================
 
.. qkd_model_uml:
 
.. figure:: figures/qkd_model_uml.*
   :align: center

   Fig.4 QKDNetSim UML Class Diagram

Helpers
=======

QKDNetSim comes with a helper class (QKD helper) which provides an easier instal-
lation of QKD managers at network nodes, setting the parameters of QKD links and
QKD buffers, and drawing the QKD graphs. Given that cryptographic operations are
called from QKD managers, the QKD module can be easily used in overlay networks
with two TCP/IP stacks or in simple networks with a single TCP/IP stack. When an
overlay network is used, it is necessary that the applications use virtual-TCP-L4 or
virtual-UDP-L4 protocols which pass the packet to the virtual-ipv4-l3 protocol. The
packet is further passed to the corresponding NetDevice and QKD manager. After
performing cryptographic operations, the packet is finally delivered to the underlying
network. In the case of a simple network when a single TCP/IP stack is used, standard
``tcp-l4``, ``udp-l4`` and ``ipv4-l3`` protocols are used, while the QKD helper
sets sending and receiving ``callback`` from NetDevice to the QKD manager to per-
form cryptographic operations. The QKD helper is realized to facilitate the procedure
for the establishment of such configurations.


Validation
**********

Although the literature states that a variety of applications have been tested in previously deployed QKD networks, the research in the performance of public channels was generally underestimated and most attention was paid to the quantum channel performances. To the best of our knowledge, no other reports on network traffic analysis over the public channel have been published. Additionally, although there are several software applications dealing with QKD, to the best of our knowledge, applications for simulating QKD networks with multiple nodes and links are not available. Therefore, QKDNetSim is a unique tool that aims at enabling the publication of the new results and findings in a communication over a public channel of the QKD link. It is important to note that QKDNetSim is a simulation module for the QKD Network which is developed in a well-proven existing |ns3| simulator. QKDNetSim uses the well-known Crypto++ open-source C++ class cryptographic library and well-tested code libraries of NS-3 simulator with minimal modifications to allow overlay network communication and the packet encapsulation with the QKD Header. Given the popularity and utilization of the AIT R10 QKD software in previously implemented projects QKDNetSim follows the network organization from the previously deployed QKD testbeds which is reflected in the design of the QKD Header and the imitation of the network traffic generated using AIT R10 QKD post-processing application.


Scope and Limitations
=====================

What can the model do:

* It is suitable for testing of various networking operations and protocols. Such as: routing, network organization, L4 protocol behaviour (TCP fragmentation), waiting queues, overlay network organization and other.

What can it not do:

* At the moment, QKD Post-processing application simulates QKD AIT Post-processing application. That is, no real QKD protocol (BB84, B92 or other) is implemented in QKDNetSim. 
* At the moment, QKDNetSim does not store QKDKey on the real storage (Hard-Drive). Intead, it stores QKDKey in temp arrays and vectors that are removed after simulation comes to the end.
* QKDNetSim at the moment only supports IPv4 addresses

Limitation:

* When performing cryptographic operations, new packets are generated to carry the encrypted payload and headers of the "raw" packet that needs to be encrypted. Therefore, these new "encrypted" packets have different ns3:packetID value (obtained using "packet->GetUid()") from the original "raw" packet.


Attributes
==========

The most important attributes are those from ``QKDBuffer`` class related to amount of key material available in the buffer and the state of QKDBuffer. Check QKDBuffer section for more details. Also, please note that QKDNetDevices allow outputing trace files in PCAP format.
 
Troubleshooting
===============

Please double check that Crypt++ library is installed correctly.

Examples
========

The examples are in the ``src/qkd/examples/`` directory. 

References
==========

Mehic, Miralem, Oliver Maurhart, Stefan Rass, and Miroslav Voznak. “Implementation of quantum key distribution network simulation module in the network simulator NS-3.” Quantum Information Processing 16, no. 10 (2017): 253. doi: 10.1007/s11128-017-1702-z
