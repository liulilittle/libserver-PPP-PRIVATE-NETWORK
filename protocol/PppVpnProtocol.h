#pragma once

#include "Error.h"
#include "../env.h"
#include "../server.h"
#include "../packet/Ipep.h"
#include "../packet/IPEndPoint.h"
#include "../io/SeekOrigin.h"
#include "../io/Stream.h"
#include "../io/MemoryStream.h"
#include "../io/BinaryReader.h"
#include "../cryptography/PppVpnCipher.h"

enum AddressType {
    None    = 0,
    IPv4    = 1,
    IPv6    = 2,
    Domain  = 3,
};

class AddressEndPoint {
public:
    AddressType                                 Type = AddressType::None;
    std::string                                 Host;
    int                                         Port = 0;
};

struct DatagramPacket {
public:
    int                                         ProtocolType; // = 0
    IPEndPoint                                  Source;
    IPEndPoint                                  Destination;
    std::shared_ptr<Byte>                       Message;
    int                                         MessageSize; // = 0
    int                                         MessageOffset;

public:
    inline DatagramPacket() noexcept : ProtocolType(0), MessageSize(0), MessageOffset(0) {}
};

class PppVpnProtocol final {
public:
    static bool                                 PortNumberToBytes(
        Stream&                                 stream, 
        const std::shared_ptr<PppVpnCipher>&    cipher, 
        int                                     port) noexcept;
    static bool                                 WriteBytesTextAddress(
        Stream&                                 stream,
        const std::shared_ptr<PppVpnCipher>&    cipher,
        const std::string&                      host,
        AddressType                             addressType) noexcept;
    inline static Byte                          ProtocolTypeToByte(int protocol) noexcept {
        int r = 0;
        switch (protocol)
        {
        case ip_hdr::IP_PROTO_ICMP:
            r = 2;
            break;
        case ip_hdr::IP_PROTO_UDP:
            r = 1;
            break;
        case ip_hdr::IP_PROTO_TCP:
            r = 0;
            break;
        }
        r = (r << 6) | (PppVpnProtocol::RandKey() & 0x3F);
        return (Byte)r;
    }
    inline static int                           ByteToProtocolType(Byte b) noexcept {
        b >>= 6;
        switch (b)
        {
        case 2:
            return ip_hdr::IP_PROTO_ICMP;
        case 1:
            return ip_hdr::IP_PROTO_UDP;
        case 0:
            return ip_hdr::IP_PROTO_TCP;
        }
        return ip_hdr::IP_PROTO_IP;
    }

public:
    static bool                                 ReadAddressFromBytesText(
        BinaryReader&                           br, 
        const std::shared_ptr<PppVpnCipher>&    cipher,
        std::string&                            hostname,
        IPEndPoint&                             addressEP,
        AddressType&                            addressType) noexcept;
    static bool                                 BytesToPortNumber(
        BinaryReader&                           br, 
        const std::shared_ptr<PppVpnCipher>&    cipher,
        int&                                    port) noexcept;
    inline static bool                          ReadEndPointFromBytesText(
        BinaryReader&                           br, 
        const std::shared_ptr<PppVpnCipher>&    cipher,
        std::string&                            hostname,
        IPEndPoint&                             addressEP,
        AddressType&                            addressType) noexcept {
        if (!ReadAddressFromBytesText(br, cipher, hostname, addressEP, addressType)) {
            return false;
        }

        int port;
        if (!BytesToPortNumber(br, cipher, port)) {
            return false;
        }

        constantof(addressEP.Port) = (UInt16)port;
        return true;
    }

private:
    static bool                                 BuildDatagramPacket(
        Stream&                                 stream,
        const std::shared_ptr<PppVpnCipher>&    cipher,
        const std::string&                      address,
        int                                     addressPort,
        AddressType                             addressType,
        int                                     protocol,
        const void*                             buffer,
        int                                     buffer_size) noexcept;

public:
    inline static Byte                          RandKey() noexcept {
        return server_random(0x00, 0xff);
    }
    static bool                                 BuildHandshakePacket(
        Stream&                                 stream,
        const std::shared_ptr<PppVpnCipher>&    cipher,
        const std::string&                      host,
        int                                     port,
        AddressType                             addressType) noexcept;
    static bool                                 ReadDatagramPacket(
        Stream&                                 stream,
        const std::shared_ptr<PppVpnCipher>&    cipher,
        DatagramPacket&                         packet) noexcept;
    static bool                                 BuildDatagramPacket(
        Stream&                                 stream, 
        const std::shared_ptr<PppVpnCipher>&    cipher, 
        const DatagramPacket&                   packet) noexcept;
};