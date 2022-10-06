#include "server.h"
#include "session.h"

void session::Close() noexcept {
    boost::system::error_code ec_;
    std::shared_ptr<transport_tunnel> lan = std::move(lan_);
    if (lan) {
        lan_.reset();
        lan->close();
    }

    std::shared_ptr<transport_tunnel> wan = std::move(wan_);
    if (wan) {
        wan_.reset();
        wan->close();
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
    if (socket) {
        server::closesocket(*socket);
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> server = server_;
    if (server) {
        server::closesocket(*server);
    }

    CancelTimeout();
}

void session::CancelTimeout() noexcept {
    boost::system::error_code ec_;
    std::shared_ptr<boost::asio::deadline_timer> timeout = std::move(timeout_);
    if (timeout) {
        timeout_.reset();
        try {
            timeout->cancel(ec_);
        }
        catch (std::exception&) {}
    }
    last_ = hosting_->CurrentMillisec();
}

bool session::Lan2Wan() noexcept {
    std::shared_ptr<transport_tunnel> lan = lan_;
    if (!lan) {
        return false;
    }

    std::shared_ptr<session> self_ = GetPtr();
    return lan->read(
        [this, self_](const std::shared_ptr<Byte>& data, int datalen) noexcept {
            bool success_ = WanWrite(data, datalen);
            if (success_) {
                last_ = hosting_->CurrentMillisec();
            }
            else {
                Close();
            }
        });
}

bool session::Wan2Lan() noexcept {
    std::shared_ptr<transport_tunnel> wan = wan_;
    if (!wan) {
        return false;
    }

    std::shared_ptr<session> self_ = GetPtr();
    return wan->read(
        [this, self_](const std::shared_ptr<Byte>& data, int datalen) noexcept {
            bool success_ = LanWrite(data, datalen);
            if (success_) {
                last_ = hosting_->CurrentMillisec();
            }
            else {
                Close();
            }
        });
    return true;
}

bool session::LanWrite(const std::shared_ptr<Byte>& data, int length) noexcept {
    std::shared_ptr<transport_tunnel> lan = lan_;
    if (!lan) {
        return false;
    }

    std::shared_ptr<session> self_ = GetPtr();
    std::shared_ptr<Byte> data_ = data;

    return lan->write(data.get(), 0, length,
        [this, self_, data_](bool success_) noexcept {
            if (success_) {
                success_ = Wan2Lan();
            }

            if (success_) {
                last_ = hosting_->CurrentMillisec();
            }
            else {
                Close();
            }
        });
}

bool session::WanWrite(const std::shared_ptr<Byte>& data, int length) noexcept {
    std::shared_ptr<transport_tunnel> wan = wan_;
    if (!wan) {
        return false;
    }

    std::shared_ptr<session> self_ = GetPtr();
    std::shared_ptr<Byte> data_ = data;

    return wan->write(data.get(), 0, length,
        [this, self_, data_](bool success_) noexcept {
            if (success_) {
                success_ = Lan2Wan();
            }

            if (success_) {
                last_ = hosting_->CurrentMillisec();
            }
            else {
                Close();
            }
        });
}

bool session::SendHanshakeError(Error error) noexcept {
    std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
    if ((!socket) || (!socket->is_open())) {
        return false;
    }

    if (error == Error::Success) {
        std::shared_ptr<Byte> messages_ = make_shared_alloc<Byte>(2);
        Byte* p_ = messages_.get();
        p_[0] = PppVpnProtocol::RandKey();
        p_[1] = error;
        boost::asio::async_write(*socket, boost::asio::buffer(p_, 2),
            [messages_](const boost::system::error_code& ec_, size_t sz) noexcept {});
    }
    else {
        int length_ = server_random(16, alignment_);
        std::shared_ptr<Byte> messages_ = make_shared_alloc<Byte>(length_);
        Byte* p_ = messages_.get();
        for (int i_ = 0; i_ < length_; i_++) {
            p_[i_] = server_random_ascii();
        }
        p_[0] = PppVpnProtocol::RandKey();
        p_[1] = (Byte)error;

        std::shared_ptr<session> self = GetPtr();
        boost::asio::async_write(*socket, boost::asio::buffer(p_, length_),
            [this, self, messages_](const boost::system::error_code& ec_, size_t sz) noexcept {
                Close();
            });
    }
    return true;
}

bool session::Handshake(const boost::asio::yield_context& y) noexcept {
    HandshakeContext context;
    Error error = HandshakeAddress(y, context, HandshakeHeader(y, context));
    if (error == Error::Success) {
        error = HandshakeConnect(y, context);
    }
    SendHanshakeError(error);

    bool handshaked_ = false;
    if (error == Error::Success) {
        handshaked_ = Lan2Wan() && Wan2Lan();
    }

    if (!handshaked_) {
        Close();
    }
    return handshaked_;
}

Error session::HandshakeConnect(const boost::asio::yield_context& y, HandshakeContext& context) noexcept {
    if (context.protocolType == ip_hdr::IP_PROTO_TCP) {
        if (context.port <= IPEndPoint::MinPort || context.port > IPEndPoint::MaxPort) {
            return Error::UnableToInitiateConnectEstablishmentWithTheServer;
        }
    }

    boost::system::error_code ec_;
    std::shared_ptr<boost::asio::ip::tcp::socket> server = make_shared_object<boost::asio::ip::tcp::socket>(*context_);
    if (ec_ || !server) {
        return Error::UnableToCreateServerSocket;
    }

    IPEndPoint remoteEP_ = Ipep::GetEndPoint(Get(configuration_->tcp.server));
    if (IPEndPoint::IsInvalid(remoteEP_)) {
        return Error::UnableToCreateServerSocket;
    }

    if (remoteEP_.GetAddressFamily() == AddressFamily::InterNetwork) {
        server->open(boost::asio::ip::tcp::v4(), ec_);
    }
    else {
        server->open(boost::asio::ip::tcp::v6(), ec_);
    }
    if (ec_) {
        return Error::UnableToInitiateConnectEstablishmentWithTheServer;
    }

    if (configuration_->tcp.fast_open) {
        server->set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec_);
    }

    if (configuration_->tcp.turbo.wan) {
        server->set_option(boost::asio::ip::tcp::no_delay(true), ec_);
    }

    int handle_ = server->native_handle();
    server::SetTypeOfService(handle_);
    server::SetSignalPipeline(handle_, false);
    server::SetDontFragment(handle_, false);
    server::ReuseSocketAddress(handle_, false);

    int err = network::asio::async_connect(*server, IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(remoteEP_), y);
    if (err < 0) {
        return Error::TimeoutSafeWaitHandleIsCloseOrIsInvalid;
    }
    elif(err > 0) {
        return Error::UnableToInitiateConnectEstablishmentWithTheServer;
    }

    MemoryStream& handshakes = context.handshakes;
    if (!network::asio::async_write(*server, boost::asio::buffer(handshakes.GetBuffer().get(), handshakes.GetPosition()), y)) {
        return Error::UnableToInitiateConnectEstablishmentWithTheServer;
    }

    using TRANSPORT_TYPE = transport_tunnel::TRANSPORT_TYPE;
    if (!network::asio::async_read(*server, boost::asio::buffer(buffer_.get(), 2), y)) {
        return Error::UnableToInitiateConnectEstablishmentWithTheServer;
    }

    Error error = (Error)buffer_.get()[1];
    if (error != Error::Success) {
        return error;
    }

    server_ = server;
    if (context.protocolType == ip_hdr::IP_PROTO_TCP) {
        wan_ = transport_tunnel::create(TRANSPORT_TYPE::TRANSPORT_TUNNEL_TCPIP, hosting_, cipher_, server, configuration_, alignment_);
        lan_ = transport_tunnel::create(TRANSPORT_TYPE::TRANSPORT_TUNNEL_TRANSPARENT, hosting_, cipher_, socket_, configuration_, alignment_);
    }
    else {
        wan_ = transport_tunnel::create(TRANSPORT_TYPE::TRANSPORT_TUNNEL_TRANSPARENT, hosting_, cipher_, server, configuration_, alignment_);
        lan_ = transport_tunnel::create(TRANSPORT_TYPE::TRANSPORT_TUNNEL_TRANSPARENT, hosting_, cipher_, socket_, configuration_, alignment_);
    }
    return Error::Success;
}

Error session::HandshakePort(const boost::asio::yield_context& y, HandshakeContext& context) noexcept {
    if (!session::async_read(context, *socket_, boost::asio::buffer(buffer_.get(), 2), y)) {
        return Error::ReceiveIsDisconnectedOrTimeout;
    }

    MemoryStream ms(buffer_, 2);
    BinaryReader br(ms);

    int port;
    if (!PppVpnProtocol::BytesToPortNumber(br, cipher_, port) || port < IPEndPoint::MinPort) {
        return Error::UnableToDecryptEncryptedBinaryData;
    }

    if (port == IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
        return Error::PortsAreNotAllowedToBeLessThanOrEqualTo0OrGreaterThan65535;
    }

    context.port = port;
    return Error::Success;
}

Error session::HandshakeAddress(const boost::asio::yield_context& y, HandshakeContext& context, Error error) noexcept {
    if (error != Error::Success) {
        return error;
    }

    if (context.addressType == AddressType::None) {
        if (context.addressLength < 2) {
            return Error::NoneTypeHeaderNotLessThanTwoBytes;
        }

        if (!session::async_read(context, *socket_, boost::asio::buffer(buffer_.get(), context.addressLength), y)) {
            return Error::ReceiveIsDisconnectedOrTimeout;
        }

        context.protocolType = PppVpnProtocol::ByteToProtocolType(buffer_.get()[0]);
        if (context.protocolType != ip_hdr::IP_PROTO_UDP) {
            return Error::ProtocolTypeIsNotSupported;
        }

        context.addressType = (AddressType)(buffer_.get()[1] >> 6);
        switch (context.addressType)
        {
        case AddressType::IPv4:
            break;
        case AddressType::IPv6:
            break;
        default:
            return Error::AddressTypeIsNotSupported;
        }

        memset(context.address, 0, sizeof(context.address));
        return Error::Success;
    }
    elif(context.addressType == AddressType::IPv4 || // IPv4
        context.addressType == AddressType::IPv6 || // IPv6
        context.addressType == AddressType::Domain) { // 域名
        // 53 61 41 80 f2 6e 1b 99 a7 95 8e 16 99 73 35 4c 5a 4e 29
        context.addressLength = 0;
        if (!session::async_read(context, *socket_, boost::asio::buffer(buffer_.get(), 1), y)) {
            return Error::ReceiveIsDisconnectedOrTimeout;
        }

        int outlen;
        std::shared_ptr<Byte> buff_ = cipher_->Protocol->Decrypt(buffer_.get(), 1, outlen);
        if (!buff_ || outlen < 1) {
            return Error::ReceiveIsDisconnectedOrTimeout;
        }

        context.addressLength = buff_.get()[0];
        if (!session::async_read(context, *socket_, boost::asio::buffer(buffer_.get(), context.addressLength), y)) {
            return Error::ReceiveIsDisconnectedOrTimeout;
        }

        buff_ = cipher_->Transport->Decrypt(buffer_.get(), context.addressLength, outlen);
        if (!buff_ || outlen < 1) {
            return Error::UnableToDecryptEncryptedBinaryData;
        }

        std::string hostname_ = std::string((char*)buff_.get(), outlen);
        if (hostname_.empty()) {
            return Error::DomainNameWithFullBlankOrEmptyStringAreNotAllowed;
        }

        boost::system::error_code ec_;
        boost::asio::ip::address address_ = boost::asio::ip::address::from_string(hostname_.data(), ec_);
        if (ec_) {
            context.addressType = AddressType::Domain;
            context.hostname = hostname_;
        }
        elif(address_.is_v4()) {
            boost::asio::ip::address_v4::bytes_type bytes_ = address_.to_v4().to_bytes();
            if ((*(uint32_t*)bytes_.data()) == UINT_MAX) {
                return Error::DestinationServerAddressIsNotAllowedToBeAnyAddress;
            }
            context.addressType = AddressType::IPv4;
            memcpy(context.address, bytes_.data(), bytes_.size());
        }
        elif(address_.is_v6()) {
            boost::asio::ip::address_v6::bytes_type bytes_ = address_.to_v6().to_bytes();
            uint64_t* address_v6_ = (uint64_t*)bytes_.data();
            if (address_v6_[0] == UINT64_MAX && address_v6_[1] == UINT64_MAX) {
                return Error::DestinationServerAddressIsNotAllowedToBeAnyAddress;
            }
            context.addressType = AddressType::IPv6;
            memcpy(context.address, bytes_.data(), bytes_.size());
        }
        else {
            return Error::AddressTypeIsNotSupported;
        }
        return HandshakePort(y, context);
    }
    else {
        return Error::AddressTypeIsNotSupported;
    }
}

Error session::HandshakeHeader(const boost::asio::yield_context& y, HandshakeContext& context) noexcept {
    int addszOrType = 0;
    context.protocolType = ip_hdr::IP_PROTO_TCP;
    context.addressLength = 0;
    context.addressType = AddressType::None;

    const std::shared_ptr<PppVpnCipher>& cipher = cipher_;
    if (cipher->Kf) {
        if (!session::async_read(context, *socket_, boost::asio::buffer(buffer_.get(), 3), y)) {
            return Error::ReceiveIsDisconnectedOrTimeout;
        }
        if (buffer_.get()[1] != cipher->Kf) {
            return Error::ReceiveIsDisconnectedOrTimeout;
        }
        addszOrType = buffer_.get()[2];
    }
    else {
        if (!session::async_read(context, *socket_, boost::asio::buffer(buffer_.get(), 2), y)) {
            return Error::ReceiveIsDisconnectedOrTimeout;
        }
        addszOrType = buffer_.get()[1];
    }
    context.addressLength = addszOrType & 0x3F;
    context.addressType = (AddressType)(addszOrType >> 6);
    return Error::Success;
}

bool session::Handshake() noexcept {
    std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
    if (!socket || !configuration_ || !context_) {
        return false;
    }

    std::shared_ptr<session> self = GetPtr();
    timeout_ = Hosting::Timeout(context_,
        [self, this]() noexcept {
            SendHanshakeError(Error::EstablishConnectTimeoutWithTheRemoteServer);
            Close();
        }, (uint64_t)GetConfiguration()->tcp.connect.timeout * 1000);
    if (!timeout_) {
        return false;
    }

    boost::asio::spawn(*context_,
        [self, this](const boost::asio::yield_context& y) noexcept {
            bool success_ = Handshake(y);
            if (!success_) {
                Close();
            }
            else {
                CancelTimeout();
            }
        });
    return true;
}
