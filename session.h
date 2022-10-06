#pragma once

#include "env.h"
#include "server.h"
#include "./tunnel/transport_tunnel.h"
#include "./protocol/Error.h"
#include "./protocol/PppVpnProtocol.h"
#include "./cryptography/PppVpnCipher.h"

#include <boost/function.hpp> 
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

class session final : public std::enable_shared_from_this<session> {
public:
    inline session(const std::shared_ptr<server>& server, const std::shared_ptr<boost::asio::io_context>& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, bool transparency) noexcept
        : transparency_(transparency)
        , handshaked_(false)
        , owner_(server)
        , hosting_(server->GetHosting())
        , configuration_(server->GetConfiguration())
        , context_(context)
        , socket_(socket)
        , alignment_(configuration_->tcp.alignment) {
        last_ = hosting_->CurrentMillisec();
        buffer_ = hosting_->GetBuffer(context.get());
        cipher_ = make_shared_object<PppVpnCipher>(configuration_->key.kf,
            Get(configuration_->key.protocol),
            Get(configuration_->key.protocol_key),
            Get(configuration_->key.transport),
            Get(configuration_->key.transport_key));
    }
    inline ~session() noexcept {
        Close();
    }

public:
    void                                                            Close() noexcept;
    inline std::shared_ptr<session>                                 GetPtr() noexcept {
        return shared_from_this();
    }
    inline const std::shared_ptr<Hosting>&                          GetHosting() const noexcept {
        return hosting_;
    }
    inline const std::shared_ptr<server>&                           GetServer() const noexcept {
        return owner_;
    }
    inline const std::shared_ptr<server_configuration>&             GetConfiguration() const noexcept {
        return configuration_;
    }
    bool                                                            Handshake() noexcept;

private:
    struct HandshakeContext {
        AddressType                                                 addressType;
        int                                                         addressLength;
        int                                                         protocolType;
        Byte                                                        address[16];
        std::string                                                 hostname;
        int                                                         port;
        MemoryStream                                                handshakes;
    };
    Error                                                           HandshakeConnect(const boost::asio::yield_context& y, HandshakeContext& context) noexcept;
    Error                                                           HandshakePort(const boost::asio::yield_context& y, HandshakeContext& context) noexcept;
    Error                                                           HandshakeAddress(const boost::asio::yield_context& y, HandshakeContext& context, Error error) noexcept;
    Error                                                           HandshakeHeader(const boost::asio::yield_context& y, HandshakeContext& context) noexcept;
    bool                                                            Handshake(const boost::asio::yield_context& y) noexcept;
    bool                                                            SendHanshakeError(Error error) noexcept;
    void                                                            CancelTimeout() noexcept;

private:
    bool                                                            Lan2Wan() noexcept;
    bool                                                            Wan2Lan() noexcept;
    bool                                                            LanWrite(const std::shared_ptr<Byte>& data, int length) noexcept;
    bool                                                            WanWrite(const std::shared_ptr<Byte>& data, int length) noexcept;

private:
    inline static size_t                                            async_read(
        HandshakeContext&                                           context_,
        boost::asio::ip::tcp::socket&                               socket_,
        const boost::asio::mutable_buffers_1&                       buffer_,
        const boost::asio::yield_context&                           y_) noexcept {
        if (!network::asio::async_read(socket_, buffer_, y_)) {
            return false;
        }
        return context_.handshakes.Write(buffer_.data(), 0, buffer_.size());
    }
    template<typename T>
    inline static T                                                 Get(const std::shared_ptr<T>& p) noexcept {
        return p ? *p : "";
    }

private:
    bool                                                            transparency_;
    bool                                                            handshaked_;
    uint64_t                                                        last_;
    std::shared_ptr<Byte>                                           buffer_;
    std::shared_ptr<server>                                         owner_;
    std::shared_ptr<Hosting>                                        hosting_;
    std::shared_ptr<server_configuration>                           configuration_;
    std::shared_ptr<boost::asio::io_context>                        context_;
    std::shared_ptr<boost::asio::ip::tcp::socket>                   socket_;
    std::shared_ptr<boost::asio::ip::tcp::socket>                   server_;
    std::shared_ptr<boost::asio::deadline_timer>                    timeout_;
    std::shared_ptr<PppVpnCipher>                                   cipher_;
    std::shared_ptr<transport_tunnel>                               lan_;
    std::shared_ptr<transport_tunnel>                               wan_;
    int                                                             alignment_;
};