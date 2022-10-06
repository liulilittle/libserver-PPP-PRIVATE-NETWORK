#pragma once

#include "../env.h"
#include "../server.h"
#include "../Hosting.h"
#include ".././cryptography/PppVpnCipher.h"
#include ".././protocol/PppVpnProtocol.h"

class transparent_tcp_channel final : public std::enable_shared_from_this<transparent_tcp_channel> {
    const int CTCP_MSS                                          = 65536;

public:
    inline transparent_tcp_channel(
        const std::shared_ptr<server_configuration>&            configuration, 
        const std::shared_ptr<Hosting>&                         hosting, 
        const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
        const int                                               alignment)
        : CTCP_MSS(alignment)
        , hosting_(hosting) 
        , socket_(socket)
        , configuration_(configuration) {
        buffer_ = make_shared_alloc<Byte>(CTCP_MSS);
    }
    inline ~transparent_tcp_channel() {
        close();
    }

public:
    inline bool                                                 read(const BOOST_ASIO_MOVE_ARG(ReadAsyncCallback) callback) {
        if (!callback) {
            return false;
        }

        std::shared_ptr<transparent_tcp_channel> self = shared_from_this();
        ReadAsyncCallback callback_ = BOOST_ASIO_MOVE_CAST(ReadAsyncCallback)(constantof(callback));

        socket_->async_read_some(boost::asio::buffer(buffer_.get(), CTCP_MSS),
            [self, this, callback_](const boost::system::error_code& ec, size_t sz) noexcept {
                int transferred_length_ = std::max<int>(-1, ec ? -1 : sz);
                if (transferred_length_ < 1) {
                    callback_(NULL, transferred_length_);
                    close();
                    return;
                }
                callback_(buffer_, transferred_length_);
            });
        return true;
    }
    inline bool                                                 write(const void* data, int offset, int length, const BOOST_ASIO_MOVE_ARG(WriteAsyncCallback) callback) {
        if (!data || offset < 0 || length < 1) {
            return false;
        }

        const std::shared_ptr<transparent_tcp_channel> self = shared_from_this();
        const WriteAsyncCallback callback_ = BOOST_ASIO_MOVE_CAST(WriteAsyncCallback)(constantof(callback));

        boost::asio::async_write(*socket_, boost::asio::buffer((char*)data + offset, length),
            [self, this, callback_](const boost::system::error_code& ec, size_t sz) noexcept {
                bool success_ = false;
                if (ec) {
                    close();
                }
                else {
                    success_ = true;
                }

                if (callback_) {
                    callback_(success_);
                }
            });
        return true;
    }
    inline void                                                 close() {
        server::closesocket(*socket_);
    }
    inline const std::shared_ptr<server_configuration>&         get_configuration() const {
        return configuration_;
    }

private:
    std::shared_ptr<Hosting>                                    hosting_;
    std::shared_ptr<boost::asio::ip::tcp::socket>               socket_;
    std::shared_ptr<server_configuration>                       configuration_;
    std::shared_ptr<Byte>                                       buffer_;
};