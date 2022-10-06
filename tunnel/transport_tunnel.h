#pragma once

#include <assert.h>
#include "../env.h"
#include "ppp_tcp_channel.h"
#include "transparent_tcp_channel.h"

class transport_tunnel final {
private:
    typedef bool(transport_tunnel::*transport_write)(void*, int, int, const BOOST_ASIO_MOVE_ARG(WriteAsyncCallback));
    inline bool                                                 transport_write_TCPIP(void* buff, int offset, int length, const BOOST_ASIO_MOVE_ARG(WriteAsyncCallback) callback) noexcept {
        return ptc_->write(buff, offset, length, forward0f(callback));
    }
    inline bool                                                 transport_write_TRANSPARENT(void* buff, int offset, int length, const BOOST_ASIO_MOVE_ARG(WriteAsyncCallback) callback) noexcept {
        return ttc_->write(buff, offset, length, forward0f(callback));
    }

private:
    typedef bool(transport_tunnel::*transport_read)(const BOOST_ASIO_MOVE_ARG(ReadAsyncCallback));
    inline bool                                                 transport_read_TCPIP(const BOOST_ASIO_MOVE_ARG(ReadAsyncCallback) callback) noexcept {
        return ptc_->read(forward0f(callback));
    }
    inline bool                                                 transport_read_TRANSPARENT(const BOOST_ASIO_MOVE_ARG(ReadAsyncCallback) callback) noexcept {
        return ttc_->read(forward0f(callback));
    }

public:
    enum TRANSPORT_TYPE {
        TRANSPORT_TUNNEL_TCPIP = 1,
        TRANSPORT_TUNNEL_TRANSPARENT = 2,
    };
    inline transport_tunnel(TRANSPORT_TYPE transport, transport_read read, transport_write write) noexcept
        : type_(transport)
        , read_(read)
        , write_(write) {
        assert(read);
        assert(write);
    }
    inline ~transport_tunnel() noexcept {
        close();
    }

public:
    inline TRANSPORT_TYPE                                       type() noexcept {
        return type_;
    }
    inline void                                                 close() noexcept {
        const std::shared_ptr<ppp_tcp_channel>& ptc = ptc_;
        if (ptc) {
            ptc->close();
        }

        const std::shared_ptr<transparent_tcp_channel>& ttc = ttc_;
        if (ttc) {
            ttc->close();
        }
    }
    inline bool                                                 read(const BOOST_ASIO_MOVE_ARG(ReadAsyncCallback) callback) noexcept {
        return (this->*read_)(forward0f(callback));
    }
    inline bool                                                 write(const void* buff, int offset, int length, const BOOST_ASIO_MOVE_ARG(WriteAsyncCallback) callback) noexcept {
        return (this->*write_)((void*)buff, offset, length, forward0f(callback));
    }
    inline static std::shared_ptr<transport_tunnel>             create(
        TRANSPORT_TYPE                                          transport, 
        const std::shared_ptr<Hosting>&                         hosting,
        const std::shared_ptr<PppVpnCipher>&                    cipher,
        const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
        const std::shared_ptr<server_configuration>&            configuration,
        const int                                               alignment) noexcept {
        if (!hosting || !socket || !configuration) {
            return NULL;
        }

        transport_read                           read  = NULL;
        transport_write                          write = NULL;

        std::shared_ptr<ppp_tcp_channel>         ptc   = NULL;
        std::shared_ptr<transparent_tcp_channel> ttc   = NULL;

        if(transport & TRANSPORT_TUNNEL_TRANSPARENT) {
            ttc = make_shared_object<transparent_tcp_channel>(configuration, hosting, socket, alignment);
            read = &transport_tunnel::transport_read_TRANSPARENT;
            write = &transport_tunnel::transport_write_TRANSPARENT;
        }
        elif(transport & TRANSPORT_TUNNEL_TCPIP) {
            if (!cipher) {
                return NULL;
            }

            ptc = make_shared_object<ppp_tcp_channel>(configuration, hosting, cipher, socket, alignment);
            read = &transport_tunnel::transport_read_TCPIP;
            write = &transport_tunnel::transport_write_TCPIP;
        }
        else {
            return NULL;
        }

        std::shared_ptr<transport_tunnel> channel_ = make_shared_object<transport_tunnel>(transport, read, write);
        channel_->ptc_   = std::move(ptc);
        channel_->ttc_   = std::move(ttc);
        return channel_;
    }
    inline std::shared_ptr<server_configuration>                get_configuration() const noexcept {
        const std::shared_ptr<ppp_tcp_channel>& ptc = ptc_;
        if (ptc) {
            return ptc->get_configuration();
        }

        const std::shared_ptr<transparent_tcp_channel>& ttc = ttc_;
        if (ttc) {
            return ttc->get_configuration();
        }
        return NULL;
    }

private:
    TRANSPORT_TYPE                                              type_;
    transport_read                                              read_;
    transport_write                                             write_;
    std::shared_ptr<ppp_tcp_channel>                            ptc_;
    std::shared_ptr<transparent_tcp_channel>                    ttc_;
};