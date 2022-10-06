#pragma once

#include "../env.h"
#include "../server.h"
#include "../Hosting.h"
#include ".././cryptography/PppVpnCipher.h"
#include ".././protocol/PppVpnProtocol.h"

class ppp_tcp_channel final : public std::enable_shared_from_this<ppp_tcp_channel> {
    static const int CTCP_TSS                                               = 3;
    const int CTCP_MSS                                                      = 65536;

public:
    inline ppp_tcp_channel(
        const std::shared_ptr<server_configuration>&                        configuration, 
        const std::shared_ptr<Hosting>&                                     hosting, 
        const std::shared_ptr<PppVpnCipher>&                                cipher, 
        const std::shared_ptr<boost::asio::ip::tcp::socket>&                socket,
        const int                                                           alignment) noexcept
        : CTCP_MSS(alignment)
        , hosting_(hosting)
        , socket_p_(socket)
        , socket_(*socket)
        , cipher_(cipher)
        , configuration_(configuration) {
        buffer_ = make_shared_alloc<Byte>(CTCP_MSS);
    }
    inline ~ppp_tcp_channel() noexcept {
        close();
    }

public:
    inline bool                                                             write(const void* data, int offset, int length, const BOOST_ASIO_MOVE_ARG(WriteAsyncCallback) callback) noexcept {
        if (!data || offset < 0 || length < 1 || length > CTCP_MSS) {
            return false;
        }

        int payload_size_;
        std::shared_ptr<Byte> payload_bytes_ = cipher_->Transport->Encrypt((char*)data + offset, length, payload_size_);
        if (NULL == payload_bytes_ || payload_size_ < 1) {
            return false;
        }

        Byte sz_[CTCP_TSS] = {
            (Byte)(payload_size_ >> 16),
            (Byte)(payload_size_ >> 8),
            (Byte)(payload_size_),
        };

        int header_bytes_size_;
        std::shared_ptr<Byte> header_bytes_ = cipher_->Protocol->Encrypt(sz_, CTCP_TSS, header_bytes_size_);
        if (NULL == header_bytes_ || header_bytes_size_ < 1) {
            return false;
        }

        int packet_size_ = header_bytes_size_ + payload_size_;
        std::shared_ptr<Byte> packet_ = make_shared_alloc<Byte>(packet_size_);

        Byte* p_ = packet_.get();
        Byte* b_ = header_bytes_.get();
        p_[0] = (Byte)(b_[0]);
        p_[1] = (Byte)(b_[1]);
        p_[2] = (Byte)(b_[2]);
        memcpy(p_ + header_bytes_size_, payload_bytes_.get(), payload_size_);

        const std::shared_ptr<ppp_tcp_channel> self = shared_from_this();
        const WriteAsyncCallback callback_ = BOOST_ASIO_MOVE_CAST(WriteAsyncCallback)(constantof(callback));

        boost::asio::async_write(socket_, boost::asio::buffer(packet_.get(), packet_size_),
            [self, this, packet_, callback_](const boost::system::error_code& ec, size_t sz) noexcept {
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
    inline void                                                             close() noexcept {
        server::closesocket(socket_);
    }
    inline const std::shared_ptr<server_configuration>&                     get_configuration() const noexcept {
        return configuration_;
    }
    inline bool                                                             read(const BOOST_ASIO_MOVE_ARG(ReadAsyncCallback) callback) noexcept {
        if (!callback) {
            return false;
        }

        std::shared_ptr<ppp_tcp_channel> self = shared_from_this();
        ReadAsyncCallback callback_ = BOOST_ASIO_MOVE_CAST(ReadAsyncCallback)(constantof(callback));

        boost::asio::async_read(socket_, boost::asio::buffer(buffer_.get(), CTCP_TSS),
            [self, this, callback_](const boost::system::error_code& ec_, size_t sz_) noexcept {
                int transferred_length_ = std::max<int>(-1, ec_ ? -1 : sz_);
                if (transferred_length_ < 1) {
                    callback_(NULL, transferred_length_);
                    close();
                    return;
                }

                int outlen_;
                std::shared_ptr<Byte> payload_ = cipher_->Protocol->Decrypt(buffer_.get(), CTCP_TSS, outlen_);
                if (NULL == payload_) {
                    callback_(NULL, -1);
                    close();
                    return;
                }

                int length_ = transform_length(payload_.get(), outlen_);
                if (length_ < 1 || length_ > CTCP_MSS) {
                    callback_(NULL, -1);
                    close();
                    return;
                }

                boost::asio::async_read(socket_, boost::asio::buffer(buffer_.get(), length_),
                    [self, this, callback_](const boost::system::error_code& ec_, size_t sz_) noexcept {
                        int length_ = std::max<int>(-1, ec_ ? -1 : sz_);
                        if (length_ < 1) {
                            callback_(NULL, length_);
                            close();
                            return;
                        }

                        int outlen_;
                        std::shared_ptr<Byte> payload_ = cipher_->Transport->Decrypt(buffer_.get(), length_, outlen_);
                        if (NULL == payload_) {
                            callback_(NULL, -1);
                            close();
                            return;
                        }
                        callback_(payload_, outlen_);
                    });
            });
        return true;
    }

private:
    inline static int                                                       transform_length(const void* p, int l) noexcept {
        if (l > 2) {
            Byte* b = (Byte*)p;
            return b[0] << 16 | b[1] << 8 | b[2];
        }
        elif(l > 1) {
            Byte* b = (Byte*)p;
            return b[0] << 8 | b[1];
        }
        elif(l > 0) {
            return *(Byte*)p;
        }
        return 0;
    }

private:
    std::shared_ptr<Hosting>                                                hosting_;
    std::shared_ptr<boost::asio::ip::tcp::socket>                           socket_p_;
    boost::asio::ip::tcp::socket&                                           socket_;
    std::shared_ptr<PppVpnCipher>                                           cipher_;
    std::shared_ptr<Byte>                                                   buffer_;
    std::shared_ptr<server_configuration>                                   configuration_;
};