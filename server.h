#pragma once

#include "env.h"

class Hosting;
class session;

std::shared_ptr<Hosting>&                                           server_hosting() noexcept;
int                                                                 server_random_r(unsigned int* seed) noexcept;
int                                                                 server_random(int min, int max) noexcept;
int                                                                 server_random_ascii() noexcept;
inline Byte                                                         server_random_byte() noexcept {
    return server_random(0x00, 0x100);
}
inline int                                                          server_random() noexcept {
    return server_random(0, -1 ^ -1 << 31); 
}
UInt64                                                              server_now() noexcept;
int                                                                 server_get_cpu_platform() noexcept;
const char*                                                         server_get_default_cipher_suites() noexcept;

inline std::string                                                  server_to_string(uint32_t address, uint16_t port) noexcept {
    char sz[128];
    uint8_t* p = (uint8_t*)&address;
    sprintf(sz, "%d.%d.%d.%d:%d", p[0], p[1], p[2], p[3], port);
    return sz;
}

template<class TProtocol>
inline std::string                                                  server_to_string(const boost::asio::ip::basic_endpoint<TProtocol>& endpoint) noexcept {
    std::string address = endpoint.address().to_string();
    std::string port = std::to_string(endpoint.port());
    return address + ":" + port;
}

class server_configuration final {
public:
    struct {
        struct {
            bool                                                    lan;
            bool                                                    wan;
        }                                                           turbo;
        int                                                         alignment;
        int                                                         backlog;
        bool                                                        fast_open;
        struct {
            int                                                     timeout;
        }                                                           connect;
        std::shared_ptr<std::string>                                server;
    } tcp;
    struct {
        int                                                         kf;
        std::shared_ptr<std::string>                                protocol;
        std::shared_ptr<std::string>                                protocol_key;
        std::shared_ptr<std::string>                                transport;
        std::shared_ptr<std::string>                                transport_key;
    } key;

public:
    inline server_configuration() noexcept {
        clear();
    }

public:
    inline void                                                     clear() noexcept {
        tcp.turbo.lan = false;
        tcp.turbo.wan = false;
        tcp.alignment = 65536;
        tcp.fast_open = true;
        tcp.backlog = 65535;
        tcp.connect.timeout = 5;
        tcp.server = make_shared_object<std::string>("127.0.0.1:20000");

        key.kf = 0;
        key.protocol = make_shared_object<std::string>("rc4-sha1");
        key.protocol_key = make_shared_object<std::string>("123");
        key.transport = make_shared_object<std::string>("aes-256-cfb");
        key.transport_key = make_shared_object<std::string>("123");
    }
};

class server final : public std::enable_shared_from_this<server> {
public:
    typedef std::shared_ptr<server>                                 Ptr;
    typedef std::mutex                                              Mutex;
    typedef std::lock_guard<Mutex>                                  MutexScope;

public:
    inline server(const std::shared_ptr<Hosting>& hosting, const std::shared_ptr<server_configuration>& configuration) noexcept
        : hosting_(hosting)
        , configuration_(configuration) {

    }

public:
    inline Ptr                                                      GetPtr() noexcept {
        return shared_from_this();
    }
    inline const std::shared_ptr<Hosting>&                          GetHosting() const noexcept {
        return hosting_;
    }
    inline const std::shared_ptr<server_configuration>&             GetConfiguration() const noexcept {
        return configuration_;
    }
    inline const boost::asio::ip::tcp::endpoint&                    GetLocalEndPoint() const noexcept {
        return localEP_;
    }

public:
    bool                                                            Run() noexcept;
    inline static bool                                              SetTypeOfService(int fd, int tos = ~0) noexcept {
        if (fd == -1) {
            return false;
        }

        if (tos < 0) {
            tos = 0x68; // FLASH
        }

        Byte b = tos;
        return ::setsockopt(fd, SOL_IP, IP_TOS, (char*)&b, sizeof(b)) == 0;
    }
    inline static bool                                              SetSignalPipeline(int fd, bool sigpipe) noexcept {
        if (fd == -1) {
            return false;
        }

        int err = 0;
#ifdef SO_NOSIGPIPE
        int opt = sigpipe ? 0 : 1;
        err = ::setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, (char*)&opt, sizeof(opt));
#endif
        return err == 0;
    }
    inline static bool                                              SetDontFragment(int fd, bool dontFragment) noexcept {
        if (fd == -1) {
            return false;
        }

        int err = 0;
#ifdef _WIN32 
        int val = dontFragment ? 1 : 0;
        err = ::setsockopt(fd, IPPROTO_IP, IP_DONTFRAGMENT, (char*)&val, sizeof(val));
#elif IP_MTU_DISCOVER
        int val = dontFragment ? IP_PMTUDISC_DO : IP_PMTUDISC_WANT;
        err = ::setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, (char*)&val, sizeof(val));
#endif
        return err == 0;
    }
    inline static bool                                              ReuseSocketAddress(int fd, bool reuse) noexcept {
        if (fd == -1) {
            return false;
        }
        int flag = reuse ? 1 : 0;
        return ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag)) == 0;
    }

public:
    static void                                                     setsockopt(int sockfd, bool v4_or_v6) noexcept;
    static void                                                     closesocket(boost::asio::ip::tcp::socket& s) noexcept;
    static void                                                     closesocket(boost::asio::ip::tcp::acceptor& s) noexcept;

private:
    bool                                                            AcceptSocket() noexcept;
    bool                                                            AcceptSocket(const std::shared_ptr<boost::asio::io_context>& context_, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket_) noexcept;
    bool                                                            OpenAcceptor() noexcept;

private:
    Mutex                                                           lockobj_;
    std::shared_ptr<Hosting>                                        hosting_;
    std::shared_ptr<server_configuration>                           configuration_;
    std::shared_ptr<boost::asio::ip::tcp::acceptor>                 acceptor_;
    boost::asio::ip::tcp::endpoint                                  localEP_;
};