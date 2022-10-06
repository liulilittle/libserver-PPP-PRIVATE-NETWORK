#include "env.h"
#include "server.h"
#include "session.h"
#include "Hosting.h"
#include "./packet/IPEndPoint.h"

static std::shared_ptr<Hosting> hosting_;

UInt64 server_now() noexcept {
    return hosting_ ? hosting_->CurrentMillisec() : UINT64_MAX;
}

int server_random_r(unsigned int* seed) noexcept {
    unsigned int next = *seed;
    int result;

    next *= 1103515245;
    next += 12345;
    result = (unsigned int)(next / 65536) % 2048;

    next *= 1103515245;
    next += 12345;
    result <<= 10;
    result ^= (unsigned int)(next / 65536) % 1024;

    next *= 1103515245;
    next += 12345;
    result <<= 10;
    result ^= (unsigned int)(next / 65536) % 1024;

    *seed = next;
    return result;
}

int server_random(int min, int max) noexcept {
    static unsigned int seed = time(NULL);

    int v = server_random_r(&seed);
    return v % (max - min + 1) + min;
}

int server_random_ascii() noexcept {
    static Byte x_[] = { 'a', 'A', '0' };
    static Byte y_[] = { 'z', 'Z', '9' };

    int i_ = server_random() % 3;
    return server_random(x_[i_], y_[i_]);
}

std::shared_ptr<Hosting>& server_hosting() noexcept {
    return hosting_;
}

bool server::Run() noexcept {
    std::shared_ptr<boost::asio::io_context> context_;
    std::shared_ptr<boost::asio::io_context> previous_;
    do {
        std::shared_ptr<server_configuration> configuration_ = GetConfiguration();
        if (!configuration_) {
            return false;
        }

        std::shared_ptr<Hosting> hosting_ = server_hosting();
        if (!hosting_) {
            return false;
        }

        MutexScope scope(lockobj_);
        context_ = make_shared_object<boost::asio::io_context>();
        if (!context_) {
            return false;
        }

        previous_ = hosting_->ExchangeDefault(context_);
        if (!hosting_->OpenTimeout()) {
            return false;
        }

        if (!OpenAcceptor()) {
            return false;
        }
    } while (0);
    boost::system::error_code ec_;
    boost::asio::io_context::work work_(*context_);
    context_->run(ec_);
    hosting_->CompareExchangeDefault(previous_, context_);
    return true;
}

bool server::OpenAcceptor() noexcept {
    std::shared_ptr<boost::asio::io_context> context_ = hosting_->GetDefault();
    if (!context_) {
        return false;
    }

    std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor = acceptor_;
    if (acceptor) {
        return false;
    }

    acceptor = make_shared_object<boost::asio::ip::tcp::acceptor>(*context_);
    if (!acceptor) {
        return false;
    }

    boost::system::error_code ec_;
    acceptor->open(boost::asio::ip::tcp::v6(), ec_);
    if (ec_) {
        return false;
    }

    std::shared_ptr<server_configuration> configuration_ = GetConfiguration();
    if (configuration_->tcp.fast_open) {
        acceptor->set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec_);
    }

    if (configuration_->tcp.turbo.lan) {
        acceptor->set_option(boost::asio::ip::tcp::no_delay(true), ec_);
    }

    int handle_ = acceptor->native_handle();
    server::setsockopt(handle_, false);
    server::SetTypeOfService(handle_);
    server::SetSignalPipeline(handle_, false);
    server::SetDontFragment(handle_, false);
    server::ReuseSocketAddress(handle_, true);

    acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec_);
    if (ec_) {
        return false;
    }

    boost::asio::ip::address_v6 address_ = boost::asio::ip::address_v6::loopback();
    acceptor->bind(boost::asio::ip::tcp::endpoint(address_, IPEndPoint::MinPort), ec_);
    if (ec_) {
        return false;
    }

    localEP_ = acceptor->local_endpoint(ec_);
    if (ec_) {
        return false;
    }

    acceptor->listen(configuration_->tcp.backlog, ec_);
    if (ec_) {
        return false;
    }
    return AcceptSocket();
}

bool server::AcceptSocket() noexcept {
    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptor_;
    if (!acceptor || !acceptor->is_open()) {
        return false;
    }

    std::shared_ptr<server> server_ = GetPtr();
    std::shared_ptr<boost::asio::io_context> context_ = hosting_->GetContext();
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_ = make_shared_object<boost::asio::ip::tcp::socket>(*context_);
    acceptor->async_accept(*socket_,
        [server_, this, context_, socket_](boost::system::error_code ec_) noexcept {
            // The operation has been canceled abort the server.
            if (ec_ == boost::system::errc::operation_canceled) {
                assert(ec_ == boost::system::errc::success);
                abort();
                return;
            }

            bool success = false;
            do { /* boost::system::errc::connection_aborted */
                if (ec_) { /* ECONNABORTED */
                    break;
                }

                int handle_ = socket_->native_handle();
                server::setsockopt(handle_, false);
                server::SetTypeOfService(handle_);
                server::SetSignalPipeline(handle_, false);
                server::SetDontFragment(handle_, false);
                server::ReuseSocketAddress(handle_, true);

                std::shared_ptr<server_configuration> configuration_ = GetConfiguration();
                if (configuration_->tcp.turbo.lan) {
                    socket_->set_option(boost::asio::ip::tcp::no_delay(true), ec_);
                    if (ec_) {
                        break;
                    }
                }

                success = AcceptSocket(context_, socket_);
            } while (0);
            if (!success) {
                socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec_);
                socket_->close(ec_);
            }
            AcceptSocket();
        });
    return true;
}

bool server::AcceptSocket(const std::shared_ptr<boost::asio::io_context>& context_, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket_) noexcept {
    std::shared_ptr<server> server_ = GetPtr();
    std::shared_ptr<session> session_ = make_shared_object<session>(server_, context_, socket_, false);
    return session_->Handshake();
}

void server::closesocket(boost::asio::ip::tcp::acceptor& s) noexcept {
    if (s.is_open()) {
        boost::system::error_code ec;
        s.close(ec);
    }
}

void server::closesocket(boost::asio::ip::tcp::socket& s) noexcept {
    if (s.is_open()) {
        boost::system::error_code ec;
        s.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        s.close(ec);
    }
}

void server::setsockopt(int sockfd, bool v4_or_v6) noexcept {
    if (sockfd != -1) {
        uint8_t tos = 0x68;
        if (v4_or_v6) {
            ::setsockopt(sockfd, SOL_IP, IP_TOS, (char*)&tos, sizeof(tos));

#ifdef _WIN32
            int dont_frag = 0;
            ::setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAGMENT, (char*)&dont_frag, sizeof(dont_frag));
#elif IP_MTU_DISCOVER
            int dont_frag = IP_PMTUDISC_WANT;
            ::setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &dont_frag, sizeof(dont_frag));
#endif
        }
        else {
            ::setsockopt(sockfd, SOL_IPV6, IP_TOS, (char*)&tos, sizeof(tos));

#ifdef _WIN32
            int dont_frag = 0;
            ::setsockopt(sockfd, IPPROTO_IPV6, IP_DONTFRAGMENT, (char*)&dont_frag, sizeof(dont_frag));
#elif IPV6_MTU_DISCOVER
            int dont_frag = IPV6_PMTUDISC_WANT;
            ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &dont_frag, sizeof(dont_frag));
#endif
        }
#ifdef SO_NOSIGPIPE
        int no_sigpipe = 1;
        ::setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
#endif
    }
}

int server_get_cpu_platform() noexcept {
#ifdef __i386__
    return 1;
#elif __x86_64__
    return 2;
#elif __arm__
    return 3;
#elif __ARM_ARCH_5T__
    return 3;
#elif __ARM_ARCH_7A__
    return 3;
#elif __aarch64__
    return 4;
#elif __powerpc64__
    return 4;
#else
    return sizeof(void*) == 8 ? 2 : 1;
#endif
}

const char* server_get_default_cipher_suites() noexcept {
    int cpu_platfrom = server_get_cpu_platform();
    if (cpu_platfrom == 3) {
        return "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
    }
    return "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
}