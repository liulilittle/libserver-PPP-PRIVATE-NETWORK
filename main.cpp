#include "env.h"
#include "server.h"
#include "Hosting.h"
#include "./json/json.h"
#include "./packet/IPEndPoint.h"
#include "./protocol/PppVpnProtocol.h"

class ___SERVER___ final {
public:
    inline std::shared_ptr<server>&                             get() noexcept {
        return server_;
    }
    inline std::shared_ptr<server_configuration>&               get_configuration() noexcept {
        return const_cast<std::shared_ptr<server_configuration>&>(get()->GetConfiguration());
    }
    inline std::shared_ptr<server_configuration>                set_configuration(std::shared_ptr<server_configuration> configuration_) noexcept {
        if (configuration_) {
            std::shared_ptr<server_configuration>& current_ = get_configuration();
            std::shared_ptr<server_configuration> result_ = current_;
            current_ = configuration_;
            return result_;
        }
        return get_configuration();
    }
    inline int                                                  get_loopback_port() noexcept {
        const std::shared_ptr<server>& server = get();
        const boost::asio::ip::tcp::endpoint& localEP = server->GetLocalEndPoint();

        int localPort = localEP.port();
        if (localPort < IPEndPoint::MinPort || localPort > IPEndPoint::MaxPort) {
            localPort = IPEndPoint::MinPort;
        }
        return localPort;
    }

public:
    inline std::shared_ptr<server>&                             init() noexcept {
        server_ = make_shared_object<server>(server_hosting(), make_shared_object<server_configuration>());
        do {
            const auto dowork_ = [this] {
                SetThreadPriorityToMaxLevel();

                server_->Run();
            };
            std::thread(dowork_).detach();
        } while (0);
        return server_;
    }

private:
    std::shared_ptr<server>                                     server_;
} server_;

#ifndef LIBSERVER_API
#ifdef __cplusplus 
#define LIBSERVER_API extern "C" __declspec(dllexport)
#else
#define LIBSERVER_API extern
#endif
#endif

LIBSERVER_API void
libserver_init() noexcept {
    std::shared_ptr<Hosting>& hosting_ = server_hosting();
    if (!hosting_) {
        hosting_ = make_shared_object<Hosting>(Hosting::GetMaxConcurrency());
        hosting_->Run();
    }
    server_.init();
    while (!server_.get_loopback_port()) {
        Sleep(1);
    }
}

LIBSERVER_API int
libserver_loopback_get_port() noexcept {
    return server_.get_loopback_port();
}

LIBSERVER_API bool
libserver_loopback_set_configuration(
    const char* server,
    int alignment,
    int kf,
    const char* protocol,
    const char* protocol_key,
    const char* transport,
    const char* transport_key) noexcept {
    // TCP/IP
    const int MAX_ALIGNMENT = -1 ^ -1 << 24;
    const int MIN_ALIGNMENT = -1 ^ -1 << 8;
    if (alignment <= MIN_ALIGNMENT || alignment > MAX_ALIGNMENT) {
        return false;
    }

    // 检查用户配置文件参数设置的合法性
    if (kf < 0x00 || kf > 0xff) {
        return false;
    }

    std::string server_;
    std::string protocol_;
    std::string protocol_key_;
    std::string transport_;
    std::string transport_key_;
    if (server) {
        server_ = server;
    }
    if (protocol) {
        protocol_ = protocol;
    }
    if (protocol_key) {
        protocol_key_ = protocol_key;
    }
    if (transport) {
        transport_ = transport;
    }
    if (transport_key) {
        transport_key_ = transport_key;
    }

    if (server_.empty() ||
        protocol_.empty() ||
        protocol_key_.empty() ||
        transport_.empty() ||
        transport_key_.empty()) {
        return false;
    }
    try {
        Cipher::Create(protocol_, protocol_key_);
    }
    catch (std::exception&) {
        return false;
    }
    try {
        Cipher::Create(transport_, transport_key_);
    }
    catch (std::exception&) {
        return false;
    }

    std::shared_ptr<server_configuration>& configuration_ = ::server_.get_configuration();
    configuration_->key.kf = kf;
    configuration_->tcp.alignment = alignment;
    configuration_->tcp.server = make_shared_object<std::string>(server_);
    configuration_->key.protocol = make_shared_object<std::string>(protocol_);
    configuration_->key.protocol_key = make_shared_object<std::string>(protocol_key_);
    configuration_->key.transport = make_shared_object<std::string>(transport_);
    configuration_->key.transport_key = make_shared_object<std::string>(transport_key_);
    return true;
}

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable: 5043)
extern void* operator new(size_t _Size) throw() {
    return Malloc(_Size);
}

extern void operator delete(void* _Block) throw() {
    Mfree(_Block);
}

extern void operator delete(void* _Block, size_t _Size) throw() {
    Mfree(_Block);
}

extern void* operator new[](size_t _Size) throw() {
    return Malloc(_Size);
}

extern void operator delete[](void* _Block, size_t _Size) throw() {
    Mfree(_Block);
}
#pragma warning(pop)
#endif