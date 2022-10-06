#pragma once

enum Error {
    Success,                                                            // 成功
    ReceiveIsDisconnectedOrTimeout,                                     // 接收超时或者断开链接
    ProvideTheKeysFrameIsIllegal,                                       // 提供关键帧无效
    TheAddressLengthOfIPv4IsIncorrect,                                  // IPv4地址簇长度无效
    UnableToDecryptEncryptedBinaryData,                                 // 无法解密加密的二进制数据
    DomainNameAddressLengthNotAllowLessOrEqualsZero,                    // 域名地址长度不允许小于或等于0
    DomainNameWithFullBlankOrEmptyStringAreNotAllowed,                  // 不允许提供全空白或者空字符串的域名
    DomainNameResolutionFailed,                                         // 解析域名时发生了故障
    ResolvedDnsSuccessfullyButNoAnyIPAddressWasFound,                   // 解析域名成功但是找不到任何IP地址
    AddressTypeIsNotSupported,                                          // 地址类型不支持
    DestinationServerAddressIsNotAllowedToBeAnyAddress,                 // 目的服务器地址不允许为任何地址(0.0.0.0)
    PortsAreNotAllowedToBeLessThanOrEqualTo0OrGreaterThan65535,         // 端口不允许小于或等于0或者大于65535
    UnableToCreateServerSocket,                                         // 无法创建服务器套接字对象
    UnableToInitiateConnectEstablishmentWithTheServer,                  // 无法发起与服务器之间的链接建立
    ManagedAndUnmanagedResourcesHeldbyObjectHaveBeenReleased,           // 对象持有的托管与非托管资源已被释放
    EstablishConnectTimeoutWithTheRemoteServer,                         // 与远程服务器之间建立链接超时
    ProblemOccurredWhileTheSynchronizationObjectWasWaitingForSignal,    // 同步对象在等待信号时发生了问题
    UnableToReadBytesNetworkStream,                                     // 无法读入网络字节流
    ProtocolTypeIsNotSupported,                                         // 协议类型不支持
    NoneTypeHeaderNotLessThanTwoBytes,                                  // None类型头不小于两个字节
    UnalbeToAllocateDatagramPort,                                       // 无法分配数据报端口
    ReferencesEndPointIsNullReferences,                                 // 引用的地址端点是空引用
    UnhandledExceptions,                                                // 未处理异常
    TimeoutSafeWaitHandleIsCloseOrIsInvalid,                            // 超时安全等待句柄已经关闭或者无效
    DenyAccessToTheServerFirewallRulesRestrictResources,                // 禁止访问服务器防火墙规则限制资源
};