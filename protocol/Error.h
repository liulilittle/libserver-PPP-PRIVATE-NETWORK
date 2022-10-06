#pragma once

enum Error {
    Success,                                                            // �ɹ�
    ReceiveIsDisconnectedOrTimeout,                                     // ���ճ�ʱ���߶Ͽ�����
    ProvideTheKeysFrameIsIllegal,                                       // �ṩ�ؼ�֡��Ч
    TheAddressLengthOfIPv4IsIncorrect,                                  // IPv4��ַ�س�����Ч
    UnableToDecryptEncryptedBinaryData,                                 // �޷����ܼ��ܵĶ���������
    DomainNameAddressLengthNotAllowLessOrEqualsZero,                    // ������ַ���Ȳ�����С�ڻ����0
    DomainNameWithFullBlankOrEmptyStringAreNotAllowed,                  // �������ṩȫ�հ׻��߿��ַ���������
    DomainNameResolutionFailed,                                         // ��������ʱ�����˹���
    ResolvedDnsSuccessfullyButNoAnyIPAddressWasFound,                   // ���������ɹ������Ҳ����κ�IP��ַ
    AddressTypeIsNotSupported,                                          // ��ַ���Ͳ�֧��
    DestinationServerAddressIsNotAllowedToBeAnyAddress,                 // Ŀ�ķ�������ַ������Ϊ�κε�ַ(0.0.0.0)
    PortsAreNotAllowedToBeLessThanOrEqualTo0OrGreaterThan65535,         // �˿ڲ�����С�ڻ����0���ߴ���65535
    UnableToCreateServerSocket,                                         // �޷������������׽��ֶ���
    UnableToInitiateConnectEstablishmentWithTheServer,                  // �޷������������֮������ӽ���
    ManagedAndUnmanagedResourcesHeldbyObjectHaveBeenReleased,           // ������е��й�����й���Դ�ѱ��ͷ�
    EstablishConnectTimeoutWithTheRemoteServer,                         // ��Զ�̷�����֮�佨�����ӳ�ʱ
    ProblemOccurredWhileTheSynchronizationObjectWasWaitingForSignal,    // ͬ�������ڵȴ��ź�ʱ����������
    UnableToReadBytesNetworkStream,                                     // �޷����������ֽ���
    ProtocolTypeIsNotSupported,                                         // Э�����Ͳ�֧��
    NoneTypeHeaderNotLessThanTwoBytes,                                  // None����ͷ��С�������ֽ�
    UnalbeToAllocateDatagramPort,                                       // �޷��������ݱ��˿�
    ReferencesEndPointIsNullReferences,                                 // ���õĵ�ַ�˵��ǿ�����
    UnhandledExceptions,                                                // δ�����쳣
    TimeoutSafeWaitHandleIsCloseOrIsInvalid,                            // ��ʱ��ȫ�ȴ�����Ѿ��رջ�����Ч
    DenyAccessToTheServerFirewallRulesRestrictResources,                // ��ֹ���ʷ���������ǽ����������Դ
};