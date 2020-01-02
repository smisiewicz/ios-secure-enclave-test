//
//  SEP.m
//  SecureEnclaveKeyExchange
//
//  Created by Bastek on 11/4/19.
//

#import "SEP.h"


BOOL SEPGenerateKeyPair(SecKeyRef *privateKeyRef,
                        SecKeyRef *publicKeyRef,
                        CFErrorRef *error)
{
    SecAccessControlRef access =
    SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                    (kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet),
                                    error);

    if (!access) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"Error when setting up SecAccessControlRef: %@", err.localizedDescription);
        return NO;
    }

    NSDictionary *attributes =
    @{
      (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
      (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
      (id)kSecAttrKeySizeInBits: @(256), // secure enclave *ONLY* support 256 elliptic (secp256r1)
      (id)kSecPrivateKeyAttrs:
          @{ (id)kSecAttrIsPermanent:    @(YES),
             (id)kSecAttrApplicationTag: @"identity",
             (id)kSecAttrAccessControl:  (__bridge id)access}
      };

    if (access) { CFRelease(access); }

    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, error);
    if (!privateKey) { return NO; }

    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);




    SecKeyRef p11 = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, error);
    SecKeyRef p12 = SecKeyCopyPublicKey(p11);

    SecKeyRef p21 = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, error);
    SecKeyRef p22 = SecKeyCopyPublicKey(p21);

    SecKeyRef p31 = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, error);
    SecKeyRef p32 = SecKeyCopyPublicKey(p31);

    NSDictionary *d = @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
//        (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
        (id)kSecKeyKeyExchangeParameterRequestedSize: @(32),
        (id)kSecAttrKeySizeInBits: @(256),
    };
    CFDictionaryRef dRef = (__bridge CFDictionaryRef)d;
    SecKeyAlgorithm a = kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256;
    CFErrorRef e = NULL;
    CFDataRef d1 = SecKeyCopyKeyExchangeResult(p11, a, p22, dRef, &e);
    NSData *dd1 = (__bridge_transfer NSData*) d1;
    NSLog(@">>>>>>>>>>> D1: %@", [dd1 base64EncodedStringWithOptions:(NSDataBase64Encoding64CharacterLineLength | NSDataBase64EncodingEndLineWithCarriageReturn)]);

    CFDataRef d2 = SecKeyCopyKeyExchangeResult(p21, a, p12, dRef, &e);
    NSData *dd2 = (__bridge_transfer NSData*) d2;
    NSLog(@">>>>>>>>>>> D2: %@", [dd2 base64EncodedStringWithOptions:(NSDataBase64Encoding64CharacterLineLength | NSDataBase64EncodingEndLineWithCarriageReturn)]);

    CFDataRef d3 = SecKeyCopyKeyExchangeResult(p31, a, p12, dRef, &e);
    NSData *dd3 = (__bridge_transfer NSData*) d3;
    NSLog(@">>>>>>>>>>> D3: %@", [dd3 base64EncodedStringWithOptions:(NSDataBase64Encoding64CharacterLineLength | NSDataBase64EncodingEndLineWithCarriageReturn)]);




    CFErrorRef errorRef = NULL;
    CFDataRef privateKeyDataRef = SecKeyCopyExternalRepresentation(publicKey, &errorRef);
    if (!privateKeyDataRef) {
        NSError *err = CFBridgingRelease(errorRef);
        NSLog(@"Error when generating random key: %@", err.localizedDescription);
    }


    *privateKeyRef = privateKey;
    *publicKeyRef = publicKey;
    return YES;
}


BOOL SEPCreatePublicKeyRefFromBase64String(NSString * _Nonnull base64Key,
                                           SecKeyRef _Nullable * _Nullable publicKeyRef)
{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:base64Key
                                                       options:(
                                                                NSDataBase64Encoding64CharacterLineLength |
                                                                NSDataBase64EncodingEndLineWithCarriageReturn)];

    // mandatory attributes:
    NSDictionary *attributes = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
                                 (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic};
    
    CFDataRef dataRef = (__bridge CFDataRef)data;
    CFDictionaryRef attrRef = (__bridge CFDictionaryRef)attributes;
    if (!dataRef || !attrRef) {
        NSLog(@"Error when creating Public Key: data or attributes failed to parse.");
        return NO;
    }
    
    CFErrorRef error = NULL;
    SecKeyRef publicKey = SecKeyCreateWithData(dataRef, attrRef, &error);
    if (!publicKey) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"Error when creating Public Key from data: %@", err.localizedDescription);
        return NO;
    }

    *publicKeyRef = publicKey;
    return YES;
}


@implementation SEP

+ (NSString * _Nullable)base64EncodedPublicKey:(SecKeyRef)publicKeyRef {
    CFErrorRef error = NULL;
    CFDataRef dataRef = SecKeyCopyExternalRepresentation(publicKeyRef, &error);
    if (!dataRef) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"Error when extracting public key data: %@", err.localizedDescription);
        return nil;
    }
    NSData *data = (__bridge_transfer NSData*) dataRef;


    // DER format - FIXME<SEB>: (to standardize cross-platform.... hopefully):
    uint8_t header[] = {
        /* sequence          */ 0x30, 0x59,
        /* |-> sequence      */ 0x30, 0x13,
        /* |---> ecPublicKey */ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // http://oid-info.com/get/1.2.840.10045.2.1 (ANSI X9.62 public key type)
        /* |---> prime256v1  */ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, // http://oid-info.com/get/1.2.840.10045.3.1.7 (ANSI X9.62 named elliptic curve)
        /* |-> bit headers   */ 0x07, 0x03, 0x42, 0x00
    };
    NSMutableData *derData = [NSMutableData new];
    [derData appendBytes:header length:sizeof(header)];
    [derData appendData:data];

    NSString *DER = [derData base64EncodedStringWithOptions:(NSDataBase64Encoding64CharacterLineLength | NSDataBase64EncodingEndLineWithCarriageReturn)];
    NSLog(@"\n>>>>>>>>>> DER:\n%@\n\n", DER);
    NSString *PEM = [NSString stringWithFormat:@"-----BEGIN PUBLIC KEY-----\n%@\n-----END PUBLIC KEY-----", DER];
    NSLog(@"\n>>>>>>>>>> PEM:\n%@\n\n", PEM);



    return [data base64EncodedStringWithOptions:
            (NSDataBase64Encoding64CharacterLineLength | NSDataBase64EncodingEndLineWithCarriageReturn)];
}


+ (NSDictionary * _Nullable)attributesFromPublicKey:(SecKeyRef)publicKeyRef {
    CFDictionaryRef dictRef = SecKeyCopyAttributes(publicKeyRef);
    if (dictRef) {
        NSDictionary *attributes = (__bridge_transfer NSDictionary*)dictRef;
        return attributes;
    }

    return nil;
}


//case sha256
//SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
//SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA256AESGCM
+ (NSString * _Nullable)encrypt:(NSString* _Nonnull)message
                           with:(SecKeyRef)publicKeyRef
{
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];

    CFErrorRef error = NULL;
    CFDataRef dataRef = (__bridge CFDataRef)data;

    // Scure Enclave only supports 256
    CFDataRef resultRef =
    SecKeyCreateEncryptedData(publicKeyRef,
                              kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
                              dataRef,
                              &error);

    if (!resultRef) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"Error when encrypting data: %@", err.localizedDescription);
        return nil;
    }

    NSData *result = (__bridge_transfer NSData*) resultRef;
    return [result base64EncodedStringWithOptions:(NSDataBase64Encoding64CharacterLineLength | NSDataBase64EncodingEndLineWithCarriageReturn)];
}


+ (NSString * _Nullable)decrypt:(NSString* _Nonnull)message
                           with:(SecKeyRef)privateKeyRef
{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:message options:(NSDataBase64Encoding64CharacterLineLength | NSDataBase64EncodingEndLineWithCarriageReturn)];

    CFErrorRef error = NULL;
    CFDataRef dataRef = (__bridge CFDataRef)data;

    CFDataRef resultRef =
    SecKeyCreateDecryptedData(privateKeyRef,
                              kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
                              dataRef,
                              &error);

    if (!resultRef) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"Error when decrypting data: %@", err.localizedDescription);
        return nil;
    }

    NSData *result = (__bridge_transfer NSData*) resultRef;
    return [[NSString alloc] initWithData:result
                                 encoding:NSUTF8StringEncoding];
}

@end
