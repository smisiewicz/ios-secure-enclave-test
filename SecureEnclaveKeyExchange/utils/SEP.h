//
//  SEP.h
//  SecureEnclaveKeyExchange
//
//  Created by Bastek on 11/4/19.
//

#import <Foundation/Foundation.h>

@import Security;


BOOL SEPGenerateKeyPair(SecKeyRef _Nonnull * _Nullable privateKeyRef,
                        SecKeyRef _Nonnull * _Nullable publicKeyRef,
                        CFErrorRef _Nullable * _Nullable error);

BOOL SEPCreatePublicKeyRefFromBase64String(NSString * _Nonnull base64Key,
                                           SecKeyRef _Nullable * _Nullable publicKeyRef);



NS_ASSUME_NONNULL_BEGIN

@interface SEP : NSObject

+ (NSString * _Nullable)base64EncodedPublicKey:(SecKeyRef)publicKeyRef;

+ (NSDictionary * _Nullable)attributesFromPublicKey:(SecKeyRef)publicKeyRef;

+ (NSString * _Nullable)encrypt:(NSString* _Nonnull)message
                           with:(SecKeyRef)publicKeyRef;

+ (NSString * _Nullable)decrypt:(NSString* _Nonnull)message
                           with:(SecKeyRef)privateKeyRef;
@end

NS_ASSUME_NONNULL_END
