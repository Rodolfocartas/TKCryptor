//
//  TKAESCCMCryptor.h
//
//  Created by Taras Kalapun on 10/25/14.
//

#import <Foundation/Foundation.h>

@interface TKAESCCMCryptor : NSObject

+ (NSData *)encrypt:(NSData *)data withKey:(NSData *)key iv:(NSData *)iv;

@end
