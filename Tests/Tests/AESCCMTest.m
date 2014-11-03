//
//  AESTest.m
//  TKCryptor
//
//  Created by Taras Kalapun on 11/3/14.
//  Copyright (c) 2014 Taras Kalapun. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <TKCryptor/TKCryptor.h>
#import <TKCryptor/TKAESCCMCryptor.h>

@interface AESCCMTest : XCTestCase

@end

@implementation AESCCMTest

static NSArray *testVectors = nil;

+ (void)initialize {
    
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"test_vectors" ofType:@"json"];
    NSData *data = [NSData dataWithContentsOfFile:path];

    NSError *error = nil;
    testVectors = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:&error];

    if (error) {
        NSLog(@"Error loading json data: %@", error.localizedDescription);
        return;
    }
    
    NSLog(@"Loaded test data: %i vectors", (int)testVectors.count);
}

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testSimple {
    NSDictionary *d = @{
                        @"data"   : @"616263313233343536",
                        @"cipher" : @"bfd034260bcb16b9f4 5f2f0689ebb43bc9",
                        @"key"  : @"546D2C7804AEC975A7AB66BCF7B4A3DFA86476CCC5EFC7062CD2E80471FD663E",
                        @"iv"   : @"547971D2272DFA601147C8C1",
                        };
    
    NSData *key     = [TKCryptor dataFromHex:d[@"key"]];
    NSData *iv      = [TKCryptor dataFromHex:d[@"iv"]];
    NSData *data    = [TKCryptor dataFromHex:d[@"data"]];
    NSData *cipher  = [TKCryptor dataFromHex:d[@"cipher"]];
    
    NSData *enc = [TKAESCCMCryptor encrypt:data withKey:key iv:iv];
    XCTAssertEqualObjects(enc, cipher);
}


- (void)testOneVector {
    NSDictionary *d = @{
                        @"data"   : @"0001020304050607 08090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
                        @"cipher" : @"0001020304050607 588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384 17E8D12CFDF926E0",
                        @"la"   : @(8),
                        @"key"  : @"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
                        @"iv"   : @"00000003020100A0A1A2A3A4A5",
                        };
    
    NSData *key     = [TKCryptor dataFromHex:d[@"key"]];
    NSData *iv      = [TKCryptor dataFromHex:d[@"iv"]];
    NSData *data    = [TKCryptor dataFromHex:d[@"data"]];
    NSData *cipher = [TKCryptor dataFromHex:d[@"cipher"]];
    size_t adataLength = [d[@"la"] intValue];
    
    NSData *plain = [data subdataWithRange:NSMakeRange(adataLength, data.length - adataLength)];
    NSData *adata = [data subdataWithRange:NSMakeRange(0, adataLength)];
    
    size_t tlen = cipher.length - data.length;
    
    NSData *enc = [TKAESCCMCryptor encrypt:plain withKey:key iv:iv tagLength:tlen adata:adata];
    XCTAssertEqualObjects(enc, cipher);
}

- (void)testAllVectors {
    
    for (NSDictionary *d in testVectors) {
        
        NSData *key     = [TKCryptor dataFromHex:d[@"key"]];
        NSData *iv      = [TKCryptor dataFromHex:d[@"iv"]];
        NSData *data    = [TKCryptor dataFromHex:d[@"data"]];
        NSData *cipher = [TKCryptor dataFromHex:d[@"cipher"]];
        size_t adataLength = [d[@"la"] intValue];
        
        NSData *plain = [data subdataWithRange:NSMakeRange(adataLength, data.length - adataLength)];
        NSData *adata = [data subdataWithRange:NSMakeRange(0, adataLength)];
        
        size_t tlen = cipher.length - data.length;
        
        NSData *enc = [TKAESCCMCryptor encrypt:plain withKey:key iv:iv tagLength:tlen adata:adata];
        XCTAssertEqualObjects(enc, cipher, @"Failed on testoing vector %@", d[@"id"]);
    }
    
    
}


@end
