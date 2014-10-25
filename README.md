# TKCryptor

## Usage

``` obj-c
// generate a unique AES key and (later) encrypt it with the public RSA key of the merchant
NSMutableData *key = [NSMutableData dataWithLength:kCCKeySizeAES256];
SecRandomCopyBytes(NULL, kCCKeySizeAES256, key.mutableBytes);

// generate a nonce
NSMutableData *iv = [NSMutableData dataWithLength:12];
SecRandomCopyBytes(NULL, 12, iv.mutableBytes);

NSData *cipherText = [TKAESCCMCryptor encrypt:data withKey:key iv:iv];

NSData *encryptedKey = [TKRSACryptor encrypt:key withKeyInHex:keyInHex];

```

Note:
* AES 256 key
* no additional auth data
* tagLength = 8
* ivLength = 12
* L = 3
* RSA stores certificate to Keychain by fingerprint (SHA1)

## Installation

TKCryptor is available through [CocoaPods](http://cocoapods.org). To install
it, simply add the following line to your Podfile:

``` ruby
pod "TKCryptor", :git => "https://github.com/xslim/TKCryptor.git"
```

## Author

* Taras Kalapun, t.kalapun@gmail.com
* Some code from [tinydtls](https://github.com/cetic/tinydtls/)
* Some code from [iphonelib](https://github.com/meinside/iphonelib)

## License

TKCryptor is available under the MIT license. See the LICENSE file for more info.

