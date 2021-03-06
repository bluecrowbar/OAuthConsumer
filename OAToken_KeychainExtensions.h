//
//  OAToken_KeychainExtensions.h
//  TouchTheFireEagle
//
//  Created by Jonathan Wight on 04/04/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import "OAToken.h"

#import <Security/Security.h>

@interface OAToken (OAToken_KeychainExtensions)

#if TARGET_OS_IPHONE

- (id)initWithKeychainUsingAppName:(NSString *)name serviceProviderName:(NSString *)provider;
- (OSStatus)storeInDefaultKeychainWithAppName:(NSString *)name serviceProviderName:(NSString *)provider;
- (OSStatus)deleteFromDefaultKeychainWithAppName:(NSString *)name serviceProviderName:(NSString *)provider;

#else

- (id)initWithKeychainUsingAppName:(NSString *)name serviceProviderName:(NSString *)provider;
- (OSStatus)storeInDefaultKeychainWithAppName:(NSString *)name serviceProviderName:(NSString *)provider;
- (OSStatus)storeInKeychain:(SecKeychainRef)keychain appName:(NSString *)name serviceProviderName:(NSString *)provider;

#endif

@end
