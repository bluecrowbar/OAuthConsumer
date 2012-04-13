//
//  OAToken_KeychainExtensions.m
//  TouchTheFireEagle
//
//  Created by Jonathan Wight on 04/04/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import "OAToken_KeychainExtensions.h"

@implementation OAToken (OAToken_KeychainExtensions)

#if TARGET_OS_IPHONE

- (id)initWithKeychainUsingAppName:(NSString *)name serviceProviderName:(NSString *)provider 
{
    [super init];
	
	NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
	[attributes setValue:(id)kSecClassGenericPassword forKey:(id)kSecClass];
	[attributes setValue:[NSString stringWithFormat:@"%@::OAuth::%@", name, provider] forKey:(id)kSecAttrService];
	[attributes setValue:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnAttributes];
	[attributes setValue:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
	
	NSMutableDictionary *outDictionary = nil;
	OSStatus status = noErr;
	status = SecItemCopyMatching((CFDictionaryRef)attributes, (CFTypeRef *)&outDictionary);
	if (status != noErr) {
		return nil;
	}
	
	self.key = [outDictionary valueForKey:kSecAttrAccount];
	self.secret = [[NSString alloc] initWithData:[outDictionary valueForKey:kSecValueData] encoding:NSUTF8StringEncoding];
    return self;
}


- (OSStatus)storeInDefaultKeychainWithAppName:(NSString *)name serviceProviderName:(NSString *)provider 
{
	NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
	[attributes setValue:(id)kSecClassGenericPassword forKey:(id)kSecClass];
	[attributes setValue:[NSString stringWithFormat:@"%@::OAuth::%@", name, provider] forKey:(id)kSecAttrService];
	[attributes setValue:self.key forKey:(id)kSecAttrAccount];
	[attributes setValue:[self.secret dataUsingEncoding:NSUTF8StringEncoding] forKey:(id)kSecValueData];
	CFTypeRef result = nil;
	OSStatus status = SecItemAdd((CFDictionaryRef)attributes, &result);
	return status;
}


- (OSStatus)deleteFromDefaultKeychainWithAppName:(NSString *)name serviceProviderName:(NSString *)provider
{
	NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
	[attributes setValue:(id)kSecClassGenericPassword forKey:(id)kSecClass];
	[attributes setValue:[NSString stringWithFormat:@"%@::OAuth::%@", name, provider] forKey:(id)kSecAttrService];
	OSStatus status = noErr;
	status = SecItemDelete((CFDictionaryRef)attributes);
	return status;
}

#else

- (id)initWithKeychainUsingAppName:(NSString *)name serviceProviderName:(NSString *)provider 
{
    [super init];
    SecKeychainItemRef item;
	NSString *serviceName = [NSString stringWithFormat:@"%@::OAuth::%@", name, provider];
	OSStatus status = SecKeychainFindGenericPassword(NULL,
													 strlen([serviceName UTF8String]),
													 [serviceName UTF8String],
													 0,
													 NULL,
													 NULL,
													 NULL,
													 &item);
    if (status != noErr) {
        return nil;
    }
    
    // from Advanced Mac OS X Programming, ch. 16
    UInt32 length;
    char *password;
    SecKeychainAttribute attributes[8];
    SecKeychainAttributeList list;
	
    attributes[0].tag = kSecAccountItemAttr;
    attributes[1].tag = kSecDescriptionItemAttr;
    attributes[2].tag = kSecLabelItemAttr;
    attributes[3].tag = kSecModDateItemAttr;
    
    list.count = 4;
    list.attr = attributes;
    
    status = SecKeychainItemCopyContent(item, NULL, &list, &length, (void **)&password);
    
    if (status == noErr) {
        self.key = [[[NSString alloc] initWithBytes:list.attr[0].data
                                             length:list.attr[0].length
                                           encoding:NSUTF8StringEncoding] autorelease];
        if (password != NULL) {
            char passwordBuffer[1024];
            
            if (length > 1023) {
                length = 1023;
            }
            strncpy(passwordBuffer, password, length);
            
            passwordBuffer[length] = '\0';
            self.secret = [NSString stringWithUTF8String:passwordBuffer];
        }
        
        SecKeychainItemFreeContent(&list, password);
        
    } else {
		// TODO find out why this always works in i386 and always fails on ppc
		NSLog(@"Error from SecKeychainItemCopyContent: %d", status);
        return nil;
    }
    
    NSMakeCollectable(item);
    
    return self;
}


- (OSStatus)storeInDefaultKeychainWithAppName:(NSString *)name serviceProviderName:(NSString *)provider 
{
    return [self storeInKeychain:NULL appName:name serviceProviderName:provider];
}

- (OSStatus)storeInKeychain:(SecKeychainRef)keychain appName:(NSString *)name serviceProviderName:(NSString *)provider 
{
	OSStatus status = SecKeychainAddGenericPassword(keychain,                                     
                                                    [name length] + [provider length] + 9, 
                                                    [[NSString stringWithFormat:@"%@::OAuth::%@", name, provider] UTF8String],
                                                    [self.key length],                        
                                                    [self.key UTF8String],
                                                    [self.secret length],
                                                    [self.secret UTF8String],
                                                    NULL
                                                    );
	return status;
}

#endif

@end
