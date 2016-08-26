/*Copyright (c) 2007-2009 Extendmac, LLC. <support@extendmac.com>
 
 Permission is hereby granted, free of charge, to any person
 obtaining a copy of this software and associated documentation
 files (the "Software"), to deal in the Software without
 restriction, including without limitation the rights to use,
 copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following
 conditions:
 
 The above copyright notice and this permission notice shall be
 included in all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
 */

#import "EMKeychain.h"

NSString * const EMKeychainErrorDomain = @"EMKeychainErrorDomain";

BOOL EMKeychainError(NSError **error, NSString *description, OSStatus keychainError) {
	if (error) {
		NSError *osError = [NSError errorWithDomain:NSOSStatusErrorDomain code:keychainError userInfo:nil];
		NSDictionary *userInfo = @{
								   NSLocalizedDescriptionKey: description,
								   NSUnderlyingErrorKey: osError,
								   };
		*error = [NSError errorWithDomain:EMKeychainErrorDomain code:osError.code userInfo:userInfo];
	}
	return NO;
}

BOOL EMError(NSError **error, NSString *description, NSString *failureReason) {
	if (error) {
		NSDictionary *userInfo = @{
								   NSLocalizedDescriptionKey: description,
								   NSLocalizedFailureReasonErrorKey: failureReason,
								   };
		*error = [NSError errorWithDomain:EMKeychainErrorDomain code:description.hash userInfo:userInfo];
	}
	return NO;
}

@interface EMKeychainItem () {
	SecKeychainItemRef _keychainItemRef;
}
@end

@implementation EMKeychainItem

+ (BOOL)lockKeychain:(NSError **)error {
	OSStatus status = SecKeychainLock(NULL);
	if (status != noErr) {
		return EMKeychainError(error, @"Keychain lock failed", status);
	}
	return YES;
}

+ (BOOL)unlockKeychain:(NSError **)error {
	OSStatus status = SecKeychainUnlock(NULL, 0, NULL, NO);
	if (status != noErr) {
		return EMKeychainError(error, @"Keychain lock failed", status);
	}
	return YES;
}

+ (const NSDictionary *)attributeMapping {
	const NSDictionary *attrObjectMapping = @{
											  @(kSecAccountItemAttr): [NSString class],
											  @(kSecLabelItemAttr): [NSString class],
											  @(kSecProtocolItemAttr): [NSNumber class],
											  @(kSecTypeItemAttr): [NSNumber class],
											  };
	return attrObjectMapping;
}

+ (instancetype)keychainItemWithRef:(SecKeychainItemRef)keychainItemRef {
	SecItemClass itemClass;
	OSStatus status = SecKeychainItemCopyContent(keychainItemRef, &itemClass, NULL, NULL, NULL);
	if (status != noErr) return nil;

	Class class = nil;
	switch (itemClass) {
		case kSecGenericPasswordItemClass: class = [EMGenericKeychainItem class]; break;
		case kSecInternetPasswordItemClass: class = [EMInternetKeychainItem class]; break;
		default: break;
	}
	if (class == nil) return nil;

	return [[class alloc] initWithKeychainItemRef:keychainItemRef];
}

- (instancetype)initWithKeychainItemRef:(SecKeychainItemRef)keychainItemRef {
	self = [super init];
	if (!self) return nil;

	_keychainItemRef = keychainItemRef;

	return self;
}

- (instancetype)init {
	[NSException raise:NSInternalInconsistencyException format:@"-init is unavailable"];
	return nil;
}

- (void)dealloc {
	if (_keychainItemRef) CFRelease(_keychainItemRef);
}

- (SecKeychainItemRef)keychainItemRef {
	return _keychainItemRef;
}

- (id)objectForAttribute:(SecItemAttr)attr error:(NSError **)error {
	Class objClass = [[self class] attributeMapping][@(attr)];
	if (!objClass) {
		EMError(error, @"Unsupported attribute", @"The attribute '%@' is not supported");
		return nil;
	}

	SecKeychainAttribute attribute[1];
	attribute[0].tag = attr;
	SecKeychainAttributeList list;
	list.count = 1;
	list.attr = attribute;

	OSStatus status = SecKeychainItemCopyContent(self.keychainItemRef, NULL, &list, NULL, NULL);
	if (status != noErr) {
		EMKeychainError(error, @"Failed to get attribute", status);
		return nil;
	}

	id object = nil;
	if (objClass == [NSString class]) {
		object = [[NSString alloc] initWithBytes:list.attr[0].data length:list.attr[0].length encoding:NSUTF8StringEncoding];
	} else if (objClass == [NSNumber class]) {
		NSData *attrData = [NSData dataWithBytes:list.attr[0].data length:list.attr[0].length];
		// Thanks, Omni
		UInt32 int4 = 0;
		UInt16 int2 = 0;
		UInt8 int1 = 0;
		switch(attrData.length) {
			case 4:
				[attrData getBytes:&int4 length:[attrData length]];
				break;
			case 2:
				[attrData getBytes:&int2 length:[attrData length]];
				int4 = int2;
				break;
			case 1:
				[attrData getBytes:&int1 length:[attrData length]];
				int4 = int1;
				break;
			default:
				EMError(error, @"Unexpected integer format in keychain item.", nil);
				return nil;
		}
		object =  [NSNumber numberWithUnsignedInt:int4];
	}

	SecKeychainItemFreeContent(&list, NULL);

	return object;
}

- (BOOL)setObject:(id)object forAttribute:(SecItemAttr)attr error:(NSError **)error {
	Class objClass = [[self class] attributeMapping][@(attr)];
	if (!objClass) {
		return EMError(error, @"Unsupported attribute", @"The attribute is not supported");
	}
	if (![object isKindOfClass:objClass]) {
		return EMError(error, @"Invalid object class for attribute", nil);
	}

	SecKeychainAttribute attributes[1];
	attributes[0].tag = attr;
	if (objClass == [NSString class]) {
		const char *string = [(NSString *)object UTF8String];
		attributes[0].length = (UInt32)strlen(string);
		attributes[0].data = (void *)string;
	} else if (objClass == [NSNumber class]) {
		long number = [(NSNumber *)object longValue];
		attributes[0].length = sizeof(long);
		attributes[0].data = &number;
	}

	SecKeychainAttributeList list;
	list.count = 1;
	list.attr = attributes;

	OSStatus status = SecKeychainItemModifyAttributesAndData(self.keychainItemRef, &list, 0, NULL);
	if (status != noErr) {
		return EMKeychainError(error, @"Attribute modification failed", status);
	}

	return YES;
}

- (BOOL)deleteItem:(NSError **)error {
	OSStatus status = SecKeychainItemDelete(self.keychainItemRef);
	if (status != noErr) {
		return EMKeychainError(error, @"Keychain item deletion failed", status);
	}

	return YES;
}

- (NSString *)username {
	return [self objectForAttribute:kSecAccountItemAttr error:NULL];
}

- (void)setUsername:(NSString *)username {
	[self setUsername:username error:NULL];
}

- (BOOL)setUsername:(NSString *)username error:(NSError *__autoreleasing *)error {
	return [self setObject:username forAttribute:kSecAccountItemAttr error:error];
}

- (NSString *)password {
	UInt32 length = 0;
	void *data;
	OSStatus status = SecKeychainItemCopyContent(self.keychainItemRef, NULL, NULL, &length, &data);
	if (status != noErr) {
		NSError *error = nil;
		EMKeychainError(&error, @"Failed to get password", status);
		NSLog(@"EMKeychainItem: %@", error);
		return nil;
	}

	NSString *passwordString = [[NSString alloc] initWithBytes:data	length:length encoding: NSUTF8StringEncoding];
	SecKeychainItemFreeContent(NULL, data);

	return passwordString;
}

- (void)setPassword:(NSString *)password {
	[self setPassword:password error:NULL];
}

- (BOOL)setPassword:(NSString *)newPasswordString error:(NSError *__autoreleasing *)error {
	NSParameterAssert(newPasswordString != nil);
	
	const char *newPassword = [newPasswordString UTF8String];
	OSStatus status = SecKeychainItemModifyAttributesAndData(_keychainItemRef, NULL, (UInt32)strlen(newPassword), (void *)newPassword);
	if (status != noErr) {
		return EMKeychainError(error, @"Password change failed", status);
	}
	return YES;
}

- (NSString *)label {
	return [self objectForAttribute:kSecLabelItemAttr error:NULL];
}

- (void)setLabel:(NSString *)label {
	[self setLabel:label error:NULL];
}

- (BOOL)setLabel:(NSString *)label error:(NSError *__autoreleasing *)error {
	return [self setObject:label forAttribute:kSecLabelItemAttr error:error];
}

@end

@implementation EMGenericKeychainItem

+ (EMGenericKeychainItem *)genericKeychainItemForService:(NSString *)serviceNameString withUsername:(NSString *)usernameString error:(NSError **)error {
	const char *serviceName  = serviceNameString == nil ? "" : [serviceNameString UTF8String];
	UInt32 serviceNameLength = serviceNameString == nil ? 0  : (UInt32)strlen(serviceName);

	const char *username  = usernameString == nil ? "" : [usernameString UTF8String];
	UInt32 usernameLength = usernameString == nil ? 0  : (UInt32)strlen(username);
	
	SecKeychainItemRef item = nil;
	OSStatus status = SecKeychainFindGenericPassword(NULL, serviceNameLength, serviceName, usernameLength, username, NULL, NULL, &item);
	if (status != noErr) {
		EMKeychainError(error, @"Generic password not found", status);
		return nil;
	}

	return [[super alloc] initWithKeychainItemRef:item];
}

+ (EMGenericKeychainItem *)addGenericKeychainItemForService:(NSString *)serviceNameString withUsername:(NSString *)usernameString password:(NSString *)passwordString  error:(NSError **)error {
	NSParameterAssert(serviceNameString && serviceNameString.length != 0);
	NSParameterAssert(usernameString && usernameString.length != 0);
	NSParameterAssert(passwordString && passwordString.length != 0);

	const char *serviceName = [serviceNameString UTF8String];
	const char *username = [usernameString UTF8String];
	const char *password = [passwordString UTF8String];
	
	SecKeychainItemRef item = nil;
	OSStatus status = SecKeychainAddGenericPassword(NULL, (UInt32)strlen(serviceName), serviceName, (UInt32)strlen(username), username, (UInt32)strlen(password), (void *)password, &item);
	
	if (status != noErr || !item) {
		EMKeychainError(error, @"Generic password creation failed", status);
		return nil;
	}
	return [[super alloc] initWithKeychainItemRef:item];
}

+ (void) setKeychainPassword:(NSString*)password forUsername:(NSString*)username service:(NSString*)serviceName error:(NSError **)error {
	EMKeychainItem *item = [EMGenericKeychainItem genericKeychainItemForService:serviceName withUsername:username error:error];
	if (item == nil)
		[EMGenericKeychainItem addGenericKeychainItemForService:serviceName withUsername:username password:password error:error];
	else
		[item setPassword:password];
}

+ (NSString *) passwordForUsername:(NSString*)username service:(NSString*)serviceName error:(NSError **)error {
	EMGenericKeychainItem *item = [EMGenericKeychainItem genericKeychainItemForService:serviceName withUsername:username error:error];
	if (!item) return nil;
	return [item password];
}

- (NSString *)serviceName {
	return [self objectForAttribute:kSecServiceItemAttr error:NULL];
}

- (void)setServiceName:(NSString *)serviceName {
	[self setServiceName:serviceName error:NULL];
}

- (BOOL)setServiceName:(NSString *)serviceName error:(NSError *__autoreleasing *)error {
	return [self setObject:serviceName forAttribute:kSecServiceItemAttr error:error];
}
@end

@implementation EMInternetKeychainItem
+ (instancetype)internetKeychainItemForServer:(NSString *)serverString withUsername:(NSString *)usernameString path:(NSString *)pathString port:(int)port protocol:(SecProtocolType)protocol error:(NSError **)error {
	
	const char *server  = serverString == nil ? "" : [serverString UTF8String];
	UInt32 serverLength = serverString == nil ? 0 : (UInt32)strlen(server);

	const char *username  = usernameString == nil ? "" : [usernameString UTF8String];
	UInt32 usernameLength = usernameString == nil ? 0 : (UInt32)strlen(username);
	
	const char *path  = pathString == nil ? "" : [pathString UTF8String];
	UInt32 pathLength = pathString == nil ? 0 : (UInt32)strlen(path);
	
	SecKeychainItemRef item = nil;
	OSStatus status = SecKeychainFindInternetPassword(NULL, serverLength, server, 0, NULL, usernameLength, username, pathLength, path, port, protocol, kSecAuthenticationTypeAny, 0, NULL, &item);
	
	if (status != noErr && protocol == kSecProtocolTypeFTP) {
		//Some clients (like Transmit) still save passwords with kSecProtocolTypeFTPAccount, which was deprecated.  Let's check for that.
		protocol = kSecProtocolTypeFTPAccount;		
		status = SecKeychainFindInternetPassword(NULL, serverLength, server, 0, NULL, usernameLength, username, pathLength, path, port, protocol, kSecAuthenticationTypeAny, 0, NULL, &item);
	}
	
	if (status != noErr) {
		EMKeychainError(error, @"Internet password not found", status);
		return nil;
	}
	return [[self alloc] initWithKeychainItemRef:item];
}

+ (instancetype)addInternetKeychainItemForServer:(NSString *)serverString withUsername:(NSString *)usernameString password:(NSString *)passwordString path:(NSString *)pathString port:(int)port protocol:(SecProtocolType)protocol error:(NSError **)error {
	NSParameterAssert(usernameString && usernameString.length != 0);
	NSParameterAssert(serverString && serverString.length != 0);
	NSParameterAssert(passwordString && passwordString.length != 0);

	const char *server = [serverString UTF8String];
	const char *username = [usernameString UTF8String];
	const char *password = [passwordString UTF8String];
	const char *path = [pathString UTF8String];
	
	if (!pathString || [pathString length] == 0)
		path = "";
	
	SecKeychainItemRef item = nil;
	OSStatus status = SecKeychainAddInternetPassword(NULL, (UInt32)strlen(server), server, 0, NULL, (UInt32)strlen(username), username, (UInt32)strlen(path), path, port, protocol, kSecAuthenticationTypeDefault, (UInt32)strlen(password), (void *)password, &item);
	
	if (status != noErr) {
		EMKeychainError(error, @"Internet password creation failed", status);
		return nil;
	}

	return [[self alloc] initWithKeychainItemRef:item];
}

- (NSString *)server {
	return [self objectForAttribute:kSecServerItemAttr error:NULL];
}

- (void)setServer:(NSString *)server {
	[self setServer:server error:NULL];
}

- (BOOL)setServer:(NSString *)server error:(NSError **)error {
	return [self setObject:server forAttribute:kSecServerItemAttr error:error];
}

- (NSString *)path {
	return [self objectForAttribute:kSecPathItemAttr error:NULL];
}

- (void)setPath:(NSString *)path {
	[self setPath:path error:NULL];
}

- (BOOL)setPath:(NSString *)path error:(NSError **)error {
	return [self setObject:path forAttribute:kSecPathItemAttr error:error];
}

- (int)port {
	NSNumber *number = [self objectForAttribute:kSecPortItemAttr error:NULL];
	int port = 0;
	if (number) port = [number intValue];
	return port;
}

- (void)setPort:(int)port {
	[self setPort:port error:NULL];
}

- (BOOL)setPort:(int)port error:(NSError **)error {
	NSNumber *number = [NSNumber numberWithInt:port];
	return [self setObject:number forAttribute:kSecPortItemAttr error:error];
}

- (SecProtocolType)protocol {
	NSNumber *number = [self objectForAttribute:kSecProtocolItemAttr error:NULL];
	SecProtocolType protocol = kSecProtocolTypeAny;
	if (number) protocol = [number intValue];
	return protocol;
}

- (void)setProtocol:(SecProtocolType)protocol {
	[self setProtocol:protocol error:NULL];
}

- (BOOL)setProtocol:(SecProtocolType)protocol error:(NSError *__autoreleasing *)error {
	NSNumber *number = [NSNumber numberWithInt:protocol];
	return [self setObject:number forAttribute:kSecProtocolItemAttr error:error];
}
@end