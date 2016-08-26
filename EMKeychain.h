/*Copyright (c) 2007 Extendmac, LLC. <support@extendmac.com>
 
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

#import <Cocoa/Cocoa.h>
#import <Security/Security.h>

extern NSString * const EMKeychainErrorDomain;

@interface EMKeychainItem : NSObject

+ (BOOL)lockKeychain:(NSError **)error;
+ (BOOL)unlockKeychain:(NSError **)error;

- (instancetype)initWithKeychainItemRef:(SecKeychainItemRef)keychainItemRef NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@property (assign, readonly) SecKeychainItemRef keychainItemRef NS_RETURNS_INNER_POINTER;

@property (copy) NSString *username;
@property (copy) NSString *password;
@property (copy) NSString *label;

- (BOOL)setUsername:(NSString *)username error:(NSError **)error;
- (BOOL)setPassword:(NSString *)password error:(NSError **)error;
- (BOOL)setLabel:(NSString *)label error:(NSError **)error;

- (BOOL)deleteItem:(NSError **)error;

@end 

@interface EMGenericKeychainItem : EMKeychainItem

+ (instancetype)genericKeychainItemForService:(NSString *)serviceNameString withUsername:(NSString *)usernameString error:(NSError **)error;
+ (instancetype)addGenericKeychainItemForService:(NSString *)serviceNameString withUsername:(NSString *)usernameString password:(NSString *)passwordString error:(NSError **)error;

@property (copy) NSString *serviceName;

- (BOOL)setServiceName:(NSString *)serviceName error:(NSError **)error;

@end

@interface EMInternetKeychainItem : EMKeychainItem

+ (instancetype)internetKeychainItemForServer:(NSString *)serverString withUsername:(NSString *)usernameString path:(NSString *)pathString port:(int)port protocol:(SecProtocolType)protocol error:(NSError **)error;
+ (instancetype)addInternetKeychainItemForServer:(NSString *)serverString withUsername:(NSString *)usernameString password:(NSString *)passwordString path:(NSString *)pathString port:(int)port protocol:(SecProtocolType)protocol error:(NSError **)error;

@property (copy) NSString *server;
@property (copy) NSString *path;
@property (assign) int port;
@property (assign) SecProtocolType protocol;

- (BOOL)setServer:(NSString *)newServer error:(NSError **)error;
- (BOOL)setPath:(NSString *)newPath error:(NSError **)error;
- (BOOL)setPort:(int)newPort error:(NSError **)error;
- (BOOL)setProtocol:(SecProtocolType)newProtocol error:(NSError **)error;
@end