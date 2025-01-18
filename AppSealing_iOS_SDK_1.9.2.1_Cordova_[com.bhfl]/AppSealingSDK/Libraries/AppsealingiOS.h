//
//  AppsealingiOS.h
//  AppsealingiOS
//
//  Created by puzznic on 23/01/2019.
//  Copyright © 2019 Inka. All rights reserved.
//

#ifndef AppsealingiOS_h
#define AppsealingiOS_h

// 앱 해킹 UI용 샘플코드에 사용되는 코드
#define ERROR_NONE                      0x00000000
#define DETECTED_JAILBROKEN             0x00000001
#define DETECTED_DRM_DECRYPTED          0x00000002
#define DETECTED_DEBUG_ATTACHED         0x00000004
#define DETECTED_HASH_INFO_CORRUPTED    0x00000008
#define DETECTED_CODESIGN_CORRUPTED     0x00000010
#define DETECTED_HASH_MODIFIED          0x00000020
#define DETECTED_EXECUTABLE_CORRUPTED   0x00000040
#define DETECTED_CERTIFICATE_CHANGED    0x00000080
#define DETECTED_BLACKLIST_CORRUPTED    0x00000100
#define DETECTED_CHEAT_TOOL             0x00000200

#import <Foundation/Foundation.h>

#if REACT_NATIVE_0_71
#if __has_include(<React/RCTAssert.h>)
#import <React/RCTBridgeModule.h>
#else
#import "RCTBridgeModule.h"
#endif
#endif

#define CFSTR(cStr)  __CFStringMakeConstantString( cStr )

extern void Appsealing(void);
extern int ObjC_IsAbnormalEnvironmentDetected();
extern int ObjC_IsSwizzlingDetected();
extern int ObjC_IsSwizzlingDetectedReturn();
extern int ObjC_GetAppSealingDeviceID( char* deviceIDBuff );
extern int ObjC_GetEncryptedCredential( char* buffer );
extern char* ObjC_DecryptString( char* string );

@interface AppSealingInterface : NSObject
- ( int )_IsAbnormalEnvironmentDetected;
+ (void)_NotifySwizzlingDetected:(void (^)(NSString*))handler;
- ( const char* )_GetAppSealingDeviceID;
- ( const char* )_GetEncryptedCredential;
+ ( NSString* )_DSS: ( NSString* )string;  // Decrypt String (for Objective-C / Swift string)
+ ( NSString* )_DSC: ( char* )string;      // Decrypt String (for C string)
@end

#if REACT_NATIVE_0_71
@interface AppSealingInterfaceBridge : NSObject <RCTBridgeModule>
@end
#endif

#endif /* AppsealingiOS_h */
