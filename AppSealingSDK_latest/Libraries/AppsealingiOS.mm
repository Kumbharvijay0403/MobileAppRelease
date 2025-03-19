#include "AppSealingiOS.h"

/////////////////////////////////////////////////////////////////////////////// LEA AREA BEGIN : DO NOT DELETE THIS LINE !!!!
bool __se_use_lea;
unsigned char __se_iv[16], __se_key[16], __se_key_table[248620];
/////////////////////////////////////////////////////////////////////////////// LEA AREA END : DO NOT DELETE THIS LINE !!!!

void iOS()
{
    Appsealing();
}

#if REACT_NATIVE_0_71
@implementation AppSealingInterfaceBridge
RCT_EXPORT_MODULE()

// Check the device for flash capabilities and return callback of success // or fail
RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(IsAbnormalEnvironmentDetectedRN)
{
    return [NSString stringWithFormat:@"%d", ObjC_IsAbnormalEnvironmentDetected()];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(IsSwizzlingDetectedReturnRN)
{
  return [NSString stringWithFormat:@"%d", ObjC_IsSwizzlingDetectedReturn()];
}

RCT_EXPORT_METHOD(ExitApp)
{
    exit( 0 );
}
@end
#endif


@interface AppSealingInterface()
@end

@implementation AppSealingInterface
- (instancetype)init
{
    return self;
}

-(int)_IsAbnormalEnvironmentDetected
{
    return ObjC_IsAbnormalEnvironmentDetected() ;
}

char appSealingDeviceID[64];
-(const char*)_GetAppSealingDeviceID
{
    if( ObjC_GetAppSealingDeviceID( appSealingDeviceID ) == 0 )
    {
        return appSealingDeviceID;
    }
    return "";
}

char appSealingCredential[290];
-(const char*)_GetEncryptedCredential
{
    if( ObjC_GetEncryptedCredential( appSealingCredential ) == 0 )
    {
        return appSealingCredential;
    }
    return "";
}

+( NSString* )_DSS: ( NSString* )string  // Decrypt String  (for Objective-C / Swift)
{
    char* ret = ObjC_DecryptString(( char* )[string UTF8String] );
    return [NSString stringWithUTF8String:ret];
}
+( NSString* )_DSC: ( char* )string  // Decrypt String (for C++)
{
    char* ret = ObjC_DecryptString( string );
    return [NSString stringWithUTF8String:ret];
}


+(void)_NotifySwizzlingDetected: (void (^)(NSString*))handler
{
    dispatch_queue_t queue = dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0 );
    dispatch_async( queue, ^{
        int ret = ObjC_IsSwizzlingDetected();
        if ( ret == 1 ) // jailbreak detected
            dispatch_async( dispatch_get_main_queue(), ^{ handler(@"Jailbreak detected !!!"); });
        if ( ret == 2 ) // swizzling detected
            dispatch_async( dispatch_get_main_queue(), ^{ handler(@"Swizzling detected !!!"); });
        if ( ret == 3 ) // hooking detected
            dispatch_async( dispatch_get_main_queue(), ^{ handler(@"Hooking detected !!!"); });
    } );
}

@end
