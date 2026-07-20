In Andrid studio

GoTo => Build => Generate Signed Bundle/APK=>Android App Bundle
1. Enter keystore, password aliasname , then app-release.aab file will be generated
2. Goto AAB file location => copy that file and paste in Bundle_tool folder
3. Check in Bundle_tool bhflkeystore.jks(copy from project) and keystore.pwd 
4. Open cmd in that folder
5. Enter command =>

java -jar bundletool.jar build-apks --local-testing --bundle=app-release.aab  --output=app.apks  --ks=bhflkeystore.jks --ks-pass=file:keystore.pwd --ks-key-alias=bhfl --key-pass=file:keystore.pwd --mode=universal

6. A new file app.apks will be generated. Remove .apks extension and give .zip extension
7. Click extract Here or extract To. Two files will be created toc.pb and universal.apks
8. Check universal.apk in our mobile if it is working
9. Send app-release.abb file to client for sealing

=========================================================================================
Step for signing APK
========================

10. After client send back Sealed aab file back, Sign using below steps
a. create new folder for signing
b. copy sealed.aab in that folder
c. copy bhflkeystore.jks file also in that folder
d. Open cmd in that folder and enter below command for signing

jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore bhflkeystore.jks BHFL_PROD_1.4.0_Testing23Oct_sealed.aab bhfl
======================
where,  bhflkeystore.jks is keystore , BHFL_Prod_V_1.0.1_sealed.aab is file to sign , bhfl is aliasname
 
/opt/www/html/BHFL
http://50.17.252.160/BHFL/BHFL_UAT_23122022_ForceUpdate-Handling-changes.apk
http://50.17.252.160/BHFL/BHFL_UAT_23122022.apk


Symbol zip :


D:\Bajaj_project\Bajaj-Home-Finance\BHFLSonarQube\PROD\platforms\android\app\build\intermediates\merged_native_libs\release\out\lib


Mapping file : 

D:\Bajaj_project\Bajaj-Home-Finance\BHFLSonarQube\PROD\platforms\android\app\build\outputs\mapping\release