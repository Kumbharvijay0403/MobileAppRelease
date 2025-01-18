#!/usr/bin/env ruby

#  ci_post_xcodebuild.sh
#  Copyright © 2023 AppsealingDev. All rights reserved.

require 'pathname'
require 'tmpdir'
require 'securerandom'
require 'net/https'
require 'json'
require 'io/console'

#------------------------------------------------------------------------------------------------------------------- EDIT HERE
APPLE_ID = "support@inka.co.kr"				# replace with your apple developer ID
APPLE_APP_PASSWORD = "aaaa-bbbb-cccc-dddd"	# replace with your apple application password (https://appleid.apple.com/account/manage)
                                            # NOT ACCOUNT PASSWORD !
#-----------------------------------------------------------------------------------------------------------------------------

UNREAL_URL_SCHEME = ""						# replace with your URL scheme of unreal app
											# Unreal Shipping IPA를 App Store Connect에 업로드 할 때 "ERROR ITMS-90158" 오류가 발생하면
											# 이 파라미터를 추가해 Info.plist의 CFBundleURLSchemes 값을 새로 설정하여 오류를 수정할 수 있음

$baseURL = 'https://api.appsealing.com/covault/gw/'
$position = 0
$isUnreal = false
$isXamarin = false

#--------------------------------------------------------------------------------------------
#  _CodeSignature/CodeResources 파일을 읽어 <key>files</key> 항목의 모든 데이터를 문자열로 변환하여 리턴
#--------------------------------------------------------------------------------------------
def generate_hash_snapshot( path )

	dict = false
	data = false
	key = ''
	expect_data = false
	snapshot = ""

	begin
		file = File.open( path )
		file.each_line do |line|
			sline = line.strip
			break if sline.start_with?( "<key>files2</key>" )	# files2 항목은 건너 뛴다
			if sline.start_with?( "<key>files</key>" ) then
				next
			end

			if !expect_data and sline.start_with?( "<key>" ) and sline.end_with?( "</key>" ) then	# key 추출
				key = sline.gsub( "<key>", "" ).gsub( "</key>", "" )
				expect_data = true
				snapshot += ( key + "\1" )	# 스냅샷에 추가
			end
			dict = true if sline.start_with?( "<dict>" ) and expect_data
			dict = expect_data = false if sline.start_with?( "</dict>" ) and dict and expect_data
			if sline.start_with?( "<data>" ) and expect_data then
				data = true
				next
			end
			if sline.start_with?( "</data>" ) then
				data = false;
				expect_data = false if !dict
			end
			if expect_data and data then
				snapshot += ( sline + "\n" )	# 스냅샷에 추가
				next
			end
		end
	rescue => e
		puts ".\n.\nInvalid IPA file has passed to an argument, check your IPA file and try again.\n.\n.\n"
		exit( false )
	ensure
		file.close unless file.nil?
	end
	return snapshot
end

#--------------------------------------------------------------------------------------------
#  Payload/app의 certificate와 entitlement를 이용하여 genesis가 추가된 Payload/app에 다시 codesign을 수행
#--------------------------------------------------------------------------------------------
def sign_app_payload( _app, folder, generate_info_only )
	cert = ''
	app = '"' + _app + '"'
	begin
		# 1 app 서명에 사용된 인증서 추출
		system( "cd " + folder + ";codesign -d --extract-certificates " + app )

		cmd = "openssl x509 -inform DER -in " + folder + "codesign0 -noout -nameopt multiline"

		if generate_info_only then
			# 2. app provision 추출				
			system( 'security cms -D -i "' + app + '/embedded.mobileprovision" > "' + folder + 'provision.plist"' )
	
			# 3. entitlement 생성
			system( "/usr/libexec/PlistBuddy -x -c 'Print :Entitlements' " + folder + "provision.plist > " + folder + "entitlements.plist" )

			# genesis에 저장할 인증서 정보 추출
			certopt = "no_header,no_version,no_serial,no_signame,no_subject,no_issuer,no_validity,no_pubkey,no_sigdump,no_aux,no_extensions"
			system( cmd + ",utf8 -subject -issuer -serial -pubkey -text -dates -certopt " + certopt + " > " + folder + "certificate.txt" )
			return
		end
		
		# 4 추출된 leaf 인증서를 X.509 형식으로 변환
		system( cmd + ",-esc_msb,utf8 -subject > " + folder + "certificate.pem" )

		# 5 인증서 명 추출
		file = File.open( folder + "certificate.pem" )
		file.each_line do |line|
			sline = line.strip
			next unless sline.start_with?( "commonName " )
			cert = sline.split( '=' )[1].strip
			break
		end
		file.close unless file.nil?

		if cert == '' then
			puts ".\n.\nCannot get certificate information, check your IPA file and try again.\n.\n.\n"
			exit( false )
		end
		
		# 6 추출된 인증서가 시스템 키체인에 등록된 인증서인지 확인
		valid = false
		system( "security find-identity -v -p codesigning > " + folder + "certificates" )
		file = File.open( folder + "certificates" )
		file.each_line do |line|
			valid = true if line.strip.include?( cert )
		end
		if !valid then
			puts ".\n.\nThe certificate used to sign your IPA does not exist in your system, check your system's key-chain and try again.\n.\n.\n"
			exit( false )
		end
		file.close unless file.nil?

		# 7 Info.plist 파일을 XML 형식으로 변환
		system( "plutil -convert xml1 " + app + "/Info.plist" )

		# 8 codesign 실행
		system( "rm -r " + app + "/_CodeSignature" )
		system( 'codesign -f -s "' + cert + '" --entitlements ' + folder + 'entitlements.plist ' + app + '/' )
	rescue => e
		puts ".\n.\nProblem has occurred while code-signing your app, please try again.\n[Error] " + e.to_s + "\nIf this error occurs continuously, contact AppSealing Help Center.\n.\n.\n"
		exit( false )
	end
end

#--------------------------------------------------------------------------------------------
#  appsealing.lic 파일 읽기
#--------------------------------------------------------------------------------------------
def get_accountID_hash_from_license_file( path )
	license = File.open( path, "r+b" )

	header = license.read( 5 )
	magic = "\x41\x53\x4C\x46\x76".force_encoding( Encoding::ASCII_8BIT )	#V2 +
	if header == magic then
		license.read( 3 )
		$sdk_version = license.read( 48 ).gsub( /\000/, '' )
		#puts " ===> version : " + $sdk_version
		license.read( 8 )
		# account ID hash 추출
		accountIDhash = license.read( 32 ).unpack( 'c*' )
		$account_id_hash = accountIDhash.pack( 'c*' ).unpack( 'H*' ).first
		#puts " ===> account id : " + $account_id_hash
	end
end

#--------------------------------------------------------------------------------------------
#  unreal 실행 파일에서 appsealing license 추출하기
#--------------------------------------------------------------------------------------------
def get_accountID_hash_from_unreal_executable( path )
	
	$current_step += 1
	puts "\n" + $current_step.to_s + ". Extracting accound ID from Unreal executable file ..."

	file_size = File.size( path )
	
	$position = 0
	parse_finished = false

	uiThread = Thread.new {
		loop do
			print "\r  ==> Searching license in Unreal-Executable : " + $position.to_s.reverse.gsub(/(\d{3})(?=\d)/, '\\1,').reverse
			sleep 0.5
			break if parse_finished
			break if $position >= file_size
		end
		puts ''
	}

	magic1 = "\x41\x53\x4C\x46".force_encoding( Encoding::ASCII_8BIT )	#V2
	magic2 = "\x76\x32\x0A\x0D".force_encoding( Encoding::ASCII_8BIT )
	sdk = "\x0\x0\x0\x0\x0\x0\x0\x0".force_encoding( Encoding::ASCII_8BIT )

	parseThread = Thread.new {
		File.open( path, 'rb' ) do |f|
			while data = f.read( 4 * 1024 * 1024 ) do
				offset = 0
				while offset < data.length do
					if data[(offset)..(offset + 3)] == magic1 then
						if data[(offset + 4)..(offset + 7)] == magic2 and data[(offset + 48)..(offset + 55)] == sdk then
							accountIDhash = data[(offset + 64)..(offset + 95)].unpack( 'c*' )
							bundle_id = data[(offset + 96)..(offset + 96 + 255)].strip
							
							if $bundle_id.strip.include? bundle_id then	# (헤더 매직 일치) AND (SDK버전 마지막 8byte가 0) AND (번들ID 포함)
								$account_id_hash = accountIDhash.pack( 'c*' ).unpack( 'H*' ).first
								parse_finished = true
								$isUnreal = true
								break
							end
						end
					end
					$position = $position + 1
					offset = offset + 1
				end
				break if parse_finished
				break if $position >= file_size
			end
		end
	}
	parseThread.join
	uiThread.join

	if !parse_finished then
		puts ".\n.\nCannot extract AppSealing license from Unreal-Executable, check unreal plugin and rebuild unreal project."
		puts "[Error] " + e.to_s + "\n"
		puts "If this error occurs continuously, contact AppSealing Help Center.\n.\n.\n"
		exit( false )
	end
end

#--------------------------------------------------------------------------------------------
#  JavaScript bytecode(main.jsbundle) 파일 암호화
#--------------------------------------------------------------------------------------------
def encrypt_javascript_bytecode( app )
	if $sdk_version.start_with?( 'NEW' ) then
		$sdk_version = '1.0.0.0'
	end
	#$sdk_version = '1.3.1.1'
	$use_ssl = true
	if $baseURL.start_with?( "http://" )
		$use_ssl = false
	end

	$current_step += 1
	puts "\n" + $current_step.to_s + ". Encrypting React Native javascript bytecode file ..."

	system( 'cd "' + app.to_s + '";zip -q main.zip main.jsbundle' )
	jsfile = File.open( app.to_s + "/main.zip", "rb" )
	result_path = app.to_s + "/enc_main.zip"

	# 7-1. bundle ID 및 account ID hash 추출
	sealing_api  = $baseURL + 'html5/requestSealingForIOS'
	check_api    = $baseURL + 'html5/sealingStatusForIOS'
	download_api = $baseURL + 'html5/downloadSealedFileForIOS'

	finished = false

	uiThread = Thread.new {
		print '  ==> Processing for sealing '
		loop do
			print '.'		
			sleep 0.5
			break if finished
		end
		print ' Done!'
		puts ''
	}

	netThread = Thread.new {
		begin
			# 7-2. 암호화(실링) 요청
			uri = URI( sealing_api )
			request = Net::HTTP::Post.new( uri )
			form_data =
			[
				['bundle_id', $bundle_id],
				['account_id_hash', $account_id_hash],
				['sdk_version', $sdk_version],
				['html5file', jsfile]
			]
			request.set_form form_data, 'multipart/form-data'
			response = Net::HTTP.start( uri.hostname, uri.port, use_ssl: $use_ssl ) do |http|
				http.request( request )
			end

			# 7-3. 결과 확인 및 pack_id 추출
			result = JSON.parse( response.body )
			code = result['result']['code']
			if code != '0000' then
				raise result['result']['message']
			end
			pack_id = result['SEALING_INFO']['pack_id']


			# 7-4. 암호화(실링) 상태 확인
			uri = URI( check_api )
			request = Net::HTTP::Post.new( uri )
			form_data = [['pack_id', pack_id]]
			request.set_form form_data, 'multipart/form-data'

			loop do
				response = Net::HTTP.start( uri.hostname, uri.port, use_ssl: $use_ssl ) do |http|
					http.request( request )
				end

				result = JSON.parse( response.body )
				code = result['result']['code']
				status = result['SEALING_INFO']['status']
				if code != '0000' then
					raise result['result']['message']
				end

				case status
				when '2'
					break
				when '3'
					raise result['SEALING_INFO']['message']
				end
				sleep 0.5	# 0.5초 간격으로 확인
			end


			# 7-5. 암호화(실링) 파일 다운로드
			uri = URI( download_api )
			request = Net::HTTP::Post.new( uri )
			form_data =
			[
				['bundle_id', $bundle_id],
				['account_id_hash', $account_id_hash],
				['pack_id', pack_id]
			]
			request.set_form form_data, 'multipart/form-data'

			response = Net::HTTP.start( uri.hostname, uri.port, use_ssl: $use_ssl ) do |http|
				http.request( request )
			end

			begin
				result = JSON.parse( response.body )
				code = result['result']['code']
			rescue => e
				# File response !!
				open( result_path, "wb") do |file|
					file.write( response.body )
				end	
				system( 'cd "' + app.to_s + '";unzip -qo enc_main.zip' )
				File.delete( app.to_s + '/main.zip' ) if File.exist?( app.to_s + '/main.zip' )
				File.delete( app.to_s + '/enc_main.zip' ) if File.exist?( app.to_s + '/enc_main.zip' )
				system( 'xattr -cr "' + app.to_s + '/main.jsbundle"' )
			end
		rescue => e
			puts ".\n.\nCannot connect to AppSealing server or bad response, check your network status and try again."
			puts "[Error] " + e.to_s + "\n"
			puts "** Your data : \n  > bundle ID : " + $bundle_id + "\n  > Account ID : " + $account_id_hash + "\n  > SDK version : " + $sdk_version + "\n"
			puts "If this error occurs continuously, contact AppSealing Help Center.\n.\n.\n"
			exit( false )
		end
		finished = true
	}
	netThread.join
	uiThread.join

	$current_step += 1
	puts "\n" + $current_step.to_s + ". Successfully encrypted javascript bytecode ..."
end

#--------------------------------------------------------------------------------------------
# main
#--------------------------------------------------------------------------------------------
if __FILE__ == $0

	#........................................................................................
	# [Step 1] IPA 압축 해제

	$IPA = ENV["CI_APP_STORE_SIGNED_APP_PATH"].to_s + '/' + ENV["CI_PRODUCT"].to_s + '.ipa'
	puts "[Target IPA]          = " + $IPA

	# 임시 temp 디렉터리 생성 및 클리어
	folder = Dir.tmpdir() + "/AppSealing/" + SecureRandom.hex + "/"

	puts "\n[Working Directory] = " + folder

	FileUtils.mkdir_p folder
	system( "rm -rf " + folder + "*" )

	# ipa 압축 해제
	system( 'unzip -q "' + $IPA + '" -d ' + folder + "Package/" )
	app = Dir[folder + "Package/Payload/*"][0]	# app name

	if !File.exist?( app.to_s + "/_CodeSignature/CodeResources" ) then
		puts ".\n.\nInvalid IPA file has created, check your build pipeline and try again.\n.\n.\n"
		exit( false )
	end
	if File.exist?( app.to_s + "/Xamarin.iOS.dll" ) then
		$isXamarin = true
	end
	if File.exist?( app.to_s + "/genesis" ) then
		system( "rm " + app.to_s + "/genesis" )
	end

	puts "\n\n1. Payload has extracted from the IPA ..."
	# URL scheme 변경
	if UNREAL_URL_SCHEME != nil and UNREAL_URL_SCHEME != '' then
		puts "\n --> Changing URL Scheme to : " + UNREAL_URL_SCHEME.to_s
		info_plist = ""
		begin
			file = File.open( app + "/Info.plist" )
			urltype = false
			urlscheme = false
			changed = false
			file.each_line do |line|
				sline = line.strip
				if !changed and sline.start_with?( "<key>CFBundleURLTypes</key>" )
					urltype = true
				end
				if !changed and urltype and sline.start_with?( "<key>CFBundleURLSchemes</key>" )
					urltype = false
					urlscheme = true
				end
				if !changed and urlscheme and sline.start_with?( "<string>" )
					urlscheme = false
					changed = true
					info_plist += ( "\t\t\t\t<string>" + UNREAL_URL_SCHEME + "</string>\r\n" )
					next
				end
				info_plist += line				
			end
			file.close
			file = File.open( app + "/Info.plist", "w+b" )
			file.write info_plist
		rescue => e
			puts ".\n.\nProblem has occurred while changing URL scheme, please change it manually.\n.\n.\n"
			puts "* Error : " + e.to_s
			exit( false )
		ensure
			file.close unless file.nil?	
		end
	end

	system( 'cp ./profile.mobileprovision "' + app + '/embedded.mobileprovision"' )
	APPSEALING_KEYCHAIN = "/Users/local/Library/Keychains/APPSEALING.keychain"
	
	system( 'security create-keychain -p 0000 ' + APPSEALING_KEYCHAIN )
	system( 'security list-keychains -d user -s login.keychain ' + APPSEALING_KEYCHAIN )
	system( 'security import ./AppleWWDRCAG3.cer -k ' + APPSEALING_KEYCHAIN + ' -t cert -A -P ""' )
	system( 'security import ./distribution.cer -k ' + APPSEALING_KEYCHAIN + ' -t cert -A -P ""' )
	system( 'security import ./private_key.p12 -k ' + APPSEALING_KEYCHAIN + ' -t priv -A -P ""' )
	system( 'security default-keychain -d user -s ' + APPSEALING_KEYCHAIN )
	system( 'security unlock-keychain -p 0000 ' + APPSEALING_KEYCHAIN )
	system( 'security set-keychain-settings ' + APPSEALING_KEYCHAIN )
	system( 'security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k 0000 ' + APPSEALING_KEYCHAIN + ' > /dev/null' )

	#........................................................................................
	# [Step 2] AppSealing 서버로 부터 WBC 키 받아 오기

	puts "\n2. Trying to receive encryption key from AppSealing server ..."

	host = $baseURL + "v3/common/wbc-tfit/key/generator"
	uri = URI( host )
	request = Net::HTTP::Get.new( uri )
	retry_count = 0
	while true do
		begin
			response = Net::HTTP.start( uri.host, uri.port, :use_ssl => uri.scheme == 'https' ) do |http|
				http.request( request )
			end
			# 암호화 키 및 Exported 키 추출
			$plainKey = JSON.parse( response.body )['WBC_KEY']['plainKey']
			$exportedKey = JSON.parse( response.body )['WBC_KEY']['exportedKey']
			break
		rescue => e
			retry_count++
			sleep( 0.5 )
			if retry_count > 10 then
				puts ".\n.\nCannot connect to AppSealing server or bad response, check your network status and try again.\n[Error] " + e.to_s + "\nIf this error occurs continuously, contact AppSealing Help Center.\n.\n.\n"
				exit( false )
			end
		end
	end

	puts "\n3. Successfully received encryption key ..."
	$current_step = 3


	#........................................................................................
	# [Step 3] 앱 서명에 사용된 인증서 정보를 읽어 genesis에 추가

	current_mode = 'none'
	capability_used =
	{
		'icloud-dev-id' => false,
		'icloud-env' => false,
		'icloud-cont-id' => false
	}
	cert_info =
	{
		'app_id' => "",
		'team_id' => "",
		'domains' => "",
		'keychain' => "",
		'icloud-dev-id' => "",
		'icloud-env' => "",
		'icloud-cont-id' => "",
		'icloud-svc' => "",
		'ubkvs_id' => "",
	}

	sign_app_payload( app, folder, true )

	modified_entitlement = ""
	file = File.open( folder + "entitlements.plist" )
	file.each_line do |line|
		modified_entitlement += line.strip
		if line.strip.start_with?( '<key>application-identifier</key>' ) then
			current_mode = 'app_id'
			next
		end
		if line.strip.start_with?( '<key>com.apple.developer.team-identifier</key>' ) then
			current_mode = 'team_id'
			next
		end
		if line.strip.start_with?( '<key>com.apple.developer.associated-domains</key>' ) then
			current_mode = 'domains'
			next
		end
		if line.strip.start_with?( '<key>keychain-access-groups</key>' ) then
			current_mode = 'keychain'
			cert_info['keychain-full'] = line.strip
			next
		end
		if line.strip.start_with?( '<key>com.apple.developer.icloud-container-development-container-identifiers</key>' ) then
			current_mode = 'icloud-dev-id'
			capability_used['icloud-dev-id'] = true
			next
		end
		if line.strip.start_with?( '<key>com.apple.developer.icloud-container-identifiers</key>' ) then
			current_mode = 'icloud-cont-id'
			capability_used['icloud-cont-id'] = true
			next
		end
		if line.strip.start_with?( '<key>com.apple.developer.icloud-container-environment</key>' ) then
			current_mode = 'icloud-env'
			capability_used['icloud-env'] = true
			next
		end
		if line.strip.start_with?( '<key>com.apple.developer.icloud-services</key>' ) then
			current_mode = 'icloud-svc'
			capability_used['icloud-svc'] = true
			next
		end
		if line.strip.start_with?( '<key>com.apple.developer.ubiquity-kvstore-identifier</key>' ) then
			current_mode = 'ubkvs_id'
			next
		end
		if line.strip.start_with?( '<key>DeveloperCertificates</key>' ) then
			current_mode = 'dev_cert'
			next
		end

		if current_mode == 'keychain' and ( line.strip.start_with?( '<array>' ) or line.strip.start_with?( '</array>' )) then
			cert_info['keychain'] = cert_info['keychain'].to_s + line.strip
		end
		if current_mode == 'dev_cert' and ( line.strip.start_with?( '<array>' ) or line.strip.start_with?( '</array>' )) then
			cert_info['dev_cert'] = cert_info['dev_cert'].to_s + line.strip
		end
		if current_mode != 'none' and line.strip.start_with?( '<array/>' ) then
			if current_mode == 'keychain' then
				cert_info['keychain'] = cert_info['keychain'].to_s + line.strip
			end
			if current_mode == 'dev_cert' then
				cert_info['dev_cert'] = cert_info['dev_cert'].to_s + line.strip
			end
			cert_info[current_mode] = ''
			current_mode = 'none'
		end
		if current_mode != 'none' and line.strip.start_with?( '<string>' ) then
			if current_mode == 'keychain' then
				cert_info['keychain'] = cert_info['keychain'].to_s + line.strip
			else
				cert_info[current_mode] = line.strip.gsub( '<string>', '' ).gsub( '</string>', '' )
				current_mode = 'none'
			end
		end
	end
	file.close unless file.nil?

	# app의 bundle ID 추출
	system( "osascript -e 'id of app \"" + app + "\"' > " + folder + "bundle_id" )

	$bundle_id = cert_info['app_id']
	file = File.open( folder + "bundle_id" )
	file.each_line do |line|
		$bundle_id = line.strip
	end
	file.close unless file.nil?	

	# app_id에 wildcard가 포함되어 있을 경우 bundle ID로 대체
	if cert_info['app_id'] != nil and cert_info['app_id'].end_with?( '.*' )
		old_app_id = cert_info['app_id']
		cert_info['app_id'] = cert_info['team_id'] + '.' + $bundle_id

		# wildcard가 제거된 bundle ID로 대체
		modified_entitlement.sub!( '<string>' + old_app_id + '</string>', '<string>' + cert_info['app_id'] + '</string>' )
		puts "  ==> Application ID replaced : " + old_app_id + " >> " + cert_info['app_id']
	end

	# ubiquity-kvstore-identifier에 wildcard가 포함되어 있을 경우 bundle ID로 대체
	if cert_info['ubkvs_id'] != nil and cert_info['ubkvs_id'].end_with?( '.*' )
		old_ubkvs_id = cert_info['ubkvs_id']
		cert_info['ubkvs_id'] = cert_info['team_id'] + '.' + $bundle_id

		# wildcard가 제거된 bundle ID로 대체
		modified_entitlement.sub!( '<string>' + old_ubkvs_id + '</string>', '<string>' + cert_info['ubkvs_id'] + '</string>' )
		puts "  ==> ubiquity-kvstore-identifier ID replaced : " + old_ubkvs_id + " >> " + cert_info['ubkvs_id']
	end


	#........................................................................................
	# [Step 4] license 에서 account ID 추출

	$sdk_version = "1.0.0.0"
	$iv = SecureRandom.hex( 16 )		# iv 값은 랜덤으로 생성하여 사용하고 genesis에 저장한다

	if File.exist?( app.to_s + "/appsealing.lic" ) then
		get_accountID_hash_from_license_file( app.to_s + "/appsealing.lic" )
	else
		get_accountID_hash_from_unreal_executable( app.to_s + '/' + File.basename( app.to_s, File.extname( app.to_s )))
	end



	#........................................................................................
	# [Step 5] entitlements.plist 처리

	# associated domains 태그의 값이 *인 경우 DistributionSummary.plist 파일에서 해당 값을 가져와 대채
	if cert_info['domains'] != nil and cert_info['domains'].to_s == '*'

		if $isUnreal or $isXamarin then
			cert_info['domains'] = cert_info['app_id']
		else
			# DistributionSummary.plist 파일 열기
			dist_summary = ENV["CI_APP_STORE_SIGNED_APP_PATH"].to_s + Pathname::SEPARATOR_LIST + 'DistributionSummary.plist'
			begin
				current_mode = 'none'
				domains = ""
				file = File.open( dist_summary )
				file.each_line do |line|
					if line.strip.start_with?( '<key>com.apple.developer.associated-domains</key>' ) then
						current_mode = 'domains'
						next
					end
					if current_mode == 'domains' then
						domains += line
					end
					if current_mode == 'domains' and line.strip.start_with?( '</array>' ) then
						current_mode = 'none'
						break
					end
				end
				cert_info['domains'] = domains.strip
			rescue => e
				puts ".\n.\nProblem has occurred while opening 'DistributionSummary.plist' file in your IPA exported folder. (:642)\n[Error] " + e.to_s + "\nYou need 'DistributionSummary.plist' file when you use associated domains entitlement feature, if there is no such file in your IPA exported folder please retry to export IPA.\n.\n.\n"
				exit( false )
			ensure
				file.close unless file.nil?	
			end
		end

		# wildcard가 제거된 associated domains로 대체
		modified_entitlement.sub!( '<string>*</string>', cert_info['domains'] )
		if cert_info['domains'] == '' or cert_info['domains'] == '*' then
			modified_entitlement.sub!( '<key>com.apple.developer.associated-domains</key>', '' )
		else
			puts "  ==> Associated domains repaired : * >> " + cert_info['domains']
		end
	end

	# keychain-access-groups 태그의 값이 *인 경우 DistributionSummary.plist 파일에서 해당 값을 가져와 대채
	if cert_info['keychain'] != nil and cert_info['keychain'].include?( '.*' )

		if $isUnreal or $isXamarin then
			cert_info['domains'] = cert_info['app_id']
		else
			# DistributionSummary.plist 파일 열기
			dist_summary = ENV["CI_APP_STORE_SIGNED_APP_PATH"].to_s + Pathname::SEPARATOR_LIST + 'DistributionSummary.plist'
			keychain = ""
			begin
				current_mode = 'none'
				file = File.open( dist_summary )
				file.each_line do |line|
					if line.strip.start_with?( '<key>keychain-access-groups</key>' ) then
						current_mode = 'keychain'
						next
					end
					if current_mode == 'keychain' then
						keychain += line
					end
					if current_mode == 'keychain' and line.strip.start_with?( '</array>' ) then
						current_mode = 'none'
						break
					end
				end
			rescue => e
				puts ".\n.\nProblem has occurred while opening 'DistributionSummary.plist' file in your IPA exported folder.\n[Error] " + e.to_s + "\nYou need 'DistributionSummary.plist' file when you use associated domains entitlement feature, if there is no such file in your IPA exported folder please retry to export IPA.\n.\n.\n"
				exit( false )
			ensure
				file.close unless file.nil?	
			end

			# wildcard가 제거된 keychain-access-groups로 대체
			if keychain != ''
				modified_entitlement.sub!( cert_info['keychain'], keychain.strip.gsub( /\s+/, '' ) )
				puts "  ==> Keychain access groups repaired : \n" + keychain
			end
		end
	end	

	# icloud-services 태그의 값이 *인 경우 DistributionSummary.plist 파일에서 해당 값을 가져와 대채
	if cert_info['icloud-svc'] != nil and cert_info['icloud-svc'].to_s == '*'

		if $isUnreal or $isXamarin then
			if $CloudServices != nil and $CloudServices != '' then
				if !$CloudServices.include?( ',' ) then
					if $CloudServices == 'none'
						cert_info['icloud-svc'] = ''
					else
						cert_info['icloud-svc'] = '<array><string>' + $CloudServices + '</string></array>'
					end
				else
					svcs = $CloudServices.split( ',' )
					cert_info['icloud-svc'] = '<array><string>' + svcs[0].strip + '</string><string>' + svcs[1].strip + '</string></array>'
				end
			else	# 콘솔에서 직접 입력
				puts "\n ------------------------------------------------------------------------------------------------------"
				puts "  You need to select iCoude-Service items info for your IPA does not include DistributionSummary.plist"
				puts " ------------------------------------------------------------------------------------------------------"
				puts "  0) Not uses iCloud        [Default] (parameter: -icloud_services=none)"
				puts "  1) CloudKit                         (parameter: -icloud_services=CloudKit)"
				puts "  2) iCloudDocuments                  (parameter: -icloud_services=CloudDocuments)"
				puts "  3) CloudKit + iCloudDocuments       (parameter: -icloud_services=CloudKit,CloudDocuments)"
				puts " ......................................................................................................"
				print "  * Select option [Enter=0] : "
				while true do
					input = STDIN.getch
					if input.ord == 27 || input.ord == 3 then
						exit( 0 )
					end
					if input.ord == 13 then
						input = '0'
						break
					end
					if input == '0' or (input.ord >= 49 && input.ord <= 52) then
						break
					end
				end
				puts input
				puts "\n"
				if input == '0' then
					cert_info['icloud-svc'] = ''
				elsif input == '1' then
					cert_info['icloud-svc'] = '<array><string>CloudKit</string></array>'
				elsif input == '2' then
					cert_info['icloud-svc'] = '<array><string>CloudDocuments</string></array>'
				else
					cert_info['icloud-svc'] = '<array><string>CloudKit</string><string>CloudDocuments</string></array>'
				end
			end
		else
			# DistributionSummary.plist 파일 열기
			dist_summary = ENV["CI_APP_STORE_SIGNED_APP_PATH"].to_s + Pathname::SEPARATOR_LIST + 'DistributionSummary.plist'
			begin
				current_mode = 'none'
				icloud = ""
				file = File.open( dist_summary )
				file.each_line do |line|
					if line.strip.start_with?( '<key>com.apple.developer.icloud-services</key>' ) then
						current_mode = 'icloud'
						next
					end
					if current_mode == 'icloud' then
						icloud += line
					end
					if current_mode == 'icloud' and line.strip.start_with?( '</array>' ) then
						current_mode = 'none'
						break
					end
				end
				cert_info['icloud-svc'] = icloud.strip
			rescue => e
				puts ".\n.\nProblem has occurred while opening 'DistributionSummary.plist' file in your IPA exported folder.\n[Error] " + e.to_s + "\nYou need 'DistributionSummary.plist' file when you use associated domains entitlement feature, if there is no such file in your IPA exported folder please retry to export IPA.\n.\n.\n"
				exit( false )
			ensure
				file.close unless file.nil?	
			end
		end

		# wildcard가 제거된 icloud-services 대체
		modified_entitlement.sub!( '<string>*</string>', cert_info['icloud-svc'] )
		if cert_info['icloud-svc'] == '' or cert_info['icloud-svc'] == '*' then
			modified_entitlement.sub!( '<key>com.apple.developer.icloud-services</key>', '' )
		else
			puts "  ==> iCloud-services repaired : * >> " + cert_info['icloud-svc']
		end
	end

	if capability_used['icloud-dev-id'] != nil and cert_info['icloud-dev-id'].strip == '' and capability_used['icloud-cont-id'] and cert_info['icloud-cont-id'].strip == '' then
		modified_entitlement.sub!( '<key>com.apple.developer.icloud-container-development-container-identifiers</key><array/>', '' )
		modified_entitlement.sub!( '<key>com.apple.developer.icloud-container-identifiers</key><array/>', '' )
		modified_entitlement.sub!( '<key>com.apple.developer.icloud-services</key><string>*</string>', '' )
	end

	if capability_used['icloud-svc'] and cert_info['icloud-env'] == '' then
		modified_entitlement.sub!( '<key>com.apple.developer.icloud-services</key>', '<key>com.apple.developer.icloud-container-environment</key><string>Production</string><key>com.apple.developer.icloud-services</key>' )
	end

	begin
		entitlement = File.open( folder + "entitlements.plist", "w+" )
		entitlement.write modified_entitlement
	rescue => e
		puts ".\n.\nProblem has occurred while modifying entitlement.plist, please try again.\n[Error] " + e.to_s + "\nIf this error occurs continuously, contact AppSealing Help Center.\n.\n.\n"
		exit( false )
	ensure
		entitlement.close unless entitlement.nil?
	end


	#........................................................................................
	# [Step 6] hermes bytecode(main.jsbuncle) 파일이 있을 경우 서버를 통해 암호화 진행

	if File.exist?( app.to_s + "/main.jsbundle" ) then
		encrypt_javascript_bytecode( app )
	end

	#........................................................................................
	# [Step 7] 변경된 파일이 있을 수 있으므로 app을 1차 재서명

	$current_step += 1
	puts "\n" + $current_step.to_s + ". Codesigning your app using certificate used to sign your IPA ..."

	sign_app_payload( app, folder, false )


	#........................................................................................
	# [Step 8] 인증서 정보 추출

	certificate = ""
	certificate += ( "##$##&AI:" + cert_info['app_id'] + "\n" )
	certificate += ( "##$##&TI:" + cert_info['team_id'] + "\n" )


	#........................................................................................
	# [Step 9] Payload/app/_CodeSignature/CodeResources 파일 읽기

	$current_step += 1
	puts "\n" + $current_step.to_s + ". Generating app integrity/certificate snapshot ..."
	snapshot = certificate + generate_hash_snapshot( app.to_s + "/_CodeSignature/CodeResources" )


	#........................................................................................
	# [Step 10] Assets.car 파일 모두 찾기
	assets = ''
	files = Dir.glob( app.to_s + '/**/Assets.car' ).select { |path| File.file?(path) }
	files.each do |car|
		assets += ( car.sub!( app.to_s + '/', '' ) + "\u0002" )
	end
	
	#........................................................................................
	# [Step 11] snapshot & assets를 API 서버로 전송해서 genesis 생성 (ruby에서 WF LEA 수행 불가능)

	$current_step += 1
	puts "\n" + $current_step.to_s + ". Encrypting app integrity/certificate snapshot ..."
	# snapshot과 assets를 hex string 포맷으로 변경
	begin
		snapshot = (snapshot.unpack ( 'H*' )).first
		assets = (assets.unpack ( 'H*' )).first
	rescue => e
		puts ".\n.\nProblem has occurred while storing integrity-snapshot of your app, please try again.\n[Error] " + e.to_s + "\nIf this error occurs continuously, contact AppSealing Help Center.\n.\n.\n"
		exit( false )
	end


	host = $baseURL + 'v3/sdk/ios/requestGenesisForIOS'
	uri = URI( host )
	request = Net::HTTP::Post.new( uri )

	form_data = [
		['account_id_hash', $account_id_hash],
		['bundle_id', $bundle_id], 
		['snapshot', snapshot],
		['assets', assets],
		['sdk_version', $sdk_version]
	]
	request.set_form form_data, 'multipart/form-data'

	begin
		response = Net::HTTP.start( uri.hostname, uri.port, use_ssl: uri.scheme == 'https' ) do |http|
			http.request( request )
		end
		result = JSON.parse( response.body )
		code = result['result']['code']
		message = result['result']['message']
		if code != '0000' then
			puts ".\n.\nError occured : " + message + "\nIf this error occurs continuously, contact AppSealing Help Center.\n.\n.\n"
			puts ".\n.\n error code : " + code + "\n"
			puts message
			exit( false )			
		end
		genesis_response = result['genesis']
	rescue => e
		puts "Request failed : " + e.to_s + "\n.\n.\n"
		exit( false )
	end

	genesis_binary = File.open( app.to_s + '/genesis', "wb" )
	genesis_binary.write([genesis_response].pack( 'H*' ))
	genesis_binary.close()


	#........................................................................................
	# [Step 12] 파라미터로 넘겨진 IPA에서 certificate / entitlement 를 추출하여 codesign 진행

	$current_step += 1
	puts "\n" + $current_step.to_s + ". Codesigning your app using certificate used to sign your IPA ..."
	sign_app_payload( app, folder, false )


	#........................................................................................
	# [Step 13] IPA로 묶음

	$current_step += 1
	puts "\n" + $current_step.to_s + ". Rebuilding & re-sigining IPA ..."
	ipa = '"' + $IPA + '_Resigned.ipa"'
	File.delete( ipa ) if File.exist?( ipa )
	
	ipa = File.basename( $IPA ) + "_Resigned.ipa"
	system( 'cd ' + folder + 'Package;zip -qr "' + ipa + '" ./' )
	system( "rm " + $IPA )
	system( 'mv "' + folder + "Package/" + ipa + '" "' + $IPA + '"' )
	system( "rm -rf " + folder + "*;rmdir " + folder )


	#........................................................................................
	# [Step 14] IPA Upload

    $current_step += 1
	puts "\n" + $current_step.to_s + ". Uploading your app to App Store Connect ..."
	system( 'xcrun altool --upload-app -t ios -f "' + $IPA + '" -u ' + APPLE_ID + ' -p ' + APPLE_APP_PASSWORD )
end

