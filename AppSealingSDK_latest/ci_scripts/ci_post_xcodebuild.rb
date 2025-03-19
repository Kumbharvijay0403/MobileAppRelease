#!/usr/bin/env ruby

#  ci_post_xcodebuild.sh
#  Copyright © 2025 AppsealingDev. All rights reserved.

require 'pathname'
require 'tmpdir'
require 'securerandom'
require 'net/https'
require 'json'
require 'io/console'
require 'open-uri'
require 'rexml/document'
include REXML

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
			system( "codesign -d --entitlements - --xml " + app + " > " + folder + "entitlements.plist" )

			# genesis에 저장할 인증서 3개 추출
			for i in ['0', '1', '2']
				cmdi = "openssl x509 -inform DER -in " + folder + "codesign" + i + " -noout -nameopt multiline"
				certopt = "no_header,no_version,no_serial,no_signame,no_subject,no_issuer,no_validity,no_pubkey,no_sigdump,no_aux,no_extensions"
				system( cmdi + ",utf8 -subject -issuer -serial -pubkey -text -dates -certopt " + certopt + " > " + folder + "certificate" + i + ".txt" )
				system("openssl rsa -pubin -inform PEM -text -noout < " + folder + "certificate" + i + ".txt > " + folder + "pemformat" + i + ".txt")
			end

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
# PlistManager 클래스는 plist 파일을 관리하는 기능을 제공합니다.
# plist 파일은 XML 형식으로 저장되며, 이 클래스는 파일 읽기, 쓰기, 수정 등의 작업을 수행합니다.
#--------------------------------------------------------------------------------------------
class PlistManager
	def initialize(file_path)
		@file_path = file_path # plist 파일 경로를 인스턴스 변수로 저장
		@doc = nil             # plist 파일의 XML 데이터를 저장할 변수
		load_file              # 파일을 로드하여 XML 문서를 초기화
	end

	# plist 파일을 읽어 XML 문서를 메모리에 로드합니다.
	def load_file
		File.open(@file_path, 'r') do |file|
			@doc = REXML::Document.new(file) # XML 문서 객체 생성
		end
		rescue StandardError => e
		puts "Error loading file: #{e.message}" # 파일 읽기 실패 시 에러 메시지 출력
		exit(false)
	end

	# 현재 메모리에 로드된 XML 문서를 plist 파일에 저장합니다.
	def save_file
		File.open(@file_path, 'w') do |file|
			formatter = REXML::Formatters::Pretty.new(4) # 들여쓰기 4칸 설정
			formatter.compact = true                     # 빈 줄 제거
			formatter.write(@doc, file)
		end

		# 저장된 파일을 다시 읽어와서 XML 선언 부분의 작은따옴표를 큰따옴표로 변환
		content = File.read(@file_path)
		content.gsub!(/<\?xml version='1\.0' encoding='UTF-8'\?>/, '<?xml version="1.0" encoding="UTF-8"?>')
		content.gsub!(/<plist version='1\.0'>/, '<plist version="1.0">')
		File.write(@file_path, content)
	rescue StandardError => e
		puts "Error saving file: #{e.message}"
		exit(false)
	end

	# 특정 key의 값을 업데이트하거나 새로 추가합니다.
	# value가 nil이면 해당 key를 plist에서 제거합니다.
	def update_key(key, value)
		element = REXML::XPath.first(@doc, "//key[text()='#{key}']") # key를 찾음
	
		if value.nil?
		# value가 nil이면 key와 값을 삭제
		remove_key(element) if element
		elsif element
		# key가 존재하면 값 업데이트
		next_element = element.next_element
	
		if next_element && next_element.name == 'string' && value.is_a?(String)
			# 기존 값이 문자열일 경우 업데이트
			next_element.text = value
		elsif next_element && next_element.name == 'array' && value.is_a?(Array)
			# 기존 값이 배열일 경우 교체
			replace_array_values(next_element, value)
		else
			# 기존 값이 다른 타입이면 교체
			replace_value(element, value)
		end
		else
		# key가 없으면 새로 추가
		add_new_key(key, value)
		end
	end
	
	# 특정 key의 값을 읽어옵니다.
	def read(key)
		element = REXML::XPath.first(@doc, "//key[text()='#{key}']")
		return nil unless element
	
		next_element = element.next_element
	
		case next_element.name
		when 'string'
		  next_element.text # 문자열 값을 반환
		when 'array'
		  next_element.elements.map(&:text) # 배열 값을 반환 (각 요소의 텍스트)
		when 'true'
		  true # <true/> 값을 처리
		when 'false'
		  false # <false/> 값을 처리
		else
		  nil # 처리하지 않는 타입의 경우 nil 반환
		end
	end

	def update_url_scheme(new_scheme)
		# Locate CFBundleURLTypes array
		url_types_array = XPath.first(@doc, "//key[text()='CFBundleURLTypes']/following-sibling::array")
		
		if url_types_array
		  # Locate the first dict element in CFBundleURLTypes array
		  dict_element = url_types_array.elements["dict"]
		  if dict_element
			# Locate CFBundleURLSchemes array within the dict
			schemes_key = dict_element.elements["key[text()='CFBundleURLSchemes']"]
			schemes_array = schemes_key&.next_element
	
			if schemes_array && schemes_array.name == "array"
			  # Replace existing schemes with the new scheme
			  schemes_array.elements.each { |e| schemes_array.delete(e) }
			  schemes_array.add_element("string").text = new_scheme
			else
			  # If CFBundleURLSchemes doesn't exist, create it
			  new_schemes_key = Element.new("key")
			  new_schemes_key.text = "CFBundleURLSchemes"
			  new_schemes_array = Element.new("array")
			  new_schemes_array.add_element("string").text = new_scheme
	
			  dict_element.add_element(new_schemes_key)
			  dict_element.add_element(new_schemes_array)
			end
		  else
			puts "No <dict> element found under CFBundleURLTypes."
		  end
		else
		  puts "No CFBundleURLTypes found in the plist."
		end
	end

	# plist 파일의 내용을 콘솔에 출력합니다.
	def print
		puts '======================================================================================================================='
		formatter = REXML::Formatters::Pretty.new(4) # 들여쓰기 4칸 설정
		formatter.compact = true # 빈 줄 제거
		formatter.write(@doc, $stdout) # 콘솔에 출력
		puts # 줄바꿈 추가 (출력 후)
		puts '-----------------------------------------------------------------------------------------------------------------------'
	end

	private
	
	# 기존 key에 문자열 요소를 추가합니다.
	def add_string_element(key_element, value)
	  dict_element = key_element.parent          # 부모 <dict> 요소를 가져옴
	  dict_element.add_element('string').text = value # 새로운 <string> 요소 추가 및 값 설정 
	end

	# Helper 메소드: 특정 key와 그 값을 plist에서 제거합니다.
	def remove_key(key_element)
		return unless key_element
	
		dict_element = key_element.parent          # 부모 <dict> 요소 가져옴
		next_element = key_element.next_element    # 해당 key의 값 요소 (<string>, <array> 등)
	
		dict_element.delete(key_element)           # key 요소 삭제
		dict_element.delete(next_element) if next_element # 값 요소도 함께 삭제
	end
	
	# Helper 메소드: 새로운 key와 값을 plist에 추가합니다.
	def add_new_key(key, value)
		dict_element = REXML::XPath.first(@doc, '//dict')   # 최상위 <dict> 요소 찾기
		return unless dict_element                         # <dict> 요소가 없으면 종료

		key_element = REXML::Element.new('key')            # 새로운 <key> 요소 생성
		key_element.text = key                             # <key>에 텍스트 설정
		dict_element.add_element(key_element)              # <dict>에 <key> 추가

		if value.is_a?(Array)
			array_element = REXML::Element.new('array')      # 배열 값일 경우 <array> 생성
			value.each { |val| array_element.add_element('string').text = val }   # 각 배열 항목 추가
			dict_element.add_element(array_element)          # <dict>에 <array> 추가
		else
			string_element = REXML::Element.new('string')    # 문자열 값일 경우 <string> 생성
			string_element.text = value                      #
			dict_element.add_element(string_element)         # <dict>에 <string> 추가
		end
	end
end

#--------------------------------------------------------------------------------------------
# main
#--------------------------------------------------------------------------------------------
if __FILE__ == $0

	$current_step = 0

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


	system( 'cp ./profile.mobileprovision "' + app + '/embedded.mobileprovision"' )
	APPSEALING_KEYCHAIN = "/Users/local/Library/Keychains/APPSEALING.keychain"
	
	system('security create-keychain -p 0000 ' + APPSEALING_KEYCHAIN)
	system('security list-keychains -d user -s login.keychain ' + APPSEALING_KEYCHAIN)
	system('security import ./AppleWWDRCAG3.cer -k ' + APPSEALING_KEYCHAIN + ' -t cert -A -P ""')
	
	if File.exist?('./distribution.p12')
	  system('security import ./distribution.p12 -k ' + APPSEALING_KEYCHAIN + ' -A -P ""')
	else
	  system('security import ./distribution.cer -k ' + APPSEALING_KEYCHAIN + ' -t cert -A -P ""')
	  system('security import ./private_key.p12 -k ' + APPSEALING_KEYCHAIN + ' -t priv -A -P ""')
	end
	
	system('security default-keychain -d user -s ' + APPSEALING_KEYCHAIN)
	system('security unlock-keychain -p 0000 ' + APPSEALING_KEYCHAIN)
	system('security set-keychain-settings ' + APPSEALING_KEYCHAIN)
	system('security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k 0000 ' + APPSEALING_KEYCHAIN + ' > /dev/null')
	

	# Info.plist 파일을 평문으로 변경
	system( '/usr/libexec/PlistBuddy -x -c \'Print \' "' + app + '/Info.plist" > "' + folder + 'Info.plist"' )
	system( 'cp "' + folder + 'Info.plist" "' + app + '/Info.plist"' )


	# app의 bundle ID 추출
	info_plist_manager = PlistManager.new( app + "/Info.plist" )
	$bundle_id = info_plist_manager.read( "CFBundleIdentifier" )

	# URL scheme 변경
	if $URL_Scheme
		puts "\n --> Changing URL Scheme to : #{$URL_Scheme}"
		info_plist_manager.update_url_scheme( $URL_Scheme )
	end

	if $version
		puts "\n --> Changing version to : #{$version}"
		info_plist_manager.update_key( 'CFBundleShortVersionString', $version )
	end	
	
	
	# ........................................................................................
	# [Step 2] Unreal 앱 AppStore Connect 업로드 오류 해결을 위해 프로퍼티 추가

	# Camera description 변경
	if $CameraDesc
		puts "\n --> Changing NSCameraUsageDescription to : #{$CameraDesc}"
		info_plist_manager.update_key( 'NSCameraUsageDescription', $CameraDesc )
	end	

	info_plist_manager.save_file
	
	#........................................................................................
	# [Step 3] 앱 서명에 사용된 인증서 정보를 읽어 genesis에 추가

	sign_app_payload( app, folder, true )
	
	if !File.exist?( folder + "entitlements.plist" )
		puts "error: Cannon extract entitlements.plist from IPA, try rebuild app..."
		exit( 0 )
	end

	plist_manager = PlistManager.new( folder + "entitlements.plist" )
	# plist_manager.print
	$app_id = plist_manager.read( 'application-identifier' )
	$team_id = $app_id.split('.').first || ""


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
	current_mode = 'none'

	cert_info =
	{
		'subject0' => "",
		'issuer0' => "",
		'serial0' => "",
		'pubkey0' => "",
		'valid_from0' => "",
		'valid_to0' => "",
		'app_id0' => "",
		'team_id0' => "",

		'subject1' => "",
		'issuer1' => "",
		'serial1' => "",
		'pubkey1' => "",
		'valid_from1' => "",
		'valid_to1' => "",
		'app_id1' => "",
		'team_id1' => "",
		
		'subject2' => "",
		'issuer2' => "",
		'serial2' => "",
		'pubkey2' => "",
		'valid_from2' => "",
		'valid_to2' => "",
		'app_id2' => "",
		'team_id2' => ""
	}

	for i in ['0', '1', '2']
		# 인증서를 ASN.1 형식의 public key와 대조하기 위한 PEM 포맷을 snapshot으로 저장
		file = File.open( folder + "pemformat" + i +".txt" )
		file.each_line do |line|
			if line.start_with?( 'Modulus' ) then
				current_mode = 'pubkey' + i
				next
			end
			if line.start_with?('Exponent') then
				current_mode = 'none'
				next
			end
	
			if current_mode == 'pubkey' + i then
				cert_info[current_mode] += line.strip
			end
		end
		file.close unless file.nil?

		#puts cert_info['pubkey' + i]

		# public key 이외의 정보 저장
		file = File.open( folder + "certificate" + i + ".txt" )
		file.each_line do |line|
			if line.start_with?( 'subject=' ) then
				current_mode = 'subject' + i
				next
			end
			if line.start_with?( 'issuer=' ) then
				current_mode = 'issuer' + i
				next
			end
			if line.start_with?( 'serial=' ) then
				cert_info['serial' + i] = line.split( '=' )[1].strip
				next
			end
			if line.start_with?( 'notBefore=' ) then
				cert_info['valid_from' + i] = line.split( '=' )[1].strip
				next
			end
			if line.start_with?( 'notAfter=' ) then
				cert_info['valid_to' + i] = line.split( '=' )[1].strip
				next
			end
			if line.start_with?( '-----BEGIN PUBLIC KEY-----' ) then
				current_mode = 'pubkey' + i
				next
			end
			if line.start_with?( '-----END PUBLIC KEY-----' ) then
				current_mode = 'none'
				next
			end

			# 'Subject' / 'Issuer' 문자열 구성
			if current_mode == 'subject' + i or current_mode == 'issuer' + i then
				key = line.split( '=' )[0].strip
				value = line.split( '=' )[1].strip	
				if key == 'userId' then
					cert_info[current_mode] += ( "/UID=" + value )
				end
				if key == 'commonName' then
					cert_info[current_mode] += ( "/CN=" + value )
				end
				if key == 'organizationalUnitName' then
					cert_info[current_mode] += ( "/OU=" + value )
				end
				if key == 'organizationName' then
					cert_info[current_mode] += ( "/O=" + value )
				end
				if key == 'countryName' then
					cert_info[current_mode] += ( "/C=" + value )
				end
			end

		end
		file.close unless file.nil?

		certificate += ( "##$##&AI" + i + $app_id + "\n" )
		certificate += ( "##$##&TI" + i + $team_id + "\n" )
		certificate += ( "##$##&SJ" + i + cert_info['subject'    + i] + "\n" )
		certificate += ( "##$##&IS" + i + cert_info['issuer'     + i] + "\n" )
		certificate += ( "##$##&SN" + i + cert_info['serial'     + i] + "\n" )
		certificate += ( "##$##&PK" + i + cert_info['pubkey'     + i] + "\n" )
		certificate += ( "##$##&VF" + i + cert_info['valid_from' + i] + "\n" )
		certificate += ( "##$##&VT" + i + cert_info['valid_to'   + i] + "\n" )
	end

	if $antiswizzle == 'enable' then
		certificate += ( "##&##*ASENABLE\n" )
	end
	if $antihook == 'disable' then
		certificate += ( "##&##*AAHDISABLE\n" )
	end

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

