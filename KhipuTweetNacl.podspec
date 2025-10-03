Pod::Spec.new do |s|
  s.name    = 'KhipuTweetNacl'
  s.version = '0.1.0'
  s.summary = 'Wrapper Swift para TweetNaCl en C, compatible con EBM (Xcode 26).'
  s.description = 'Incluye C (CTweetNacl) y wrapper Swift (KhipuTweetNacl).'
  s.homepage    = 'https://khipu.com'
  s.license     = { :type => 'MIT', :file => 'LICENSE' }
  s.author      = { 'Khipu' => 'Khipu' }
  s.source      = { :git => 'https://example.com/KhipuTweetNacl.git', :tag => s.version.to_s }

  s.ios.deployment_target = '12.0'
  s.swift_version         = '5.0'
  s.static_framework      = true

  s.subspec 'CTweetNacl' do |ss|
    ss.source_files        = 'Sources/CTweetNacl/*.{h,c}'
    ss.public_header_files = 'Sources/CTweetNacl/ctweetnacl.h'
    ss.pod_target_xcconfig = {
      'DEFINES_MODULE'                => 'YES',
      'CLANG_ENABLE_MODULES'          => 'YES',
      'SWIFT_ENABLE_EXPLICIT_MODULES' => 'YES'
    }
  end

  s.subspec 'Swift' do |ss|
    ss.dependency   'KhipuTweetNacl/CTweetNacl'
    ss.source_files = 'Sources/KhipuTweetNacl/*.swift'
    ss.pod_target_xcconfig = {
      'BUILD_LIBRARY_FOR_DISTRIBUTION' => 'YES',
      'SWIFT_ENABLE_EXPLICIT_MODULES'  => 'YES'
    }
  end

  s.default_subspecs = ['CTweetNacl', 'Swift']
end

