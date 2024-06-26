Pod::Spec.new do |s|
  s.name         = "KHTweetNacl"
  s.version      = "1.1.4"
  s.summary      = "TweetNacl wrapper library written in Swift."
  s.description  = <<-DESC
    A Swift wrapper for TweetNacl C library, this is a fork of the original proyect just to be able to set the IOS_DEPLOYMENT_TARGET to 12 to be able to use it as a dependency in other pods.
  DESC
  s.homepage     = "https://github.com/khipu/tweetnacl-swiftwrap"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author             = { "Bitmark Inc" => "support@bitmark.com" }
  s.social_media_url   = "https://twitter.com/bitmarkinc"
  s.ios.deployment_target = "12.0"
  s.source       = { :git => "https://github.com/khipu/tweetnacl-swiftwrap.git", :tag => s.version }
  s.source_files  = "Sources/**/*.{h,c,swift}"
  s.private_header_files = 'Sources/CTweetNacl/include/*.h'
  s.preserve_paths = 'Sources/module.map'
  s.frameworks  = "Foundation"
  s.xcconfig = { 'SWIFT_INCLUDE_PATHS' => '$(PODS_ROOT)/KHTweetNacl/Sources' }
  s.swift_version = "5.0"
end
