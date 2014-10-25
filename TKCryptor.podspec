# Validate with `pod lib lint TKCryptor.podspec`

Pod::Spec.new do |s|
  s.name             = "TKCryptor"
  s.version          = "0.1.0"
  s.summary          = "AES-CCM encryption and RSA from modulus & exponent "
  s.description      = <<-DESC
                       An optional longer description of TKCryptor
                       DESC
  s.homepage         = "https://github.com/xslim/TKCryptor"
  s.license          = 'MIT'
  s.author           = { "Taras Kalapun" => "t.kalapun@gmail.com" }
  s.source           = { :git => "https://github.com/xslim/TKCryptor.git", :tag => s.version.to_s }


  s.platform     = :ios, '7.0'
  s.requires_arc = true

  s.source_files = 'TKCryptor'

  # s.public_header_files = 'TKCryptor/*.h'
  s.frameworks = 'Security'
end
