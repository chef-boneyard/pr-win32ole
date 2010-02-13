require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'pr-win32ole'
  spec.version    = '1.0.0'
  spec.authors    = ['Park Heesob', 'Daniel Berger']
  spec.license    = 'Artistic 2.0'
  spec.email      = 'phasis@gmail.com'
  spec.homepage   = 'http://www.rubyforge.org/projects/pure'
  spec.platform   = Gem::Platform::RUBY
  spec.summary    = 'Pure Ruby version of the win32ole library'
  spec.test_files = Dir['test/*.rb']
  spec.has_rdoc   = true
  spec.files      = Dir["**/*"].reject{ |f| f.include?('SVN') || f.include?('git') }
      
  spec.rubyforge_project = 'pure'
  spec.extra_rdoc_files  = ['README', 'CHANGES', 'MANIFEST']
   
  spec.add_development_dependency('test-unit', '>= 2.0.6')
   
  spec.description = <<-EOF
    The pr-win32ole library is a pure Ruby implementation of both the
    win32ole C library that ships as part of the Ruby standard library.
  EOF
end
