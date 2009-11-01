require 'rubygems'

spec = Gem::Specification.new do |gem|
   gem.name       = 'pr-win32ole'
   gem.version    = '1.0.0'
   gem.authors    = ['Park Heesob', 'Daniel Berger']
   gem.license    = 'Artistic 2.0'
   gem.email      = 'phasis@gmail.com'
   gem.homepage   = 'http://www.rubyforge.org/projects/pure'
   gem.platform   = Gem::Platform::RUBY
   gem.summary    = 'Pure Ruby version of the win32ole library'
   gem.test_files = Dir['test/*.rb']
   gem.has_rdoc   = true
   gem.files      = Dir["**/*"].reject{ |f| f.include?('SVN') }
      
   gem.rubyforge_project = 'pure'
   gem.extra_rdoc_files  = ['README', 'CHANGES', 'MANIFEST']
   
   gem.add_dependency('test-unit', '>= 2.0.2')
   
   gem.description = <<-EOF
      The pr-win32ole library is a pure Ruby implementation of both the
      win32ole C library that ships as part of the Ruby standard library.
   EOF
end

Gem::Builder.new(spec).build
