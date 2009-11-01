require 'rake'
require 'rake/testtask'
require 'rbconfig'

desc 'Install the pr-win32ole library'
task :install do
   install_dir = File.join(Config::CONFIG['sitelibdir'], 'pr')
   Dir.mkdir(install_dir) unless File.exists?(install_dir)
   FileUtils.cp('lib/pr/win32ole.rb', install_dir, :verbose => true)
end

desc 'Install the pr-win32ole library as win32ole'
task :install_as_win32ole do
   install_dir = File.join(Config::CONFIG['sitelibdir'], 'pr')
   Dir.mkdir(install_dir) unless File.exists?(install_dir)
   FileUtils.cp('lib/pr/win32ole.rb', Config::CONFIG['sitelibdir'], :verbose => true)
end

desc 'Install the pr-win32ole library as a gem'
task :install_gem do
   ruby 'pr-win32ole.gemspec'
   file = Dir["*.gem"].first
   sh "gem install #{file}"
end

Rake::TestTask.new do |t|
   t.warning = true
   t.verbose = true   
end
