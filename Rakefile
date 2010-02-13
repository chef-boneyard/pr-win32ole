require 'rake'
require 'rake/testtask'
require 'rbconfig'
include Config

desc 'Install the pr-win32ole library'
task :install do
  install_dir = File.join(CONFIG['sitelibdir'], 'pr')
  Dir.mkdir(install_dir) unless File.exists?(install_dir)
  FileUtils.cp('lib/pr/win32ole.rb', install_dir, :verbose => true)
end

desc 'Install the pr-win32ole library as win32ole'
task :install_as_win32ole do
  install_dir = File.join(CONFIG['sitelibdir'], 'pr')
  Dir.mkdir(install_dir) unless File.exists?(install_dir)
  FileUtils.cp('lib/pr/win32ole.rb', CONFIG['sitelibdir'], :verbose => true)
end

desc 'Cleanup any .gem files'
task :clean do
  Dir['*.gem'].each{ |f| File.delete(f) }
end

namespace 'gem' do
  desc 'Create the pr-win32ole gem'
  task :create => [:clean] do
    spec = eval(IO.read('pr-win32ole.gemspec'))
    Gem::Builder.new(spec).build
  end

  desc 'Install the pr-win32ole gem'
  task :install => [:create] do
    file = Dir["*.gem"].first
    sh "gem install #{file}"
  end
end

Rake::TestTask.new do |t|
  t.warning = true
  t.verbose = true   
end
