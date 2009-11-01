#######################################################################
# test_win32ole.rb
#
# Test suite for the pr-win32ole library. You can run these tests via
# the 'rake test' task.
#######################################################################
require 'rubygems'
gem 'test-unit'

require 'pr/win32ole'
require 'socket'
require 'test/unit'

class TC_WIN32OLE < Test::Unit::TestCase
   def self.startup
      @@host = Socket.gethostname      
   end
   
   def setup
      @adsi   = WIN32OLE.connect("WinNT://#{@@host}/guests")
      @ie_app = 'InternetExplorer.Application'
      @ole    = nil
      eval("module IE; end")
   end
   
   def test_version
      assert_equal('1.3.9', WIN32OLE::VERSION)      
   end

   def test_new_server_basic
      assert_respond_to(WIN32OLE, :new)
      assert_nothing_raised{ @ole = WIN32OLE.new }
      assert_kind_of(WIN32OLE, @ole)
   end

   def test_new_server_string
      assert_nothing_raised{ WIN32OLE.new(@ie_app) }
   end

   def test_ole_initialize
      assert_respond_to(WIN32OLE, :ole_initialize)
      assert_nothing_raised{ WIN32OLE.ole_initialize }
   end

   def test_ole_uninitialize
      assert_respond_to(WIN32OLE, :ole_uninitialize)
      assert_nothing_raised{ WIN32OLE.ole_uninitialize }
   end

   def test_const_load_basic
      assert_respond_to(WIN32OLE, :const_load)
   end

   def test_const_load_ole
      @ole = WIN32OLE.new(@ie_app)
      assert_nothing_raised{ WIN32OLE.const_load(@ole, IE) }
   end

   def test_const_load_string
      string = 'Microsoft Internet Controls'
      assert_nothing_raised{ WIN32OLE.const_load(string, IE) }
   end

   def test_ole_reference_count
      @ole = WIN32OLE.new(@ie_app)
      assert_respond_to(WIN32OLE, :ole_reference_count)
      assert_nothing_raised{ WIN32OLE.ole_reference_count(@ole) }
      assert_kind_of(Fixnum, WIN32OLE.ole_reference_count(@ole))
   end

   def test_ole_free
      @ole = WIN32OLE.new(@ie_app)
      assert_respond_to(WIN32OLE, :ole_free)
      assert_nothing_raised{ WIN32OLE.ole_free(@ole) }
      assert_kind_of(Fixnum, WIN32OLE.ole_free(@ole))
   end

   def test_codepage_get
      assert_respond_to(WIN32OLE, :codepage)
      assert_nothing_raised{ WIN32OLE.codepage }
      assert_kind_of(Fixnum, WIN32OLE.codepage)
   end

   def test_codepage_set
      assert_respond_to(WIN32OLE, :codepage)
      assert_nothing_raised{ WIN32OLE.codepage = WIN32OLE::CP_UTF8 }
   end

   def test_code_page_set_expected_errors
      msg =  "codepage should be WIN32OLE::CP_ACP, WIN32OLE::CP_OEMCP, "
      msg << "WIN32OLE::CP_MACCP, WIN32OLE::CP_THREAD_ACP, "
      msg << "WIN32OLE::CP_SYMBOL, WIN32OLE::CP_UTF7, WIN32OLE::CP_UTF8"

      assert_raise(WIN32OLERuntimeError){ WIN32OLE.codepage = 0xFFFFFFFF }
      assert_raise_message(msg){ WIN32OLE.codepage = 0xFFFFFFFF }
   end

   def teardown
      @adsi = nil
      @ole  = nil
      self.class.send(:remove_const, :IE)
   end
   
   def self.shutdown
      @@host = nil
   end
end
