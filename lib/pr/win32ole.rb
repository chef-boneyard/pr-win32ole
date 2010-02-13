require 'windows/com'
require 'windows/com/automation'
require 'windows/com/variant'
require 'windows/com/accessibility'
require 'windows/unicode'
require 'windows/error'
require 'windows/national'
require 'windows/registry'
require 'windows/window'
require 'windows/window/message'
require 'windows/msvcrt/buffer'
require 'windows/msvcrt/string'
require 'date'

require 'windows/thread'

include Windows::COM
include Windows::COM::Automation
include Windows::COM::Variant
include Windows::COM::Accessibility
include Windows::Unicode
include Windows::National
include Windows::Registry
include Windows::Error
include Windows::Window
include Windows::Window::Message
include Windows::MSVCRT::Buffer
include Windows::MSVCRT::String

class WIN32OLERuntimeError < RuntimeError
end
   
class WIN32OLE
   
   VERSION = "1.3.9"
   ARGV = []

   CP_ACP = Windows::Unicode::CP_ACP
   CP_OEMCP = Windows::Unicode::CP_OEMCP
   CP_MACCP = Windows::Unicode::CP_MACCP
   CP_THREAD_ACP = Windows::Unicode::CP_THREAD_ACP
   CP_SYMBOL = Windows::Unicode::CP_SYMBOL
   CP_UTF7 = Windows::Unicode::CP_UTF7
   CP_UTF8 = Windows::Unicode::CP_UTF8

   LOCALE_SYSTEM_DEFAULT = Windows::National::LOCALE_SYSTEM_DEFAULT
   LOCALE_USER_DEFAULT = Windows::National::LOCALE_USER_DEFAULT

   LCID_INSTALLED            = 0x00000001
   CP_INSTALLED              = 0x00000001

   @@ole_initialized = false
   @@lcid = LOCALE_SYSTEM_DEFAULT
   @@cp = CP_ACP
   @@nil_to = VT_ERROR
   @@com_hash = {}
   
   IID_IDispatch = [0x00020400,0x0000,0x0000,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46].pack('LSSC8')
   IID_IUnknown = [0x00000000,0x0000,0x0000,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46].pack('LSSC8')
   IID_NULL = [0x00000000,0x0000,0x0000,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00].pack('LSSC8')
   IID_IEnumVARIANT = [0x00020404,0x0000,0x0000,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46].pack('LSSC8')
   IID_IPersistMemory = [0xBD1AE5E0,0xA6AE,0xBD37,0xBD,0x37,0x50,0x42,0x00,0xC1,0x00,0x00].pack('LSSC8')
   IID_IConnectionPointContainer = [0xB196B284,0xBAB4,0x101A,0xB6,0x9C,0x00,0xAA,0x00,0x34,0x1D,0x07].pack('LSSC8')
   IID_IProvideClassInfo = [0xB196B283,0xBAB4,0x101A,0xB6,0x9C,0x00,0xAA,0x00,0x34,0x1D,0x07].pack('LSSC8')
   IID_IProvideClassInfo2 = [0xA6BC3AC0,0xDBAA,0x11CE,0x9D,0xE3,0x00,0xAA,0x00,0x4B,0xB8,0x51].pack('LSSC8')

   ComVtbl = Struct.new(:QueryInterface,:AddRef,:Release,:GetTypeInfoCount,:GetTypeInfo,:Invoke,:GetIDsOfNames)
   Win32OLEIDispatch = Struct.new(:dispatch,:refcount,:obj)
      
   @@QueryInterface = Win32::API::Callback.new('PPP','L',&lambda {|p,riid,ppv|
      if riid == IID_IUnknown || riid == IID_IDispatch
         refcount = 0.chr * 4
         memcpy(refcount,p+4,4)
         refcount = [refcount.unpack('L').first + 1].pack('L')
         memcpy(p+4,refcount,4)
         ppv[0,4] = [p].pack('L')
         return S_OK
      end
      E_NOINTERFACE
   })
   @@AddRef = Win32::API::Callback.new('P','L') {|p|
      refcount = 0.chr * 4
      memcpy(refcount,p+4,4)
      refcount = [refcount.unpack('L').first + 1].pack('L')
      memcpy(p+4,refcount,4)
   }
   @@Release = Win32::API::Callback.new('P','L') {|p|
      dispatch = 0.chr * 12
      memcpy(dispatch,p,12)
      _,refcount,obj = dispatch.unpack('L*')
      refcount -= 1
      memcpy(p+4,[refcount].pack('L'),4)
      u = refcount
      if u == 0
         key = ObjectSpace._id2ref(obj)
         @@com_hash.delete(key)
      end
      u
   }
   @@Invoke = Win32::API::Callback.new('PLPLLPPPP','L') {|p,dispid,riid,lcid,wFlags,pdispparams,pvarResult,pexceptinfo,puArgErr|
      obj = 0.chr * 4
      memcpy(obj,p+8,4)
      obj = ObjectSpace._id2ref(obj.unpack('L').first)
      dispparam = 0.chr * 16
      memcpy(dispparam,pdispparams,16)
      args = dispparam[8,4].unpack('L').first
      parg = []
      for i in 0 ... args
         var = 0.chr * 16
         memcpy(var,dispparam[0,4].unpack('L').first + (args-i-1)*16,16)
         parg[i] = ole_variant2val(var)
      end
      if dispid == DISPID_VALUE
         if wFlags == DISPATCH_METHOD
            dispid = :call
         elsif (wFlags & DISPATCH_PROPERTYGET) != 0
            dispid = :value
         end
      else
         dispid = ObjectSpace._id2ref(dispid)
      end
      v = obj.send(dispid,*parg)
      p = 0.chr * 16
      WIN32OLE.ole_val2variant(v,p)
      pvarResult[0,16] = p
      S_OK
   }
   @@GetIDsOfNames = Win32::API::Callback.new('PPLLLP','L') {|p,riid,sznames,cNames,lcid,pDispID|
      str = 0.chr * 256
      wcscpy(str,sznames)
      pDispID[0,4] = [wide_to_mult(str).to_sym.object_id].pack('L')
      S_OK
   }
   @@GetTypeInfoCount = Win32::API::Callback.new('PP','L') {|p,pct|
      E_NOTIMPL
   }
   @@GetTypeInfo = Win32::API::Callback.new('PLLP','L') {|p,info,lcid,pInfo|
      E_NOTIMPL
   }
   @@installed_lcid_proc = Win32::API::Callback.new('L','L',&lambda { |ptr|
      str = 0.chr * 8
      strcpy(str,ptr)
      if str == @lcid
         @installed = true
         return 0
      end
      1
   })
   @@installed_code_page_proc = Win32::API::Callback.new('L','L',&lambda { |ptr|
      str = 0.chr * 10
      strcpy(str,ptr)
      if str.to_i == @cp
         @installed = true
         return 0
      end
      1
   })
   
   @@com_vtbl = ComVtbl.new(@@QueryInterface,@@AddRef,@@Release,@@GetTypeInfoCount,@@GetTypeInfo,@@GetIDsOfNames,@@Invoke).to_a.map{|x|x.address}.pack('L*')
   
   attr_accessor :pDispatch

   def self.ole_uninitialize
      OleUninitialize()
      @@ole_initialized = false
   end

   def self.ole_initialize
      if !@@ole_initialized
         hr = OleInitialize.call()
         if hr != S_OK
            raise RuntimeError,"fail: OLE initialize"
         end
         @@ole_initialized = true
         at_exit { ole_uninitialize }
      end
   end

   def ole_set_member(dispatch)
      if @pDispatch
         WIN32OLE.ole_release(@pDispatch)
      end
      @pDispatch = dispatch
      self
   end

   def self._ole_free(dispatch)
      if @@ole_initialized
         if dispatch
            WIN32OLE.ole_release(dispatch)
         end
      end
      nil
   end

   def self.ole_release(dispatch)
      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      memcpy(lpVtbl,dispatch,4)
      memcpy(table,lpVtbl.unpack('L').first,28)
      table = table.unpack('L*')
      release = Win32::API::Function.new(table[2],'P','L')
     release.call(dispatch)
   end

   def self.ole_addref(dispatch)
      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      memcpy(lpVtbl,dispatch,4)
      memcpy(table,lpVtbl.unpack('L').first,28)
      table = table.unpack('L*')
      addRef = Win32::API::Function.new(table[1],'P','L')
     addRef.call(dispatch)
   end

   def clsid_from_remote(host,server,clsid)
      hr = S_OK
      hlm = 0.chr * 4
      err = RegConnectRegistry(host, HKEY_LOCAL_MACHINE, hlm)
      if err != ERROR_SUCCESS
         return HRESULT_FROM_WIN32(err)
      end
      subkey = "SOFTWARE\\Classes\\" + server + "\\CLSID"
      hpid = 0.chr * 4
      err = RegOpenKeyEx(hlm, subkey, 0, KEY_READ, hpid)
      if err != ERROR_SUCCESS
         return HRESULT_FROM_WIN32(err)
      else
         len = clsid.length.pack('L')
         dwtype = 0.chr * 4
         clsid2 = 0.chr * 100
         err = RegQueryValueEx(hpid, "", nil, dwtype, clsid2, len)
         if err == ERROR_SUCCESS && dwtype.unpack('L').first == REG_SZ
            hr = CLSIDFromString(multi_to_wide(clsid2), clsid)
         else
            hr = HRESULT_FROM_WIN32(err)
         end
         RegCloseKey(hpid)
      end
      RegCloseKey(hlm)
      hr
   end

   def ole_create_dcom(server,host)
      clsid = 0.chr * 16
      serverw = multi_to_wide(server)
      hostw = multi_to_wide(host)
      hr = CLSIDFromProgID(serverw,clsid)
      if hr != S_OK
         hr = clsid_from_remote(host, server, clsid)
      end
      if hr != S_OK
         hr = CLSIDFromString(serverw,clsid)
      end
      if hr != S_OK
         raise WIN32OLERuntimeError, "unknown OLE server: `#{server}'"
      end
      serverinfo = 0.chr * 16
      serverinfo[4,4] = [hostw].pack('P')
      multi_qi = 0.chr * 12
      multi_qi[0,4] = [IID_IDispatch].pack('P')
      hr = CoCreateInstanceEx(clsid,nil,CLSCTX_REMOTE_SERVER,serverinfo,1,multi_qi)
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to create DCOM server `#{server}' in `#{host}'"
      end
      ole_set_member(multi_qi[4,4].unpack('L').first)
      self
   end

   def self.get_control_from_hwnd(hnd)
      CoInitialize(0)
      reg_msg = RegisterWindowMessage("WM_HTML_GETOBJECT")

      iid =[0x626FC520,0xA41E,0x11CF,0xA7,0x31,0x00,0xA0,0xC9,0x08,0x26,0x37].pack('LSSC8')

      result = 0.chr*4
      hnd = hnd.hex if hnd.is_a?(String)
      SendMessageTimeout(hnd, reg_msg, 0, 0, SMTO_ABORTIFHUNG,1000, result)

      result = result.unpack('L')[0]
      idisp = 0.chr * 4
      r = ObjectFromLresult(result, iid, 0, idisp)
      if r == 0
         idisp = idisp.unpack('L').first
         self.attach(idisp)
      else
         nil
      end      
   end
   
    def self.attach(dispatch)
        obj = self.new.ole_set_member(dispatch)
    end

   # Creates a new Win32::OLE server object on +host+, or the localhost if
   # no host is specified. The +server+ can be either a Program ID or a
   # Class ID.
   #
   # Examples:
   #
   #    # Program ID (Excel)
   #    ole = Win32::OLE.new('Excel.Application')
   #
   #    # Class ID (Excel)
   #    ole = Win32::OLE.new('{00024500-0000-0000-C000-000000000046}')
   #--
   # TODO: explain numeric server and host behavior.
   #
   def initialize(server=nil, host=nil)
      WIN32OLE.ole_initialize()

      @pDispatch = nil

      return self if server.nil?

      if server.is_a?(Numeric)
         ole_set_member(server)
         return self
      end

      if host
         return ole_create_dcom(server, host)
      end

      clsid = 0.chr * 16
      serverw = multi_to_wide(server)

      hr = CLSIDFromProgID(serverw, clsid)

      if hr != S_OK
         hr = CLSIDFromString(serverw, clsid)
      end

      if hr != S_OK
         raise WIN32OLERuntimeError, "unknown OLE server: '#{server}'"
      end

      ptr = 0.chr * 4

      hr = CoCreateInstance(
         clsid,
         nil,
         CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
         IID_IDispatch,
         ptr
      )

      if hr != S_OK
         error = "failed to create WIN32OLE object from '#{server}'"
         raise WIN32OLERuntimeError, error
      end

      ole_set_member(ptr.unpack('L').first)

      self
   end

   def self.ole_bind_obj(moniker)
      pBindCtx = 0.chr * 4
      hr = CreateBindCtx(0, pBindCtx)

      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to create bind context"
      end

      pBindCtx = pBindCtx.unpack('L').first
      monikerw = multi_to_wide(moniker)

      pMoniker = 0.chr * 4
      eaten = 0.chr * 4

      hr = MkParseDisplayName(pBindCtx, monikerw, eaten, pMoniker)

      if hr != S_OK
         WIN32OLE.ole_release(pBindCtx)
         raise WIN32OLERuntimeError, "failed to parse display name of moniker '#{moniker}'"
      end

      pMoniker = pMoniker.unpack('L').first
      lpVtbl = 0.chr * 4
      table = 0.chr * 4 * 23

      memcpy(lpVtbl, pMoniker, 4)
      memcpy(table, lpVtbl.unpack('L').first, 92)

      table = table.unpack('L*')
      ptr = 0.chr * 4

      bindToObject = Win32::API::Function.new(table[8], 'PPPPP', 'L')

      hr = bindToObject.call(pMoniker, pBindCtx, nil, IID_IDispatch, ptr)

      pDispatch = ptr.unpack('L').first
      WIN32OLE.ole_release(pMoniker)
      WIN32OLE.ole_release(pBindCtx)

      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to bind moniker '#{moniker}'"
      end

      self.attach(pDispatch)
   end

   def self.connect(server)
      ole_initialize()
      clsid = 0.chr * 16
      serverw = Windows::Unicode::multi_to_wide(server)
      hr = CLSIDFromProgID(serverw,clsid)
      if hr != S_OK
         hr = CLSIDFromString(serverw,clsid)
      end
      if hr != S_OK
         return ole_bind_obj(server)
      end

      pUnknown = 0.chr * 4
      hr = GetActiveObject(clsid, nil, pUnknown)
      if hr != S_OK
         raise WIN32OLERuntimeError, "OLE server `#{server}' not running"
      end
      pUnknown = pUnknown.unpack('L').first
        lpVtbl = 0.chr * 4
        table = 0.chr * 28
        memcpy(lpVtbl,pUnknown,4)
        memcpy(table,lpVtbl.unpack('L').first,28)
        table = table.unpack('L*')
        queryInterface = Win32::API::Function.new(table[0],'PPP','L')
      p = 0.chr * 4
       hr = queryInterface.call(pUnknown,IID_IDispatch,p)
      if hr != S_OK
         WIN32OLE.ole_release(pUnknown)
         raise WIN32OLERuntimeError, "failed to create WIN32OLE server `#{server}'"
      end
      pDispatch = p.unpack('L').first
      WIN32OLE.ole_release(pUnknown)
      self.attach(pDispatch)
   end

   def self.ary_new_dim(myary,pid,plb,dim)
       ids = Array.new(dim)
       for i in 0 ... dim
           ids[i] = pid[i] - plb[i]
       end
       obj = myary
       pobj = myary
       for i in 0 ... (dim-1)
           obj = pobj[ids[i]]
           if obj.nil?
               pboj[ids[i]] = []
           end
           obj = pobj[ids[i]]
           pobj = pbj
       end
       obj
    end

    def self.ary_store_dim(myary,pid,plb,dim,val)
        id = pid[dim-1] - plb[dim-1]
        obj = ary_new_dim(myary, pid, plb, dim)
        obj[id] = val
    end

   def self.time_object2date(tm)
      jd = Date.civil_to_jd(tm.year,tm.month,tm.mday)
      t = Date.time_to_day_fraction(tm.hour,tm.min,tm.sec).to_f
      t + jd - 2415019
   end

   def val2dispatch(val)
      if (pdisp = @@com_hash[val])
         refcount = data[4,4].unpack('L').first
         pdisp[4,4] = [refcount+1].pack('L')
      else
         pdisp = [@@com_vtbl].pack('P') + [1,val.object_id].pack('L*')     
         @@com_hash[val] = pdisp
      end
      [pdisp].unpack('P').unpack('L').first
   end

   def self.ole_val2variant2(val,var)
      @@nil_to = VT_EMPTY
      ole_val2variant(val,var)
      @@nil_to = VT_ERROR
   end

   def self.ole_val2variant_ex(val,var,vt)
      if val.nil?
         if vt == VT_VARIANT
            ole_val2variant2(val,var)
         else
            var[0,2] = [vt & ~VT_BYREF].pack('S')
            if vt & ~VT_BYREF == VT_DISPATCH
               var[8,4] = [0].pack('L')
            elsif vt & ~VT_BYREF == VT_UNKNOWN
               var[8,4] = [0].pack('L')
            end
         end
         return
      end
      case vt & ~VT_BYREF
      when VT_I8
         var[0,2] = [VT_I8].pack('S')
         var[8,8] = [val].pack('q')
      when VT_UI8
         var[0,2] = [VT_UI8].pack('S')
         var[8,8] = [val].pack('Q')
      else
         ole_val2variant2(val, var)
      end
   end

    def self.dimension(val)
        dim = 0
        if val.is_a?(Array)
            val.each do |x|
                dim1 = dimension(x)
                dim = dim1 if dim < dim1    
            end
            dim += 1
        end
        dim
    end
    
    def self.ary_len_of_dim(ary,dim)
        ary_len = 0
        if dim == 0
            if ary.is_a?(Array)
                ary_len = ary.length
            end
        else
            if ary.is_a?(Array)
                ary.each do |x|
                    ary_len1 = ary_len_of_dim(x,dim-1)
                    ary_len = ary_len1 if ary_len < ary_len1
                end
            end
        end
        ary_len
    end

    def self.ole_ary_m_entry(val,pid)
        obj = val
        i = 0
        while obj.is_a?(Array)
            obj = obj[pid[i]]
            i += 1
        end
        obj
    end
    
    def self.get_ptr_of_variant(pvar)
        case pvar[0,2].unpack('S').first
        when VT_UI1,VT_I2,VT_UI2,VT_I4,VT_UI4,VT_R4,VT_R8,VT_I8,VT_UI8,VT_INT,VT_UINT,VT_CY,VT_DATE,
             VT_ERROR,VT_BOOK,VT_ARRAY        
            return [pvar].pack('P').unpack('L').first + 8
        when VT_BSTR,VT_DISPATCH,VT_UNKNOWN
            return pvar[8,4].unpack('L').first
        else
            return 0
        end
    end

    def self.val2variant_ptr(val,var,vt)
        ole_val2variant_ex(val,var,vt)
        if (vt & ~VT_BYREF) == VT_VARIANT
            p = var
        else
            if (vt & ~VT_BYREF) != var[0,2].unpack('S').first 
                hr = VariantChangeTypeEx(var, var, 
                        @@lcid, 0, vt & ~VT_BYREF)
                if hr != S_OK
                    raise RuntimeError, "failed to change type"
                end
            end
            p = get_ptr_of_variant(var)
        end
        if p.nil?
            raise RuntimeError, "failed to get pointer of variant"
        end
        p
    end

    def self.is_all_index_under(pid,pub,dim)
        for i in 0 ... dim
            return false if pid[i] > pub[i]
        end
        true
    end

    def self.ole_set_safe_array(n,psa,pid,pub,val,dim,vt)
        var = 0.chr * 16
        i = n
        while i >= 0
            val1 = ole_ary_m_entry(val, pid)
            VariantInit(var)
            p = val2variant_ptr(val1,var,vt)
            if is_all_index_under(pid, pub, dim) == true
                vvt = var[0,2].unpack('S').first 
                dispatch = var[8,4].unpack('L').first
                if (vvt == VT_DISPATCH || vvt == VT_UNKNOWN) && dispatch == 0
                    raise WIN32OLERuntimeError, "element of array does not have IDispatch or IUnknown Interface"
                end
                hr = SafeArrayPutElement(psa, pid.pack('L*'), p)
            end
            if hr != S_OK
                raise RuntimeError, "failed to SafeArrayPutElement"
            end
            pid[i] += 1
            if pid[i] > pub[i]
                pid[i] = 0
                i -= 1
            else
                i = dim - 1
            end
        end
    end

    def self.ole_val_ary2variant_ary(val,var,vt)
        unless val.is_a?(Array)
            raise TypeError, "1st parameter must be Array"
        end
        
        dim = dimension(val)
        psab = 0.chr * 8 * dim
        pub = Array.new(dim)
        pid = Array.new(dim)
        
        for i in 0 ... dim
            psab[i*8,4] = [ary_len_of_dim(val,i)].pack('L')
            psab[i*8+4,4] = 0.chr * 4
            pub[i] = psab[i*8,4].unpack('L').first - 1
            pid[i] = 0
        end
        
        if (vt & ~VT_BYREF) == VT_ARRAY
            vt = (vt | VT_VARIANT)
        end
        psa = SafeArrayCreate(vt & VT_TYPEMASK,dim,psab)
        if psa == 0
            hr = E_OUTOFMEMORY
        else
            hr = SafeArrayLock(psa)
        end
        if hr == S_OK
            ole_set_safe_array(dim-1,psa,pid,pub,val,dim,vt & VT_TYPEMASK)
            hr = SafeArrayUnlock(psa)
        end
        if hr == S_OK
            var[0,2] = [vt].pack('S')
            var[8,4] = [psa].pack('L')
        else
            if psa != 0
                SafeArrayDestroy(psa)
            end           
        end
        hr
    end

   def self.ole_val2variant(val,var)
      if val.is_a?(WIN32OLE)
         ole_addref(val.pDispatch)
         var[0,2] = [VT_DISPATCH].pack('S')
         var[8,4] = [val.pDispatch].pack('L')
         return
      end
      if val.is_a?(WIN32OLE_VARIANT)
         VariantCopy(var,val.var)
         return
      end

      if val.is_a?(Time)
         var[0,2] = [VT_DATE].pack('S')
         var[8,8] = [time_object2date(val)].pack('d')
         return
      end
      
      case val
      when Array
         ole_val_ary2variant_ary(val,var,VT_VARIANT|VT_ARRAY)
      when String
         var[0,2] = [VT_BSTR].pack('S')
         var[8,4] = [SysAllocString(multi_to_wide(val,WIN32OLE.codepage))].pack('L')
      when Fixnum
         var[0,2] = [VT_I4].pack('S')
         var[8,4] = [val].pack('L')
      when Bignum
         var[0,2] = [VT_R8].pack('S')
         var[8,8] = [val].pack('d')
      when Float
         var[0,2] = [VT_R8].pack('S')
         var[8,8] = [val].pack('d')
      when TrueClass
         var[0,2] = [VT_BOOL].pack('S')
         var[8,2] = [VARIANT_TRUE].pack('S')
      when FalseClass
         var[0,2] = [VT_BOOL].pack('S')
         var[8,2] = [VARIANT_FALSE].pack('S')
      when NilClass
         if @@nil_to == VT_ERROR
            var[0,2] = [VT_ERROR].pack('S')
            var[8,4] = [DISP_E_PARAMNOTFOUND].pack('L')
         else
            var[0,2] = [VT_EMPTY].pack('S')
         end
      else
         var[0,2] = [VT_DISPATCH].pack('S')
         var[8,4] = [val2dispatch(val)].pack('L')
      end
   end

   def self.ole_variant2val(pvar)
       val = nil
       var = 0.chr * 16
       memcpy(var,pvar,16)
       var = var.unpack('SSSSLL')
       while var[0]== (VT_BYREF | VT_VARIANT)
           pvar = var[4]
          var = 0.chr * 16
          memcpy(var,pvar,16)
          var = var.unpack('SSSSLL')
       end
       if (var[0] & VT_ARRAY) != 0
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               psa = ptr.unpack('L').first
           else
               psa = var[4]
           end
           return val if psa == 0

           dim = SafeArrayGetDim(psa)
           variant = 0.chr * 16
           VariantInit(variant)
           variant[0,2] = (var[0] & ~VT_ARRAY) | VT_BYREF
           pid = Array.new(dim)
           plb = Array.new(dim)
           pub = Array.new(dim)

           for i in 0 ... dim
               v = 0.chr * 4
               SafeArrayGetLBound(psa,i+1,v)
               plb[i] = v.unpack('L').first
               v = 0.chr * 4
               SafeArrayGetLBound(psa,i+1,v)
               pid[i] = v.unpack('L').first
               v = 0.chr * 4
               SafeArrayGetUBound(psa,i+1,v)
               pub[i] = v.unpack('L').first
           end
           hr = SafeArrayLock(psa)
           if hr == S_OK
               val = []
               i = 0
               while i < dim
                   ary_new_dim(val, pid, plb, dim)
                   ref = 0.chr * 4
                   hr = SafeArrayPtrOfIndex(psa, pid, ref)
                   variant[4,4] = ref
                   if hr == S_OK
                       v = ole_variant2val([variant].pack('P').unpack('L').first)
                       ary_store_dim(val, pid, plb, dim, v)
                   end
                   for i in 0 ... dim
                       pid[i] += 1
                       break if pid[i] <= pub[i]
                       pid[i] = plb[i]
                   end
               end
               SafeArrayUnlock(psa)
           end
           return val
       end

       case var[0] & ~VT_BYREF
       when VT_EMPTY,VT_NULL
           val = nil
       when VT_I1
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               val = ptr.unpack('c').first
           else
               val = [var[4]].pack('L').unpack('c').first
           end
       when VT_UI1
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               val = ptr.unpack('C').first
           else
               val = [var[4]].pack('L').unpack('C').first
           end
       when VT_I2
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               val = ptr.unpack('s').first
           else
               val = [var[4]].pack('L').unpack('s').first
           end
       when VT_UI2
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               val = ptr.unpack('S').first
           else
               val = [var[4]].pack('L').unpack('S').first
           end
       when VT_I4
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               val = ptr.unpack('i').first
           else
               val = [var[4]].pack('L').unpack('i').first
           end
       when VT_UI4
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               val = ptr.unpack('L').first
           else
               val = var[4]
           end
       when VT_INT
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               val = ptr.unpack('i').first
           else
               val = [var[4]].pack('L').unpack('i').first
           end
       when VT_UINT
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               val = ptr.unpack('L').first
           else
               val = var[4]
           end
       when VT_I8
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 8
               memcpy(ptr,var[4],8)
               val = ptr.unpack('q').first
           else
               val = [var[4],var[5]].pack('LL').unpack('q').first
           end
       when VT_UI8
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 8
               memcpy(ptr,var[4],8)
               val = ptr.unpack('Q').first
           else
               val = [var[4],var[5]].pack('LL').unpack('Q').first
           end
       when VT_R4
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               val = ptr.unpack('f').first
           else
               val = [var[4]].pack('L').unpack('f').first
           end
       when VT_R8
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 8
               memcpy(ptr,var[4],8)
               val = ptr.unpack('d').first
           else
               val = [var[4],var[5]].pack('LL').unpack('d').first
           end
       when VT_BSTR
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
            ptr.unpack('L').first
            str = 0.chr * 256
            wcscpy(str,ptr.unpack('L').first)
            val = wide_to_multi(str,WIN32OLE.codepage)
           else
            str = 0.chr * 256
            wcscpy(str,var[4])
            val = wide_to_multi(str,WIN32OLE.codepage)
           end
       when VT_ERROR
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               val = ptr.unpack('L').first
           else
               val = var[4]
           end
       when VT_BOOL
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               val = ptr.unpack('S').first != 0
           else
               val = [var[4]].pack('L').unpack('S').first != 0
           end
       when VT_DISPATCH
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               pDispatch = ptr.unpack('L').first
           else
               pDispatch = var[4]
           end
           if pDispatch != 0
            ole_addref(pDispatch)
            val = WIN32OLE.new(pDispatch)
         end
       when VT_UNKNOWN
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 4
               memcpy(ptr,var[4],4)
               punk = ptr.unpack('L').first
           else
               punk = var[4]
           end
         if punk != 0
            lpVtbl = 0.chr * 4
            table = 0.chr * 28
            memcpy(lpVtbl,punk,4)
            memcpy(table,lpVtbl.unpack('L').first,28)
            table = table.unpack('L*')
            p = 0.chr * 4
            queryInterface = Win32::API::Function.new(table[0],'PPP','L')
            hr = queryInterface.call(punk,IID_IDispatch,p)
            if hr == S_OK
               pDispatch = p.unpack('L').first
               val = WIN32OLE.new(pDispatch)
            end
         end
       when VT_DATE
           if (var[0] & VT_BYREF) != 0
               ptr = 0.chr * 8
               memcpy(ptr,var[4],8)
               date = ptr.unpack('d').first
           else
               date = [var[4],var[5]].pack('LL').unpack('d').first
           end
         d = date.to_i
           t = date - d
         yy,mm,dd = Date.jd_to_civil(2415019+d)
         hh,mi,ss = Date.day_fraction_to_time(t)
         val = "%04d/%02d/%02d %02d:%02d:%02d" % [yy,mm,dd,hh,mi,ss]
      else
         variant = 0.chr * 16
         VariantInit(variant)
         hr = VariantChangeTypeEx(variant,var,@@lcid,0,VT_BSTR)
         var = variant.unpack('SSSSLL')
         if hr == S_OK && var[0] == VT_BSTR
            str = 0.chr * 256
            wcscpy(str,var[4])
            val = wide_to_multi(str)
         end
         VariantClear(variant)
       end

       val
    end

   def self.ole_types_from_typelib(pTypeLib,classes)
      lpVtbl = 0.chr * 4
      table = 0.chr * 56
      memcpy(lpVtbl,pTypeLib,4)
      memcpy(table,lpVtbl.unpack('L').first,40)
      table = table.unpack('L*')
      getTypeInfoCount = Win32::API::Function.new(table[3],'P','L')
      getTypeInfo = Win32::API::Function.new(table[4],'PLP','L')
      getDocumentation = Win32::API::Function.new(table[9],'PLPPPP','L')
      count = getTypeInfoCount.call(pTypeLib)
      for i in 0 ... count
         bstr = 0.chr * 4
         hr = getDocumentation.call(pTypeLib,i,bstr,nil,nil,nil)
         next if hr != S_OK

         p = 0.chr * 4
         hr = getTypeInfo.call(pTypeLib,i,p)
         next if hr != S_OK

         pTypeInfo = p.unpack('L').first
         type = WIN32OLE_TYPE.new
         str = 0.chr * 256
         wcscpy(str,bstr.unpack('L').first)
         type.oletype_set_member(pTypeInfo,wide_to_multi(str))
         classes.push(type)
         ole_release(pTypeInfo)
      end
      classes
   end

   def self.oleclass_from_typelib(obj,pTypeLib,oleclass)
      found = false
      lpVtbl = 0.chr * 4
      table = 0.chr * 56
      memcpy(lpVtbl,pTypeLib,4)
      memcpy(table,lpVtbl.unpack('L').first,40)
      table = table.unpack('L*')
      getTypeInfoCount = Win32::API::Function.new(table[3],'P','L')
      getTypeInfo = Win32::API::Function.new(table[4],'PLP','L')
      getDocumentation = Win32::API::Function.new(table[9],'PLPPPP','L')
      count = getTypeInfoCount.call(pTypeLib)
      for i in 0 ... count
         break if found
         p = 0.chr * 4
         hr = getTypeInfo.call(pTypeLib,i,p)
         next if hr != S_OK
         pTypeInfo = p.unpack('L').first
         bstr = 0.chr * 4
         hr = getDocumentation.call(pTypeLib,i,bstr,nil,nil,nil)
         next if hr != S_OK
         str = 0.chr * 256
         wcscpy(str,bstr.unpack('L').first)
         typelib = wide_to_multi(str)
         if oleclass == typelib
            obj.oletype_set_member(pTypeInfo,typelib)
            found = true
         end
         ole_release(pTypeInfo)
      end
      found
   end
   
   def self.ole_const_load(pTypeLib,mod)
      constant = {}
      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      memcpy(lpVtbl,pTypeLib,4)
      memcpy(table,lpVtbl.unpack('L').first,28)
      table = table.unpack('L*')
      getTypeInfoCount = Win32::API::Function.new(table[3],'P','L')
      getTypeInfo = Win32::API::Function.new(table[4],'PLP','L')
      count = getTypeInfoCount.call(pTypeLib)
      for index in 0 ... count
         p = 0.chr * 4
         hr = getTypeInfo.call(pTypeLib,index, p)
         next if hr != S_OK
         pTypeInfo = p.unpack('L').first
         lpVtbl = 0.chr * 4
         table = 0.chr * 88
         memcpy(lpVtbl,pTypeInfo,4)
         memcpy(table,lpVtbl.unpack('L').first,88)
         table = table.unpack('L*')
         getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
         getVarDesc = Win32::API::Function.new(table[6],'PLP','L')
         getNames = Win32::API::Function.new(table[7],'PLPLP','L')
         releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
         releaseVarDesc = Win32::API::Function.new(table[21],'PP','L')
         p = 0.chr * 4
         hr = getTypeAttr.call(pTypeInfo,p)
         if hr != S_OK
            WIN32OLE.ole_release(pTypeInfo)
            next
         end
         pTypeAttr = p.unpack('L').first
         typeAttr = 0.chr * 76
         memcpy(typeAttr,pTypeAttr,76)
         for iVar in 0 ... typeAttr[46,2].unpack('S').first
             p = 0.chr * 4
            getVarDesc.call(pTypeInfo,iVar,p)
            pVarDesc = p.unpack('L').first
             next if hr != S_OK
             varDesc = 0.chr * 36
             memcpy(varDesc,pVarDesc,36)
             if varDesc[32,4].unpack('L').first == VAR_CONST &&
               (varDesc[28,2].unpack('S').first & (VARFLAG_FHIDDEN |
                 VARFLAG_FRESTRICTED | VARFLAG_FNONBROWSABLE))==0
                 len = 0.chr * 4
                 bstr = 0.chr * 4
                 hr = getNames.call(pTypeInfo,varDesc[0,4].unpack('L').first,bstr,1,len)
                 if hr != S_OK || len.unpack('L').first == 0 ||
                  bstr.unpack('L').first == 0
                     next
                 end
                 bstr = bstr.unpack('L').first
                 str = 0.chr * 256
                 wcscpy(str,bstr)
               SysFreeString(bstr)  
                 pName = wide_to_multi(str)
               pName[0,1] = pName[0,1].upcase
               var = 0.chr * 16
               memcpy(var,varDesc[8,4].unpack('L').first,16)
                 val = ole_variant2val(var)
                 if pName[0,1].between?('A','Z')
                     mod.const_set(pName.to_sym,val)
                 else
                     constant[pName] = val
                 end
             end
             releaseVarDesc.call(pTypeInfo, pVarDesc)
          end
          releaseTypeAttr.call(pTypeInfo, pTypeAttr)
          WIN32OLE.ole_release(pTypeInfo)
      end
      mod.const_set("CONSTANTS",constant)
   end

   #  Defines a constant of an OLE Automation server as a +mod+ constant.
   #  The +ole+ argument is WIN32OLE object or type library name. The
   #  +mod+ argument is a class or module name, which defaults to WIN32OLE
   #  if omitted.
   #
   #  The first letter of a Ruby constant is always upper case. Therefore,
   #  a constant name of WIN32OLE object is capitalized. For example, the
   #  'xlTop' constant of Excel is changed to 'XlTop' in WIN32OLE.
   #
   #  If the first letter of an OLE constant is not in the A-Z range, then
   #  the constant must be referenced via the CONSTANTS hash variable.
   #
   #  Example:
   #
   #     module EXCEL_CONST; end
   #
   #     excel = WIN32OLE.new('Excel.Application')
   #
   #     WIN32OLE.const_load(excel, EXCEL_CONST)
   #
   #     puts EXCEL_CONST::XlTop # => -4160
   #     puts EXCEL_CONST::CONSTANTS['_xlDialogChartSourceData'] # => 541
   #     
   #     WIN32OLE.const_load(excel)
   #     puts WIN32OLE::XlTop # => -4160
   #
   #     module MSO; end
   #
   #     WIN32OLE.const_load('Microsoft Office 9.0 Object Library', MSO)
   #     puts MSO::MsoLineSingle # => 1
   # 
   def self.const_load(ole, mod=WIN32OLE)
      unless [Class, Module].include?(mod.class)
         raise TypeError, '2nd parameter must be Class or Module'
      end

      if ole.is_a?(WIN32OLE)
         pDispatch = ole.pDispatch
         lpVtbl = 0.chr * 4
         table  = 0.chr * 28

         memcpy(lpVtbl, pDispatch, 4)
         memcpy(table, lpVtbl.unpack('L').first, 28)

         table = table.unpack('L*')

         ptr = 0.chr * 4

         getTypeInfo = Win32::API::Function.new(table[4], 'PLLP', 'L')
         hr = getTypeInfo.call(pDispatch, 0, @@lcid, ptr)

         if hr != S_OK
            raise RuntimeError, 'failed to GetTypeInfo'
         end

         pTypeInfo = ptr.unpack('L').first
         lpVtbl = 0.chr * 4
         table  = 0.chr * 88

         memcpy(lpVtbl, pTypeInfo,4)
         memcpy(table, lpVtbl.unpack('L').first, 88)

         table = table.unpack('L*')
         getContainingTypeLib = Win32::API::Function.new(table[18], 'PPP', 'L')

         ptr = 0.chr * 4
         index = 0.chr * 4
         hr = getContainingTypeLib.call(pTypeInfo, ptr, index)

         if hr != S_OK
            WIN32OLE.ole_release(pTypeInfo)
            raise RuntimeError, 'failed to GetContainingTypeLib'
         end

         pTypeLib = ptr.unpack('L').first
         WIN32OLE.ole_release(pTypeInfo)
         ole_const_load(pTypeLib, mod)
         WIN32OLE.ole_release(pTypeLib)
      elsif ole.is_a?(String)
         file = WIN32OLE_TYPELIB.typelib_file(ole)
         file = ole if file.nil?

         buf = multi_to_wide(file)
         p = 0.chr * 4

         hr = LoadTypeLibEx.call(buf, REGKIND_NONE, p)
         pTypeLib = p.unpack('L').first

         if hr != S_OK
            raise WIN32OLERuntimeError, "failed to LoadTypeLibEx"
         end

         if mod
            ole_const_load(pTypeLib, mod)
         else
            ole_const_load(pTypeLib, WIN32OLE)
         end

         WIN32OLE.ole_release(pTypeLib)
      else
         raise TypeError, "1st parameter must be WIN32OLE instance"
      end

      nil
   end

   # Invokes the Release() method of the Dispatch interface of the WIN32OLE
   # object. It returns the reference counter of the OLE object.
   #
   # This method is used for debugging only.
   #
   def self.ole_free(obj)
      if obj.pDispatch
         if ole_reference_count(obj) > 0
            n = WIN32OLE.ole_release(obj.pDispatch)
         end
      end

      n
   end

   # Returns the reference counter of the Dispatch interface of the WIN32OLE
   # object.
   #
   # This method is used for debugging only.
   #
   def self.ole_reference_count(obj)
      n = 0

      if obj.pDispatch
         ole_addref(obj.pDispatch)
         n = ole_release(obj.pDispatch)
      end

      n
   end

   def self.ole_show_help(info, helpcontext=nil)
      if info.is_a?(WIN32OLE_TYPE) || info.is_a?(WIN32OLE_METHOD)
         helpfile = info.helpfile

         if helpfile == ''
            name = info.name
            raise RuntimeError, "no helpfile of '#{name}'"
         end

         helpcontext = info.helpcontext
      else
         helpfile = info
      end

      unless helpfile.is_a?(String)
         raise TypeError, "1st parameter must be (String|WIN32OLE_TYPE|WIN32OLE_METHOD)"
      end

      hwnd = 0

      begin
         htmlHelpA = Win32::API.new('HtmlHelpA', 'LPLL', 'L', 'HHCtrl.ocx')
         hwnd = htmlHelpA.call(GetDesktopWindow(), helpfile, 0xF, helpcontext)
         if hwnd == 0
            hwnd = htmlHelpA.call(GetDesktopWindow(), helpfile, 0, helpcontext)
         end
      rescue Win32::API::LoadLibraryError
      end

      if hwnd == 0
         raise RuntimeError, "failed to open help file `#{helpfile}'"
      end

      nil
   end

   private

   def self.code_page_installed(cp)
      @cp = cp
      @installed = false
      EnumSystemCodePages(@@installed_code_page_proc, CP_INSTALLED)
      @installed
   end

   public

   # Returns the current code page.
   #
   # Example:
   #
   #    WIN32OLE.codepage # => WIN32OLE::CP_ACP
   #
   def self.codepage
      @@cp
   end

   def self.ole_cp2encoding(cp)
      # TODO
      nil
   end

   # Sets the current code page. The code page must be an installed code page
   # or one of the following values:
   #
   # WIN32OLE::CP_ACP
   # WIN32OLE::CP_OEMCP
   # WIN32OLE::CP_MACCP
   # WIN32OLE::CP_THREAD_ACP
   # WIN32OLE::CP_SYMBOL
   # WIN32OLE::CP_UTF7
   # WIN32OLE::CP_UTF8
   #
   # Example:
   #
   #    WIN32OLE.codepage = WIN32OLE::CP_UTF8
   #--
   # TODO: What is load_conv_function51932?
   #
   def self.codepage=(cp)
      if code_page_installed(cp)
         @@cp = cp
      else
         case cp
         when CP_ACP, CP_OEMCP, CP_MACCP, CP_THREAD_ACP,
              CP_SYMBOL, CP_UTF7, CP_UTF8, 51932
         then
            @@cp = cp
            if cp == 51932
               load_conv_function51932()
            end
         else
            msg =  "codepage should be WIN32OLE::CP_ACP, WIN32OLE::CP_OEMCP, "
            msg << "WIN32OLE::CP_MACCP, WIN32OLE::CP_THREAD_ACP, "
            msg << "WIN32OLE::CP_SYMBOL, WIN32OLE::CP_UTF7, WIN32OLE::CP_UTF8"
            raise WIN32OLERuntimeError, msg
         end
      end
      @@enc = ole_cp2encoding(@@cp)
      nil
   end

   def self.locale
      @@lcid
   end

   def self.lcid_installed(lcid)
      @installed = false
      @lcid = "%08x" % lcid
      EnumSystemLocales(@@installed_lcid_proc, LCID_INSTALLED)
      @installed
   end

   def self.locale=(lcid)
      if lcid_installed(lcid)
         @@lcid = lcid
      else
         case lcid
         when LOCALE_SYSTEM_DEFAULT,LOCALE_USER_DEFAULT
            @@lcid = lcid
         else
            raise WIN32OLERuntimeError, "not installed locale: #{lcid}"
         end
      end
      nil
   end

   def self.create_guid
      guid = 0.chr * 16
      hr = CoCreateGuid(guid)
      if hr != S_OK
         raise = WIN32OLERuntimeError, "failed to create GUID"
      end
      bstr = 0.chr * 160
      len = StringFromGUID2(guid,bstr,80)
      if len == 0
         raise RuntimeError, "failed to create GUID(buffer over)"
      end
      wide_to_multi(bstr)
   end

   def set_argv(realargs,st,ed)
      argv = WIN32OLE::ARGV
      argv.clear
      while (ed-=1) > st
         argv.push(WIN32OLE.ole_variant2val(realargs[ed*16,16]))
         p = realargs[ed*16,16]
         VariantClear(p)
         realargs[ed*16,16] = p
      end
      argv
   end

   def ole_excepinfo2msg(execinfo)
      source = nil
      description = nil
      code,_,src,desc,helpfile,helpconext,_,fillin,scode = execinfo.unpack('SSLLLLLLL')
      if fillin != 0
         fnDeferredFillIn = Win32::API::Function.new(fillin,'P','L')
         fnDeferredFillIn.call(execinfo)
      end
      if src != 0
         str = 0.chr * 256
         wcscpy(str,src)
         source = wide_to_multi(str)
      end
      if desc != 0
         str = 0.chr * 256
         wcscpy(str,desc)
         description = wide_to_multi(str)
      end
      if code == 0
         error_msg = "\n    OLE error code:%X in " % scode
      else
         error_msg = "\n    OLE error code:%u in " % code
      end
      if source
         error_msg << source
      else
         error_msg << "<Unknown>"
      end
      error_msg << "\n      "
      if description
         error_msg << description
      else
         error_msg << "<No Description>"
      end
      error_msg
   end

   def ole_propertyput(property,value)
      dispIDParam = [DISPID_PROPERTYPUT].pack('L')
      wFlags = DISPATCH_PROPERTYPUT|DISPATCH_PROPERTYPUTREF
      dispParams = 0.chr * 16
      propertyValue = 0.chr * 32
      argErr = 0.chr * 4
   
      p = propertyValue[0,16]
      VariantInit(p)
      propertyValue[0,16] = p
      p = propertyValue[16,16]
      VariantInit(p)
      propertyValue[16,16] = p
      excepinfo = 0.chr * 32

      wproperty = multi_to_wide(property)
      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      memcpy(lpVtbl,@pDispatch,4)
      memcpy(table,lpVtbl.unpack('L').first,28)
      table = table.unpack('L*')
      getIDsOfNames = Win32::API::Function.new(table[5],'PPPLLP','L')
      invoke = Win32::API::Function.new(table[6],'PLPLLPPPP','L')
      p = 0.chr * 4
      hr = getIDsOfNames.call(@pDispatch,IID_NULL,[wproperty].pack('P'),1,@@lcid,p)
      dispid = p.unpack('L').first
      if hr != S_OK
         raise WIN32OLERuntimeError,"unknown property or method: `#{property}'"
      end

      p = propertyValue[0,16]
      WIN32OLE.ole_val2variant(value,p)
      propertyValue[0,16] = p
      dispParams[4,4] = [dispIDParam].pack('P')
      dispParams[0,4] = [propertyValue].pack('P')
      dispParams[8,4] = [1].pack('L')
      dispParams[12,4] = [1].pack('L')
      hr = invoke.call(@pDispatch,dispid,IID_NULL,@@lcid,wFlags,dispParams,nil,excepinfo,argErr)
      cArgs = dispParams[8,4].unpack('L').first
      for index in 0 ... cArgs
         p = propertyValue[index*16,16]
         VariantClear(p)
         propertyValue[index*16,16] = p
      end
      if hr != S_OK
         v = ole_excepinfo2msg(excepinfo)
         raise WIN32OLERuntimeError, "(in setting property `#{property}': )#{v}"
      end
      nil
   end

   def ole_invoke2(dispid,args,types,dispkind)
      unless args.is_a?(Array)
         raise TypeError, "wrong argument type #{args.class} (excepted Array)"
      end
      unless types.is_a?(Array)
         raise TypeError, "wrong argument type #{types.class} (excepted Array)"
      end
      result = 0.chr * 16
      excepinfo = 0.chr * 32
      dispParams = 0.chr * 16
      VariantInit(result)
      dispParams[8,4] = [args.length].pack('L')
      rgvarg = 0.chr * 16 * args.length
      dispParams[0,4] = [rgvarg].pack('P')
      realargs = 0.chr * 16 * args.length
      j = args.length
      for i in 0 ... args.length
         j-=1
         p = realargs[i*16,16]
         VariantInit(p)
         realargs[i*16,16] = p
         p = rgvarg[i*16,16]
         VariantInit(p)
         rgvarg[i*16,16] = p
         vt = types[j]
         rgvarg[i*16,2] = [vt].pack('S')
         param = args[j]
         if param.nil?
            rgvarg[i*16,2] = realargs[i*16,2] = [VT_ERROR].pack('S')
            rgvarg[i*16+8,4] = realargs[i*16+8,4] = [DISP_E_PARAMNOTFOUND].pack('L')
         else
            if (vt & VT_ARRAY) != 0
               unless param.is_a?(Array)
                  raise TypeError, "wrong argument type #{param.class} (excepted Array)"
               end
               rgsabound = [param.length,0].pack('LL')
               v = vt & ~(VT_ARRAY | VT_BYREF)
               realargs[i*16+8,4] = [SafeArrayCreate(v, 1, rgsabound)].pack('L')
               realargs[i*16,2] = [VT_ARRAY | v].pack('S')
               SafeArrayLock(realargs[i*16+8,4].unpack('L').first)
               arr = 0.chr * 12
               memcpy(arr,realargs[i*16+8,4].unpack('L').first,12)
               pb = arr[12,4].unpack('L').first
               for ent in 0 ... param.length
                  velem = 0.chr * 16
                  elem = param[ent]
                  WIN32OLE.ole_val2variant(elem,velem)
                  if v != VT_VARIANT
                     VariantChangeTypeEx(velem,velem,@@lcid,0,v)
                  end
                  case v
                  when VT_VARIANT
                     memcpy(pb,velem,16)
                     pb += 16
                  when VT_R8,VT_CY,VT_DATE
                     memcpy(pb,velem[8,8],8)
                     pb += 8
                  when VT_BOOL,VT_I2,VT_UI2
                     memcpy(pb,velem[8,2],2)
                     pb += 2
                  when VT_UI1,VT_I1
                     memcpy(pb,vleme[8,1],1)
                     pb += 1
                  else
                     memcpy(pb,vleme[8,4],4)
                     pb += 4
                  end
               end
               SafeArrayUnlock(realargs[i*16+8,4].unpack('L').first)
            else
               p = realargs[i*16,16]
               WIN32OLE.ole_val2variant(param,p)
               realargs[i*16,16] = p
               if vt & ~VT_BYREF != VT_VARIANT
                  p = realargs[i*16,16]
                  hr = VariantChangeTypeEx(p,p,@@lcid,0,vt & ~VT_BYREF)
                  realargs[i*16,16] = p
                  if hr != S_OK
                     raise TypeError, "not valid value"
                  end
               end
            end
            if (vt & VT_BYREF) != 0 || vt == VT_VARIANT
               if vt == VT_VARIANT
                  rgvarg[i*16,2] = [VT_VARIANT | VT_BYREF].pack('S')
               end
               case vt & ~VT_BYREF
               when VT_VARIANT
                  rgvarg[i*16+8,4] = [realargs[i*16,16]].pack('P')
               when VT_R8,VT_CY,VT_DATE
                  rgvarg[i*16+8,4] = [realargs[i*16+8,8]].pack('P')
               when VT_BOOL,VT_I2,VT_UI2
                  rgvarg[i*16+8,4] = [realargs[i*16+8,4]].pack('P')
               when VT_UI1,VT_I1
                  rgvarg[i*16+8,4] = [realargs[i*16+8,1]].pack('P')
               else
                  rgvarg[i*16+8,4] = [realargs[i*16+8,4]].pack('P')
               end
            else
               rgvarg[i*16+8,4] = [realargs[i*16+8,8]].pack('P')
            end
         end
      end
      dispParams[0,4] = [rgvarg].pack('P')

      if (dispkind & DISPATCH_PROPERTYPUT) != 0
         dispParams[12,4] = [1].pack('L')
         dispParams[4,4] = [DISPID_PROPERTYPUT].pack('L')
      end

      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      memcpy(lpVtbl,@pDispatch,4)
      memcpy(table,lpVtbl.unpack('L').first,28)
      table = table.unpack('L*')
      invoke = Win32::API::Function.new(table[6],'PLPLLPPPP','L')
      argErr = 0.chr * 4
      hr = invoke.call(@pDispatch,dispid,IID_NULL,@@lcid,dispkind,dispParams,result,excepinfo,argErr)
      if hr != S_OK
         v = ole_excepinfo2msg(excepinfo)
         raise WIN32OLERuntimeError, "(in OLE method `<dispatch id:#{dispid}>': #{v})"
      end
      cArgs = dispParams[8,4].unpack('L').first
      if cArgs > 0
         set_argv(realargs, 0, cArgs)
      end

      obj = WIN32OLE.ole_variant2val(result)
      VariantClear(result)
      obj
   end

   def ole_invoke(method,args,flags,is_bracket)
      excepinfo = 0.chr * 32
      result = 0.chr * 16
      VariantInit(result)
      dp = 0.chr * 16
      argErr = 0.chr * 4
      if !method.is_a?(String) && !method.is_a?(Symbol) && !is_bracket
         raise TypeError, "method is wrong type (expected String or Symbol)"
      end
      if method.is_a?(Symbol)
         method = method.to_s
      end
      if @pDispatch.nil?
         raise RuntimeError, "failed to get dispatch interface"
      end
      if is_bracket
         dispid = DISPID_VALUE
         args.unshift(method)
      else
         wcmdname = multi_to_wide(method)
         lpVtbl = 0.chr * 4
         table = 0.chr * 28
         memcpy(lpVtbl,@pDispatch,4)
         memcpy(table,lpVtbl.unpack('L').first,28)
         table = table.unpack('L*')
         getIDsOfNames = Win32::API::Function.new(table[5],'PPPLLP','L')
         p = 0.chr * 4
         hr = getIDsOfNames.call(@pDispatch,IID_NULL,[wcmdname].pack('P'),1,@@lcid,p)
         dispid = p.unpack('L').first
         if hr != S_OK
            raise WIN32OLERuntimeError,"unknown property or method: `#{method}'"
         end
      end

      param = args[-1]
      dp[12,4] = [0].pack('L')
      if param.is_a?(Hash)
         cNamedArgs = param.length
         cArgs = cNamedArgs + args.length - 1
         rgvarg = 0.chr * 16 * cArgs
         dp[8,4] = [cArgs].pack('L')
         pNamedArgs = 0.chr * 4 * (cNamedArgs+1)
         index = 0
         param.each do |key,val|
            if !key.is_a?(String) && !key.is_a?(Symbol)
               for i in 1 .. index
                  VariantClear(rgvarg[i*4,4].unpack('L').first)
               end
               raise TypeError, "wrong argument type (expected String or Symbol)"
            end
            if key.is_a?(Symbol)
               key = key.to_s
            end
            pNamedArgs[(index+1)*4,4] = [multi_to_wide(key)].pack('P')
            p = rgvarg[index*16,16]
            VariantInit(p)
            rgvarg[index*16,16] = p
            p = rgvarg[index*16,16]
            WIN32OLE.ole_val2variant(val,p)
            rgvarg[index*16,16] = p
            index += 1
         end
         dp[12,4] = [index].pack('L')
         pDispID = 0.chr * 4 * (cNamedArgs+1)
         pNamedArgs[0,4] = [multi_to_wide(method)].pack('P')
         hr = getIDsOfNames.call(@pDispatch,IID_NULL,pNamedArgs,cNamedArgs+1,@@lcid,pDispID)
         if hr != S_OK
            for i in 0 ... cArgs
               p = rgvarg[i*16,16]
               VariantClear(p)
               rgvarg[i*16,16] = p
            end
            raise WIN32OLERuntimeError, "failed to get named argument info: `#{method}'"
         end
         dp[4,4] = [[pDispID].pack('P').unpack('L').first + 4].pack('L')
      else
         cNamedArgs = 0
         cArgs = args.length
         dp[8,4] = [cArgs].pack('L')
         pNamedArgs = 0.chr * 4 * (cNamedArgs + 1)
         if cArgs > 0
            rgvarg = 0.chr * 16 * cArgs
         end
      end
      if cArgs > cNamedArgs
         realargs = 0.chr * 16 * (cArgs - cNamedArgs + 1)
         for i in cNamedArgs ... cArgs
            n = cArgs - i + cNamedArgs - 1
            p = realargs[n*16,16]
            VariantInit(p)
            realargs[n*16,16] = p
            p = rgvarg[n*16,16]
            VariantInit(p)
            rgvarg[n*16,16] = p
            param = args[i-cNamedArgs]
            if param.is_a?(WIN32OLE_VARIANT)
               p = rgvarg[n*16,16]
               VariantCopy(p,param.var)
               rgvarg[n*16,16] = p
            else
               p = realargs[n*16,16]
               WIN32OLE.ole_val2variant(param,p)
               realargs[n*16,16] = p
               rgvarg[n*16,2] = [VT_VARIANT | VT_BYREF].pack('S')
               rgvarg[n*16+8,4] = [[realargs].pack('P').unpack('L').first + n*16].pack('L')              
               rgvarg[n*16,16] = p
            end
         end
      end
      dp[0,4] = [rgvarg].pack('P')
      if (flags & DISPATCH_PROPERTYPUT) != 0
         if cArgs == 0
            raise WIN32OLERuntimeError, "argument error"
         end
         dp[12,4] = [1].pack('L')
         rgdispidNamedArgs = [DISPID_PROPERTYPUT].pack('L')
         dp[4,4] = [rgdispidNamedArgs].pack('P')
      end
      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      memcpy(lpVtbl,@pDispatch,4)
      memcpy(table,lpVtbl.unpack('L').first,28)
      table = table.unpack('L*')
      invoke = Win32::API::Function.new(table[6],'PLPLLPPPP','L')
      hr = invoke.call(@pDispatch,dispid,IID_NULL,@@lcid,flags,dp,result,excepinfo,argErr)      
      if hr != S_OK
         cArgs = dp[8,4].unpack('L').first
         if cArgs >= cNamedArgs
            for i in cNamedArgs ... cArgs
               n = cArgs - i + cNamedArgs - 1
               param = args[i-cNamedArgs]
               p = rgvarg[n*16,16]
               WIN32OLE.ole_val2variant(param,p)
               rgvarg[n*16,16] = p
            end
            dp[0,4] = [rgvarg].pack('P')
            excepinfo = 0.chr * 32
            VariantInit(result)
            hr = invoke.call(@pDispatch,dispid,IID_NULL,@@lcid,flags,dp,result,excepinfo,argErr)
            if (hr & DISP_E_EXCEPTION == DISP_E_EXCEPTION || hr & DISP_E_MEMBERNOTFOUND == DISP_E_MEMBERNOTFOUND) && dispid > 0x8000
               excepinfo = 0.chr * 32
               hr = invoke.call(@pDispatch,dispid,IID_NULL,@@lcid,flags,dp,nil,excepinfo,argErr)
            end
            cArgs = dp[8,4].unpack('L').first
            for i in cNamedArgs ... cArgs
               n = cArgs - i + cNamedArgs - 1
               p = rgvarg[n*16,16]
               VariantClear(p)
               rgvarg[n*16,16] = p
            end
         end
         if hr != S_OK
            if cArgs > cNamedArgs
               for i in cNamedArgs ... cArgs
                  n = cArgs - i + cNamedArgs - 1
                  param = args[i-cNamedArgs]
                  p = rgvarg[n*16,16]
                  WIN32OLE.ole_val2variant2(param,p)
                  rgvarg[n*16,16] = p
               end
               dp[0,4] = [rgvarg].pack('P')
               excepinfo = 0.chr * 32
               VariantInit(result)
               hr = invoke.call(@pDispatch,dispid,IID_NULL,@@lcid,flags,dp,result,excepinfo,argErr)
               cArgs = dp[8,4].unpack('L').first
               for i in cNamedArgs ... cArgs
                  n = cArgs - i + cNamedArgs - 1
                  p = rgvarg[n*16,16]
                  VariantClear(p)
                  rgvarg[n*16,16] = p
               end
            end
         end
      end

      if cArgs > cNamedArgs
         for i in cNamedArgs ... cArgs
            n = cArgs - i + cNamedArgs - 1
            param = args[i-cNamedArgs]
            if param.is_a?(WIN32OLE_VARIANT)
               p = realargs[n*16,16]
               WIN32OLE.ole_val2variant(param,p)
               realargs[n*16,16] = p
            end
         end
         set_argv(realargs,cNamedArgs,cArgs)
      else
         for i in 0 ... cArgs
            p = rgvarg[i*16,16]
            VariantClear(p)
            rgvarg[i*16,16] = p
         end
      end

      if hr != S_OK
         v = ole_excepinfo2msg(excepinfo)
         raise WIN32OLERuntimeError, "(in OLE method `#{method}': #{v})"
      end
      obj = WIN32OLE.ole_variant2val(result)
      VariantClear(result)
      obj
   end

   def invoke(method, *args)
      ole_invoke(method,args,DISPATCH_METHOD|DISPATCH_PROPERTYGET, false)
   end

   def [](method,*args)
      #ole_invoke(method,args,DISPATCH_PROPERTYGET, true)
      ole_invoke(method,args,DISPATCH_PROPERTYGET, false)
   end

   def _invoke(dispid, args, types)
       ole_invoke2(dispid,args,types,DISPATCH_METHOD)
   end

   def _getproperty(dispid, args, types)
      ole_invoke2(dispid, args, types, DISPATCH_PROPERTYGET)
   end

   def _setproperty(dispid, args, types)
      ole_invoke2(dispid, args, types, DISPATCH_PROPERTYPUT)
   end

   def []=(method,*args)
      #ole_invoke(method, args, DISPATCH_PROPERTYPUT, true)
      ole_invoke(method, args, DISPATCH_PROPERTYPUT, false)
   end

   def ole_free
      WIN32OLE._ole_free(@pDispatch)
      @pDispatch = nil
      nil
   end

   def each(&blk)
      raise ArgumentError, "no block" unless block_given?
      result = 0.chr * 16
      dispParams = 0.chr * 16
      excepinfo = 0.chr * 32
      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      argErr = 0.chr * 4
      memcpy(lpVtbl,@pDispatch,4)
      memcpy(table,lpVtbl.unpack('L').first,28)
      table = table.unpack('L*')
      invoke = Win32::API::Function.new(table[6],'PLPLLPPPP','L')
      hr = invoke.call(@pDispatch,DISPID_NEWENUM,IID_NULL,@@lcid,DISPATCH_METHOD | DISPATCH_PROPERTYGET,dispParams,result,excepinfo,argErr)
      if hr != S_OK
         VariantClear(result)
         raise WIN32OLERuntimeError, "failed to get IEnum Interface"
      end
      if [VT_UNKNOWN,VT_DISPATCH].include?(result[0,2].unpack('S').first)
         pUnknown = result[8,4].unpack('L').first
         lpVtbl = 0.chr * 4
         table = 0.chr * 28
         memcpy(lpVtbl,pUnknown,4)
         memcpy(table,lpVtbl.unpack('L').first,28)
         table = table.unpack('L*')
         p = 0.chr * 4
         queryInterface = Win32::API::Function.new(table[0],'PPP','L')
         hr = queryInterface.call(pUnknown,IID_IEnumVARIANT,p)
         pEnum = p.unpack('L').first
      end
      if hr != S_OK || pEnum == 0
         VariantClear(result)
         raise RuntimeError, "failed to get IEnum Interface"
      end

      VariantClear(result)
      begin
          variant = 0.chr * 16
          VariantInit(variant)
         lpVtbl = 0.chr * 4
         table = 0.chr * 16
         memcpy(lpVtbl,pEnum,4)
         memcpy(table,lpVtbl.unpack('L').first,16)
         table = table.unpack('L*')
         next_ = Win32::API::Function.new(table[3],'PLPP','L')
         while next_.call(pEnum,1,variant,nil) == S_OK
            obj = WIN32OLE.ole_variant2val(variant)
            VariantClear(variant)
            VariantInit(variant)
            yield obj
         end
      ensure
         WIN32OLE.ole_release(pEnum)
      end
      nil
   end

   def method_missing(id,*args)
      method = id.to_s
      if method[-1] == ?=     
         method = method[0..-2]
         return ole_propertyput(method,args.first)
      else
         return ole_invoke(method, args, DISPATCH_METHOD|DISPATCH_PROPERTYGET, false)
      end
   end

   def setproperty(property, *args)
      ole_invoke(property, args, DISPATCH_PROPERTYPUT, false)
   end

   def typeinfo_from_ole(ppti)
      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      memcpy(lpVtbl,@pDispatch,4)
      memcpy(table,lpVtbl.unpack('L').first,28)
      table = table.unpack('L*')
      getTypeInfo = Win32::API::Function.new(table[4],'PLLP','L')
      p = 0.chr * 4
      hr = getTypeInfo.call(@pDispatch,0,@@lcid,p)
      if hr != S_OK
         raise rb_eRuntimeError, "failed to GetTypeInfo"
      end
      pTypeInfo = p.unpack('L').first
      lpVtbl = 0.chr * 4
      table = 0.chr * 80
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,80)
      table = table.unpack('L*')
        getDocumentation = Win32::API::Function.new(table[12],'PLPPPP','L')
      getContainingTypeLib = Win32::API::Function.new(table[18],'PPP','L')
      bstr = 0.chr * 4
      hr = getDocumentation.call(pTypeInfo,-1,bstr,nil,nil,nil)
      str = 0.chr * 256
      wcscpy(str,bstr.unpack('L').first)
      type = wide_to_multi(str)
      p = 0.chr * 4
      i = 0.chr * 4
      hr = getContainingTypeLib.call(pTypeInfo,p,i)
      WIN32OLE.ole_release(pTypeInfo)
      if hr != S_OK
         raise RuntimeError, "failed to GetContainingTypeLib"
      end
      pTypeLib = p.unpack('L').first
      lpVtbl = 0.chr * 4
      table = 0.chr * 40
      memcpy(lpVtbl,pTypeLib,4)
      memcpy(table,lpVtbl.unpack('L').first,40)
      table = table.unpack('L*')
      getTypeInfoCount = Win32::API::Function.new(table[3],'P','L')
      getTypeInfo = Win32::API::Function.new(table[4],'PLP','L')
      getDocumentation = Win32::API::Function.new(table[9],'PLPPPP','L')
      count = getTypeInfoCount.call(pTypeLib)
      for i in 0 ... count
         bstr = 0.chr * 4
         hr = getDocumentation.call(pTypeLib,i,bstr,nil,nil,nil)
         if hr == S_OK
            str = 0.chr * 256
            wcscpy(str,bstr.unpack('L').first)
            if wide_to_multi(str) == type
               p = 0.chr * 4
               hr = getTypeInfo.call(pTypeLib,i,p)
               if hr == S_OK
                  ppti[0,4] = p
                  break
               end
            end
         end
      end
      WIN32OLE.ole_release(pTypeLib)
      hr
   end

   def self.ole_methods_sub(pOwnerTypeInfo,pTypeInfo,methods,mask)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      getNames = Win32::API::Function.new(table[7],'PLPLP','L')
      getDocumentation = Win32::API::Function.new(table[12],'PLPPPP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to GetTypeAttr"
      end
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      for i in 0 .. typeAttr[44,2].unpack('S').first
         p = 0.chr * 4
         hr = getFuncDesc.call(pTypeInfo,i,p)
         next if hr != S_OK
         pFuncDesc = p.unpack('L').first
         funcDesc = 0.chr * 52
         memcpy(funcDesc,pFuncDesc,52)
         memid = funcDesc[0,4].unpack('L').first
         bstr = 0.chr * 4
         hr = getDocumentation.call(pTypeInfo,memid,bstr,nil,nil,nil)
         if hr != S_OK
            releaseFuncDesc.call(pTypeInfo,pFuncDesc)
            next
         end
         if (funcDesc[16,4].unpack('L').first & mask) != 0
            str = 0.chr * 256
            wcscpy(str,bstr.unpack('L').first)
            method = WIN32OLE_METHOD.new
            method.olemethod_set_member(pTypeInfo,pOwnerTypeInfo,i,wide_to_multi(str))
            methods.push(method)
         end
         releaseFuncDesc.call(pTypeInfo,pFuncDesc)
         pFuncDesc = nil
      end
      releaseTypeAttr.call(pTypeInfo, pTypeAttr)
      methods
   end

   def self.ole_methods_from_typeinfo(pTypeInfo,mask)
      methods = []
      lpVtbl = 0.chr * 4
      table = 0.chr * 80
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,80)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      getRefTypeOfImplType = Win32::API::Function.new(table[8],'PLP','L')
      getRefTypeInfo = Win32::API::Function.new(table[14],'PLP','L')
      getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      getDocumentation = Win32::API::Function.new(table[12],'PLPPPP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to GetTypeAttr"
      end
      ole_methods_sub(0, pTypeInfo, methods, mask)
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      for i in 0 ... typeAttr[48,2].unpack('S').first
         p = 0.chr * 4
         hr = getRefTypeOfImplType.call(pTypeInfo, i, p)
         next if hr != S_OK
         href = p.unpack('L').first
         p = 0.chr * 4
         hr = getRefTypeInfo.call(pTypeInfo, href,p)
         next if hr != S_OK
         pRefTypeInfo = p.unpack('L').first
         ole_methods_sub(pTypeInfo,pRefTypeInfo,methods,mask)
         ole_release(pRefTypeInfo)
      end
      releaseTypeAttr.call(pTypeInfo, pTypeAttr)
      methods
   end

   def _ole_methods(mask)
      methods = []
      p = 0.chr * 4
      hr = typeinfo_from_ole(p)
      pTypeInfo = p.unpack('L').first
      if hr != S_OK
         return methods
      end
      methods.concat(WIN32OLE.ole_methods_from_typeinfo(pTypeInfo, mask))
      WIN32OLE.ole_release(pTypeInfo)
      methods
   end

   def ole_methods
      _ole_methods(INVOKE_FUNC | INVOKE_PROPERTYGET | INVOKE_PROPERTYPUT | INVOKE_PROPERTYPUTREF)
   end

   def ole_get_methods
      _ole_methods(INVOKE_PROPERTYGET)
   end

   def ole_put_methods
      _ole_methods(INVOKE_PROPERTYPUT|INVOKE_PROPERTYPUTREF)
   end

   def ole_func_methods
      _ole_methods(INVOKE_FUNC)
   end

   def ole_method(cmdname)
      unless cmdname.is_a?(String)
         raise TypeError, "1st parameter must be String"
      end
      p = 0.chr * 4
      hr = typeinfo_from_ole(p)
      if hr != S_OK
         rasie RuntimeError, "failed to get ITypeInfo"
      end
      pTypeInfo = p.unpack('L').first
      method = WIN32OLE_METHOD.new
      obj = method.olemethod_from_typeinfo(pTypeInfo, cmdname)
      WIN32OLE.ole_release(pTypeInfo)
      if obj.nil?
          raise WIN32OLERuntimeError, "not found #{cmdname}"
       end
       obj
   end
   alias :ole_method_help :ole_method

   def ole_activex_initialize
        lpVtbl = 0.chr * 4
        table = 0.chr * 28
        memcpy(lpVtbl,@pDispatch,4)
        memcpy(table,lpVtbl.unpack('L').first,28)
        table = table.unpack('L*')
        queryInterface = Win32::API::Function.new(table[0],'PPP','L')
      p = 0.chr * 4
       hr = queryInterface.call(pUnknown,IID_IPersistMemory,p)
      pPersistMemory = p.unpack('L').first
      if hr == S_OK
         lpVtbl = 0.chr * 4
         table = 0.chr * 36
         memcpy(lpVtbl,@pDispatch,4)
         memcpy(table,lpVtbl.unpack('L').first,36)
         table = table.unpack('L*')
         initNew = Win32::API::Function.new(table[8],'P','L')
         hr = initNew.call(pPersistMemory)
         WIN32OLE.ole_release(pPersistMemory)
         return nil if hr == S_OK
      end
      if hr != S_OK
         raise WIN32OLERuntimeError, "fail to initialize ActiveX control"
      end
      nil
   end

   def self.ole_type_from_itypeinfo(pTypeInfo)
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      pTypeInfo = 0.chr * 4
      getContainingTypeLib = Win32::API::Function.new(table[18],'PPP','L')
      getDocumentation = Win32::API::Function.new(table[12],'PLPPPP','L')
      p = 0.chr * 4
      i = 0.chr * 4
      getContainingTypeLib.call(pTypeInfo, p, i)
      return nil if hr != S_OK
      pTypeLib = p.unpack('L').first
      index = i.unpack('L').first
      bstr = 0.chr * 4
      hr = getDocumentation.call(pTypeLib,index,bstr,nil,nil,nil)
      WIN32OLE.ole_release(pTypeLib)
      return nil if hr != S_OK
      str = 0.chr * 256
      wcscpy(str,bstr.unpack('L').first)
      type = WIN32OLE_TYPE.new
      type.oletype_set_member(pTypeInfo,wide_to_multi(str))
      type
   end

   def ole_type
      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      memcpy(lpVtbl,@pDispatch,4)
      memcpy(table,lpVtbl.unpack('L').first,28)
      table = table.unpack('L*')
      pTypeInfo = 0.chr * 4
      getTypeInfo = Win32::API::Function.new(table[4],'PLLP','L')
      hr = getTypeInfo.call(pDispatch,0,@lcid,pTypeInfo)
      if hr != S_OK
         raise RuntimeError, "failed to GetTypeInfo"
      end
      pTypeInfo = pTypeInfo.unpack('L').first
      type = ole_type_from_itypeinfo(pTypeInfo)
      WIN32OLE.ole_release(pTypeInfo)
      if type.nil?
         riase RuntimeError, "failed to create WIN32OLE_TYPE obj from ITypeInfo"
      end
      type
   end
   alias :ole_obj_help :ole_type

   def self.ole_typelib_from_itypelib(pTypeLib)
      guid = nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 52
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,52)
      table = table.unpack('L*')
      getLibAttr = Win32::API::Function.new(table[7],'PP','L')
      releaseTLibAttr = Win32::API::Function.new(table[12],'PP','L')
      p = 0.chr * 4
      hr = getLibAttr.call(pTypeLib,p)
      return nil if hr != S_OK
      pTLibAttr = p.unpack('L').first
      tLibAttr = 0.chr * 32
      bstr = 0.chr * 160
      memcpy(tLibAttr,pTLibAttr,32)
      len = StringFromGUID2(pTLibAttr,bstr,80)
      if len > 3
         guid = wide_to_multi(bstr)
      end
      major,minor = tLibAttr[24,4].unpack('SS')
      releaseTLibAttr.call(pTypeLib, pTLibAttr)
      return nil if guid.nil?
      WIN32OLE_TYPELIB.new(guid,major,minor)
   end

   def self.ole_typelib_from_itypeinfo(pTypeInfo)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getContainingTypeLib = Win32::API::Function.new(table[18],'PPP','L')
      p = 0.chr * 4
      index = 0.chr * 4
      getContainingTypeLib.call(pTypeInfo, p, index)
      return nil if hr != S_OK
      pTypeLib = p.unpack('L').first
      retval = WIN32OLE.ole_typelib_from_itypelib(pTypeLib)
      WIN32OLE.ole_release(pTypeLib)
      retval
   end

   def ole_typelib
      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      memcpy(lpVtbl,@pDispatch,4)
      memcpy(table,lpVtbl.unpack('L').first,28)
      table = table.unpack('L*')
      getTypeInfo = Win32::API::Function.new(table[4],'PLLP','L')
      p = 0.chr * 4
      hr = getTypeInfo.call(pDispatch,0,@lcid,p)
      if hr != S_OK
         raise RuntimeError, "failed to GetTypeInfo"
      end
      pTypeInfo = p.unpack('L').first
      vtlib = ole_typelib_from_itypeinfo(pTypeInfo)
      WIN32OLE.ole_release(pTypeInfo)
      if vtlib.nil?
         raise RuntimeError, "failed to get type library info."
      end
      vtlib
   end

   def ole_query_interface(iid)
      pBuf = multi_to_wide(iid)
      id = 0.chr * 16
      hr = CLSIDFromString(pBuf,id)
      if hr != S_OK
         raise WIN32OLERuntimeError, "invalid iid: `#{iid}'"
      end
      if @pDispatch.nil?
         raise RuntimeError, "failed to get dispatch interface"
      end
        lpVtbl = 0.chr * 4
        table = 0.chr * 28
        memcpy(lpVtbl,@pDispatch,4)
        memcpy(table,lpVtbl.unpack('L').first,28)
        table = table.unpack('L*')
        queryInterface = Win32::API::Function.new(table[0],'PPP','L')
      p = 0.chr * 4
      hr = queryInterface.call(@pDispatch,id,p)
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to get interface `#{iid}'"
      end
      pDispatch = p.unpack('L').first
      WIN32OLE.new(pDispatch)
   end

   def ole_respond_to?(method)
      if !method.is_a?(String) && !method.is_a?(Symbol)
         raise TypeError, "wrong argument type (expected String or Symbol)"
      end
      method = method.to_s if method.is_a?(Symbol)
      wcmdname = multi_to_wide(method)
      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      memcpy(lpVtbl,@pDispatch,4)
      memcpy(table,lpVtbl.unpack('L').first,28)
      table = table.unpack('L*')
      getIDsOfNames = Win32::API::Function.new(table[5],'PPPLLP','L')
      p = 0.chr * 4
      hr = getIDsOfNames.call(@pDispatch,IID_NULL,[wcmdname].pack('P'),1,@@lcid,p)
      hr == S_OK
   end

   module VARIANT
      VT_EMPTY = Windows::COM::VT_EMPTY
      VT_NULL = Windows::COM::VT_NULL
      VT_I2 = Windows::COM::VT_I2
      VT_I4 = Windows::COM::VT_I4
      VT_R4 = Windows::COM::VT_R4
      VT_R8 = Windows::COM::VT_R8
      VT_CY = Windows::COM::VT_CY
      VT_DATE = Windows::COM::VT_DATE
      VT_BSTR = Windows::COM::VT_BSTR
      VT_USERDEFINED = Windows::COM::VT_USERDEFINED
      VT_PTR = Windows::COM::VT_PTR
      VT_DISPATCH = Windows::COM::VT_DISPATCH
      VT_ERROR = Windows::COM::VT_ERROR
      VT_BOOL = Windows::COM::VT_BOOL
      VT_VARIANT = Windows::COM::VT_VARIANT
      VT_UNKNOWN = Windows::COM::VT_UNKNOWN
      VT_I1 = Windows::COM::VT_I1
      VT_UI1 = Windows::COM::VT_UI1
      VT_UI2 = Windows::COM::VT_UI2
      VT_UI4 = Windows::COM::VT_UI4
      VT_I8 = Windows::COM::VT_I8
      VT_UI8 = Windows::COM::VT_UI8
      VT_INT = Windows::COM::VT_INT
      VT_UINT = Windows::COM::VT_UINT
      VT_ARRAY = Windows::COM::VT_ARRAY
      VT_BYREF = Windows::COM::VT_BYREF
   end
end

class WIN32OLE_TYPELIB

   def self.reg_open_key(hkey,name,phkey)
      RegOpenKeyEx(hkey, name, 0, KEY_READ, phkey)
   end

   def self.reg_open_vkey(hkey,key,phkey)
      reg_open_key(hkey, key, phkey)
   end

   def self.reg_enum_key(hkey, i)
      buf = 0.chr * 256
      size_buf = [256].pack('L')
      err = RegEnumKeyEx(hkey, i, buf, size_buf, nil, nil, nil, nil)
      if(err == ERROR_SUCCESS)
         return buf.strip
      end
      nil
   end

   def self.reg_get_val(hkey,subkey)
      dwtype = 0.chr * 4
      size = 0.chr * 4
      val = nil
      err = RegQueryValueEx(hkey, subkey, nil, dwtype, nil, size)
      if (err == ERROR_SUCCESS)
         pbuf = 0.chr * (size.unpack('L').first + 1)
         err = RegQueryValueEx(hkey, subkey, nil, dwtype, pbuf, size)
         if (err == ERROR_SUCCESS)
            val = pbuf.strip
         end
      end
      val
   end

   def self.reg_get_val2(hkey,subkey)
      val = nil
      hsubkey = 0.chr * 4
      err = RegOpenKeyEx(hkey, subkey, 0, KEY_READ, hsubkey)
      if (err == ERROR_SUCCESS)
         hsubkey = hsubkey.unpack('L').first
         val = reg_get_val(hsubkey, nil)
         RegCloseKey(hsubkey)
      end
      if val.nil?
         val = reg_get_val(hkey, subkey)
      end
      val
   end

   def self.typelibs
      typelibs = []
      typelib = nil
      htypelib    = [0].pack('L')
      err = reg_open_key(HKEY_CLASSES_ROOT, "TypeLib", htypelib)
      return typelibs if err != ERROR_SUCCESS
      i = 0    
      htypelib = htypelib.unpack('L').first
      while true
         guid = reg_enum_key(htypelib, i)
         break if guid.nil?
         hguid = 0.chr * 4
         err = reg_open_vkey(htypelib, guid, hguid)
         if err != ERROR_SUCCESS
           i += 1
           next
         end
         j = 0
         hguid = hguid.unpack('L').first
         while true
            version = reg_enum_key(hguid, j)
            break if version.nil?

            if ( name = reg_get_val2(hguid, version))
               typelib = WIN32OLE_TYPELIB.new
               typelib.oletypelib_set_member(name, guid, version)
               typelibs.push(typelib)
            end

            j += 1
         end
         RegCloseKey(hguid)
         i += 1
      end
      RegCloseKey(htypelib)
      typelibs
   end

   def self.typelib_file_from_clsid(ole)
      path = 0.chr * 256
      hroot = 0.chr * 4
      err = reg_open_key(HKEY_CLASSES_ROOT, "CLSID", hroot)
      if err != ERROR_SUCCESS 
         return nil
      end
      hclsid = 0.chr * 4
      hroot = hroot.unpack('L').first
      err = reg_open_key(hroot, ole, hclsid)
      if err != ERROR_SUCCESS
         RegCloseKey(hroot)
         return nil
      end
      typelib = reg_get_val2(hclsid, "InprocServer32")
      RegCloseKey(hroot)
      RegCloseKey(hclsid)
      if typelib
         ExpandEnvironmentStrings(typelib, path, 256)
         typelib = path.strip
      end
      typelib
   end

   def self.typelib_file_from_typelib(ole)
      found = false
      htypelib = 0.chr * 4
      err = reg_open_key(HKEY_CLASSES_ROOT, "TypeLib", htypelib)
      if err != ERROR_SUCCESS
         return nil
      end
      htypelib = htypelib.unpack('L').first
      i = 0
      while !found      
         clsid = reg_enum_key(htypelib, i)
         break if clsid.nil?
         hclsid = 0.chr * 4
         err = reg_open_vkey(htypelib, clsid, hclsid)
         if err != ERROR_SUCCESS
            i += 1
            next 
         end
         hclsid = hclsid.unpack('L').first
         fver = 0
         j = 0
         while !found         
            ver = reg_enum_key(hclsid, j)
            break if ver.nil?
            hversion = 0.chr * 4
            err = reg_open_vkey(hclsid, ver, hversion)
            if err != ERROR_SUCCESS || fver > ver.to_f
               j += 1
               next
            end
            hversion = hversion.unpack('L').first
            fver = ver.to_f
            typelib = reg_get_val(hversion, nil)
            if typelib.nil?
               j += 1
               next
            end
            if typelib == ole
               k = 0
               while !found               
                  lang = reg_enum_key(hversion, k)
                  break if lang.nil?
                  hlang = 0.chr * 4
                  err = reg_open_vkey(hversion, lang, hlang)
                  if err == ERROR_SUCCESS
                     hlang = hlang.unpack('L').first
                     if (file = reg_get_typelib_file_path(hlang))
                        found = true
                     end
                     RegCloseKey(hlang)
                  end
                  k += 1
               end
            end
            RegCloseKey(hversion)
            j += 1
         end
         RegCloseKey(hclsid)
         i += 1
      end
      RegCloseKey(htypelib)
      file
   end

   def self.typelib_file(ole)
      file = typelib_file_from_clsid(ole)
      return file if file
      typelib_file_from_typelib(ole)
   end
   
   def self.make_version_str(major,minor)
      return nil if major.nil?
      version = major.dup
      if minor
         version << '.' + minor
      end
      version
   end

   def self.oletypelib_search_registry2(obj,args)
      found = false
      guid = args[0]

      version = make_version_str(args[1],args[2])

      htypelib = 0.chr * 4
      err = reg_open_key(HKEY_CLASSES_ROOT, "TypeLib", htypelib)
      return false if err != ERROR_SUCCESS
      hguid = 0.chr * 4
      err = reg_open_vkey(htypelib, guid, hguid)
      if err != ERROR_SUCCESS
         RegCloseKey(htypelib)
         return false
      end
      if version
         hversion = 0.chr * 4
         err = reg_open_vkey(hguid, version_str, hversion)
         if err == ERROR_SUCCESS
            tlib = reg_get_val(hversion, nil)
            if tlib
               typelib = tlib
            end
         end
         RegCloseKey(hversion)
      else
         fver = 0.0;
         j = 0
         while true
            ver = reg_enum_key(hguid, j)
            break if ver.nil?
            hversion = 0.chr * 4
            err = reg_open_vkey(hguid, ver, hversion)
            if err != ERROR_SUCCESS
               j += 1
               next
            end
            tlib = reg_get_val(hversion, nil)
            if tlib.nil?
                RegCloseKey(hversion)
                j += 1
                next
            end
            if fver < ver.to_f
               fver = ver.to_f
               version = ver.dup
               typelib = tlib.dup
            end
            RegCloseKey(hversion)
            j += 1
         end
      end
      RegCloseKey(hguid)
      RegCloseKey(htypelib)
      if typelib
         found = true
         obj.oletypelib_set_member(typelib, guid, version)
      end
      found
   end

   def self.oletypelib_search_registry(obj,typelib)
      found = false
      htypelib = 0.chr * 4
      err = reg_open_key(HKEY_CLASSES_ROOT, "TypeLib", htypelib)
      if err != ERROR_SUCCESS
         return false
      end
      i = 0
      htypelib = htypelib.unpack('L').first
      while !found
         guid = reg_enum_key(htypelib, i)
         break if guid.nil?
         hguid = 0.chr * 4
         err = reg_open_vkey(htypelib, guid, hguid)
         if (err != ERROR_SUCCESS)
            i += 1
            next
         end
         j = 0
         hguid = hguid.unpack('L').first
         while !found
            ver = reg_enum_key(hguid, j)
            break if ver.nil?
            hversion = 0.chr * 4
            err = reg_open_vkey(hguid, ver, hversion)
            if err != ERROR_SUCCESS
               j += 1
               next
            end
            hversion = hversion.unpack('L').first
            tlib = reg_get_val(hversion, nil)
            if tlib.nil?
               RegCloseKey(hversion)
               j += 1
               next
            end
            if typelib == tlib
               obj.oletypelib_set_member(typelib, guid, ver)
               found = true
            end
            RegCloseKey(hversion)
            j += 1
         end
         RegCloseKey(hguid)
         i += 1
      end
      RegCloseKey(htypelib)
      found
   end

   def self.reg_get_typelib_file_path(hkey)
      path = reg_get_val2(hkey, "win32")
      if path.nil?
         path = reg_get_val2(hkey, "win16")
      end
      path
   end

   def oletypelib_set_member(name, guid, version)
      @name = name
      @guid = guid
      @version = version
   end

   def initialize(*args)
      WIN32OLE.ole_initialize()
      @pTypeInfo = nil
      typelib = args[0]
      if args.length>0
         if !typelib.is_a?(String)
            raise TypeError, "typelib is wrong type (expected String)"
         end

         found = WIN32OLE_TYPELIB.oletypelib_search_registry(self,typelib)
         if !found
            found = WIN32OLE_TYPELIB.oletypelib_search_registry2(self,args)
         end
         if !found
            buf = multi_to_wide(typelib)
            p = 0.chr * 4
            hr = LoadTypeLibEx(buf, REGKIND_NONE, p)
            if hr == S_OK
               pTypeLib = p.unpack('L').first
               retval = WIN32OLE.ole_typelib_from_itypelib(pTypeLib)
               WIN32OLE.ole_release(pTypeLib)
               if retval
                  found = true
                  oletypelib_set_member(retval.name,retval.guid,retval.version)
               end
            end
         end

         if !found
            raise WIN32OLERuntimeError, "not found type library `#{typelib}`"
         end
      end
      self
   end

   def guid
      @guid
   end

   def name
      @name
   end
   alias :to_s :name

   def version
      @version
   end

   def major_version
      @version.split('.')[0]
   end

   def minor_version
      @version.split('.')[1]
   end

   def oletypelib_path(guid,version)
      path = nil
      key = "TypeLib\\" + guid+ "\\" + version
      hkey = 0.chr * 4
      err = WIN32OLE_TYPELIB.reg_open_vkey(HKEY_CLASSES_ROOT, key, hkey)
      return nil if err != ERROR_SUCCESS
      hkey = hkey.unpack('L').first
      k = 0
      while path.nil?
         lang = WIN32OLE_TYPELIB.reg_enum_key(hkey, k)
         break if lang.nil?
         hlang = 0.chr * 4
         err = WIN32OLE_TYPELIB.reg_open_vkey(hkey, lang, hlang)
         hlang = hlang.unpack('L').first
         if err == ERROR_SUCCESS
            path = WIN32OLE_TYPELIB.reg_get_typelib_file_path(hlang)
            RegCloseKey(hlang)
         end
         k += 1
      end
      RegCloseKey(hkey)
      path
   end

   def path
      oletypelib_path(@guid,@version)
   end

   def oletypelib2itypelib(pptl)
      path = self.path
      if path
         pbuf = multi_to_wide(path)
         hr = LoadTypeLibEx(pbuf, REGKIND_NONE, pptl)
         if hr != S_OK
            raise WIN32OLERuntimeError, "failed to LoadTypeLibEx from `#{path}'"
         end
      else
         raise WIN32OLERuntimeError, "failed to get type library path"
      end
   end

   def ole_types()
      classes = []
      p = 0.chr * 4
      oletypelib2itypelib(p)
      pTypeLib = p.unpack('L').first
      WIN32OLE.ole_types_from_typelib(pTypeLib, classes)
      WIN32OLE.ole_release(pTypeLib)
      classes
   end
   alias :ole_classes :ole_types

   def visible?
      visible = true
      p = 0.chr * 4
      oletypelib2itypelib(p)
      pTypeLib = p.unpack('L').first
      lpVtbl = 0.chr * 4
      table = 0.chr * 52
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,52)
      table = table.unpack('L*')
      getLibAttr = Win32::API::Function.new(table[7],'PP','L')
      releaseTLibAttr = Win32::API::Function.new(table[12],'PP','L')
      p = 0.chr * 4
      getLibAttr.call(pTypeLib,p)
      if hr != S_OK
         WIN32OLE.ole_release(pTypeLib)
         raise WIN32OLERuntimeError, "failed to get TLIBATTR information"
      end
      pTLibAttr = p.unpack('L').first
      tLibAttr = 0.chr * 32
      memcpy(tLibAttr,pTLibAttr,32)
      wLibFlags = tLibAttr[28,2].unpack('S').first
      if wLibFlags == 0 || (wLibFlags & LIBFLAG_FRESTRICTED)!=0 || (wLibFlags & LIBFLAG_FHIDDEN)!=0
         visible = false
      end
      releaseTLibAttr.call(pTypeLib,pTLibAttr)
      WIN32OLE.ole_release(pTypeLib)
      visible
   end

   def library_name
      p = 0.chr * 4
      oletypelib2itypelib(p)
      pTypeLib = p.unpack('L').first
      lpVtbl = 0.chr * 4
      table = 0.chr * 40
      memcpy(lpVtbl,pTypeLib,4)
      memcpy(table,lpVtbl.unpack('L').first,40)
      table = table.unpack('L*')
      getTypeInfoCount = Win32::API::Function.new(table[3],'P','L')
      getTypeInfo = Win32::API::Function.new(table[4],'PLP','L')
      getDocumentation = Win32::API::Function.new(table[9],'PLPPPP','L')
      bstr = 0.chr * 4
      getDocumentation.call(pTypeLib,-1,bstr,nil,nil,nil)
      if hr != S_OK
         WIN32OLE.ole_release(pTypeLib)
         raise WIN32OLERuntimeError, "failed to get library name"
      end
      WIN32OLE.ole_release(pTypeLib)      
      str = 0.chr * 256
      wcscpy(str,bstr.unpack('L').first)
      wide_to_multi(str)      
   end

   def inspect
      "#<#{self.class}:#{self.to_s}>"
   end

end

class WIN32OLE_TYPE
   
   attr_accessor :pTypeInfo
   
   def oletype_set_member(pTypeInfo,name)
      @name = name
      @pTypeInfo = pTypeInfo
      WIN32OLE.ole_addref(pTypeInfo) if pTypeInfo
   end
   
   def self.ole_classes(typelib)
      WIN32OLE_TYPELIB.new(typelib).ole_types
   end

   def self.typelibs
      WIN32OLE_TYPELIB.typelibs.collect{|t|t.name}
   end

   def self.progids
      progids = []
      hclsids = 0.chr * 4
       err = WIN32OLE_TYPELIB.reg_open_key(HKEY_CLASSES_ROOT, "CLSID", hclsids)
      if err != ERROR_SUCCESS
         return progids
      end
      hclsids = hclsids.unpack('L').first
      i = 0
      while true
         clsid = WIN32OLE_TYPELIB.reg_enum_key(hclsids, i)
         break if clsid.nil?
         hclsid = 0.chr * 4
         err = WIN32OLE_TYPELIB.reg_open_vkey(hclsids, clsid, hclsid)
         if err != ERROR_SUCCESS
            i += 1
            next
         end
         hclsid = hclsid.unpack('L').first
         if (v = WIN32OLE_TYPELIB.reg_get_val2(hclsid, "ProgID"))
            progids.push(v)
         end
         if (v = WIN32OLE_TYPELIB.reg_get_val2(hclsid, "VersionIndependentProgID")) 
            progids.push(v)
         end
         RegCloseKey(hclsid);
      
         i += 1
      end
      RegCloseKey(hclsids)
      progids
   end

   def initialize(typelib=nil, ole_class=nil)
      WIN32OLE.ole_initialize()
      @pTypeInfo = nil
      
      return self if typelib.nil?
      
      unless typelib.is_a?(String)
         raise TypeError, "wrong argument type (expected String)"
      end
      unless ole_class.is_a?(String)
         raise TypeError, "wrong argument type (expected String)"
      end
      file = WIN32OLE_TYPELIB.typelib_file(typelib)
      type = typlelib if file.nil?
      buf = multi_to_wide(file)
      p = 0.chr * 4
      hr = LoadTypeLibEx(buf, REGKIND_NONE, p)
      pTypeLib = p.unpack('L').first
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to LoadTypeLibEx"
      end
      if WIN32OLE.oleclass_from_typelib(self, pTypeLib, ole_class) == false
         WIN32OLE.ole_release(pTypeLib)
         raise WIN32OLERuntimeError, "not found `#{ole_class}` in `#{typelib}`"
      end
      WIN32OLE.ole_release(pTypeLib)
      self
   end

   def name
      @name
   end
   alias :to_s :name

   def ole_ole_type(pTypeInfo)
      type = nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      return type if hr != S_OK     
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      typekind = typeAttr[40,4].unpack('L').first
      case typekind
      when TKIND_ENUM
         type = "Enum"
      when TKIND_RECORD
         type = "Record"
      when TKIND_MODULE
         type = "Module"
      when TKIND_INTERFACE
         type = "Interface"
      when TKIND_DISPATCH
         type = "Dispatch"
      when TKIND_COCLASS
         type = "Class"
      when TKIND_ALIAS
         type = "Alias"
      when TKIND_UNION
         type = "Union"
      when TKIND_MAX
         type = "Max"
      else
         type = nil
      end
      releaseTypeAttr.call(pTypeInfo,pTypeAttr)
      type
   end
   
   def ole_type
      ole_ole_type(@pTypeInfo)
   end

   def ole_type_guid(pTypeInfo)
      guid = nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      return guid if hr != S_OK     
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      bstr = 0.chr * 160
      len = StringFromGUID2(typeAttr[0,16], bstr, 80)
      if len > 3
         guid = wide_to_multi(bstr)
      end
      releaseTypeAttr.call(pTypeInfo,pTypeAttr)
      guid
   end
   
   def guid
      ole_type_guid(@pTypeInfo)
   end

   def ole_type_progid(pTypeInfo)
      progid = nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      return progid if hr != S_OK      
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      bstr = 0.chr * 4
      hr = ProgIDFromCLSID(typeAttr[0,16], bstr)
      if hr == S_OK
         str = 0.chr * 256
         wcscpy(str,bstr.unpack('L').first)
         progid = wide_to_multi(str)
         CoTaskMemFree(bstr)
      end
      releaseTypeAttr.call(pTypeInfo,pTypeAttr)
      progid
   end
   
   def progid
      ole_type_progid(@pTypeInfo)
   end

   def ole_type_visible(pTypeInfo)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      return true if hr != S_OK     
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      if (typeAttr[54,2].unpack('S').first & (TYPEFLAG_FHIDDEN | TYPEFLAG_FRESTRICTED)) != 0
         visible = false
      else
         visible = true
      end
      releaseTypeAttr.call(pTypeInfo,pTypeAttr)
      visible
   end
   
   def visible?
      ole_type_visible(@pTypeInfo)
   end

   def ole_type_major_version(pTypeInfo)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      if hr != S_OK     
         raise WIN32OLERuntimeError, "failed to GetTypeAttr"
      end      
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      ver = typeAttr[56,2].unpack('S').first    
      releaseTypeAttr.call(pTypeInfo,pTypeAttr)
      ver
   end
   
   def major_version
      ole_type_major_version(@pTypeInfo)
   end

   def ole_type_minor_version(pTypeInfo)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      if hr != S_OK     
         raise WIN32OLERuntimeError, "failed to GetTypeAttr"
      end      
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      ver = typeAttr[58,2].unpack('S').first    
      releaseTypeAttr.call(pTypeInfo,pTypeAttr)
      ver
   end

   def minor_version
      ole_type_minor_version(@pTypeInfo)
   end

   def ole_type_typekind(pTypeInfo)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      if hr != S_OK     
         raise WIN32OLERuntimeError, "failed to GetTypeAttr"
      end      
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      typekind = typeAttr[40,4].unpack('L').first
      releaseTypeAttr.call(pTypeInfo,pTypeAttr)
      typekind
   end
   
   def typekind
      ole_type_typekind(@pTypeInfo)
   end

   def self.ole_docinfo_from_type(pTypeInfo,name,helpstr,helpcontext,helpfile)
      lpVtbl = 0.chr * 4
      table = 0.chr * 80
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,80)
      table = table.unpack('L*')
      getContainingTypeLib = Win32::API::Function.new(table[18],'PPP','L')
      p = 0.chr * 4
      i = 0.chr * 4
      hr = getContainingTypeLib.call(pTypeInfo,p,i)
      return hr if hr != S_OK
      i = i.unpack('L').first
      pTypeLib = p.unpack('L').first
      lpVtbl = 0.chr * 4
      table = 0.chr * 40
      memcpy(lpVtbl,pTypeLib,4)
      memcpy(table,lpVtbl.unpack('L').first,40)
      table = table.unpack('L*')
      getDocumentation = Win32::API::Function.new(table[9],'PLPPPP','L')
      hr = getDocumentation.call(pTypeLib, i, name, helpstr, helpcontext, helpfile)
      WIN32OLE.ole_release(pTypeLib)
      hr    
   end
   
   def self.ole_type_helpstring(pTypeInfo)
      bhelpstr = 0.chr * 4
      hr = ole_docinfo_from_type(pTypeInfo, nil, bhelpstr, nil, nil)
      return nil if hr != S_OK
      str = 0.chr * 256
      wcscpy(str,bhelpstr.unpack('L').first)
      wide_to_multi(str)
   end
   
   def helpstring
      WIN32OLE_TYPE.ole_type_helpstring(@pTypeInfo)
   end

   def self.ole_usertype2val(pTypeInfo,pTypeDesc,typedetails)
      lpVtbl = 0.chr * 4
      table = 0.chr * 80
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,80)
      table = table.unpack('L*')
      getRefTypeInfo = Win32::API::Function.new(table[14],'PLP','L')
      p = 0.chr * 4
      hr = getRefTypeInfo.call(pTypeInfo,pTypeDesc.unpack('L').first,p)
      pRefTypeInfo = p.unpack('L').first
      return nil if hr != S_OK
      bstr = 0.chr * 4
      hr = ole_docinfo_from_type(pRefTypeInfo, bstr, nil, nil, nil)
      if hr != S_OK
         WIN32OLE.ole_release(pRefTypeInfo)
         return nil
      end
      WIN32OLE.ole_release(pRefTypeInfo)
      str = 0.chr * 256
      wcscpy(str,bstr.unpack('L').first)
      type = wide_to_multi(str)
      if typedetails
         typedetails.push(type)
      end
      type
   end
   
   def self.ole_ptrtype2val(pTypeInfo,pTypeDesc,typedetails)
      type = ""
      vt = pTypeDesc[4,2].unpack('S').first
      if vt == VT_PTR || vt == VT_SAFEARRAY
         typedesc = 0.chr * 8
         memcpy(typedesc,pTypeDesc[0,4].unpack('L').first,8)         
         type = ole_typedesc2val(pTypeInfo, typedesc, typedetails)
      end
      type
   end
   
   
   def self.ole_typedesc2val(pTypeInfo,pTypeDesc,typedetails)
      typestr = nil
      vt = pTypeDesc[4,2].unpack('S').first
      case vt
      when VT_I2
         typestr = "I2"
      when VT_I4
         typestr = "I4"
      when VT_R4
         typestr = "R4"
      when VT_R8
         typestr = "R8"
      when VT_CY
         typestr = "CY"
      when VT_DATE
         typestr = "DATE"
      when VT_BSTR
         typestr = "BSTR"
      when VT_BOOL
         typestr = "BOOL"
      when VT_VARIANT
         typestr = "VARIANT"
      when VT_DECIMAL
         typestr = "DECIMAL"
      when VT_I1
         typestr = "I1"
      when VT_UI1
         typestr = "UI1"
      when VT_UI2
         typestr = "UI2"
      when VT_UI4
         typestr = "UI4"
      when VT_I8
         typestr = "I8"
      when VT_UI8
         typestr = "UI8"
      when VT_INT
         typestr = "INT"
      when VT_UINT
         typestr = "UINT"
      when VT_VOID
         typestr = "VOID"
      when VT_HRESULT
         typestr = "HRESULT"
      when VT_PTR
         typestr = "PTR"
         if typedetails
            typedetails.push(typestr)
         end
         return ole_ptrtype2val(pTypeInfo,pTypeDesc,typedetails)
      when VT_SAFEARRAY
         typestr = "SAFEARRAY"
         if typedetails
            typedetails.push(typestr)
         end
         return ole_ptrtype2val(pTypeInfo,pTypeDesc,typedetails)
      when VT_CARRAY
         typestr = "CARRAY"
      when VT_USERDEFINED
         typestr = "USERDEFINED"
         if typedetails
            typedetails.push(typestr)
         end
         str = WIN32OLE_TYPE.ole_usertype2val(pTypeInfo,pTypeDesc,typedetails)
         return str if str
         return typestr
      when VT_UNKNOWN
         typestr = "UNKNOWN"
      when VT_DISPATCH
         typestr = "DISPATCH"
      when VT_ERROR
         typestr = "ERROR"
      when VT_LPWSTR
         typestr = "LPWSTR"
      when VT_LPSTR
         typestr = "LPSTR"
      else
         typestr = "Unknown Type #{vt}"
      end
      if typedetails
         typedetails.push(typestr)
      end
      typestr
   end
   
   def ole_type_src_type(pTypeInfo)
      _alias = nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      return _alias if hr != S_OK      
      
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      typekind = typeAttr[40,4].unpack('L').first
      if typekind != TKIND_ALIAS    
         releaseTypeAttr.call(pTypeInfo,pTypeAttr)
         return _alias
      end
      _alias = WIN32OLE_TYPE.ole_typedesc2val(pTypeInfo,typeAttr[60,8],nil)
      releaseTypeAttr.call(pTypeInfo,pTypeAttr)
      return _alias
   end
   
   def src_type
      ole_type_src_type(@pTypeInfo)
   end

   def ole_type_helpfile(pTypeInfo)
      bhelpfile = 0.chr * 4
      hr = WIN32OLE_TYPE.ole_docinfo_from_type(pTypeInfo, nil, nil, nil, bhelpfile)
      return nil if hr != S_OK
      str = 0.chr * 256
      wcscpy(str,bhelpfile.unpack('L').first)
      wide_to_multi(str)
   end
   
   def helpfile
      ole_type_helpfile(@pTypeInfo)
   end

   def ole_type_helpcontext(pTypeInfo)
      helpcontext = 0.chr * 4
      hr = WIN32OLE_TYPE.ole_docinfo_from_type(pTypeInfo, nil, nil, helpcontext, nil)
      return nil if hr != S_OK
      helpcontext.unpack('L').first
   end
   
   def helpcontext
      ole_type_helpcontext(@pTypeInfo)
   end

   def ole_variables(pTypeInfo)
      variables = []
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      getVarDesc = Win32::API::Function.new(table[6],'PLP','L')
      getNames = Win32::API::Function.new(table[7],'PLPLP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      releaseVarDesc = Win32::API::Function.new(table[21],'PP','L')
      p = 0.chr * 4     
      hr = getTypeAttr.call(pTypeInfo,p)
      pTypeAttr = p.unpack('L').first
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to GetTypeAttr"
      end
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      for i in 0 ... typeAttr[46,2].unpack('S').first
         p = 0.chr * 4
         getVarDesc.call(pTypeInfo,i,p)
         pVarDesc = p.unpack('L').first
         next if hr != S_OK
         varDesc = 0.chr * 36
         memcpy(varDesc,pVarDesc,36)
         bstr = 0.chr * 4
         len = 0.chr * 4
         hr = getNames.call(pTypeInfo,varDesc[0,4].unpack('L').first,bstr,1,len)
         if hr != S_OK || len.unpack('L').first == 0 ||
            bstr.unpack('L').first == 0
            next
         end
         
         var = WIN32OLE_VARIABLE.new
         var.pTypeInfo = pTypeInfo
         var.index = i
         bstr = bstr.unpack('L').first
         str = 0.chr * 256
         wcscpy(str,bstr)
         SysFreeString(bstr)
         var.name = wide_to_multi(str)
         variables.push(var)
         releaseVarDesc.call(pTypeInfo,pVarDesc)
         pVarDesc = nil
      end
      releaseTypeAttr.call(pTypeInfo,pTypeAttr)
      variables
   end
   
   def variables
      ole_variables(@pTypeInfo)
   end

   def ole_methods
      WIN32OLE.ole_methods_from_typeinfo(@pTypeInfo,INVOKE_FUNC | INVOKE_PROPERTYGET | INVOKE_PROPERTYPUT | INVOKE_PROPERTYPUTREF)
   end

   def ole_typelib
      WIN32OLE.ole_typelib_from_itypeinfo(@pTypeInfo)
   end

   def ole_type_impl_ole_types(pTypeInfo,implflags)
      types = []
      lpVtbl = 0.chr * 4
      table = 0.chr * 80
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,80)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      getRefTypeOfImplType = Win32::API::Function.new(table[8],'PLP','L')
      getImplTypeFlags = Win32::API::Function.new(table[9],'PLP','L')
      getRefTypeInfo = Win32::API::Function.new(table[14],'PLP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      pTypeAttr = p.unpack('L').first
      return types if hr != S_OK
         
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      for i in 0 ... typeAttr[48,2].unpack('S').first
         flags = 0.chr * 4
         hr = getImplTypeFlags.call(pTypeInfo, i,flags)
         next if hr != S_OK
         flags = flags.unpack('L').first
         href = 0.chr * 4
         hr = getRefTypeOfImplType.call(pTypeInfo, i, href)
         next if hr != S_OK
         href = href.unpack('L').first
         p = 0.chr * 4
         hr = getRefTypeInfo.call(pTypeInfo, href, p)
         next if hr != S_OK
         pRefTypeInfo = p.unpack('L').first
         if (flgas & implflags) == implflags
            type = WIN32OLE.ole_type_from_itypeinfo(pRefTypeInfo)
            if type
               types.push(type)
            end
         end
         WIN32OLE.ole_release(pRefTypeInfo)
      end
      releaseTypeAttr(pTypeInfo, pTypeAttr)
      types
   end
   
   def implemented_ole_types
      ole_type_impl_ole_types(@pTypeInfo,0)
   end

   def source_ole_types
      ole_type_impl_ole_types(@pTypeInfo, IMPLTYPEFLAG_FSOURCE)
   end

   def default_event_sources
      ole_type_impl_ole_types(@pTypeInfo, IMPLTYPEFLAG_FSOURCE|IMPLTYPEFLAG_FDEFAULT)
   end

   def default_ole_types
      ole_type_impl_ole_types(@pTypeInfo, IMPLTYPEFLAG_FDEFAULT)
   end

   def inspect
      "#<#{self.class}:#{self.to_s}>"
   end
end

class WIN32OLE_VARIABLE

   attr_accessor :pTypeInfo, :index, :name
   
   alias :to_s :name

   def ole_variable_ole_type(pTypeInfo,var_index)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      
      getVarDesc = Win32::API::Function.new(table[6],'PLP','L')
      releaseVarDesc = Win32::API::Function.new(table[21],'PP','L')
      p = 0.chr * 4
      hr = getVarDesc.call(pTypeInfo,var_index,p)
      pVarDesc = p.unpack('L').first
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to GetVarDesc"
      end
      varDesc = 0.chr * 36
      memcpy(varDesc,pVarDesc,36)      
      type = WIN32OLE_TYPE.ole_typedesc2val(pTypeInfo, varDesc[12,8], nil)
      releaseVarDesc.call(pTypeInfo, pVarDesc)
      type
   end
   
   def ole_type
      ole_variable_ole_type(@pTypeInfo,@index)
   end

   def ole_variable_ole_type_detail(pTypeInfo,var_index)
      type = []
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      
      getVarDesc = Win32::API::Function.new(table[6],'PLP','L')
      releaseVarDesc = Win32::API::Function.new(table[21],'PP','L')
      p = 0.chr * 4
      hr = getVarDesc.call(pTypeInfo,var_index,p)
      pVarDesc = p.unpack('L').first
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to GetVarDesc"
      end
      varDesc = 0.chr * 36
      memcpy(varDesc,pVarDesc,36)      
      WIN32OLE_TYPE.ole_typedesc2val(pTypeInfo,varDesc[12,8],type)
      releaseVarDesc.call(pTypeInfo, pVarDesc)
      type
   end
   
   def ole_type_detail
      ole_variable_ole_type_detail(@pTypeInfo, @index)
   end

   def ole_variable_value(pTypeInfo,var_index)
      val = nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      
      getVarDesc = Win32::API::Function.new(table[6],'PLP','L')
      releaseVarDesc = Win32::API::Function.new(table[21],'PP','L')
      p = 0.chr * 4
      hr = getVarDesc.call(pTypeInfo,var_index,p)
      pVarDesc = p.unpack('L').first
      return nil if hr != S_OK
         
      varDesc = 0.chr * 36
      memcpy(varDesc,pVarDesc,36)      
      if varDesc[32,4].unpack('L').first == VAR_CONST
         val = WIN32OLE.ole_variant2val(varDesc[8,4].unpack('L').first)
      end
      releaseVarDesc.call(pTypeInfo, pVarDesc)
      val
   end

   def value
      ole_variable_value(@pTypeInfo, @index)
   end
   
   def ole_variable_visible(pTypeInfo,var_index)
      visible = false
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')    
      getVarDesc = Win32::API::Function.new(table[6],'PLP','L')
      releaseVarDesc = Win32::API::Function.new(table[21],'PP','L')
      p = 0.chr * 4
      hr = getVarDesc.call(pTypeInfo,var_index,p)
      pVarDesc = p.unpack('L').first
      return visible if hr != S_OK
      varDesc = 0.chr * 36
      memcpy(varDesc,pVarDesc,36)      
      if (varDesc[28,2].unpack('S').first & (VARFLAG_FHIDDEN |
                                 VARFLAG_FRESTRICTED |
                                 VARFLAG_FNONBROWSABLE)) == 0
         visible = true
      end
      releaseVarDesc.call(pTypeInfo, pVarDesc)
      visible
   end

   def visible?
      ole_variable_visible(@pTypeInfo, @index)
   end

   def ole_variable_kind(pTypeInfo,var_index)
      kind = "UNKNOWN"
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      
      getVarDesc = Win32::API::Function.new(table[6],'PLP','L')
      releaseVarDesc = Win32::API::Function.new(table[21],'PP','L')
      p = 0.chr * 4
      hr = getVarDesc.call(pTypeInfo,var_index,p)
      pVarDesc = p.unpack('L').first
      return kind if hr != S_OK
      varDesc = 0.chr * 36
      memcpy(varDesc,pVarDesc,36)            
      case varDesc[32,4].unpack('L').first
      when VAR_PERINSTANCE
         kind = PERINSTANCE
      when VAR_STATIC
         kind = STATIC
      when VAR_CONST
         kind = CONSTANT
      when VAR_DISPATCH
         kind = DISPATCH
      end
      releaseVarDesc.call(pTypeInfo, pVarDesc)
      kind
   end
   
   def variable_kind
      ole_variable_kind(@pTypeInfo, @index)
   end

   def ole_variable_varkind(pTypeInfo,var_index)
      kind = nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      
      getVarDesc = Win32::API::Function.new(table[6],'PLP','L')
      releaseVarDesc = Win32::API::Function.new(table[21],'PP','L')
      p = 0.chr * 4
      hr = getVarDesc.call(pTypeInfo,var_index,p)
      pVarDesc = p.unpack('L').first
      return kind if hr != S_OK
      varDesc = 0.chr * 36
      memcpy(varDesc,pVarDesc,36)      
      kind = varDesc[32,4].unpack('L').first
      releaseVarDesc.call(pTypeInfo, pVarDesc)
      kind
   end
   
   def varkind
      ole_variable_varkind(@pTypeInfo, @index)
   end

   def inspect
      "#<#{self.class}:#{self.to_s}=#{self.value.inpect}>"
   end
end

class WIN32OLE_METHOD
    IMPLTYPEFLAG_FDEFAULT  =  0x1 
    IMPLTYPEFLAG_FSOURCE   =  0x2 
    IMPLTYPEFLAG_FRESTRICTED  =  0x4 
    IMPLTYPEFLAG_FDEFAULTVTABLE  =  0x8 

   def olemethod_set_member(pTypeInfo,pOwnerTypeInfo,index,name)
      @pTypeInfo = pTypeInfo
      WIN32OLE.ole_addref(pTypeInfo)
      @pOwnerTypeInfo = pOwnerTypeInfo
      WIN32OLE.ole_addref(pOwnerTypeInfo) if pOwnerTypeInfo != 0
      @index = index
      @name = name
      self
   end

   def ole_method_sub(pOwnerTypeInfo,pTypeInfo,name)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      getNames = Win32::API::Function.new(table[7],'PLPLP','L')
      getDocumentation = Win32::API::Function.new(table[12],'PLPPPP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to GetTypeAttr"
      end
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      method = nil
      for i in 0 .. typeAttr[44,2].unpack('S').first
         break if method != nil
         p = 0.chr * 4
         hr = getFuncDesc.call(pTypeInfo,i,p)
         next if hr != S_OK
         pFuncDesc = p.unpack('L').first
         funcDesc = 0.chr * 52
         memcpy(funcDesc,pFuncDesc,52)
         memid = funcDesc[0,4].unpack('L').first
         bstr = 0.chr * 4
         hr = getDocumentation.call(pTypeInfo,memid,bstr,nil,nil,nil)
         if hr != S_OK
            releaseFuncDesc.call(pTypeInfo,pFuncDesc)
            next
         end
         str = 0.chr * 256
         wcscpy(str,bstr.unpack('L').first)
         fname = wide_to_multi(str)
         if name.casecmp(fname)==0
            olemethod_set_member(pTypeInfo,pOwnerTypeInfo,i,fname)
            method = self
         end
         releaseFuncDesc.call(pTypeInfo,pFuncDesc)
         pFuncDesc = nil
      end
      releaseTypeAttr.call(pTypeInfo, pTypeAttr)
      method
   end

   def olemethod_from_typeinfo(pTypeInfo,name)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      pTypeAttr = 0.chr * 4
      getRefTypeOfImplType = Win32::API::Function.new(table[8],'PLP','L')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      getRefTypeInfo = Win32::API::Function.new(table[14],'PLP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to GetTypeAttr"
      end
      method = ole_method_sub(0,pTypeInfo,name)
      return method if method
      pTypeAttr = p.unpack('L').first
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      for i in 0 ... typeAttr[48,2].unpack('S').first
         break if method
         p = 0.chr * 4
         hr = getRefTypeOfImplType.call(pTypeInfo, i, p)
         next if hr != S_OK
         href = p.unpack('L').first
         p = 0.chr * 4
         hr = getRefTypeInfo.call(pTypeInfo, href,p)
         next if hr != S_OK
         pRefTypeInfo = p.unpack('L').first
         method = ole_method_sub(pTypeInfo,pRefTypeInfo,name)
         WIN32OLE.ole_release(pRefTypeInfo)
      end
      releaseTypeAttr.call(pTypeInfo, pTypeAttr)
      method
   end

   def initialize(oletype=nil, method=nil)
      @pTypeInfo = nil 
      @pOwnerTypeInfo = nil
      @index = 0
      return self if oletype.nil?
      if oletype.is_a?(WIN32OLE_TYPE)
         unless method.is_a?(String)
            raise TypeError,"2nd parameter must be String"
         end
         obj = olemethod_from_typeinfo(oletype.pTypeInfo,method)
         if obj.nil?
            raise WIN32OLERuntimeError, "not found #{method}"
         end
      else
         raise TypeError, "1st argument should be WIN32OLE_TYPE object"
      end      
   end

   def name
      @name
   end
   alias :to_s :name

   def ole_method_return_type(pTypeInfo,method_index)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')    
      getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
      hr = getFuncDesc.call(pTypeInfo,method_index,p)
      pFuncDesc = p.unpack('L').first
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to GetFuncDesc"
      end
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      type = WIN32OLE_TYPE.ole_typedesc2val(pTypeInfo,funcDesc[32,8],nil)
      releaseFuncDesc.call(pTypeInfo, pFuncDesc)
      type
   end
   
   def return_type
      ole_method_return_type(@pTypeInfo,@index)
   end

   def ole_method_return_vtype(pTypeInfo,method_index)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')    
      getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
      hr = getFuncDesc.call(pTypeInfo,method_index,p)
      pFuncDesc = p.unpack('L').first
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to GetFuncDesc"
      end
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      vvt = funcDesc[36,2].unpack('S').first
      releaseFuncDesc.call(pTypeInfo, pFuncDesc)
      vvt
   end
   
   def return_vtype
      ole_method_return_vtype(@pTypeInfo,@index)
   end

   def ole_method_return_type_detail(pTypeInfo,method_index)
      type = []
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')    
      getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
      hr = getFuncDesc.call(pTypeInfo,method_index,p)
      pFuncDesc = p.unpack('L').first
      return type if hr != S_OK
      
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      WIN32OLE_TYPE.ole_typedesc2val(pTypeInfo,funcDesc[32,8],type)
      releaseFuncDesc.call(pTypeInfo, pFuncDesc)
      type
   end
   
   def return_type_detail
      ole_method_return_type_detail(@pTypeInfo,@index)
   end

   def ole_method_invkind(pTypeInfo,method_index)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')    
      getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
      hr = getFuncDesc.call(pTypeInfo,method_index,p)
      pFuncDesc = p.unpack('L').first
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to GetFuncDesc"
      end
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      invkind = funcDesc[16,4].unpack('L').first
      releaseFuncDesc.call(pTypeInfo, pFuncDesc)
      invkind
   end

   def ole_method_invoke_kind(pTypeInfo,method_index)
      type = "UNKNOWN"
      invkind = ole_method_invkind(pTypeInfo, method_index)
      if (invkind & INVOKE_PROPERTYGET) != 0 && (invkind & INVOKE_PROPERTYPUT) != 0 
         type = "PROPERTY"
      elsif (invkind & INVOKE_PROPERTYGET) != 0
         type = "PROPERTYGET"
      elsif (invkind & INVOKE_PROPERTYPUT) != 0
         type = "PROPERTYPUT"
      elsif (invkind & INVOKE_PROPERTYPUTREF) != 0
         type = "PROPERTYPUTREF"
      elsif (invkind & INVOKE_FUNC) != 0
         type = "FUNC"
      end
      type
   end
   
   def invoke_kind
      ole_method_invoke_kind(@pTypeInfo,@index)
   end
   
   def invkind
      ole_method_invkind(@pTypeInfo,@index)
   end

   def ole_method_visible(pTypeInfo,method_index)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')    
      getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
      hr = getFuncDesc.call(pTypeInfo,method_index,p)
      pFuncDesc = p.unpack('L').first
      return false if hr != S_OK
      
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      if (funcDesc[48,2].unpack('S').first & (FUNCFLAG_FRESTRICTED |
                                 FUNCFLAG_FHIDDEN |
                                 FUNCFLAG_FNONBROWSABLE)) != 0
         visible = false
      else
         visible = true
      end      
      releaseFuncDesc.call(pTypeInfo, pFuncDesc)
      visible  
   end
   
   def visible?
      ole_method_visible(@pTypeInfo,@index)
   end

   def ole_method_event(pTypeInfo,method_index,method_name)
       event = false
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      getDocumentation = Win32::API::Function.new(table[12],'PLPPPP','L')
      getRefTypeOfImplType = Win32::API::Function.new(table[8],'PLP','L')
      getImplTypeFlags = Win32::API::Function.new(table[9],'PLP','L')
      getRefTypeInfo = Win32::API::Function.new(table[14],'PLP','L')
        getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      pTypeAttr = p.unpack('L').first
      return event if hr != S_OK
      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      if typeAttr[40,4].unpack('L').first != TKIND_COCLASS
          releaseTypeAttr.call(pTypeInfo, pTypeAttr)
          return event         
      end
      for i in 0 ... typeAttr[48,2].unpack('S').first
         flags = 0.chr * 4
         hr = getImplTypeFlags.call(pTypeInfo, i,flags)
         next if hr != S_OK
            if (flags.unpack('L').first & IMPLTYPEFLAG_FSOURCE) != 0
                href = 0.chr * 4
                hr = getRefTypeOfImplType.call(pTypeInfo,i,href)
                next if hr != S_OK
                href = href.unpack('L').first
                p = 0.chr * 4
                hr = getRefTypeInfo.call(pTypeInfo,href,p)
                next if hr != S_OK
                pRefTypeInfo = p.unpack('L').first
                p = 0.chr * 4
                hr = getFuncDesc.call(pRefTypeInfo,method_index,p)
                if hr != S_OK
                    WIN32OLE.ole_release(pRefTypeInfo)
                    next
                end
                pFuncDesc = p.unpack('L').first
            funcDesc = 0.chr * 52
            memcpy(funcDesc,pFuncDesc,52)
            memid = funcDesc[0,4].unpack('L').first
            bstr = 0.chr * 4
                hr = getDocumentation.call(pRefTypeInfo,memid,bstr,nil,nil,nil)
                if hr != S_OK
                    releaseFuncDesc.call(pRefTypeInfo, pFuncDesc)
                    WIN32OLE.ole_release(pRefTypeInfo)
                    next
                end
                str = 0.chr * 256
                wcscpy(str,bstr.unpack('L').first)
                name = wide_to_multi(str)
                releaseFuncDesc.call(pRefTypeInfo,pFuncDesc)
                WIN32OLE.ole_release(pRefTypeInfo)
                if method_name == name
                    event = true
                    break
                end
            end
        end  
        releaseTypeAttr.call(pTypeInfo, pTypeAttr)           
        event
   end
   
   def event?
      ole_method_event(@pOwnerTypeInfo,@index,self.name)
   end

   def event_interface
       if event?
           name = 0.chr * 4
           hr = WIN32OLE_TYPE.ole_docinfo_from_type(@pTypeInfo, name, nil, nil, nil)
           if hr == S_OK
               str = 0.chr * 256
               wcscpy(str,name.unpack('L').first)
               return wide_to_multi(str)
           end
       end
       nil
   end

    def ole_method_docinfo_from_type(pTypeInfo,method_index,name,helpstr,helpcontext,helpfile)
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
        getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')      
      getDocumentation = Win32::API::Function.new(table[12],'PLPPPP','L')
      getRefTypeOfImplType = Win32::API::Function.new(table[8],'PLP','L')
      getImplTypeFlags = Win32::API::Function.new(table[9],'PLP','L')
      getRefTypeInfo = Win32::API::Function.new(table[14],'PLP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
        hr = getFuncDesc.call(pTypeInfo, method_index, p)
        return hr if hr != S_OK
        pFuncDesc = p.unpack('L').first
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      memid = funcDesc[0,4].unpack('L').first
        hr = getDocumentation.call(pTypeInfo,memid,name,helpstr,helpcontext,helpfile)        
        releaseFuncDesc.call(pTypeInfo, pFuncDesc)
        hr
    end

    def ole_method_helpstring(pTypeInfo,method_index)
        bhelpstring = 0.chr * 4
        hr = ole_method_docinfo_from_type(pTypeInfo,method_index,nil,bhelpstring,nil,nil)
        return nil if hr != S_OK
        str = 0.chr * 256
        wcscpy(str,bhelpstring.unpack('L').first)
        wide_to_multi(str)
    end

   def helpstring
       ole_method_helpstring(@pTypeInfo,@index)
   end

    def ole_method_helpfile(pTypeInfo,method_index)
        bhelpfile = 0.chr * 4
        hr = ole_method_docinfo_from_type(pTypeInfo, method_index, nil, nil, nil, bhelpfile)
        return nil if hr != S_OK
        str = 0.chr * 256
        wcscpy(str,bhelpfile.unpack('L').first)
        wide_to_multi(str)        
    end

   def helpfile
       ole_method_helpfile(@pTypeInfo,@index)
   end

    def ole_method_helpcontext(pTypeInfo,method_index)
        helpcontext = 0.chr * 4
        hr = ole_method_docinfo_from_type(pTypeInfo, method_index, nil, nil, helpcontext, nil)
        return nil if hr != S_OK
        helpcontext.unpack('L').first
    end

   def helpcontext
       ole_method_helpcontext(@pTypeInfo,@index)
   end

    def ole_method_dispid(pTypeInfo,method_index)
        dispid = nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
        getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
        hr = getFuncDesc.call(pTypeInfo, method_index, p)
        return dispid if hr != S_OK
        pFuncDesc = p.unpack('L').first
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      dispid = funcDesc[0,4].unpack('L').first
        releaseFuncDesc.call(pTypeInfo, pFuncDesc)
        dispid
    end

   def dispid
       ole_method_dispid(@pTypeInfo,@index)
   end

    def ole_method_offset_vtbl(pTypeInfo,method_index)
        offset_vtbl = nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
        getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
        hr = getFuncDesc.call(pTypeInfo, method_index, p)
        return offset_vtbl if hr != S_OK
        pFuncDesc = p.unpack('L').first
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      offset_vtbl = funcDesc[28,2].unpack('S').first
        releaseFuncDesc.call(pTypeInfo, pFuncDesc)
        offset_vtbl 
    end

   def offset_vtbl
       ole_method_offset_vtbl(@pTypeInfo,@index)
   end

    def ole_method_size_params(pTypeInfo,method_index)
        size_params = nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
        getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
        hr = getFuncDesc.call(pTypeInfo, method_index, p)
        return size_params if hr != S_OK
        pFuncDesc = p.unpack('L').first
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      size_params = funcDesc[24,2].unpack('S').first
        releaseFuncDesc.call(pTypeInfo, pFuncDesc)
        size_params 
    end

   def size_params
       ole_method_size_params(@pTypeInfo,@index)
   end

    def ole_method_size_opt_params(pTypeInfo,method_index)
        size_opt_params = nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
        getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
        hr = getFuncDesc.call(pTypeInfo, method_index, p)
        return size_opt_params if hr != S_OK
        pFuncDesc = p.unpack('L').first
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      size_opt_params = funcDesc[26,2].unpack('S').first
        releaseFuncDesc.call(pTypeInfo, pFuncDesc)
        size_opt_params 
    end

   def size_opt_params
       ole_method_size_opt_params(@pTypeInfo,@index)
   end

    def ole_method_params(pTypeInfo,method_index)
        params = []
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
        getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      getNames = Win32::API::Function.new(table[7],'PLPLP','L')
      p = 0.chr * 4
        hr = getFuncDesc.call(pTypeInfo, method_index, p)
        return params if hr != S_OK
        pFuncDesc = p.unpack('L').first           
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)    
      memid = funcDesc[0,4].unpack('L').first
      cParams = funcDesc[24,2].unpack('S').first
        bstrs = 0.chr * 4 * (cParams + 1)
        len = 0.chr * 4
      hr = getNames.call(pTypeInfo,memid,bstrs,cParams + 1,len)
      if hr != S_OK
          releaseFuncDesc.call(pTypeInfo, pFuncDesc)
          params
       end
       if cParams > 0
           for i in 1 ... len.unpack('L').first
               param = WIN32OLE_PARAM.new
               param.pTypeInfo = pTypeInfo
               WIN32OLE.ole_addref(pTypeInfo)
               param.method_index = method_index
               param.index = i - 1
               bstr = bstrs[i*4,4].unpack('L').first
               str = 0.chr * 256
               wcscpy(str,bstr)
               SysFreeString(bstr)
               param.name = wide_to_multi(str)
               params.push(param)
           end
       end
        releaseFuncDesc.call(pTypeInfo, pFuncDesc)
        params
    end

   def params
       ole_method_params(@pTypeInfo,@index)
   end

   def inspect
      "#<#{self.class}:#{self.to_s}>"
   end
end

class WIN32OLE_PARAM
   attr_accessor :pTypeInfo
   attr_accessor :method_index
   attr_accessor :name
   attr_accessor :index
    
   alias :to_s :name

   def ole_param_ole_type(pTypeInfo,method_index,index)
      type = "unknown type"
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
        getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
        hr = getFuncDesc.call(pTypeInfo, method_index, p)
        return type if hr != S_OK
        pFuncDesc = p.unpack('L').first
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      tdesc = 0.chr * 16
      memcpy(tdesc,funcDesc[8,4].unpack('L').first + index*16,16)    
      type = WIN32OLE_TYPE.ole_typedesc2val(pTypeInfo,tdesc,nil)     
        releaseFuncDesc.call(pTypeInfo, pFuncDesc)
        type 
    end

   def ole_type
       ole_param_ole_type(@pTypeInfo,@method_index,@index)
   end

    def ole_param_ole_type_detail(pTypeInfo,method_index,index)
        typedetail = []
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
        getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
        hr = getFuncDesc.call(pTypeInfo, method_index, p)
        return typedetail if hr != S_OK
        pFuncDesc = p.unpack('L').first
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      tdesc = 0.chr * 16
      memcpy(tdesc,funcDesc[8,4].unpack('L').first + index*16,16)    
      WIN32OLE_TYPE.ole_typedesc2val(pTypeInfo,tdesc,typedetail)     
        releaseFuncDesc.call(pTypeInfo, pFuncDesc)
        typedetail 
    end

   def ole_type_detail
       ole_param_ole_type_detail(@pTypeInfo,@method_index,@index)
   end

    def ole_param_flag_mask(pTypeInfo,method_index,index,mask)
        ret = false
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
        getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
        hr = getFuncDesc.call(pTypeInfo, method_index, p)
        return ret if hr != S_OK
        pFuncDesc = p.unpack('L').first
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      tdesc = 0.chr * 16
      memcpy(tdesc,funcDesc[8,4].unpack('L').first + index*16,16)    
      if (tdesc[12,2].unpack('S').first & mask) != 0
          ret = true
       end
        releaseFuncDesc.call(pTypeInfo, pFuncDesc)
        ret 
    end
    
   def input?
       ole_param_flag_mask(@pTypeInfo,@method_index,@index,PARAMFLAG_FIN)
   end

   def output?
       ole_param_flag_mask(@pTypeInfo,@method_index,@index,PARAMFLAG_FOUT)
   end

   def optional?
       ole_param_flag_mask(@pTypeInfo,@method_index,@index,PARAMFLAG_FOPT)
   end

   def retval?
       ole_param_flag_mask(@pTypeInfo,@method_index,@index,PARAMFLAG_FRETVAL)
   end

    def ole_param_default(pTypeInfo,method_index,index)
        mask = PARAMFLAG_FOPT|PARAMFLAG_FHASDEFAULT
        defval = nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
        getFuncDesc = Win32::API::Function.new(table[5],'PLP','L')
      releaseFuncDesc = Win32::API::Function.new(table[20],'PP','L')
      p = 0.chr * 4
        hr = getFuncDesc.call(pTypeInfo, method_index, p)
        return ret if hr != S_OK
        pFuncDesc = p.unpack('L').first
      funcDesc = 0.chr * 52
      memcpy(funcDesc,pFuncDesc,52)
      tdesc = 0.chr * 16
      memcpy(tdest,funcDesc[8,4].unpack('L').first + index*16,16)    
      if (tdesc[12,2].unpack('S').first & mask) == mask
          pParamDescEx = 0.chr * 24
          memcpy(pParamDescEx,tdesc[8,4].unpack('L').first,24)        
          defval = WIN32OLE.ole_variant2val(pParamDescEx[8,16])
       end
        releaseFuncDesc.call(pTypeInfo, pFuncDesc)
        defval 
    end
    
   def default
       ole_param_default(@pTypeInfo,@method_index,@index)
   end

   def inspect
       detail = self.detail
       defval = self.default
       if defval
           detail << '=' + defval.inspect
       end
      "#<#{self.class}:#{detail}>"
   end
end

class WIN32OLE_EVENT
  @@ary_ole_event = []
      
  @@g_IsEventSinkVtblInitialized = false

  IEventSinkVtbl = Struct.new(:QueryInterface,:AddRef,:Release,:GetTypeInfoCount,:GetTypeInfo,:GetIDsOfNames,:Invoke)
  IEVENTSINKOBJ = Struct.new(:lpVtbl,:m_cRef,:m_iid,:m_event_id,:pTypeInfo)
   
  @@EVENTSINK_QueryInterface = Win32::API::Callback.new('LLL','L',&lambda { |pEV,riid,ppv|
    ref = 0.chr * 20
    memcpy(ref, pEV, 20)

    iid = 0.chr * 16
    memcpy(iid,riid,16)

    ptr = IEVENTSINKOBJ.new(*ref.unpack('L*'))
    m_iid = ptr.m_iid
    ref = 0.chr * 16
    memcpy(ref, m_iid, 16)

    if iid == WIN32OLE::IID_IUnknown || iid == WIN32OLE::IID_IDispatch || iid == ref
      memcpy(ppv, [pEV].pack('L'), 4)
    else
      memcpy(ppv, 0.chr * 4, 4)
      return E_NOINTERFACE
    end

    lpVtbl = 0.chr * 4
    table = 0.chr * 28
    memcpy(lpVtbl,pEV,4)
    memcpy(table,lpVtbl.unpack('L').first,28)
    table = table.unpack('L*')

    addRef = Win32::API::Function.new(table[1],'P','L')
    addRef.call(pEV)

    S_OK     
  })

  @@EVENTSINK_AddRef = Win32::API::Callback.new('L','L') { |pEV|
    m_cRef = 0.chr * 4
    memcpy(m_cRef, pEV+4, 4)
    m_cRef = [m_cRef.unpack('L').first+1].pack('L')
    memcpy(pEV+4, m_cRef, 4)
    m_cRef.unpack('L').first
  }

  @@EVENTSINK_Release = Win32::API::Callback.new('L','L') { |pEV|
    m_cRef = 0.chr * 4
    memcpy(m_cRef,pEV+4,4)
    m_cRef = [m_cRef.unpack('L').first-1].pack('L')
    memcpy(pEV+4,m_cRef,4)  

    if m_cRef.unpack('L').first != 0
      m_cRef.unpack('L').first
    else
      WIN32OLE_EVENT.EVENTSINK_Destructor(pEV)
      0
    end
  }

  @@EVENTSINK_Invoke = Win32::API::Callback.new('LLPLLLPPP', 'L', &lambda{ |pEventSink,dispid,riid,lcid,wFlags,pdispparams,pvarResult,pexceptinfo,puArgErr|
    ptr = 0.chr * 20
    memcpy(ptr, pEventSink, 20)
    pEV = IEVENTSINKOBJ.new(*ptr.unpack('L*'))
    pTypeInfo = pEV.pTypeInfo
    m_event_id = pEV.m_event_id
    obj = @@ary_ole_event[m_event_id]

    if !obj.is_a?(WIN32OLE_EVENT)
      return S_OK
    end

    ary = obj.events

    if ary.nil? || !ary.is_a?(Array)
      return S_OK
    end

    lpVtbl = 0.chr * 4
    table = 0.chr * 32
    memcpy(lpVtbl, pTypeInfo, 4)
    memcpy(table, lpVtbl.unpack('L').first, 32)
    table = table.unpack('L*')
    getNames = Win32::API::Function.new(table[7], 'PLPLP', 'L')
    bstr = 0.chr * 4
    count = 0.chr * 4
    hr = getNames.call(pTypeInfo,dispid,bstr,1,count)

    if hr != S_OK
      return S_OK
    end

    bstr = bstr.unpack('L').first
    str = 0.chr * 256
    wcscpy(str,bstr)
    SysFreeString(bstr)
    ev = wide_to_multi(str)
    event, is_default_handler = WIN32OLE_EVENT.ole_search_event(ary, ev)

    if event.is_a?(Array)
      handler = event[0]
      mid = 'call'
      is_outarg = event[3]
    else
      handler = obj.handler
      if handler.nil?
        return S_OK
      end
      mid, is_default_handler = ole_search_handler_method(handler, ev)
    end

    if handler.nil? || mid.nil?
      return S_OK
    end
    
    args = []

    if is_default_handler
      args.push(ev)
    end

    cArgs = 0.chr * 4
    memcpy(cArgs,pdispparams+8,4)
    cArgs = cArgs.unpack('L').first

    for i in 0 ... cArgs
       rgvarg = 0.chr * 4
       memcpy(rgvarg,pdispparams,4)
       pvar = 0.chr * 16
       memcpy(pvar,rgvarg.unpack('L').first + (cArgs-i-1)*16,16)
       args.push(WIN32OLE.ole_variant2val(pvar))
    end

    outargv = nil

    if is_outarg 
      outargv = []
      args.push(outargv)
    end
    
    arg = [handler,mid,args]

    begin
      result = handler.send(mid,*args)
    rescue Exception => err
      raise err
    end

    if result.is_a?(Hash)
      hash2ptr_dispparams(result, pTypeInfo, dispid, pdispparams)
      result = hash2result(result)
    elsif is_outarg && outargv.is_a?(Array)
      ary2ptr_dispparams(outargv, pdispparams)
    end
    
    if pvarResult
      varResult = 0.chr * 16
      WIN32OLE.ole_val2variant(result, varResult)
      memcpy(pvarResult, varResult, 16)
    end
    
    S_OK
  })

  @@EVENTSINK_GetIDsOfNames = Win32::API::Callback.new('LPPLLP','L'){ |pEventSink,riid,sznames,cNames,lcid,pDispID|
    pEV = pEventSink
    ptr = 0.chr * 4
    memcpy(ptr, pEV+12, 4)
    pTypeInfo = ptr.unpack('L').first

    if pTypeInfo != 0
      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      memcpy(lpVtbl, pTypeInfo, 4)
      memcpy(table, lpVtbl.unpack('L').first, 28)
      table = table.unpack('L*')
      getIDsOfNames = Win32::API::Function.new(table[5], 'PPPLLP', 'L')
      return getIDsOfNames.call(pTypeInfo, szNames, cNames, pDIspID)
    end

    DISP_E_UNKNOWNNAME
  }

  @@EVENTSINK_GetTypeInfoCount = Win32::API::Callback.new('LP','L'){ |pEV,pct|
    pct[0,4] = 0.chr * 4
    S_OK
  }

  @@EVENTSINK_GetTypeInfo = Win32::API::Callback.new('LLLL','L'){ |pEV,info,lcid,pInfo|
    memcpy(pInfo,0.chr * 4,4)
    DISP_E_BADINDEX
  }
   
  attr_accessor :events
  attr_accessor :handler
   
  def hash2ptr_dispparams(hash,pTypeInfo,dispid,pdispparams)
    cArgs = 0.chr * 4
    memcpy(cArgs,pdispparams+8,4)
    cArgs = cArgs.unpack('L').first
    bstrs = 0.chr * 4 * (cArgs+1)
    lpVtbl = 0.chr * 4
    table = 0.chr * 32
    memcpy(lpVtbl,pTypeInfo,4)
    memcpy(table,lpVtbl.unpack('L').first,32)
    table = table.unpack('L*')
    getNames = Win32::API::Function.new(table[7],'PLPLP','L')
    len = 0.chr * 4
    hr = getNames.call(pTypeInfo,dispid,bstrs,cArgs+1,len)
    len = len.unpack('L').first

    return if hr != S_OK

    for i in 0 ... len-1
      str = 0.chr * 256
      bstr = bstrs[(i+1)*4,4].unpack('L').first
      wcscpy(str,bstr)
      SysFreeString(bstr)
      key = wide_to_multi(str)
      val = hash[i]
      if val.nil?
        val = hash[key]
      end
      if val.nil?
        val = hash[key.intern]
        rgvarg = 0.chr * 4
        memcpy(rgvarg,pdispparams,4)
        pvar = 0.chr * 16
        memcpy(pvar,rgvarg.unpack('L').first + (cArgs-i-1)*16,16)
        ole_val2ptr_variant(val, pvar)
      end
    end
  end
   
  def hash2result(hash)
    ret = hash['return']
    if ret.nil?
      ret = hash[:return]
    end
    ret
  end
   
  def ary2ptr_dispparams(ary,pdispparams)
    i = 0
    cArgs = 0.chr * 4
    memcpy(cArgs,pdispparams+8,4)
    cArgs = cArgs.unpack('L').first

    while i < ary.length && i < cArgs
      v = ary[i]
      rgvarg = 0.chr * 4
      memcpy(rgvarg,pdispparams,4)
      pvar = 0.chr * 16
      memcpy(pvar,rgvarg.unpack('L').first + (cArgs-i-1)*16,16)
      ole_val2ptr_variant(v, pvar)
      i += 1
    end
  end
   
  def EVENTSINK_Constructor() 
    if !@@g_IsEventSinkVtblInitialized
      @@vtEventSink = IEventSinkVtbl.new
      @@vtEventSink.QueryInterface=@@EVENTSINK_QueryInterface.address
      @@vtEventSink.AddRef = @@EVENTSINK_AddRef.address
      @@vtEventSink.AddRef = @@EVENTSINK_AddRef.address
      @@vtEventSink.Release = @@EVENTSINK_Release.address
      @@vtEventSink.Invoke = @@EVENTSINK_Invoke.address
      @@vtEventSink.GetIDsOfNames = @@EVENTSINK_GetIDsOfNames.address
      @@vtEventSink.GetTypeInfoCount = @@EVENTSINK_GetTypeInfoCount.address
      @@vtEventSink.GetTypeInfo = @@EVENTSINK_GetTypeInfo.address
      @@vtEventSinktbl = @@vtEventSink.to_a.pack('L*')
      @@g_IsEventSinkVtblInitialized = true        
    end

    pEv = IEVENTSINKOBJ.new
    pEv.lpVtbl = [@@vtEventSinktbl].pack('P').unpack('L').first
    pEv.m_cRef = 0
    pEv.m_event_id = 0
    pEv.pTypeInfo = 0
    pEv
  end

  def self.EVENTSINK_Destructor(pEV)
    if pEV != 0
      pEVObj = 0.chr * 20
      memcpy(pEVObj,pEV,20)
      pEVObj = IEVENTSINKOBJ.new(*pEVObj.unpack('L*'))
      WIN32OLE.ole_release(pEVObj.pTypeInfo)
      pEVObj = nil
    end
  end

  def find_iid(ole,ptif,piid,ppTypeInfo)
    is_found = false
    pDispatch = ole.pDispatch
    lpVtbl = 0.chr * 4
    table = 0.chr * 28
    memcpy(lpVtbl, pDispatch, 4)
    memcpy(table, lpVtbl.unpack('L').first, 28)
    table = table.unpack('L*')
    ptr = 0.chr * 4
    getTypeInfo = Win32::API::Function.new(table[4],'PLLP','L')
    hr = getTypeInfo.call(pDispatch, 0, WIN32OLE.locale, ptr)
    pTypeInfo = ptr.unpack('L').first
    return hr if hr != S_OK
      
    lpVtbl = 0.chr * 4
    table = 0.chr * 4 * 22
    memcpy(lpVtbl,pTypeInfo,4)
    memcpy(table,lpVtbl.unpack('L').first,88)
    table = table.unpack('L*')

    getContainingTypeLib = Win32::API::Function.new(table[18],'PPP','L')
    ptr = 0.chr * 4
    index = 0.chr * 4
    getContainingTypeLib.call(pTypeInfo, ptr, index)
    pTypeLib = ptr.unpack('L').first
    WIN32OLE.ole_release(pTypeInfo)
    return hr if hr != S_OK
      
    lpVtbl = 0.chr * 4
    table = 0.chr * 24
    memcpy(lpVtbl,pTypeLib,4)
    memcpy(table,lpVtbl.unpack('L').first,24)
    table = table.unpack('L*')
    getTypeInfo = Win32::API::Function.new(table[4],'PLP','L')
    getTypeInfoCount = Win32::API::Function.new(table[3],'P','L')
    getTypeInfoOfGuid = Win32::API::Function.new(table[5],'PPP','L')
    getTypeInfoOfGuid = Win32::API::Function.new(table[5],'PPP','L')

    if ptif.nil?
      hr = getTypeInfoOfGuid.call(pTypeLib,ppid,ppTypeInfo)
      WIN32OLE.ole_release(pTypeInfo)
      return hr
    end

    count = getTypeInfoCount.call(pTypeLib)

    for index in 0 ... count
      ptr = 0.chr * 4
      hr = getTypeInfo.call(pTypeLib, index, ptr)
      pTypeInfo = ptr.unpack('L').first
      break if hr != S_OK
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl, pTypeInfo, 4)
      memcpy(table, lpVtbl.unpack('L').first, 88)
      table = table.unpack('L*')

      getTypeAttr = Win32::API::Function.new(table[3], 'PP','L')
      getVarDesc = Win32::API::Function.new(table[6], 'PLP','L')
      getNames = Win32::API::Function.new(table[7], 'PLPLP','L')
      getRefTypeOfImplType = Win32::API::Function.new(table[8], 'PLP','L')
      getRefTypeInfo = Win32::API::Function.new(table[14], 'PLP','L')
      getFuncDesc = Win32::API::Function.new(table[5], 'PLP','L')
      getDocumentation = Win32::API::Function.new(table[12], 'PLPPPP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19], 'PP','L')
      releaseVarDesc = Win32::API::Function.new(table[21], 'PP','L')
      addRef = Win32::API::Function.new(table[1],'P','L')

      ptr = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo, ptr)
      pTypeAttr = ptr.unpack('L').first

      if hr != S_OK
        WIN32OLE.ole_release(pTypeInfo)
        break
      end

      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      typekind = typeAttr[40,4].unpack('L').first
      cImplTypes = typeAttr[48,2].unpack('S').first

      if typekind == TKIND_COCLASS
        for type in 0 ... cImplTypes
          ref = 0.chr * 4
          hr = getRefTypeOfImplType.call(pTypeInfo,type,ref)
          break if hr != S_OK
          ref = ref.unpack('L').first
          p = 0.chr * 4
          hr = getRefTypeInfo.call(pTypeInfo,ref,p)
          pImplTypeInfo = p.unpack('L').first
          bstr = 0.chr * 4
          hr = getDocumentation.call(pImplTypeInfo,-1,bstr,nil,nil,nil)

          if hr != S_OK
            WIN32OLE.ole_release(pTypeInfo)
            break
          end

          str = 0.chr * 256
          wcscpy(str,bstr.unpack('L').first)
          pstr = wide_to_multi(str)

          if ptif == pstr
            p = 0.chr * 4
            hr = getTypeAttr.call(pImplTypeInfo,p)
            pImplTypeAttr = p.unpack('L').first
            if hr == S_OK
              is_found = true
              memcpy(piid,pImplTypeAttr,16)
              if ppTypeInfo
                ppTypeInfo[0,4] = [pImplTypeInfo].pack('L')
                addRef.call(pImplTypeInfo)
              end
              releaseTypeAttr.call(pImplTypeInfo,pImplTypeAttr)
            end
          end
          WIN32OLE.ole_release(pImplTypeInfo)
          break if is_found || hr != S_OK              
        end
      end
      releaseTypeAttr.call(pTypeInfo, pTypeAttr)
      WIN32OLE.ole_release(pTypeInfo)
      break if is_found || hr != S_OK              
    end

    WIN32OLE.ole_release(pTypeLib)
    return [E_NOINTERFACE].pack('L').unpack('l').first if !is_found
    hr
  end
   
  def find_coclass(pTypeInfo,pTypeAttr,pCOTypeInfo,pCOTypeAttr)
    found = false
    lpVtbl = 0.chr * 4
    table = 0.chr * 4 * 22
    memcpy(lpVtbl,pTypeInfo,4)
    memcpy(table,lpVtbl.unpack('L').first,88)
    table = table.unpack('L*')
    pTypeInfo = 0.chr * 4

    getContainingTypeLib = Win32::API::Function.new(table[18],'PPP','L')
    getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
    getVarDesc = Win32::API::Function.new(table[6],'PLP','L')
    getNames = Win32::API::Function.new(table[7],'PLPLP','L')
    releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
    getRefTypeOfImplType = Win32::API::Function.new(table[8],'PLP','L')
    getImplTypeFlags = Win32::API::Function.new(table[9],'PLP','L')
    getRefTypeInfo = Win32::API::Function.new(table[14],'PLP','L')

    p = 0.chr * 4
    hr = getContainingTypeLib.call(pTypeInfo, p, nil)
    pTypeLib = p.unpack('L').first
    return hr if hr != S_OK
    lpVtbl = 0.chr * 4
    table = 0.chr * 56
    memcpy(lpVtbl,pTypeLib,4)
    memcpy(table,lpVtbl.unpack('L').first,40)
    table = table.unpack('L*')
    getTypeInfoCount = Win32::API::Function.new(table[3],'P','L')
    getTypeInfo = Win32::API::Function.new(table[4],'PLP','L')

    count = getTypeInfoCount.call(pTypeLib)
    for i in 0 ... count
      break if found

      p = 0.chr * 4
      h = getTypeInfo.call(pTypeLib, i, p)
      pTypeInfo2 = p.unpack('L').first

      next if hr != S_OK

      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo2,p)
      pTypeAttr2 = p.unpack('L').first

      if hr != S_OK
        WIN32OLE.ole_release(pTypeInfo2)
        next
      end

      typeAttr = 0.chr * 76
      memcpy(typeAttr,pTypeAttr,76)
      typekind = typeAttr[40,4].unpack('L').first
      cImplTypes = typeAttr[48,2].unpack('S').first

      if typekind != TKIND_COCLASS
        releaseTypeAttr.call(pTypeInfo2, pTypeAttr2)
        WIN32OLE.ole_release(pTypeInfo2)
        next
      end  

      for j in 0 ... cImplTypes
        break if found
        flags = 0.chr * 4
        hr = getImplTypeFlags.call(pTypeInfo2, j, flags)
        next if hr != S_OK
        next if (flags.unpack('L').first & IMPLTYPEFLAG_FDEFAULT) == 0
        href = 0.chr * 4
        hr = getRefTypeOfImplType.call(pTypeInfo2, j, href)
        next if hr != S_OK
        href = href.unpack('L').first
        p = 0.chr * 4
        hr = getRefTypeInfo.call(pTypeInfo2, href, p)
        next if hr != S_OK
        pRefTypeInfo = p.unpack('L').first
        p = 0.chr * 4
        hr = getTypeAttr.call(pRefTypeInfo,p)
        pRefTypeAttr = p.unpack('L').first

        if hr != S_OK
          WIN32OLE.ole_release(pRefTypeInfo)
          next
        end

        guid1 = 0.chr * 16
        memcpy(typeAttr,pTypeAttr,76)
        guid2 = 0.chr * 16
        memcpy(typeAttr,pRefTypeAttr,76)

        if guid1 == guid2
          found = true
        end
      end

      if !found
        releaseTypeAttr.call(pTypeInfo2, pTypeAttr2)
        WIN32OLE.ole_release(pTypeInfo2)
      end
    end

    WIN32OLE.ole_release(pTypeLib)

    if found
      pCOTypeInfo[0,4] = [pTypeInfo2].pack('L')
      pCOTypeAttr[0,4] = [pTypeAttr2].pack('L')
      hr = S_OK
    else
      hr = [E_NOINTERFACE].pack('L').unpack('l').first
    end

    hr
  end
      
  def find_default_source_from_typeinfo(pTypeInfo,pTypeAttr,ppTypeInfo)
    typeAttr = 0.chr * 76
    memcpy(typeAttr,pTypeAttr,76)
    typekind = typeAttr[40,4].unpack('L').first
    cImplTypes = typeAttr[48,2].unpack('S').first
    lpVtbl = 0.chr * 4
    table = 0.chr * 80

    memcpy(lpVtbl,pTypeInfo,4)
    memcpy(table,lpVtbl.unpack('L').first,80)

    table = table.unpack('L*')
    getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
    getRefTypeOfImplType = Win32::API::Function.new(table[8],'PLP','L')
    getImplTypeFlags = Win32::API::Function.new(table[9],'PLP','L')
    getRefTypeInfo = Win32::API::Function.new(table[14],'PLP','L')
    releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
    hr = E_NOINTERFACE

    for i in 0 ... cImplTypes
      flags = 0.chr * 4
      hr = getImplTypeFlags.call(pTypeInfo, i, flags)
      next if hr != S_OK
      flags = flags.unpack('L').first
       
      if (flgas & IMPLTYPEFLAG_FDEFAULT) != 0 && (flgas & IMPLTYPEFLAG_FSOURCE) != 0 
        ref = 0.chr * 4
        hr = getRefTypeOfImplType.call(pTypeInfo, i, ref)
        next if hr != S_OK
        hRefType = ref.unpack('L').first
        hr = getRefTypeInfo.call(pTypeInfo,hRefType,ppTypeInfo)
        break if hr == S_OK
      end
    end
    hr
  end
   
   def find_default_source(ole,piid,ppTypeInfo)
      pDispatch = ole.pDispatch
        lpVtbl = 0.chr * 4
        table = 0.chr * 28
        memcpy(lpVtbl,pDispatch,4)
        memcpy(table,lpVtbl.unpack('L').first,28)
        table = table.unpack('L*')
        queryInterface = Win32::API::Function.new(table[0],'PPP','L')
      getTypeInfo = Win32::API::Function.new(table[4],'PLLP','L')
      p = 0.chr * 4
      hr = queryInterface.call(pDispatch,IID_IProvideClassInfo2,p)
      if hr == S_OK
         pProvideClassInfo2 = p.unpack('L').first
         lpVtbl = 0.chr * 4
         table = 0.chr * 20
         memcpy(lpVtbl,pProvideClassInfo2,4)
         memcpy(table,lpVtbl.unpack('L').first,20)
         table = table.unpack('L*')
         getGUID = Win32::API::Function.new(table[4],'PLP','L')
         ppid = 0.chr * 16
         hr = getGUID.call(pProvideClassInfo2,GUIDKIND_DEFAULT_SOURCE_DISP_IID,ppid)
         WIN32OLE.olerelease(pProvideClassInfo2)
         if hr == S_OK
            hr = find_iid(ole,nil,ppid,ppTypeInfo)
         end
      end
      return hr if hr == S_OK
      p = 0.chr * 4
      hr = queryInterface.call(pDispatch,IID_IProvideClassInfo,p)
      if hr == S_OK
         pProvideClassInfo = p.unpack('L').first
         lpVtbl = 0.chr * 4
         table = 0.chr * 20
         memcpy(lpVtbl,pProvideClassInfo2,4)
         memcpy(table,lpVtbl.unpack('L').first,20)
         table = table.unpack('L*')       
         getClassInfo = Win32::API::Function.new(table[3],'PP','L')
         p = 0.chr * 4
         hr = getClassInfo.call(pProvideClassInfo,p)
         pTypeInfo = p.unpack('L').first
         WIN32OLE.olerelease(pProvideClassInfo2)
      end
      if hr != S_OK
         p = 0.chr * 4
         hr = getTypeInfo.call(pDispatch,0,WIN32OLE.locale,p)
      end
      return hr if hr != S_OK
      pTypeInfo = p.unpack('L').first
      lpVtbl = 0.chr * 4
      table = 0.chr * 88
      memcpy(lpVtbl,pTypeInfo,4)
      memcpy(table,lpVtbl.unpack('L').first,88)
      table = table.unpack('L*')
      getTypeAttr = Win32::API::Function.new(table[3],'PP','L')
      getVarDesc = Win32::API::Function.new(table[6],'PLP','L')
      getNames = Win32::API::Function.new(table[7],'PLPLP','L')
      releaseTypeAttr = Win32::API::Function.new(table[19],'PP','L')
      p = 0.chr * 4
      hr = getTypeAttr(pTypeInfo,p)
      pTypeAttr = p.unpack('L').first
      if hr != S_OK
         WIN32OLE.olerelease(pTypeInfo)
         return hr
      end
      ppTypeInfo[0,4] = 0.chr * 4
      hr = find_default_source_from_typeinfo(pTypeInfo, pTypeAttr, ppTypeInfo)
      if ppTypeInfo.unpack('L').first == 0
         pTypeInfo2 = 0.chr * 4
         pTypeAttr2 = 0.chr * 4
         hr = find_coclass(pTypeInfo, pTypeAttr, pTypeInfo2, pTypeAttr2)
         if hr == S_OK
            pTypeInfo2 = pTypeInfo2.unpack('L').first
            pTypeAttr2 = pTypeAttr2.unpack('L').first
            hr = find_default_source_from_typeinfo(pTypeInfo2, pTypeAttr2, ppTypeInfo)
            releaseTypeAttr.call(pTypeInfo2, pTypeAttr2)
            WIN32OLE.olerelease(pTypeInfo2)
         end
      end
      releaseTypeAttr.call(pTypeInfo, pTypeAttr)
      WIN32OLE.olerelease(pTypeInfo)
      if ppTypeInfo.unpack('L').first == 0
         hr = E_UNEXPECTED if hr == S_OK
         return hr
      end
      pTypeInfo = ppTypeInfo.unpack('L').first
      p = 0.chr * 4
      hr = getTypeAttr.call(pTypeInfo,p)
      pTypeAttr = p.unpack('L').first
      if hr == S_OK
         memcpy(piid,pTypeAttr,16)
         releaseTypeAttr.call(pTypeInfo,pTypeAttr)
      else
         WIN32OLE.olerelease(pTypeInfo)
      end
      hr
   end
   
  def ev_advise(ole, itf)
    if !ole.is_a?(WIN32OLE)
      raise TypeError, "1st parameter must be WIN32OLE object"
    end

    if itf
      if $SAFE > 0 && itf.tainted
        raise SecurityError, "Insecure Event Creation - #{itf}"
      end

      unless itf.is_a?(String)
        raise TypeError, "2nd parameter must be String"          
      end

      p = 0.chr * 4
      iid = 0.chr * 16
      hr = find_iid(ole,itf,iid,p)
      pTypeInfo = p.unpack('L').first
      lpVtbl = 0.chr * 4
      memcpy(lpVtbl,pTypeInfo,4)
    else
      p = 0.chr * 4
      hr = find_default_source(ole, iid, p)
      pTypeInfo = p.unpack('L').first
    end

    if hr != S_OK
      raise RuntimeError, "interface not found"
    end
      
    pDipatch = ole.pDispatch
    lpVtbl = 0.chr * 4
    memcpy(lpVtbl,pDipatch,4)
    table = 0.chr * 28
    memcpy(table,lpVtbl.unpack('L').first,28)
    table = table.unpack('L*')
    queryInterface = Win32::API::Function.new(table[0],'PPP','L')
    ptr = 0.chr * 4
    hr = queryInterface.call(pDipatch, WIN32OLE::IID_IConnectionPointContainer, ptr)

    if hr != S_OK
      WIN32OLE.ole_release(pTypeInfo)
      raise RuntimeError,"failed to query IConnectionPointContainer"
    end

    pContainer = p.unpack('L').first
    lpVtbl = 0.chr * 4
    table = 0.chr * 28
    memcpy(lpVtbl, pContainer, 4)
    memcpy(table, lpVtbl.unpack('L').first, 28)
    table = table.unpack('L*')
    findConnectionPoint = Win32::API::Function.new(table[4],'PPP','L')

    ptr = 0.chr * 4
    hr = findConnectionPoint.call(pContainer, iid, ptr)
    WIN32OLE.ole_release(pContainer)
    pConnectionPoint = ptr.unpack('L').first

    if hr != S_OK
      WIN32OLE.ole_release(pTypeInfo)
      raise RuntimeError, "failed to query IConnectionPoint"
    end

    pIEV = EVENTSINK_Constructor()
    pIEV.m_iid = [iid].pack('P').unpack('L').first
    @pIEV = pIEV.to_a.pack('L*')
    lpVtbl = 0.chr * 4
    table = 0.chr * 28

    memcpy(lpVtbl, pConnectionPoint, 4)
    memcpy(table, lpVtbl.unpack('L').first, 28)

    table = table.unpack('L*')
    advise = Win32::API::Function.new(table[5],'LLP','L')
    dwCookie = 0.chr * 4
    hr = advise.call(pConnectionPoint, [@pIEV].pack('P').unpack('L').first, dwCookie)
    dwCookie = dwCookie.unpack('L').first

    if hr != S_OK
      raise RuntimeError, "Advise Error"
    end

    pIEV = IEVENTSINKOBJ.new(*@pIEV.unpack('L*'))
    pIEV.m_event_id = @@ary_ole_event.length
    pIEV.pTypeInfo = pTypeInfo
    @dwCookie = dwCookie
    @pConnectionPoint = pConnectionPoint
    @event_id = pIEV.m_event_id
    memcpy([@pIEV].pack('P').unpack('L').first, pIEV.to_a.pack('L*'), 20)

    self     
  end
   
  def self.ole_msg_loop
    msg = 0.chr * 100
    while(PeekMessage(msg,nil,0,0,1)) 
      TranslateMessage(msg)
      DispatchMessage(msg)
    end
  end
   
  def self.message_loop
    ole_msg_loop()
    nil
  end

  def initialize(ole,event=nil)
    if Win32::API::VERSION<='1.4.0'
      raise WIN32OLERuntimeError,'win32-api version 1.4.1 or higher required'
    end

    @dwCookie = 0
    @pConnectionPoint = nil
    @event_id = 0
    ev_advise(ole,event)
    @@ary_ole_event.push(self)
    @events = []
    @handler = nil
    self
  end

  def ole_search_event_at(ary,ev)
    ret = -1
    for i in 0 ... ary.length
      event = ary[i]
      event_name = event[1]
      if event_name.nil? && ev.nil?
        ret = i
        break
      elsif ev.is_a?(String) && event_name.is_a?(String) && ev == event_name
        ret = i
        break
      end         
    end
    ret
  end

  def self.ole_search_event(ary,ev)
    is_default = false
    for i in 0 ... ary.length
      event = ary[i]
      event_name = event[1]
      if event_name.nil? 
        is_default = true
        def_event = event
      elsif ev == event_name
        is_default = false
        return [event,is_default]
      end         
    end
    [def_event,is_default]     
  end
   
  def ole_search_handler_method(handler,ev) 
    is_default_handler = false
    mid = "on#{ev}"
    if handler.respond_to?("on#{ev}")
      return mid,is_default_handler
    end
    mid = "method_missing"
    if handler.respond_to?(mid)
      is_default_handler = true
      return [mid,is_default_handler]
    end
    [nil,is_default_handler]
  end
   
  def ole_delete_event(ary,ev)
    at = ole_search_event_at(ary, ev)
    if at>=0
      ary.delete_at(at)
    end
  end
   
  def add_event_call_back(event,data)
    events = @events
    if events.nil? || !events.is_a?(Array)
      events = []
      @events = events
    end
    ole_delete_event(events,event)
    events.push(data)
  end
   
  def ev_on_event(args,is_ary_arg,&blk)
    if @pConnectionPoint.nil?
      raise WIN32OLERuntimeError, "IConnectionPoint not found. You must call advise at first."
    end
    event = args.shift
    if event
      if !event.is_a?(String) && event.is_a?(Symbol)
        raise TypeError, "wrong argument type (expected String or Symbol)"
      end
      if event.is_a?(Symbol)
        event = event.to_s
      end
    end
    data = [blk,event,args,is_ary_arg]
    add_event_call_back(event,data)
    nil
  end
   
  def on_event(*args,&blk)
    ev_on_event(args,false,&blk)
  end

  def on_event_with_outargs(*args,&blk)
    ev_on_event(args,true,&blk)
  end

  def off_event(event=nil)
    if event
      if !event.is_a?(String) && event.is_a?(Symbol)
        raise TypeError, "wrong argument type (expected String or Symbol)"
      end
      if event.is_a?(Symbol)
        event = event.to_s
      end
    end

    events = @events
    return nil if events.nil?
    ole_delete_event(events, event)
    nil
  end

  def unadvise
    if @pConnectionPoint
      WIN32OLE_EVENT.ole_msg_loop()
      @@ary_ole_event[@event_id]=nil
      lpVtbl = 0.chr * 4
      table = 0.chr * 28
      memcpy(lpVtbl,@pConnectionPoint,4)
      memcpy(table,lpVtbl.unpack('L').first,28)
      table = table.unpack('L*')
      unadvise = Win32::API::Function.new(table[6],'LP','L')
      unadvise.call(@pConnectionPoint,@dwCookie)
      WIN32OLE.ole_release(@pConnectionPoint)
      @pConnectionPoint = nil
    end
    nil
  end
end

class WIN32OLE_VARIANT

   def self.ole_val2olevariantdata(val,vt)
      hr = S_OK

      if (vt & ~VT_BYREF) ==  (VT_ARRAY | VT_UI1) && val.class == String
         len = val.length
         psa = SafeArrayCreateVector(VT_UI1, 0, len)
         if psa == 0
            raise RuntimeError, "fail to SafeArrayCreateVector"
         end
         pdest = 0.chr * 4
         hr = SafeArrayAccessData(psa, pdest)
         if hr == S_OK
            memcpy(pdest.unpack('L').first, val, len)
            SafeArrayUnaccessData(psa)
            @realvar[0,2] = [(vt & ~VT_BYREF)].pack('S')
            p = @realvar[8,4].unpack('L').first
            if p != 0
               SafeArrayDestroy(p)
            end
            @realvar[8,4] = [psa].pack('L')
            if (vt & VT_BYREF) != 0
               @var[0,2] = [vt].pack('S')
               @var[8,4] = [[@realvar].pack('P')].pack('L')
             else 
               hr = VariantCopy(@var, @realvar)
            end
         else 
            if psa != 0
               SafeArrayDestroy(psa)
            end
         end
       elsif (vt & VT_ARRAY) != 0
         if val.nil?
            @var[0,2] = [vt].pack('S')
            if (vt & VT_BYREF) != 0
               @var[8,4] = [[@realvar].pack('P')].pack('L')
            end
         else 
            hr = ole_val_ary2variant_ary(val, @realvar, (vt & ~VT_BYREF))
            if hr == S_OK
               if (vt & VT_BYREF) != 0
                  @var[0,2] = [vt].pack('S')
                  @var[8,4] = [[@realvar].pack('P')].pack('L')
               else 
                  hr = VariantCopy(@var,@realvar)
               end 
            end         
         end
       elsif  (vt & ~VT_BYREF) == VT_I8 || (vt & ~VT_BYREF) == VT_UI8 
         ole_val2variant_ex(val, @realvar, (vt & ~VT_BYREF))
         ole_val2variant_ex(val, @var, (vt & ~VT_BYREF))
         @var[0,2] = [vt].pack('S')
         if (vt & VT_BYREF) != 0
            ole_set_byref(@realvar, @var, vt)
         end
       else 
         if val.nil?
            @var[0,2] = [vt].pack('S')
            if (vt == (VT_BYREF | VT_VARIANT)) 
               ole_set_byref(@realvar, @var, vt)
            else 
               @realvar[0,2] = [vt & ~VT_BYREF].pack('S')
               if (vt & VT_BYREF) != 0
                  ole_set_byref(@realvar, @var, vt)
               end
            end
         else 
            ole_val2variant_ex(val, @realvar, (vt & ~VT_BYREF))
            if (vt == (VT_BYREF | VT_VARIANT)) 
               ole_set_byref(@realvar, @var, vt)
            elsif (vt & VT_BYREF) != 0
               if  (vt & ~VT_BYREF) != @realvar[0,2].unpack('S').first 
                  hr = VariantChangeTypeEx(@realvar, @realvar, 
                        WIN32OLE.locale, 0, (vt & ~VT_BYREF))
               end
               if hr == S_OK
                  ole_set_byref(@realvar, @var, vt)
               end
            else 
               if vt == @realvar[0,2].unpack('S').first 
                  hr = VariantCopy(@var, @realvar)
               else 
                  hr = VariantChangeTypeEx(@var, @realvar, 
                        WIN32OLE.locale, 0, vt)
               end
            end   
         end   
      end   
      
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to change type"
      end
   
   end
   
   def self.array(ary,vt)
       obj = nil
      dim = 0
      i = 0

      WIN32OLE.ole_initialize()

      vt = (vt | VT_ARRAY)
      unless ary.is_a?(Array)
         raise TypeError, "1st parameter must be Array"
      end
      obj = WIN32OLE_VARIANT.new

      dim = ary.length

      psab = 0.chr * 8 * dim

      for i in 0 ... dim
         psab[i*8,4] = [ary[i]].pack('L')
         psab[i*8+4,4] = [0].pack('L')
      end

      psa = SafeArrayCreate((vt & VT_TYPEMASK), dim, psab)
      if psa == 0
         raise RuntimeError, "memory allocation error(SafeArrayCreate)"
      end

      @var[0,2] = [vt].pack('S')
      if (vt & VT_BYREF) != 0
         @realvar[0,2] = [vt & ~VT_BYREF].pack('S')
         @realvar[8,4] = [psa].pack('P')
         @var[8,4] = [@realvar.unpack('P')].pack('P')
      else
         @var[8,4] = [psa].pack('P')
      end
      obj
   end

   def initialize(val=nil, vartype=nil)
      WIN32OLE.ole_initialize    
      @var = 0.chr * 16
      @realvar = 0.chr * 16
      return self if val.nil?
      if !val.is_a?(WIN32OLE) && !val.is_a?(WIN32OLE_VARIANT) && !val.is_a?(Time)
         case val
         when Array,String,Fixnum,Bignum,TrueClass,FalseClass,NilClass
         else
            raise TypeError, "can not convert WIN32OLE_VARIANT from type #{val.class}"
         end
      end
      if vartype.nil?
         WIN32OLE.ole_val2variant(val,@var)
      else
         WIN32OLE_VARIANT.ole_val2olevariantdata(val,vartype)
      end
   end

   def value
      val = WIN32OLE.ole_variant2val(@var)
      vt = @var[0,2].unpack('S').first

      if (vt & ~VT_BYREF) == (VT_UI1|VT_ARRAY)
         if (vt & VT_BYREF) != 0
            memcpy(ref,@var[8,4].unpack('L').first,16)            
            psa = ref[8,4].unpack('L').first
         else 
            psa = @var[8,4].unpack('L').first
         end
         if psa == 0
            return val
         end
         dim = SafeArrayGetDim(psa)
         if dim == 1
            val = val.pack('C*')
         end
      end
      val
   end

   def value=(val)
      vt = @var[0,2].unpack('S').first
      if (vt & VT_ARRAY) != 0 && ((vt & ~VT_BYREF) != (VT_UI1|VT_ARRAY) || val.class != String)
         raise WIN32OLERuntimeError, "`value=' is not available for this variant type object"
      end
      WIN32OLE_VARIANT.ole_val2olevariantdata(val, vt)
      nil
   end

   def vartype
      @var.unpack('S').first
   end

   def get_locked_safe_array
      if (@var[0,2].unpack('S').first & VT_ARRAY) != 0
         raise TypeError, "variant type is not VT_ARRAY."
      end
      if (@var[0,2].unpack('S').first & VT_BYREF) != 0
         ref = 0.chr * 16
         memcpy(ref,@var[8,4].unpack('L').first,16)
         pas = ref[8,4].unpack('L').first
      else
         psa = @var[8,4].unpack('L').first
      end
      return psa if psa == 0
      hr = SafeArrayLock(psa)
      if hr != S_OK
         raise eRuntimeError, "failed to SafeArrayLock"
      end
      psa
   end
   
   def ary2safe_array_index(ary,psa)
      dim = SafeArrayGetDim(psa)
      if dim != ary.length
         raise ArgError, "unmatch number of indices"        
      end
      pid = 0.chr * 4 * dim
      for i in 0 ... dim
         pid[i*4,4] = [ary[i]].pack('L')
      end
      pid
   end
   
   def unlock_safe_array(psa)
      hr = SafeArrayUnlock(psa)
      if hr != S_OK
         raise RuntimeError, "failed to SafeArrayUnlock"
      end
   end
   
   def [](*args)
      val = nil
      if (@var[0,2].unpack('S').first & VT_ARRAY) != 0
         raise WIN32OLERuntimeError, "`[]' is not available for this variant type object"
      end
      psa = get_locked_safe_array()
      return val if psa==0
      
      pid = ary2safe_array_index(args, psa)
      variant = 0.chr*16
      VariantInit(variant)
      variant[0,2] = [(@var[0,2].unpack('S').first & ~VT_ARRAY) | VT_BYREF].pack('S')
      hr = SafeArrayPtrOfIndex(psa, pid, variant[8,4])
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to SafeArrayPtrOfIndex"
      end
      val = WIN32OLE.ole_variant2val(variant)

      unlock_safe_array(psa)
      val      
   end

   def []=(*args)
      if (@var[0,2].unpack('S').first & VT_ARRAY) != 0
         raise WIN32OLERuntimeError, "`[]' is not available for this variant type object"
      end
      psa = get_locked_safe_array()
      if psa == 0
         raise RuntimeError, "failed to get SafeArray pointer"
      end
      pid = ary2safe_array_index(args[0..-2], psa)
      var = 0.chr * 16
      VariantInit(var)
      vt = @var[0,2].unpack('S').first & ~VT_ARRAY
      p = val2variant_ptr(args[-1], var, vt)
      if (var[0,2].unpack('S').first == VT_DISPATCH || var[0,2].unpack('S').first == VT_UNKNOWN) && var[8,4].unpack('L').first == 0
         raise WIN32OLERuntimeError, "argument does not have IDispatch or IUnknown Interface"
      end
      hr = SafeArrayPutElement(psa, pid, p)
      if hr != S_OK
         raise WIN32OLERuntimeError, "failed to SafeArrayPutElement"
      end

      unlock_safe_array(psa)
      args[1]
   end

   Empty = WIN32OLE_VARIANT.new(WIN32OLE::VARIANT::VT_EMPTY)
   Null = WIN32OLE_VARIANT.new(WIN32OLE::VARIANT::VT_NULL)
   Nothing = WIN32OLE_VARIANT.new(WIN32OLE::VARIANT::VT_DISPATCH)
end
