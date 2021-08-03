---
title: Security Interview Preparation
date: 2021-08-03 13:28:16
tags: [Security, Study Notes]
---

以下代码中存在什么漏洞？

```
import java.io.*;
import javax.servlet.http.*;
import java.nio.file.*;
public class ReadFile extends HttpServlet{
    protected void test(HttpServletRequest request, HttpServletResponse response) throws IOException{
        try{
            String url = request.getParameter("url");
            String data = new String(Files.readAllBytes(Paths.get(url)));
        }catch(IOException e){
            PrintWriter out = response.getWriter();
            out.print("File not found");
            out.flush();
        }
    }
}
```
答案：
- 本地文件包含 LFI
- 服务器请求伪造 SSRF: Path.get(url) and readAllbytes(), when url is a remote url 
- UNC path 注入, Path.get() can also parse UNC path: 
    - [近期Zoom安全问题频繁进入安全圈的视野](https://www.4hou.com/posts/v9Om)
    - Windows就会尝试使用SMB文件共享协议连接到远程站点来打开一个远程文件, 默认情况下，Windows会发送用户的login用户名和NTLM password哈希值. 可以修改组策略： Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers 为 deny all
    - [纯干货-内网渗透系列教程——NTLM 与 NTLM 身份认证](https://zhuanlan.zhihu.com/p/372961591)

sql注入中报错注入常用的函数有:
- floor():
    - [Mysql报错注入之floor(rand(0)*2)报错原理探究](https://www.freebuf.com/column/235496.html)
- updatexml()
    - updatexml():是mysql对xml文档数据进行查询和修改的xpath函数, updatexml(xml_document,XPthstring,new_value), xpath must be valid path, concat(0x7e, database()), 0x7e is `~`, is an invalid xpath format
- extractvalue()
    - similar to updatexml(), takes an xpath arg
- exp()
    - return error when argument > 709, `~0` always > 709, usually a statement returns 0. so try `exp~(select version())` will return error, and sometimes the `version()` in error message will be evluated

以下哪个操作在Linux 下需要 root 权限:
- `iptables -t nat -L` 
- `nc -l -p 1024` (不需要， 因为是listen在>=1024的port上，不属于privileged port)

以下哪些属于缓冲区溢出保护手段？
- PIE, -fPIE, position independent executable, is used to support ASLR
- NX, none executable page
- Stack Canary

不属于：SE(secure element):


PHP变量覆盖：
[php中哪些函数使用不当会导致变量覆盖,PHP变量覆盖漏洞小结](https://blog.csdn.net/weixin_34486302/article/details/115153306)
- extract(),  parse_str(), import_request_variables()

redis未授权的利用方法包括以下哪几种:
- 写入ssh秘钥
- 向web目录中写入webshell
- 向crontab中写入计划任务

APK V1 签名v1 仅针对单个 ZIP 条目进行验证

Cookie 中的secure属性代表什么：
- secure属性可防止信息在传递的过程中被监听捕获后导致信息泄露，如果设置为true，可以限制只有通过https访问时，才会将浏览器保存的cookie传递到服务端，如果通过http访问，不会传递cookie。
- httpOnly属性可以防止程序获取cookie，如果设置为true，通过js等将无法读取到cookie，能有效的防止XSS攻击


CC攻击：Challenge Collapsar Attack， DDoS的一种


Web Application Firewall  
[WAF机制及绕过方法总结](https://www.freebuf.com/articles/web/229982.html)
- 编码绕过
- 字母大小写转换绕过
- 空格过滤绕过 (使用空白符或者`+`)
- 双关键字绕过
- 内联注释绕过
- 请求方式差异规则松懈性绕过 (例如用Post代替Get)
- 异常Method绕过 （DigAPi）,similar to the above
- 超大数据包绕过
- 复参数绕过
- 添加%绕过过滤
- 协议未覆盖绕过
- 宽字节绕过
- %00截断
。。。。等等

以下哪个工具可以拦截和修改数据包：
- Burpsuite
- Fiddler

防御CSRF漏洞:
- 校验referer
- 请求中添加token
- 验证码 


SSRF： Server-side request Forgery (https://websec.readthedocs.io/zh/latest/vuln/ssrf.html)
SSRF涉及到的危险函数主要是网络访问，支持伪协议的网络读取。以PHP为例，涉及到的函数有 file_get_contents() / fsockopen() / curl_exec() 等。

一些开发者会通过对传过来的URL参数进行正则匹配的方式来过滤掉内网IP
对于这种过滤我们采用改编IP的写法的方式进行绕过，例如192.168.0.1这个IP地址可以被改写成：
- 8进制格式：0300.0250.0.1
- 16进制格式：0xC0.0xA8.0.1
- 10进制整数格式：3232235521
- 16进制整数格式：0xC0A80001
- 合并后两位：1.1.278 / 1.1.755
- 合并后三位：1.278 / 1.755 / 3.14159267


产生死锁的四个必要条件：
- 互斥条件：一个资源每次只能被一个进程使用。
- 请求与保持条件：一个进程因请求资源而阻塞时，对已获得的资源保持不放。
- 不剥夺条件:进程已获得的资源，在末使用完之前，不能强行剥夺。
- 循环等待条件:若干进程之间形成一种头尾相接的循环等待资源关系。
这四个条件是死锁的必要条件，只要系统发生死锁，这些条件必然成立，而只要上述条件之一不满足，就不会发生死锁。

[DSA与RSA](https://blog.csdn.net/qq_35180983/article/details/82665269)

[浅析DOM型XSS](https://www.mi1k7ea.com/2019/06/25/%E6%B5%85%E6%9E%90DOM%E5%9E%8BXSS/) 不会与后台产生交互

参数化查询防范sql注入(parameterized query)
e.g.
```
INSERT INTO myTable (c1, c2, c3, c4) VALUES (@c1, @c2, @c3, @c4)
UPDATE myTable SET c1 = ?, c2 = ?, c3 = ? WHERE c4 = ?
```

[/var/log目录下的20个Linux日志文件功能详解](https://www.huaweicloud.com/articles/833518860d4664d9e8d835c7195571ab.html)

hydra 是一款爆破工具


数学家冯·诺依曼提出了计算机制造的三个基本原则，即采用二进制逻辑、程序存储执行以及计算机由五个部分组成（运算器、控制器、存储器、输入设备、输出设备），这套理论被称为冯·诺依曼体系结构。

越权：[越权（水平越权和垂直越权）](https://www.jianshu.com/p/ec517c3df7cd)（Broken Access Control，简称BAC）

以下命令可以用来在Linux中查看selinux状态的是:
`getenforce` 

```
pr - convert text files for printing
```
Usual Linux: DAC (Discretionary Access Control)
- Users are allowed to alter the access contorol lists on objects they own
SELinux: MAC (Mandatory Access Control)
- The system (admin) sets up the access control lists and users have no control over changing the list

[SELinux 入门](https://zhuanlan.zhihu.com/p/30483108)

XSS 防御：
htmlspecialchars:可以把输入内容转换为HTML实体.

RCE Remote code execution




