# Cyber-Threat-Hunting
A curated list of threat detection and hunting resources


### [Persistence](https://attack.mitre.org/tactics/TA0003/)
Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code.
  * Component Object Model Hijacking: Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system. References to various COM objects are stored in the Registry.
  * Scheduled Task	: use hidden schtask
  * [Web Shell](https://attack.mitre.org/techniques/T1505/003/): Adversaries may backdoor web servers with web shells to establish persistent access to systems


### [Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
  * Bypassed: Anti-virus, Application control, Digital Certificate Validation
  * Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries. Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files.
  * example:
  ```
  rundll32 zipfldr.dll, RouteTheCall calc.exe
  ```

### [Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
Lateral Movement consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it. Reaching their objective often involves pivoting through multiple systems and accounts to gain. Adversaries might install their own remote access tools to accomplish Lateral Movement or use legitimate credentials with native network and operating system tools, which may be stealthier.
 * [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
  * work with pipe for remote work with other system like telnet 
 * [Windows Management Instrumentation - WMI](https://attack.mitre.org/techniques/T1047/) Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.
  * wmi dosent export data, attacker must use smb!
  * [SharpRDP](https://github.com/0xthirteen/SharpRDP) Remote Desktop Protocol .NET Console Application for Authenticated Command Execution




#### [Security Support Provider(ssp)](https://attack.mitre.org/techniques/T1547/005/) Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.
 * wdigest: IIS(HTTP)
 * credssp: remote auth (RDP)
 * MSV1_0: msv(NTLM)
 * kerberos
 ```
 mimikatz#securlsa::wdigest
 ```



### Tools
* [impacket](https://github.com/SecureAuthCorp/impacket): Impacket is a collection of Python classes for working with network protocols.
 * we can disable SMB (port 455) to disable some impacket, for transfer data from vitcim to hacker use share=SMB !
* [mimikatz](https://github.com/gentilkiwi/mimikatz): Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins and passwords, along with many other features that make it useful for testing the security of networks.
