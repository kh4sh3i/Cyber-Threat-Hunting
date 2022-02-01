# Cyber-Threat-Hunting
A curated list of threat detection and hunting resources


### [Persistence](https://attack.mitre.org/tactics/TA0003/)
Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code.
  * Component Object Model Hijacking: Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system. References to various COM objects are stored in the Registry.


### [Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
  * Bypassed: Anti-virus, Application control, Digital Certificate Validation
  * Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries. Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files.
  * example:
  ```
  rundll32 zipfldr.dll, RouteTheCall calc.exe
  ```



### Tools
* [impacket](https://github.com/SecureAuthCorp/impacket): Impacket is a collection of Python classes for working with network protocols.
* 
