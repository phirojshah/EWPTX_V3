---
description: https://www.indusface.com/learning/file-inclusion-attacks-lfi-rfi/
---

# 6.3 File Inclusion (LFI and RFI)

## File Inclusion (LFI and RFI)

Local file inclusion (LFI) and remote file inclusion (RFI) are vulnerabilities that allow attackers to include files on a web server. Both can lead to malware being uploaded to the server.&#x20;

|                    | Local file inclusion (LFI)                      | Remote file inclusion (RFI)              |
| ------------------ | ----------------------------------------------- | ---------------------------------------- |
| How it happens     | Exploits local file upload functions            | Exploits vulnerable inclusion procedures |
| What it includes   | Files that are already on the server            | Files from remote sources                |
| How it's exploited | Malicious characters are uploaded to the server | External URLs are injected into the page |

To prevent these vulnerabilities, you can:&#x20;

* Use secure coding techniques
* Sanitize user-supplied input
* Don't rely on blacklisting, encoding, or filtering

You can test for file inclusion vulnerabilities using:&#x20;

* The PHP Filter, which can prevent the server from executing a file
* Testing for directory traversal characters, such as ../

These vulnerabilities are often found in PHP applications. They can lead to: Outputting the contents of a file, Arbitrary code execution, and Uploading malware to the server.&#x20;

### **File Inclusion vs. Directory Path Traversal**

**Directory Path Traversal** is a vulnerability that occurs when an attacker can manipulate the file path used by an application to access files.

This manipulation allows attackers to traverse directories and access files or directories outside the intended scope. The vulnerability arises when an application doesn’t properly validate or sanitize user input when constructing file paths.

Directory Path Traversal can often be a means to exploit File Inclusion vulnerabilities. If an attacker can manipulate the file path, they can use it to achieve LFI (Local File Inclusion).

While Directory Path Traversal primarily focuses on manipulating the file system path, File Inclusion vulnerabilities deal with including external files (either locally or remotely).

### Other Resources

* [LFI and RFI](https://www.indusface.com/learning/file-inclusion-attacks-lfi-rfi/)
