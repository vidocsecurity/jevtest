## UI - User Interaction

This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable component. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner. The Base Score is greatest when no user interaction is required. The list of possible values is presented in Table 4.

- `UI:N` None - The vulnerable system can be exploited without interaction from any user.
- `UI:R` Required - Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator.

## Examples

- Cantemo Portal Stored Cross-site Scripting Vulnerability (CVE-2019-7551), `UI:R` - The victim needs to navigate to a web page on the vulnerable server that contains malicious scripts injected by the attacker.
- SearchBlox Cross-Site Request Forgery Vulnerability (CVE-2015-0970), `UI:R` - The victim must click a specially crafted link provided by the attacker.
- Google Chrome Sandbox Bypass vulnerability (CVE-2012-5376), `UI:R` - The victim must click a specially crafted link provided by the attacker.
- Microsoft Windows Bluetooth Remote Code Execution Vulnerability (CVE-2011-1265), `UI:N` - No user interaction is required for this attack.
- Failure to Lock Flash on Resume from sleep (CVE-2015-2890), `UI:N` - Many affected systems may enter the S3 sleep state on their own in standard configurations after some time has passed without user activity.
- OpenSSL Heartbleed Vulnerability (CVE-2014-0160), `UI:N` - No user access is required for an attacker to launch a successful attack.
