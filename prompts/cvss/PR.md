## PR - Privileges Required

This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability. The Base Score is greatest if no privileges are required. The list of possible values is presented in Table 3.

- `PR:N` None - The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.
- `PR:L` Low - The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.
- `PR:H` High - The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files.

## Scoring guidance

- Privileges Required is usually None for hard-coded credential vulnerabilities or vulnerabilities requiring social engineering (e.g., reflected cross-site scripting, cross-site request forgery, or file parsing vulnerability in a PDF reader).

## Examples

- Cisco IOS Arbitrary Command Execution Vulnerability (CVE-2012-0384), `PR:H` - While several variants are possible, assume worst-case scenario of captive admin exploiting vulnerability.
- SearchBlox Cross-Site Request Forgery Vulnerability (CVE-2015-0970), `PR:N` - The attacker does not need any permissions to perform this attack, the attacker lets the victim perform the action on the attacker’s behalf.
- MySQL Stored SQL Injection (CVE-2013-0375), `PR:L` - The attacker requires an account with the ability to change user-supplied identifiers, such as table names. Basic users do not get this privilege by default, but it is not considered a sufficiently trusted privilege to warrant this metric being High.
- VMware Guest to Host Escape Vulnerability (CVE-2012-1516), `PR:L` - The attacker must have access to the guest virtual machine. This is easy in a tenant environment.
- Apache Tomcat XML Parser Vulnerability (CVE-2009-0783), `PR:H` - The user requires high privileges to be able to modify Tomcat configuration files.
- Lenovo ThnkPwn Exploit (CVE-2016-5729), `PR:H` - The attacker must be able to run kernel level (ring 0) code on the target system.
