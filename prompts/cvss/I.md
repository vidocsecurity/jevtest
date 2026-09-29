## I - Integrity

This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. The Base Score is greatest when the consequence to the impacted component is highest. The list of possible values is presented in Table 7.

- `I:H` High - There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.
- `I:L` Low - Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component.
- `I:N` None - There is no loss of integrity within the impacted component.

## Scoring guidance

- The Impact metrics capture the effects of a successfully exploited vulnerability on the component that suffers the worst outcome that is most directly and predictably associated with the attack. Analysts should constrain impacts to a reasonable, final outcome which they are confident an attacker is able to achieve. Only the increase in access, privileges gained, or other negative outcome as a result of successful exploitation should be considered when scoring the Impact metrics of a vulnerability. For example, consider a vulnerability that requires read-only permissions prior to being able to exploit the vulnerability. After successful exploitation, the attacker maintains the same level of read access, and gains write access. In this case, only the Integrity impact metric should be scored, and the Confidentiality and Availability Impact metrics should be set as None. Note that when scoring a delta change in impact, the final impact should be used. For example, if an attacker starts with partial access to restricted information (Confidentiality Low) and successful exploitation of the vulnerability results in complete loss in confidentiality (Confidentiality High), then the resultant CVSS Base Score should reference the “end game” Impact metric value (Confidentiality High). If a scope change has not occurred, the Impact metrics should reflect the Confidentiality, Integrity, and Availability impacts to the vulnerable component. However, if a scope change has occurred, then the Impact metrics should reflect the Confidentiality, Integrity, and Availability impacts to either the vulnerable component, or the impacted component, whichever suffers the most severe outcome.

## Examples

- Apple iOS Security Control Bypass Vulnerability (CVE-2014-2019), `I:H` - High due to importance (security) of this feature
- DNS Kaminsky Bug (CVE-2008-1447), `I:H` - The victim user has trusted a poisoned cache and is being directed to any destination the attacker wishes.
- Failure to Lock Flash on Resume from sleep (CVE-2015-2890), `I:H` - If the BIOS Flash part is not properly protected, the BIOS can be completely overwritten.
- Cisco Access Control Bypass Vulnerability (CVE-2012-1342), `I:L` - Exploitation results in an integrity impact on the network or devices (impacted component) under the protection of the CRS (vulnerable component).
- WordPress Mail Plugin Reflected Cross-site Scripting Vulnerability (CVE-2017-5942), `I:L` - Information in the victim's browser associated with the vulnerable WordPress website can be modified by the malicious JavaScript code.
- OpenSSL Heartbleed Vulnerability (CVE-2014-0160), `I:N` - No information can be modified by the attacker.
