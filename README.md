# BadTakeover-BOF

An associated blog post covering this BOF can be found at: https://specterops.io/blog/2025/10/20/the-near-return-of-the-king-account-takeover-using-the-badsuccessor-technique/

Shortly after the release of Yuval Gordon’s [(YuG0rd)](https://x.com/YuG0rd) [BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) dMSA privilege escalation vector, Microsoft issued a patch fixing the flawed logic in how the Key Distribution Center (KDC) acknowledged Delegated Managed Service Account (dMSA) migration, without protecting sensitive writeable attributes when a dMSA object is controlled by the current user. In a follow-up [blog post](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch) from Yuval, he noted that the technique could still be utilized for account takeover on principals in which we control their object properties, like a Resource-Based Constrained Delegation (RBCD) attack on computer objects or Shadow Credentials attack. 

This motivated me to not only update my previous tooling in .NET for dMSA abuse titled [SharpSuccessor](https://github.com/logangoins/SharpSuccessor) but also create some additional tooling for executing this attack in a stealthy manner during Red Team Operations.

Introducing BadTakeover, a Beacon Object File (BOF) for performing account takeover using the BadSuccessor technique. Using a write primitive over a target object, in addition to the CreateChild edge over an Organizational Unit (OU), it’s possible to impersonate the target object for account takeover via requesting a ticket for the newly created dMSA. 

Execution of the BOF in an Apollo agent as an example is shown below:

<img width="1407" height="760" alt="2025-09-26 22_07_18-" src="https://github.com/user-attachments/assets/d3cf0f24-010a-4264-aad0-3045826505ee" />

Unfortunately for requesting the dMSA ticket, dMSA authentication has not been implemented into BOF related Kerberos repositories such as [Kerbeus-BOF](https://github.com/RalfHacker/Kerbeus-BOF) or [nanorobeus](https://github.com/wavvs/nanorobeus), meaning that unfortunately to request the ticket impersonating a target principal you'll still be required to execute Rubeus (.NET assembly). I hope in the future an established Kerberos BOF respository will expand their `asktgs` functionality to support dMSA authentication once Windows Server 2025 is more popular in corporate environments. 

Requesting the dMSA ticket can be done using the same command as specified in the SharpSuccessor repo:

```
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/ludus.domain /opsec /dmsa /nowrap /ptt /ticket:doIFTDCCB.....
```

With this ticket in memory, you inherit the privileges of the target account configured on the dMSA object. In our case, we're impersonating an account in the `Domain Admins` group, allowing us full control of the Domain Controller.

<img width="1414" height="873" alt="2025-09-27 18_31_09-C__Users_lgoins_Desktop_2025-09-27 18_28_09-C__Users_lgoins_Desktop_image (3) pn" src="https://github.com/user-attachments/assets/a3d0a879-f6fe-4f67-837d-c85b0846b21e" />


