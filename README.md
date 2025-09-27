# BadTakeover-BOF
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

<img width="1567" height="766" alt="image (2)" src="https://github.com/user-attachments/assets/795dc211-5e25-4555-91f5-57f7183aabdf" />

With this ticket in memory, you inherit the privileges of the target account configured on the dMSA object. In our case, we're impersonating an account in the `Domain Admins` group, allowing us full control of the Domain Controller.

<img width="920" height="347" alt="image" src="https://github.com/user-attachments/assets/0959585e-c6c5-4307-81ab-4419bb4f50c0" />

