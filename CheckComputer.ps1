# Written by Scott Sheppard
# sock0pen@gmail.com
# Updated script to list total and used RAM slots and to show if AD account is Lync enabled.
# Parameters. This must be before anything else. 
param
  (
    [string]$strComp
  )
#Since we run this with our A account, we need to set the background color to something readable. Default is DarkBlue so lets use that.
#$Host.UI.RawUI.BackgroundColor = ($bckgrnd = 'Black')
$Host.UI.RawUI.ForegroundColor = ($frgrnd = 'Gray')

#Set global variable for the Admin account
#This is a generic user account. Replace "Administrator" with the admin user for your environment
$MyAdmin = "EmrLocalAdmin"
 
 
#Clear the screen
cls
# Check parameters input
if( $strComp -eq "" )
  {
    $res = "Missing parameters - Usage: .\CheckComputer.ps1 hostname"
    echo $res
    exit
  }

  
#Setting ErrorHandling to silently continue
$ErrorActionPreference = "SilentlyContinue"
#Load AD module if it's not loaded
If (!(Get-module ActiveDirectory )) {
Import-Module ActiveDirectory
}

#The below function was borrowed from http://stackoverflow.com/questions/2688547/muliple-foreground-colors-in-powershell-in-one-command
#This helps set the color of the text
function Write-Color([String[]]$Text, [ConsoleColor[]]$Color = "White", [int]$StartTab = 0, [int] $LinesBefore = 0,[int] $LinesAfter = 0) {
$DefaultColor = $Color[0]
if ($LinesBefore -ne 0) {  for ($i = 0; $i -lt $LinesBefore; $i++) { Write-Host "`n" -NoNewline } } # Add empty line before
if ($StartTab -ne 0) {  for ($i = 0; $i -lt $StartTab; $i++) { Write-Host "`t" -NoNewLine } }  # Add TABS before text
if ($Color.Count -ge $Text.Count) {
    for ($i = 0; $i -lt $Text.Length; $i++) { Write-Host $Text[$i] -ForegroundColor $Color[$i] -NoNewLine } 
} else {
    for ($i = 0; $i -lt $Color.Length ; $i++) { Write-Host $Text[$i] -ForegroundColor $Color[$i] -NoNewLine }
    for ($i = $Color.Length; $i -lt $Text.Length; $i++) { Write-Host $Text[$i] -ForegroundColor $DefaultColor -NoNewLine }
}
Write-Host
if ($LinesAfter -ne 0) {  for ($i = 0; $i -lt $LinesAfter; $i++) { Write-Host "`n" } }  # Add empty line after
}




#This was borrowed from http://poshcode.org/5827
function Get-Monitorinfo {
           
                        $Monitors = get-wmiobject -ComputerName $strComp -ClassName wmimonitorid -Namespace root/wmi -ErrorAction SilentlyContinue
                        Foreach($Monitor in $Monitors){
						    $Manufacturer = [System.Text.Encoding]::ASCII.GetString($Monitor.ManufacturerName)
                            $Model = [System.Text.Encoding]::ASCII.GetString($Monitor.UserFriendlyName)
                            $SerialNumber = [System.Text.Encoding]::ASCII.GetString($Monitor.SerialNumberID)
                            New-Object -TypeName PSCustomObject -Property @{
							    Manufacturer = $Manufacturer
                                Model = $Model
                                SerialNumber = $SerialNumber
                            }
                        }

}


#Lets test if the computer is online first before throwing a metric ton of commands at it.
#As a side note, I tried wrapping all this into a single function but that didn't work.
if(Test-Connection -cn $strComp -Quiet -BufferSize 16 -Count 1)
   {

#This is to check if Imprivata exists
#$Imprivata = $False
#if(Test-Path -Path "\\$strComp\C$\Program files\Imprivata\OneSign Agent" -pathtype Container)
#{
#    $Imprivata = $True
#}
#if(Test-Path -Path "\\$strComp\C$\Program files (x86)\Imprivata\OneSign Agent" -pathtype Container)
#{
#    $Imprivata = $True
#}

#This code is to check for the presence of $myadmin
#This ran slowly. The fix is to tell it to not search AD for the user by specifying the Domain string.
$found = (Get-WmiObject -ComputerName $strComp -Class Win32_UserAccount -Filter "Domain='$strComp' and Name='$myadmin'") 
  if($found -eq $null)
  { $MyAdmins = "Not Present" }
   Else
   { $MyAdmins = "Present" }

#This gets the users running processes on the computer
$UsersRunningProc = (Get-WmiObject -cn $strComp win32_process).getowner().user | Select -Unique
$RunningProc = Foreach ($ProRunner in $UsersRunningProc) {
If (($ProRunner -ne "SYSTEM") -and ($ProRunner -ne "NETWORK SERVICE") -and ($ProRunner -ne "LOCAL SERVICE")) {
   $RunProc = "$RunProc `n $ProRunner"
 }
}

  
#Instead of running several Get-WMIObject we're going to run it 6 times and get our data from there
#Once for ComputerSystem, Once for OperatingSystem, once for network adapter info, Once for BIOS, once for RAM, and once for Processor info
$win32_CS = Get-WmiObject -cn $strComp Win32_ComputerSystem
$win32_OS = Get-WmiObject -cn $strComp Win32_OperatingSystem
$win32_NIC = Get-WMIObject -cn $strComp Win32_NetworkAdapterConfiguration  |Where{$_.IpEnabled -Match "True"}
$win32_BIOS = Get-WMIObject -cn $strComp Win32_BIOS
$win32_RAM = Get-WMIObject -cn $strComp Win32_PhysicalMemory
$win32_CPU = Get-WMIObject -cn $strComp Win32_Processor

#Checks if computer is 32-Bit or 64-Bit
$Archi = $win32_OS.OSArchitecture
#Get the computer model
$ModelInfo = $win32_CS.model
#Get the computer serial number
$SerNum = (Get-WmiObject -computername $strComp -Class Win32_BIOS).SerialNumber

#Get the CPU Model
$CPU_Model = ($win32_CPU).Name

#If we add things that require the Get-ADComputer function later then it will speed up the script slightly
#By running one Get-ADComputer and then getting our data from that variable.
$ADComp = Get-ADCOmputer $strComp -Properties *

#Gets the computer's OU
$OU = ($ADComp).CanonicalName

#Gets currently logged in user. Returns in a format of either <Domain>\<User> or <Computername>\<user> for local accounts
$LoggedOnUser = $win32_CS.username

#Split so domain is $Split[0] and user is $Split[1]
$Split = $LoggedOnUser.Split('\')

# Get just the Username
$User = $Split[1]

#Lets set the domain as a variable too
$DomainName = $Split[0]

#One query to AD. Speeds things up
$ad_USER = Get-ADUser -Identity $User -Properties *


#Function for days since password change borrowed from http://www.workingsysadmin.com/powershell-function-to-get-time-since-a-users-password-was-last-changed/
function Get-TimeSinceLastPWSet {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True,
                Position=1,
        ValueFromPipeline=$True)]
        [string]$Username
    )
    
    $tsSinceLastPWSet = New-TimeSpan $($ad_USER).Passwordlastset $(get-date)
    $strFormatted = '{0:dd} days, {0:hh} hours' -f $tsSinceLastPWSet
    return $strFormatted
    }

$LoggedOnName = $ad_USER.Name


$ExpirationDate=$ad_USER.AccountExpirationDate
if ($ExpirationDate -ne $Null) {
$Result = ($ExpirationDate -lt (Get-Date))
}
else { $Result = "Never" }

$DaysSinceChange = Get-TimeSinceLastPWSet $User	

#Is the user locked out now?
$LockedOut = $ad_USER.LockedOut

#Get a users employee type
$EmployeeType = ($ad_USER).extensionAttribute4

#BS to get it to show display name correctly
$LastName = $ad_USER.SurName
$FirstName = $ad_USER.GivenName

#Get a users office number
$OfficeLoc = $ad_USER.physicaldeliveryofficename

#Get a users Street Address
$OfficeAddr = $ad_USER.StreetAddress

#Get a users office city
$OfficeCity = $ad_USER.City

#Break out the first 3 chars of Office location
$OfficeGeo = $OfficeLoc.substring(0, 3)

#Get Department
$Department = $ad_USER.Department

#Get Job title
$Title = $ad_USER.Title

#Get Costcenter
$CostCenter = $ad_USER.departmentNumber

#When did they change thier password last?
$PasswdLastSet = $ad_USER.PasswordLastSet

#What department are they with?
#This works most places. Commented out because of my specific environment.
#$Department = $ad_USER | Select-Object -expandproperty Department

#Get Network home drive
$HomeDir = $ad_USER | Select-Object -expandproperty homeDirectory

#Get logon script
$LogonScript = $ad_USER | Select-Object -expandproperty ScriptPath

#Get phone number
$PhoneNum =  $ad_USER | Select-Object -expandproperty officephone

#US Citizen check
If ((Get-ADUser $User -Properties memberof).memberof -like "CN=GP_USCitizens*") { $USCITIZEN = "TRUE" } else { $USCITIZEN = "False" }



#Sadly this needs to be formatted this way. When I tried ($win32_OS).LastBootUpTime it didn't return correctly
#Anyway, the next few lines are the magic to get it in a readable format
$BootTime = Get-WmiObject -ComputerName $strComp -Query "SELECT LastBootUpTime FROM Win32_OperatingSystem"

$now = Get-Date

$bootedTime = $BootTime.ConvertToDateTime($BootTime.LastBootUpTime)

$uptime = $now - $bootedTime

$d =$uptime.days

$h =$uptime.hours

$m =$uptime.Minutes

$s = $uptime.Seconds

#This Get's what OS is installed
$OS = $win32_OS.Caption

#Get Build number
$KEYPATH = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$BUILDID = Invoke-command -computer $strComp -ScriptBlock {$KEYID = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; (Get-ItemProperty $KEYID).ReleaseId}

#Get C drive total size and free space
$disk = Get-WmiObject Win32_LogicalDisk -ComputerName $strComp -Filter "DeviceID='C:'" | Select-Object Size, FreeSpace

#Get installed RAM
$RAM = [Math]::Round($win32_CS.TotalPhysicalMemory/1Gb)

#Get the amount of available RAM
$RAMFree = [Math]::Round(($freemem.FreePhysicalMemory / 1024 / 1024), 2)

#Get RAM Slots
$colSlots = Get-WmiObject -Class "win32_PhysicalMemoryArray" -namespace "root\CIMV2" -cn $strComp
$colRAM = Get-WmiObject -Class "win32_PhysicalMemory" -namespace "root\CIMV2" -cn $strComp
$NumSlots = 0

 $colSlots | ForEach {
#       “Total Number of Memory Slots: ” + $_.MemoryDevices
       $NumSlots = $_.MemoryDevices
 }


$SlotsFilled = 0
 $TotMemPopulated = 0

$colRAM | ForEach {
#        “Memory Installed: ” + $_.DeviceLocator
#        “Memory Size: ” + ($_.Capacity / 1GB) + ” GB”       
        $SlotsFilled = $SlotsFilled + 1
        $TotMemPopulated = $TotMemPopulated + ($_.Capacity / 1GB)
 #      if ($_.Capacity = 0)
 #      {write-host "found free slot"}

}

$TrueBIOS = ($win32_BIOS).SMBIOSBIOSVersion

#Get description of wired NIC
$NICDesc = ($win32_NIC | ? { $_.IPAddress -ne $null }).Description

#The next few lines is the secret sauce to get the IP address and gateway
$Desc = $NICDesc.Split(',')

$TrueNIC = $Desc[0]

$NIC = ($win32_NIC | ? { $_.IPAddress -ne $null }).ipaddress

$IPs = $NIC.Split(',')

$IPv4 = $IPs[0]

$Gateway = ($win32_NIC | ? { $_.IPAddress -ne $null }).DefaultIPGateway

$GW = $Gateway | Select-Object -First 1

$MAC =  ($win32_NIC | where { $_.IpAddress -eq $IPv4}).MACAddress

#Windows install date
$Insdate = ([WMI] '').ConvertToDateTime($win32_OS.InstallDate)

#Get the local admin pw
$LAPW = ($ADComp | Select-Object ms-Mcs-AdmPwd)
if ($LAPW -match '=([^=]+)$')
{
    $LocalAdminPW = $matches[1]
}
$LocalAdminPW = $LocalAdminPW.Substring(0,$LocalAdminPW.Length-1)
#$LocalAdminPW = $LAPW.Split("=")[10]

#This is a dirty way of getting the userid that is listed as owner for an asset in Ad
$CompOwnerF = (Get-ADUser (Get-ADComputer $strComp -Property Managedby).ManagedBy).GivenName 
$CompOwnerS = (Get-ADUser (Get-ADComputer $strComp -Property Managedby).ManagedBy).SurName
$CompOwnerU = (Get-ADUser (Get-ADComputer $strComp -Property Managedby).ManagedBy).SamAccountName

#Lets get the Bitlocker Key
$BitLockComp = Get-ADComputer -Filter {Name -eq $strComp}
$BitLockerObjects = Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $BitLockComp.DistinguishedName -Properties 'msFVE-RecoveryPassword'
$BitLockerKey = $BitLockerObjects | Select -expandproperty msFVE-RecoveryPassword
 
}
#This function was to get services that are set to auto for startup, but are currently not running. 
#Yes, even though I love powershell I still get frustrated. 
function IHatePowershell {
$Services = (Get-WmiObject -cn $strComp win32_service | Where-Object -FilterScript { $_.state -ne "Running" -and $_.StartMode -eq "Auto" }).Name
foreach ($service in $services) {
Write-Color "$service" -Color Green
}
}

#This function is kind of a break-fix function. If we ran this script against a computer with a local account logged in,
#it pukes up errors. So we have to create two seperate functions. One for an AD account and one for a local account and one is if noone is logged in
#It's ugly, but works. 

#This is the function for if no one is logged into the workstation
Function NoLoggedInUser {
Write-Color "#########################################" -Color Red
Write-Color "There is currently nobody actively logged into this machine" -Color White
Write-Color "#########################################" -Color Red
}

#This is the function if an AD account is logged in. 
Function DisplayADAccount {
Write-Color "#########################################" -Color Red
Write-Color "Currently logged in name: ", "$FirstName $LastName" -Color White, Green
Write-Color "Currently logged on user: ", "$User" -Color White, Green
Write-Color "Current User locked: ", "$LockedOut" -Color White, Green
Write-Color "Current User Password last set: ", "$DaysSinceChange ago" -Color White, Green
Write-Color "Current User Account Expiration: ", "$Result" -Color White, Green
Write-Color "Current User Department: ", "$Department" -Color White, Green
Write-Color "Current User Job Title: ", "$Title" -Color White, Green
Write-Color "Current User CostCenter: ", "$CostCenter" -Color White, Green
Write-Color "Current User Home Directory: ", "$HomeDir" -Color White, Green
Write-Color "Current User Logon Script: ", "$LogonScript" -Color White, Green
Write-Color "Current User Phone Number: ", "$PhoneNum" -Color White, Green
Write-Color "Current User US Citizen: ", "$USCITIZEN" -Color White, Green
Write-Color "Current User Employee Type: ", "$EmployeeType" -Color White, Green
Write-Color "Current User Employee Office Address: ", "$OfficeAddr" -Color White, Green
Write-Color "Current User Employee Office City: ", "$OfficeCity" -Color White, Green
Write-Color "Current User Employee Office: ", "$OfficeLoc" -Color White, Green
$LyncEnabled = $ad_USER.'msRTCSIP-PrimaryUserAddress'

If ($LyncEnabled -ne $null) {
 
$LyncStatus = Write-Color "Current User Lync Enabled:", " Yes" -Color White, Green
 }
Elseif (LyncEnabled -eq $null) {
 
$LyncStatus = Write-Color "Current User Lync Enabled:", "No" -Color White, Red
}
Write-Color "#########################################" -Color Red
}

#This is the function if a non-AD account is logged in. 
Function DisplayLocalAccount {
Write-Color "#########################################" -Color Red
Write-Color "Current logged in user is a local account" -Color White
Write-Color "Currently logged on user: $User" -Color White
Write-Color "#########################################" -Color Red
}



#Lets test if the computer is on the network before we throw lots of commands at it
if(Test-Connection -cn $strComp -Quiet -BufferSize 16 -Count 1)
   {
   Write-Color "#########################################" -Color Red
   Write-Color "Information for ", "$strComp" -Color White, Green
   Write-Color "#########################################" -Color Red
   Write-Color "Local Admin password: ", "$LocalAdminPW" -Color White, Green 
   Write-Color "#########################################" -Color Red
   Write-Color "Computer OU: ", "$OU" -Color White, Green
   Write-Color "Computer Owner: ", "$CompOwnerF $CompOwnerS - $CompOwnerU" -Color White, Green
   Write-Color "#########################################" -Color Red
   Write-Color "Operating System: ", "$OS $BUILDID $Archi" -Color White, Green
   Write-Color "Computer Model: ", "$ModelInfo" -Color White, Green
   Write-Color "CPU Model: ", "$CPU_Model" -Color White, Green
   Write-Color "BIOS Version: ", "$TrueBIOS" White, Green
   Write-Color "Computer Serial Number: ", "$SerNum" -Color White, Green
   Write-Color "Computer uptime: ", "$d ", "Days ", "$h ", "Hours ", "$m ", "Minutes ", "$s ", "Seconds"  -Color White, Green, White, Green, White, Green, White, Green
   Write-Color "Computer OS was installed on ", "$InsDate" -Color White, Green
   Write-Color "Computer Network information: ", "$Info" -Color White, Green
   Write-Color "Network Card: ", "$TrueNIC" -Color White, Green
   Write-Color "IP Address: ", "$IPv4" -Color White, Green
   Write-Color "MAC Addresses: ", "$MAC" -Color White, Green
   Write-Color "Default Gateway: ", "$GW" -Color White, Green
   Write-Color "MyAdmin account: ", "$MyAdmins" -Color White, Green
If ($BitlockerKey -eq $Null) {
   Write-Color "Bitlocker Key: " "Not present" -Color White, Green
   }
   else {
   Write-Color "Bitlocker Key: " "$BitLockerKey" -Color White, Green
   }
   Write-Color "Bitlocker key: ", "$BitLockerKey" -Color White, Green
   if($User -eq $Null)
      {
	  NoLoggedInUser
	  }
    elseif($DomainName -eq $strComp)
      {
	  DisplayLocalAccount
	  }
	elseif($DomainName -ne $strComp)
	         {
			 DisplayADAccount
			 }
   Write-Color "Hard drive information for C:" -Color White
   Write-Color ("{0}GB total" -f [math]::truncate($disk.Size / 1GB)) -Color Green
   Write-Color ("{0}GB free" -f [math]::truncate($disk.FreeSpace / 1GB)) -Color Green
   Write-Color "#########################################" -Color Red
   Write-Color "RAM information for ", " $strComp" -Color White, Green
   Write-Color "Installed RAM: ", "$RAM GB" -Color White, Green
   Write-Color "Number of RAM Slots: ", "$NumSlots" -Color White, Green
   Write-Color "Slots in use: ", "$SlotsFilled" -Color White, Green
   Write-Color "#########################################" -Color Red
#   Write-Color "Has Imprivata: ", "$Imprivata" -Color White, Green
   Write-Color "#########################################" -Color Red
   Write-Color "Services that are set to auto but not running:" -Color White, Green
   IHatePowershell
   Write-Color "#########################################" -Color Red
   Write-Color "Users running processes: ", "$RunProc" -Color White, Green
   Write-Color "#########################################" -Color Red
   Write-Color "Monitor Information:" -Color White, Green
   Get-Monitorinfo | Format-Table -Auto
   }
Else
  {
   Write-Color "$strComp is offline" -Color Red
  }