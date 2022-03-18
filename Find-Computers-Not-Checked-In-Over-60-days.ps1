#Written by Scott Sheppard
#Find AD computers that havent checked into AD in over 60 days

$d=Get-Date
$s=Get-ADComputer -Filter * -prop Name,LastLogonDate | Where {$_.LastLogonDate -le $d.AddDays(-60).Date} 
$s | select Name,LastLogonDate | sort LastLogonDate -descending | ConvertTo-Html | Out-File C:\Scripts\ComputersNotCheckedIn.htm