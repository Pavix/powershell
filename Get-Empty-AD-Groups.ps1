#Written by Scott Sheppard

Get-ADGroup -Filter * -Properties Members | where {-not $_.members} | select Name | Export-Csv C:\Scripts\emprtygroups.csv