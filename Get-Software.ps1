# Written by Scott Sheppard
# sock0pen@gmail.com
# Parameters. This must be before anything else. 
param
 (
    [string]$strComp
 )
  
  # Check parameters input
if( $strComp -eq "" )
 {
  $res = "Missing parameters - Usage: .\Get-Software.ps1 hostname"
  echo $res
  exit
 }


Get-WmiObject Win32_Product -ComputerName $strComp  | Sort Name | select Name,Version,InstallDate 