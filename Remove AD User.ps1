#Open As Admin
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}

#This script was created  by Tom Bindloss - 2019
#You're free to use this script however you please.
# You can find more of my scripts here - https://github.com/TomBindloss    


#PSA Logon
$PSUser = 'Exchange service account username - usually an email'
$PSPass = 'Password for the account'
$PsPassword = ConvertTo-SecureString -AsPlainText $PSPass -Force
$SecureString = $PsPassword
$PSCreds = New-Object System.Management.Automation.PSCredential($PSUser,$PsPassword)


#Get the deets to make the yeets
$Fname = Read-Host -Prompt "Input First Name"
$Lname = Read-Host -Prompt "Input Surname"
$Email = (Get-ADUser -Identity "$fname$lname" -Properties Mail).Mail
$SAMName = "$fname$Lname"
$Emailname = "$fname $Lname"
$Pword = "Set there password as this"
$Securepassword = ConvertTo-SecureString $PWord -AsPlainText -Force
$disabled = "Disabled Users OU in AD"



#Disable Account & Change Password

Disable-ADAccount -Identity $SAMName 
Set-ADAccountPassword -Identity $SAMName -NewPassword $SecurePassword
Get-ADUser -Identity $SAMName | ForEach-Object { Move-ADObject -Identity $_.ObjectGUID -TargetPath $disabled }
Get-ADUser -Identity $SAMName -Properties MemberOf | ForEach-Object {
  $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
}

echo "Disabling $fname $lname's account"




$Shr = Read-Host -Prompt "Do you want to Convert mailbox to shared and remove license? Y/N"

#If Yes to Shared Mailbox
if ($shr -eq 'Y'){
$FrwUsr = Read-Host -Prompt "Who do you want emails to forward to? (enter email address)"
$AutoRep = "Emails to this mailbox are forwarded to $FrwUsr to respond accordingly."
Connect-MsolService -Credential $PSCreds
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $PSCreds -Authentication Basic -AllowRedirection
Import-PSSession $Session
Set-Mailbox -Identity $EmailName -ForwardingSMTPAddress $FRWUsr
Add-MailboxPermission -Identity $emailname -User $FrwUsr -AccessRights FullAccess -InheritanceType All
Set-MailboxAutoReplyConfiguration -Identity $emailname -AutoReplyState Enabled -ExternalMessage $Autorep -InternalMessage $AutoRep
Set-Mailbox -Type Shared -Identity $Emailname
echo "Mailbox has been set to shared."
Start-Sleep -Milliseconds 300
(get-MsolUser -UserPrincipalName $email).licenses.AccountSkuId |
foreach{
    Set-MsolUserLicense -UserPrincipalName $email -RemoveLicenses $_
}
echo "License removed"

read-host -Prompt "Mailbox set to shared and license removed. Press any button to exit"
Exit
}

#If No to shared mailbox
if ($shr -eq 'N'){
Exit
}
