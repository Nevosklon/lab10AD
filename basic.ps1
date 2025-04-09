$S_OU_PATH = "OU=Staff_OU,OU=4AWS,DC=W2K19AD,DC=local"
$L_OU_PATH = "OU=Student_OU,OU=4AWS,DC=W2K19AD,DC=local"
$PASSWORD = ConvertTo-SecureString -String "Password1" -AsPlainText -Force;

New-ADOrganizationalUnit -Name "4AWS" -Path "DC=W2K19AD,DC=local" -ProtectedFromAccidentalDeletion $False
New-ADOrganizationalUnit -Name "Student_OU" -Path "OU=4AWS,DC=W2K19AD,DC=local" -ProtectedFromAccidentalDeletion $False
New-ADOrganizationalUnit -Name "Staff_OU" -Path "OU=4AWS,DC=W2K19AD,DC=local" -ProtectedFromAccidentalDeletion $False
$USERS = [ordered]@{
    'Username' = @("APeters", "GBega", "OEvans", "EEvans");
    'Name' = @("Allen", "Greg", "Oscar", "Erfyl");
    'Lastname' = @("Peters", "Bega", "Evans", "Evans");
    'Descriptions' = @('Lecturer', 'Student', 'Lecturer', 'Student');
}

New-ADGroup `
    -Name "gg_lectures" `
    -SamAccountName "gg_lectures" `
    -GroupCategory Security `
    -GroupScope Global `
    -DisplayName "gg_lectures" `
    -Path $L_OU_PATH
    
New-ADGroup `
    -Name "gg_students" `
    -SamAccountName "gg_students" `
    -GroupCategory Security `
    -GroupScope Global `
    -DisplayName "gg_students" `
    -Path $S_OU_PATH
    
New-ADGroup `
    -Name  "DL_Student_Files_R" `
    -SamAccountName "DL_Student_Files_R" `
    -GroupCategory Security `
    -GroupScope DomainLocal `
    -DisplayName "DL_Student_Files_R" `
    -Path $S_OUT_PATH
    
New-ADGroup `
    -Name  "DL_Student_Files_M" `
    -SamAccountName "DL_Student_Files_M" `
    -GroupCategory Security `
    -GroupScope DomainLocal `
    -DisplayName "DL_Student_Files_M" `
    -Path $L_OUT_PATH

Add-ADGroupMember -Identity "DL_Student_Files_M" -Members "gg_lectures"
Add-ADGroupMember -Identity "DL_Student_Files_R" -Members "gg_students"

for ( $i=0; $i -le 3; $i++ ) {
    $OU_PATH = $S_OU_PATH
    $GROUP = "gg_students"
    if ( $USERS['Descriptions'][$i] -eq 'Lecturer' ) {
        $OU_PATH = $L_OU_PATH
        $GROUP = "gg_lectures"
    }
    
    New-ADUser `
        -SamAccountName $USERS['Username'][$i] `
        -GivenName $USERS['Name'][$i] `
        -LastName $USERS['Lastname'][$i] `
        -Description $USERS['Descriptions'][$i] `
        -Path $OU_PATH `
        -ChangePasswordAtLogon $false `
        -HomeDirectory '\\Server1\homes\%username%' `
        -HomeDrive "H:" `
        -Enabled $true 
        
    Add-ADGroupMember -Identity $GROUP -Members $USERS['Username'][$i]
}

md C:\Student_Files

$folder_Path = "C:\Student_Files"
New-SmbShare `
    -Name "Student_Files" `
    -Path $folder_path `
    -FullAccess "Everyone"
    

$NewAcl = Get-Acl -Path $folder_path
$isProtected = $true
$preserveInheritance = $true
$NewAcl.SetAccessRuleProtection($isProtected, $preserveInheritance)
Set-Acl -Path $folder_path -AclObject $NewAcl

$acl = Get-Acl $folder_path
$permissionR = "DL_Student_Files_R","ReadAndExecute, ListDirectory, ReadData","Allow"
$accessRuleR = New-Object System.Security.AccessControl.FileSystemAccessRule $permissionR
$acl.SetAccessRule($accessRuleR)
Set-Acl -Path $folder_path -AclObject $acl

$permissionM = "DL_Student_Files_M","ReadAndExecute, ListDirectory, ReadData, WriteData, Modify","Allow"
$accessRuleM = New-Object System.Security.AccessControl.FileSystemAccessRule $permissionM
$acl.SetAccessRule($accessRuleM)
Set-Acl -Path $folder_path -AclObject $acl

Get-Acl $folder_path

mkdir C:\resources
New-SmbShare `
    -Name "resources" `
    -Path "C:\resources" `
    -FullAccess "Everyone"


mkdir C:\homes    
New-SmbShare `
    -Name "homes" `
    -Path "C:\homes" `
    -FullAccess "Everyone"

Write-Host "net use H:\ \\Server1\homes\%username%"
    

    
# Password1	Password1	Password1	Password1
# Lecturer	Student	Lecturer	Student
# Allen	Greg	Oscar	Erfyl
# Peters	Bega	Evans	Evans
# Password1	Password1	Password1	Password1
# Lecturer	Student	Lecturer	Student
