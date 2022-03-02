
<#
    .SYNOPSIS
        Displays a UI to rename device using specific naming convention

    .DESCRIPTION
        Renames device using serial, chassis and office name ad naming convention. The UI displays a message to user for a reboot

    .PARAMETER PrefixCheck

        String Value
        Used to check the prefix name is the same as specific in Autopilot deployment profile or Intunes domain join configuration profile
        Exits script if not matches. Ignored if Test is set to $True

    .PARAMETER RecordStatus

        Boolean Value [True or False]. Defaults to True
        Records each step in the script will record a registry key status. This way it can be recorded and control the UI.
        If set to False, Intune may run the UI multiple times. To negate that, the UI is designed to check if the name has even changed

    .PARAMETER NoCreds

        Boolean Value [True or False]. Defaults to False
        Ignore the embedded credential
        Useful if used by other delivery tools or the script is ran with 'run as'


    .PARAMETER ForceReboot

        Boolean Value [True or False]. Defaults to True
        Reboot the device even if rename fails.

    .PARAMETER Test

        Boolean Value [True or False]. Defaults to False
        If set to True, the whatif feature is enabled and no actions will be performed. Also the UI will display a new input box for computer name.

    .EXAMPLE
        .\RenameAutoPilotDeviceUI.ps1

    .EXAMPLE
        .\RenameAutoPilotDeviceUI.ps1 -NoCreds:$true -Test:$true

        Result: Run UI with no credentials and show the status of what would have been done

    .EXAMPLE
        .\RenameAutoPilotDeviceUI.ps1 -NoCreds:$true -ForceReboot:$false

        Result: Run UI with no credentials and rename device, but do not reboot device

    .NOTES
        Author		: Dick Tracy II <richard.tracy@microsoft.com>
	    Source	    : https://www.powershellcrack.com/
        Version		: 1.0.0
        #Requires -Version 3.0
#>
<#
## STORE THESE STEPS ELSEWHERE
##*=============================================

#How to “Obfuscate" password (encrypt & decrypt)

$ADUser = 'contoso\admin'
#STEP 1 - create random passphase (256 AES). Save the output as a variable (copy/paste)
#NOTE: this key is unique; the same key must be used to decrypt
$AESKey = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
Write-host ('$AESKey = @(' + ($AESKey -join ",").ToString() + ')')

#STEP 2 - Encrypt password with AES key. Save the output as a variable (copy/paste)
$AESEncryptedPassword = ConvertTo-SecureString -String '!QAZ1qaz!QAZ1qaz' -AsPlainText -Force | ConvertFrom-SecureString -Key $AESKey
Write-host ('$ADEncryptedPassword = "' + $AESEncryptedPassword + '"')

#STEP 3 - Store as useable credentials; converts encrypted key into secure key for use (used in the script)
$SecurePass = $AESEncryptedPassword | ConvertTo-SecureString -Key $AESKey
$credential = New-Object System.Management.Automation.PsCredential($ADUser, $SecurePass)

#STEP 4 - Test password output (clear text) from creds
$credential.GetNetworkCredential().password

##*=============================================
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory=$False)]
    [String]$PrefixCheck = 'DTOLAB',
    [boolean]$RecordStatus = $False,
    [boolean]$NoCreds = $False,
    [boolean]$ForceReboot = $True,
    [Boolean]$Test = $False,
    [boolean]$Force = $False
)
##*=============================================
##* Variables
##*=============================================
#Generate AES key
$AESKey = @(230,69,177,190,75,214,231,63,142,85,221,38,174,145,77,7,79,129,30,78,194,205,177,239,194,219,126,7,206,212,71,29)

#add username with domain
$ADUser = 'contoso\admin'

#Encrypt password (use AESkey and steps above)
$ADEncryptedPassword = '76492d1116743f0423413b16050a5345MgB8ADAAWQBnADYAYwBsAEsANgBsADAARABEAHMATABGAEgAeQBGAEEASgBPAEEAPQA9AHwANwBhAGYANwBkAGYAZAAxADYAMgAzAGMAYwBlADkAMgBiADQAYgA2ADQAYQBjAGEAOQBlADkAZgBmADYAYgAwADMAZQBkAGIAMgBjADEAOQAxADMAZgBmADYANwBlADMANg
AyADAANAA0AGEAMQBiADkAMQA2ADUAZQA3ADkAMQAyADcAYQBmADYAZQAzAGYAMgAwAGQAOQA3ADEANQAzAGEAOQA4ADAAYwA1ADUAOAA4ADIAYwBjADAAZAA3ADMA'

#*=============================================
##* Runtime Function - REQUIRED
##*=============================================
#region FUNCTION: Check if running in WinPE
Function Test-WinPE{
    return Test-Path -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Control\MiniNT
}
#endregion

#region FUNCTION: Check if running in ISE
Function Test-IsISE {
    # try...catch accounts for:
    # Set-StrictMode -Version latest
    try {
        return ($null -ne $psISE);
    }
    catch {
        return $false;
    }
}
#endregion

#region FUNCTION: Check if running in Visual Studio Code
Function Test-VSCode{
    if($env:TERM_PROGRAM -eq 'vscode') {
        return $true;
    }
    Else{
        return $false;
    }
}
#endregion

#region FUNCTION: Find script path for either ISE or console
Function Get-ScriptPath {
    <#
        .SYNOPSIS
            Finds the current script path even in ISE or VSC
        .LINK
            Test-VSCode
            Test-IsISE
    #>
    param(
        [switch]$Parent
    )

    Begin{}
    Process{
        if ($PSScriptRoot -eq "")
        {
            if (Test-IsISE)
            {
                $ScriptPath = $psISE.CurrentFile.FullPath
            }
            elseif(Test-VSCode){
                $context = $psEditor.GetEditorContext()
                $ScriptPath = $context.CurrentFile.Path
            }Else{
                $ScriptPath = (Get-location).Path
            }
        }
        else
        {
            $ScriptPath = $PSCommandPath
        }
    }
    End{

        If($Parent){
            Split-Path $ScriptPath -Parent
        }Else{
            $ScriptPath
        }
    }

}
#endregion


#region FUNCTION: Attempt to connect to Task Sequence environment
Function Test-SMSTSENV{
    <#
        .SYNOPSIS
            Tries to establish Microsoft.SMS.TSEnvironment COM Object when running in a Task Sequence
        .REQUIRED
            Allows Set Task Sequence variables to be set
        .PARAMETER ReturnLogPath
            If specified, returns the log path, otherwise returns ts environment
    #>
    [CmdletBinding()]
    param(
        [switch]$ReturnLogPath
    )

    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $MyInvocation.MyCommand
    }
    Process{
        try{
            # Create an object to access the task sequence environment
            $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
            #grab the progress UI
            $TSProgressUi = New-Object -ComObject Microsoft.SMS.TSProgressUI
            Write-Verbose ("Task Sequence environment detected!")
        }
        catch{

            Write-Verbose ("Task Sequence environment NOT detected.")
            #set variable to null
            $tsenv = $null
        }
        Finally{
            #set global Logpath
            if ($null -ne $tsenv)
            {
                # Convert all of the variables currently in the environment to PowerShell variables
                #$tsenv.GetVariables() | ForEach-Object { Set-Variable -Name "$_" -Value "$($tsenv.Value($_))" }

                # Query the environment to get an existing variable
                # Set a variable for the task sequence log path

                #Something like C:\WINDOWS\CCM\Logs\SMSTSLog
                [string]$LogPath = $tsenv.Value("_SMSTSLogPath")
                If($null -eq $LogPath){$LogPath = $env:Temp}
            }
            Else{
                $LogPath = $env:Temp
                $tsenv = $false
            }
        }
    }
    End{
        If($ReturnLogPath){
            return $LogPath
        }
        Else{
            return $tsenv
        }
    }
}
#endregion

Function Write-LogEntry{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory=$false,Position=2)]
		[string]$Source,

        [parameter(Mandatory=$false)]
        [ValidateSet(0,1,2,3,4,5)]
        [int16]$Severity = 1,

        [parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputLogFile = $Global:LogFilePath,

        [parameter(Mandatory=$false)]
        [switch]$Outhost
    )
    ## Get the name of this function
    #[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    if (-not $PSBoundParameters.ContainsKey('Verbose')) {
        $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
    }

    if (-not $PSBoundParameters.ContainsKey('Debug')) {
        $DebugPreference = $PSCmdlet.SessionState.PSVariable.GetValue('DebugPreference')
    }
    #get BIAS time
    [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
	[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
	[int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes
	[string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias

    #  Get the file name of the source script
    If($Source){
        $ScriptSource = $Source
    }
    Else{
        Try {
    	    If ($script:MyInvocation.Value.ScriptName) {
    		    [string]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
    	    }
    	    Else {
    		    [string]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
    	    }
        }
        Catch {
    	    $ScriptSource = ''
        }
    }

    #if the severity is 4 or 5 make them 1; but output as verbose or debug respectfully.
    If($Severity -eq 4){$logSeverityAs=1}Else{$logSeverityAs=$Severity}
    If($Severity -eq 5){$logSeverityAs=1}Else{$logSeverityAs=$Severity}

    #generate CMTrace log format
    $LogFormat = "<![LOG[$Message]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$ScriptSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$logSeverityAs`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"

    # Add value to log file
    try {
        Out-File -InputObject $LogFormat -Append -NoClobber -Encoding Default -FilePath $OutputLogFile -ErrorAction Stop
    }
    catch {
        Write-Host ("[{0}] [{1}] :: Unable to append log entry to [{1}], error: {2}" -f $LogTimePlusBias,$ScriptSource,$OutputLogFile,$_.Exception.ErrorMessage) -ForegroundColor Red
    }

    #output the message to host
    If($Outhost)
    {
        If($Source){
            $OutputMsg = ("[{0}] [{1}] :: {2}" -f $LogTimePlusBias,$Source,$Message)
        }
        Else{
            $OutputMsg = ("[{0}] [{1}] :: {2}" -f $LogTimePlusBias,$ScriptSource,$Message)
        }

        Switch($Severity){
            0       {Write-Host $OutputMsg -ForegroundColor Green}
            1       {Write-Host $OutputMsg -ForegroundColor Gray}
            2       {Write-Host $OutputMsg -ForegroundColor Yellow}
            3       {Write-Host $OutputMsg -ForegroundColor Red}
            4       {Write-Verbose $OutputMsg}
            5       {Write-Debug $OutputMsg}
            default {Write-Host $OutputMsg}
        }
    }
}



##*=============================================
##* VARIABLE DECLARATION
##*=============================================
#region VARIABLES: Building paths & values
[string]$scriptPath = Get-ScriptPath
[string]$scriptName = [IO.Path]::GetFileNameWithoutExtension($scriptPath)

#Return log path (either in task sequence or temp dir)
#build log name
[string]$FileName = $scriptName +'.log'
#build global log fullpath
$Global:LogFilePath = Join-Path (Test-SMSTSENV -ReturnLogPath -Verbose) -ChildPath $FileName
Write-Host "logging to file: $LogFilePath" -ForegroundColor Cyan


#===========================================================================
# UI: XAML FORMAT
#===========================================================================
$XAML = @"
<Window x:Class="Win10RebootUI.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:Win10RebootUI"
        mc:Ignorable="d"
        WindowState="Maximized"
        WindowStartupLocation="CenterScreen"
        WindowStyle="None"
        Title="Time Zone Selection"
        Width="1024" Height="768"
        Background="#1f1f1f">
    <Window.Resources>
        <ResourceDictionary>

            <Style TargetType="{x:Type Window}">
                <Setter Property="FontFamily" Value="Segoe UI" />
                <Setter Property="FontWeight" Value="Light" />
                <Setter Property="Background" Value="#1f1f1f" />
                <Setter Property="Foreground" Value="white" />
            </Style>

            <!-- TabControl Style-->
            <Style  TargetType="TabControl">
                <Setter Property="OverridesDefaultStyle" Value="true"/>
                <Setter Property="SnapsToDevicePixels" Value="true"/>
                <Setter Property="Template">
                    <Setter.Value>
                        <ControlTemplate TargetType="{x:Type TabControl}">
                            <Grid KeyboardNavigation.TabNavigation="Local">
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto" />
                                    <RowDefinition Height="*" />
                                </Grid.RowDefinitions>

                                <TabPanel x:Name="HeaderPanel"
                                  Grid.Row="0"
                                  Panel.ZIndex="1"
                                  Margin="0,0,4,-3"
                                  IsItemsHost="True"
                                  KeyboardNavigation.TabIndex="1"
                                  Background="Transparent" />

                                <Border x:Name="Border"
                            Grid.Row="1"
                            BorderThickness="0,3,0,0"
                            KeyboardNavigation.TabNavigation="Local"
                            KeyboardNavigation.DirectionalNavigation="Contained"
                            KeyboardNavigation.TabIndex="2">

                                    <Border.Background>
                                        <SolidColorBrush Color="#4c4c4c"/>
                                    </Border.Background>

                                    <Border.BorderBrush>
                                        <SolidColorBrush Color="#4c4c4c" />
                                    </Border.BorderBrush>

                                    <ContentPresenter x:Name="PART_SelectedContentHost"
                                          Margin="0,0,0,0"
                                          ContentSource="SelectedContent" />
                                </Border>
                            </Grid>
                        </ControlTemplate>
                    </Setter.Value>
                </Setter>
            </Style>

            <!-- TabItem Style -->
            <Style x:Key="OOBETabStyle" TargetType="{x:Type TabItem}" >
                <!--<Setter Property="Foreground" Value="#FFE6E6E6"/>-->
                <Setter Property="Template">
                    <Setter.Value>

                        <ControlTemplate TargetType="{x:Type TabItem}">
                            <Grid>
                                <Border
                                    Name="Border"
                                    Margin="0"
                                    CornerRadius="0">
                                    <ContentPresenter x:Name="ContentSite" VerticalAlignment="Center"
                                        HorizontalAlignment="Center" ContentSource="Header"
                                        RecognizesAccessKey="True" />
                                </Border>
                            </Grid>

                            <ControlTemplate.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Foreground" Value="#313131" />
                                    <Setter TargetName="Border" Property="BorderThickness" Value="0,0,0,3" />
                                    <Setter TargetName="Border" Property="BorderBrush" Value="#4c4c4c" />
                                </Trigger>
                                <Trigger Property="IsMouseOver" Value="False">
                                    <Setter Property="Foreground" Value="#313131" />
                                    <Setter TargetName="Border" Property="BorderThickness" Value="0,0,0,3" />
                                    <Setter TargetName="Border" Property="BorderBrush" Value="#4c4c4c" />
                                </Trigger>
                                <Trigger Property="IsSelected" Value="True">
                                    <Setter Property="Panel.ZIndex" Value="100" />
                                    <Setter Property="Foreground" Value="white" />
                                    <Setter TargetName="Border" Property="BorderThickness" Value="0,0,0,3" />
                                    <Setter TargetName="Border" Property="BorderBrush" Value="White" />
                                </Trigger>
                            </ControlTemplate.Triggers>
                        </ControlTemplate>
                    </Setter.Value>
                </Setter>

            </Style>

            <Style x:Key="DataGridContentCellCentering" TargetType="{x:Type DataGridCell}">
                <Setter Property="Template">
                    <Setter.Value>
                        <ControlTemplate TargetType="{x:Type DataGridCell}">
                            <Grid Background="{TemplateBinding Background}">
                                <ContentPresenter VerticalAlignment="Center" />
                            </Grid>
                        </ControlTemplate>
                    </Setter.Value>
                </Setter>
            </Style>

            <!-- Sub TabItem Style -->
            <!-- TabControl Style-->
            <Style x:Key="ModernStyleTabControl" TargetType="TabControl">
                <Setter Property="OverridesDefaultStyle" Value="true"/>
                <Setter Property="SnapsToDevicePixels" Value="true"/>
                <Setter Property="Template">
                    <Setter.Value>
                        <ControlTemplate TargetType="{x:Type TabControl}">
                            <Grid KeyboardNavigation.TabNavigation="Local">
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="40" />
                                    <RowDefinition Height="*" />
                                </Grid.RowDefinitions>

                                <TabPanel x:Name="HeaderPanel"
                                    Grid.Row="0"
                                    Panel.ZIndex="1"
                                    IsItemsHost="True"
                                    KeyboardNavigation.TabIndex="1"
                                    Background="#FF1D3245" />

                                <Border x:Name="Border"
                                    Grid.Row="0"
                                    BorderThickness="1"
                                    BorderBrush="Black"
                                    Background="#FF1D3245">

                                    <ContentPresenter x:Name="PART_SelectedContentHost"
                                          Margin="0,0,0,0"
                                          ContentSource="SelectedContent" />
                                </Border>
                                <Border Grid.Row="1"
                                        BorderThickness="1,0,1,1"
                                        BorderBrush="#FF1D3245">
                                    <ContentPresenter Margin="4" />
                                </Border>
                            </Grid>
                        </ControlTemplate>
                    </Setter.Value>
                </Setter>
            </Style>


            <Style x:Key="ModernStyleTabItem" TargetType="{x:Type TabItem}">
                <Setter Property="Template">
                    <Setter.Value>

                        <ControlTemplate TargetType="{x:Type TabItem}">
                            <Grid>
                                <Border
                                    Name="Border"
                                    Margin="10,10,10,10"
                                    CornerRadius="0">
                                    <ContentPresenter x:Name="ContentSite" VerticalAlignment="Center"
                                        HorizontalAlignment="Center" ContentSource="Header"
                                        RecognizesAccessKey="True" />
                                </Border>
                            </Grid>

                            <ControlTemplate.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Foreground" Value="#FF9C9C9C" />
                                    <Setter Property="FontSize" Value="16" />
                                    <Setter TargetName="Border" Property="BorderThickness" Value="1,0,1,1" />
                                    <Setter TargetName="Border" Property="BorderBrush" Value="#FF1D3245" />
                                </Trigger>
                                <Trigger Property="IsMouseOver" Value="False">
                                    <Setter Property="Foreground" Value="#FF666666" />
                                    <Setter Property="FontSize" Value="16" />
                                    <Setter TargetName="Border" Property="BorderThickness" Value="1,0,1,1" />
                                    <Setter TargetName="Border" Property="BorderBrush" Value="#FF1D3245" />
                                </Trigger>
                                <Trigger Property="IsSelected" Value="True">
                                    <Setter Property="Panel.ZIndex" Value="100" />
                                    <Setter Property="Foreground" Value="white" />
                                    <Setter Property="FontSize" Value="16" />
                                    <Setter TargetName="Border" Property="BorderThickness" Value="1,0,1,1" />
                                    <Setter TargetName="Border" Property="BorderBrush" Value="#FF1D3245" />
                                </Trigger>
                            </ControlTemplate.Triggers>
                        </ControlTemplate>
                    </Setter.Value>
                </Setter>
            </Style>
            <Style TargetType="{x:Type Button}">
                <Setter Property="Background" Value="#FF1D3245" />
                <Setter Property="Foreground" Value="#FFE8EDF9" />
                <Setter Property="FontSize" Value="15" />
                <Setter Property="SnapsToDevicePixels" Value="True" />

                <Setter Property="Template">
                    <Setter.Value>
                        <ControlTemplate TargetType="Button" >

                            <Border Name="border"
                                BorderThickness="1"
                                Padding="4,2"
                                BorderBrush="#336891"
                                CornerRadius="5"
                                Background="#0078d7">
                                <ContentPresenter HorizontalAlignment="Center"
                                                VerticalAlignment="Center"
                                                TextBlock.TextAlignment="Center"
                                                />
                            </Border>

                            <ControlTemplate.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter TargetName="border" Property="BorderBrush" Value="#FFE8EDF9" />
                                </Trigger>

                                <Trigger Property="IsPressed" Value="True">
                                    <Setter TargetName="border" Property="BorderBrush" Value="#FF1D3245" />
                                    <Setter Property="Button.Foreground" Value="#FF1D3245" />
                                    <Setter Property="Effect">
                                        <Setter.Value>
                                            <DropShadowEffect ShadowDepth="0" Color="#FF1D3245" Opacity="1" BlurRadius="10"/>
                                        </Setter.Value>
                                    </Setter>
                                </Trigger>
                                <Trigger Property="IsEnabled" Value="False">
                                    <Setter TargetName="border" Property="BorderBrush" Value="#336891" />
                                    <Setter Property="Button.Foreground" Value="#336891" />
                                </Trigger>
                                <Trigger Property="IsFocused" Value="False">
                                    <Setter TargetName="border" Property="BorderBrush" Value="#336891" />
                                    <Setter Property="Button.Background" Value="#336891" />
                                </Trigger>

                            </ControlTemplate.Triggers>
                        </ControlTemplate>
                    </Setter.Value>
                </Setter>
            </Style>

        </ResourceDictionary>
    </Window.Resources>

    <Grid HorizontalAlignment="Center" VerticalAlignment="Center">

        <TabControl HorizontalAlignment="Center" VerticalAlignment="Center" Width="1024" Height="700" Margin="0,0,0,40">

            <TabItem x:Name="tabTitle" Style="{DynamicResource OOBETabStyle}" Header="Pending Reboot" Width="167" Height="60" BorderThickness="0" Margin="0,0,-20,0">
                <Grid Background="#004275">
                    <Label x:Name="lblComputerName" Content="After reboot the device will be named:" HorizontalAlignment="Left" FontSize="16" Margin="263,236,0,0" VerticalAlignment="Top" Foreground="White"/>
                    <TextBox x:Name="inputTxtComputerName" FontWeight="Medium"  HorizontalAlignment="Left" Height="44" Margin="263,272,0,0" TextWrapping="NoWrap" VerticalAlignment="Top" Width="502" BorderThickness="0" FontSize="30" IsReadOnly="False" CharacterCasing="Upper"/>

                    <TextBlock x:Name="txtTitle" Text="Ready to use this device?" HorizontalAlignment="Center" VerticalAlignment="Top" FontSize="48" Margin="0,36,0,0" Width="1024" TextAlignment="Center" FontFamily="Segoe UI Light"/>
                    <TextBlock x:Name="txtSubTitle" Text="This device needs to be rebooted before use" HorizontalAlignment="Center" VerticalAlignment="Top" FontSize="16" FontFamily="Segoe UI Light" Margin="0,100,0,0" Width="1024" TextAlignment="Center"/>
                    <Button x:Name="btnReboot" Content="Reboot Now" Height="100" Width="280" HorizontalAlignment="Center" VerticalAlignment="Center" FontSize="24" Padding="10" Margin="372,340,372,200"/>
                    <TextBlock x:Name="txtVersion" HorizontalAlignment="Right" VerticalAlignment="Top" FontSize="12" FontFamily="Segoe UI Light" Width="1004" TextAlignment="right" Margin="0,0,10,0" Foreground="gray"/>
                    <TextBox x:Name="txtError" Margin="10,585,10,10" HorizontalAlignment="Center" Foreground="Black" IsEnabled="False" Text="" FontSize="20" VerticalContentAlignment="Center" HorizontalContentAlignment="Center" Width="1004" />

                </Grid>
            </TabItem>

        </TabControl>
    </Grid>
</Window>
"@


#replace some default attributes to support powershell
[string]$XAML = $XAML -replace 'mc:Ignorable="d"','' -replace "x:N",'N'  -replace '^<Win.*', '<Window'

#=======================================================
# LOAD ASSEMBLIES AND UI
#=======================================================
[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')       | out-null #creating Windows-based applications
[System.Reflection.Assembly]::LoadWithPartialName('WindowsFormsIntegration')    | out-null # Call the EnableModelessKeyboardInterop; allows a Windows Forms control on a WPF page.
[System.Reflection.Assembly]::LoadWithPartialName('System.Windows')             | out-null #Encapsulates a Windows Presentation Foundation application.
[System.Reflection.Assembly]::LoadWithPartialName('System.ComponentModel')      | out-null #systems components and controls and convertors
[System.Reflection.Assembly]::LoadWithPartialName('System.Data')                | out-null #represent the ADO.NET architecture; allows multiple data sources
[System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')      | out-null #required for WPF
[System.Reflection.Assembly]::LoadWithPartialName('PresentationCore')           | out-null #required for WPF
[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Application') | out-null #Encapsulates a Windows Presentation Foundation application.

#convert to XML
[xml]$XAML = $XAML
#Read XAML
$reader=(New-Object System.Xml.XmlNodeReader $xaml)
try{$RebootUI=[Windows.Markup.XamlReader]::Load( $reader )}
catch{
    Write-LogEntry ("Unable to load Windows.Markup.XamlReader. {0}" -f $_.Exception.Message) -Severity 3 -Outhost
    Exit $_.Exception.HResult
}


#take the xaml properties and make them variables
$xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name "ui_$($_.Name)" -Value $RebootUI.FindName($_.Name)}

Function Get-FormVariables{
    if ($global:ReadmeDisplay -ne $true){
        Write-Verbose "To reference this display again, run Get-FormVariables"
        $global:ReadmeDisplay=$true
    }
    Write-Verbose "Displaying elements from the form"
    Get-Variable ui_*
}

If($DebugPreference){Get-FormVariables}


#====================
# Form Functions
#====================

Function Set-StatusKey{
    param(
        [parameter(Mandatory=$False)]
        [ValidateSet('HKLM','HKCU')]
        [string]$Hive = 'HKLM',
        [parameter(Mandatory=$True)]
        [string]$Name,
        [parameter(Mandatory=$True)]
        [string]$Value
    )
    Begin
    {
        $HivePath = "$($Hive):\SOFTWARE"
        $KeyPath = "PowerShellCrack\AutopilotRenamer"
        New-Item -Path $HivePath -Name $KeyPath -Force -ErrorAction SilentlyContinue | Out-Null
        $FullKeyPath = $HivePath + '\' + $KeyPath
    }
    Process
    {
        Try{
            Set-ItemProperty -Path $FullKeyPath -Name $Name -Value $Value -Force -ErrorAction Stop | Out-Null
        }
        Catch{
            Write-LogEntry ("Unable to set status key name [{0}] with value [{1}]. {2}" -f $Name,$Value,$_.Exception.Message) -Severity 3 -Outhost
        }
    }
    End
    {
        Set-ItemProperty -Path $FullKeyPath -Name "LastRan" -Value (Get-Date) -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

#region FUNCTION: Throw errors to Form's Output field
Function Invoke-UIMessage {
    Param(
        [String]$Message,
        [ValidateSet('Warning', 'Error', 'Info','OK')]
        [String]$Type = 'Error',
        $HighlightObject,
        [System.Windows.Controls.TextBox]$OutputErrorObject,
        [switch]$ReturnBool
    )
    ## Get the name of this function
    [string]${CmdletName} = $MyInvocation.MyCommand

    switch($Type){
        'Warning'   {$BgColor = 'Orange';$FgColor='Black';$Severity = 2}
        'Error'     {$BgColor = 'Red';$FgColor='Black';$Severity = 3}
        'Info'      {$BgColor = 'Green';$FgColor='Black';$Severity = 1}
        'OK'      {$BgColor = 'Black';$FgColor='White';$Severity = 0}
    }
    #default to true for retune value
    $ReturnValue = $true

    Try{
        If($Message.Length -gt 0){
            #put a red border around input
            $HighlightObject.BorderThickness = "2"
            $HighlightObject.BorderBrush = $BgColor

            #show error message
            $OutputErrorObject.Visibility = 'Visible'
            $OutputErrorObject.BorderBrush = $FgColor
            $OutputErrorObject.Background = $BgColor
            $OutputErrorObject.Foreground = $FgColor
            $OutputErrorObject.Text = $Message

            If($DebugPreference){Write-LogEntry ("{1} : {0}" -f $Message,$Type) -Source ${CmdletName} -Severity $Severity}
            $ReturnValue = $false
        }
        Else{
            $OutputErrorObject.Visibility = 'Hidden'
            $ReturnValue = $true
        }
    }
    Catch{
        If($DebugPreference){Write-LogEntry ("Unable to display {1} message [{0}] in UI..." -f $Message,$Type) -Source ${CmdletName} -Severity 3}
        If($message.Length -gt 0){$ReturnValue = $false}Else{$ReturnValue = $true}
    }

    If($ReturnBool){
        return $ReturnValue
    }
}
#endregion

Function Test-ComputerName
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [switch]$Outhost
    )

    if ($Name.Length -eq 0)
    {
        Invoke-UIMessage -Message "Please enter a computer name." -HighlightObject $ui_inputTxtComputerName -OutputErrorObject $ui_txtError -Type Error
        Write-LogEntry ("Please enter a computer name.") -Severity 3 -Outhost:$Outhost
        Return $false
    }

    elseif ($Name.Length -gt 15)
    {
        Invoke-UIMessage -Message "Computer name cannot be more than 15 characters." -HighlightObject $ui_inputTxtComputerName -OutputErrorObject $ui_txtError -Type Error
        Write-LogEntry ("Computer name [{0}] cannot be more than 15 characters." -f $Name) -Severity 3 -Outhost:$Outhost
        Return $false
    }

    #Validation Rule for computer names.
    elseif ($Name -match "^[-_]|[^a-zA-Z0-9-_]")
    {
        Invoke-UIMessage -Message "Computer name has invalid characters." -HighlightObject $ui_inputTxtComputerName -OutputErrorObject $ui_txtError -Type Error -Outhost
        Write-LogEntry ("Computer name [{0}] has invalid characters " -f $Name) -Severity 3 -Outhost:$Outhost
        Return $false
    }

    else
    {
        Write-LogEntry ("[{0}] is a valid Computer name" -f $Name) -Severity 1 -Outhost:$Outhost
        Return $true
    }
}


Function Start-RenameUI{
    <#TEST VALUES
    $UIObject=$RebootUI
    $UpdateStatusKeyHive=HKLM
    $UpdateStatusKeyHive="HKLM"
    #>
    [CmdletBinding()]
    param(
        $UIObject,
        [switch]$UpdateStatusKeyHive
    )
    If($PSBoundParameters.ContainsKey('UpdateStatusKeyHive')){Set-StatusKey -Name 'Status' -Value "Running"}

    Try{
        #$UIObject.ShowDialog() | Out-Null
        # Credits to - http://powershell.cz/2013/04/04/hide-and-show-console-window-from-gui/
        Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
        # Allow input to window for TextBoxes, etc
        [Void][System.Windows.Forms.Integration.ElementHost]::EnableModelessKeyboardInterop($UIObject)

        #for ISE testing only: Add ESC key as a way to exit UI
        $code = {
            [System.Windows.Input.KeyEventArgs]$esc = $args[1]
            if ($esc.Key -eq 'ESC')
            {
                $UIObject.Close()
                [System.Windows.Forms.Application]::Exit()
                #this will kill ISE
                [Environment]::Exit($ExitCode);
            }
        }
        $null = $UIObject.add_KeyUp($code)

        $UIObject.Add_Closing({
            [System.Windows.Forms.Application]::Exit()
        })

        $async = $UIObject.Dispatcher.InvokeAsync({
            #make sure this display on top of every window
            $UIObject.Topmost = $true
            # Running this without $appContext & ::Run would actually cause a really poor response.
            $UIObject.Show() | Out-Null
            # This makes it pop up
            $UIObject.Activate() | Out-Null

            #$UI.window.ShowDialog()
        })
        $async.Wait() | Out-Null

        ## Force garbage collection to start form with slightly lower RAM usage.
        [System.GC]::Collect() | Out-Null
        [System.GC]::WaitForPendingFinalizers() | Out-Null

        # Create an application context for it to all run within.
        # This helps with responsiveness, especially when Exiting.
        $appContext = New-Object System.Windows.Forms.ApplicationContext
        [void][System.Windows.Forms.Application]::Run($appContext)
    }
    Catch{
        #If($PSBoundParameters.ContainsKey('UpdateStatusKeyHive')){Set-StatusKey -Name 'Status' -Value 'Failed'}
        #Write-LogEntry ("Exit {1}. Unable to load Windows Presentation UI. {0}" -f $_.Exception.Message,$_.Exception.HResult) -Severity 3 -Outhost
        #Exit $_.Exception.HResult
    }
}

function Stop-RenameUI{
    <#TEST VALUES
    $UIObject=$RebootUI
    $UpdateStatusKeyHive="HKLM\$RegPath"
    $UpdateStatusKeyHive="HKLM:\SOFTWARE\PowerShellCrack\AutopilotRenamer"
    #>
    [CmdletBinding()]
    param(
        $UIObject,
        [switch]$UpdateStatusKeyHive,
        [string]$CustomStatus
    )

    If($CustomStatus){$status = $CustomStatus}
    Else{$status = 'Completed'}

    Try{
        If($PSBoundParameters.ContainsKey('UpdateStatusKeyHive')){Set-StatusKey -Name 'Status' -Value $status}
        #$UIObject.Close() | Out-Null
        $UIObject.Close()
    }
    Catch{
        If($PSBoundParameters.ContainsKey('UpdateStatusKeyHive')){Set-StatusKey -Name 'Status' -Value 'Failed'}
        Write-LogEntry ("Failed to stop Windows Presentation UI properly. {0}" -f $_.Exception.Message) -Severity 2 -Outhost
        #Exit $_.Exception.HResult
    }
}


#==============================
# START: LOGIC CODE
#==============================
Function Test-IsDomainJoined{
    <#
    .SYNOPSIS
        Determine is the device is domain joined or not

    .DESCRIPTION
        Determine is the device is domain joined or not

    .PARAMETER PassThru
        A switch to return the domain name instead of boolean

    .NOTES
        Author		: Dick Tracy II <richard.tracy@microsoft.com>
	    Source	    : https://www.powershellcrack.com/
        Version		: 1.0.0
    #>
    param(
	    [switch]$PassThru
	)
    ## Variables: Domain Membership
    [boolean]$IsMachinePartOfDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').PartOfDomain
    [string]$envMachineWorkgroup = ''
    [string]$envMachineADDomain = ''
    If ($IsMachinePartOfDomain) {
    	If($Passthru){
        	[string]$envMachineADDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').Domain | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
            return $envMachineADDomain
	    }Else{
            return $true
	    }
    }
    Else {
    	If($Passthru){
            [string]$envMachineWorkgroup = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').Domain | Where-Object { $_ } | ForEach-Object { $_.ToUpper() }
            return $envMachineWorkgroup

        }Else{
            return $false
        }
    }

}


Function Get-ADUserOffice {
    <#
    .SYNOPSIS
        Get Active directory users Office attribute

    .DESCRIPTION
        Get Active directory users Office attribute using adsisearcher

    .PARAMETER User
        Specify a users instead of list of users

    .PARAMETER AllProperties
        A switch to return to all properties of user instead of office

    .PARAMETER Credential
        Use alternate credentials when pulling AD objects

    .NOTES
        Author		: Dick Tracy II <richard.tracy@microsoft.com>
	    Source	    : https://www.powershellcrack.com/
        Version		: 1.0.0
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $false)]
        [String]$User,
        [parameter(Mandatory = $false)]
        [switch]$AllProperties,
        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    #Define the Credential
    #$Credential = Get-Credential -Credential $Credential

    # Create an ADSI Search
    $Searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher

    # Get only the Group objects
    $Searcher.Filter = "(objectCategory=User)"

    # Limit the output to 50 objects
    $Searcher.SizeLimit = 0
    $Searcher.PageSize = 10000

    # Get the current domain
    $DomainDN = $(([adsisearcher]"").Searchroot.path)

    If($Credential){
        # Create an object "DirectoryEntry" and specify the domain, username and password
        $Domain = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $DomainDN,$($Credential.UserName),$($Credential.GetNetworkCredential().password)
    }

    # Add the Domain to the search
    #$Searcher.SearchRoot = $Domain

    #set the properties to parse
    $props=@('displayname','userprincipalname','givenname','sn','samaccountname','physicaldeliveryofficename','objectsid')
    [void]$Searcher.PropertiesToLoad.AddRange($props)

    $Results = @()
    # Execute the Search; build object with properties
    Try{
    $Searcher.FindAll() | %{

            $Object = New-Object PSObject -Property @{
                DisplayName = $($_.Properties.displayname)
                UserPrincipalName = $($_.Properties.userprincipalname)
                GivenName = $($_.Properties.givenname)
                SamAccountName = $($_.Properties.samaccountname)
                Surname=$($_.Properties.sn)
                Office=$($_.Properties.physicaldeliveryofficename)
                SID=(new-object System.Security.Principal.SecurityIdentifier $_.Properties.objectsid[0],0).Value
                DN=$_.Path
            }
            $Results += $Object
        }
    }
    Catch{
        #unable to grab attributes
    }

    #return user and properties if specified
    If($User){
        If($AllProperties){
            $Results | Where SamAccountName -eq $User
        }Else{
            $Results | Where SamAccountName -eq $User | Select -ExpandProperty Office
        }
    }
    Else{
        If($AllProperties){
            $Results
        }Else{
            $Results | Select -ExpandProperty Office
        }
    }
}


#if the computer name does not start with the prefix check, assume computer is renamed properly and exit process
If($env:COMPUTERNAME -notmatch "^$PrefixCheck" -and !$Test){
    Write-LogEntry ("Device name [{0}] does not start with [{1}], no need to continue." -f $env:COMPUTERNAME, $PrefixCheck) -Severity 3 -Outhost
    Exit 0
    #Break
}

Write-LogEntry "Grabbing computer information..." -Outhost
#get bios information and serial
$Bios = Get-WMIObject -Class Win32_Bios
#grab computer details
$System = Get-WMIObject -Class Win32_ComputerSystemProduct
#get chassis information
$Enclosure = Get-WMIObject -Class Win32_SystemEnclosure
#Get current username
$username = (Get-WMIObject -Class win32_computersystem | select -ExpandProperty Username).split('\')[1]

#dynamically build parameters
if($NoCreds)
{
    $OfficeParams = @{
        User=$username
    }
}
Else{
    #convert encrypted password into secure string for creds
    $SecurePass = $ADEncryptedPassword | ConvertTo-SecureString -Key $AESKey
    $creds = New-Object System.Management.Automation.PsCredential($ADUser, $SecurePass)

    $OfficeParams = @{
        User=$username
        Credential=$creds
    }
}


Write-LogEntry "Determining Chassis type abbreviation..." -Outhost
#determine the type of device
#lenovo will always default
If($System.Name -match 'Lenovo'){
    $Type='L'
}
Else
{
    #get the chassis type and determine the type value
    Switch ($Enclosure.ChassisTypes)
    {
        "1" {$Type="L"} #Other
        "2" {$Type="D"} #Virtual Machine
        "3" {$Type="D"} #Desktop
        "4" {$Type="D"} #Low Profile Desktop
        "5" {$Type="D"} #Pizza Box
        "6" {$Type="D"} #Mini Tower
        "7" {$Type="D"} #Tower
        "8" {$Type="L"} #Portable
        "9" {$Type="L"} #Laptop
        "10" {$Type="L"} #Notebook
        "11" {$Type="T"} #Handheld
        "12" {$Type="D"} #Docking Station
        "13" {$Type="L"} #All-in-One
        "14" {$Type="L"} #Sub-Notebook
        "15" {$Type="D"} #Space Saving
        "16" {$Type="D"} #Lunch Box
        "17" {$Type="D"} #Main System Chassis
        "18" {$Type="L"} #Expansion Chassis
        "19" {$Type="L"} #Sub-Chassis
        "20" {$Type="L"} #Bus Expansion Chassis
        "21" {$Type="L"} #Peripheral Chassis
        "22" {$Type="L"} #Storage Chassis
        "23" {$Type="L"} #Rack Mount Chassis
        "24" {$Type="D"} #Sealed-Case PC
        "30" {$Type="T"} #Tablet
        "31" {$Type="L"} #Convertible
        "32" {$Type="L"} #Detachable
        Default {$Type="L"} #Unknown
    }
}

Write-LogEntry "Determining User Office abbreviation..." -Outhost

$OfficeName = Get-ADUserOffice @OfficeParams

#convert office name into 2 char Abbreviation
switch($OfficeName){
    'DTREM' {$OfficeDN = 'RM'}
    'DTFIN' {$OfficeDN = 'FN'}
    'DTADM' {$OfficeDN = 'AD'}
    default {$OfficeDN = 'RM'}
}

#build new name; combining each value
[String]$NewComputername = [String]::Concat(($Bios.SerialNumber).ToUpper(),'-', $OfficeDN, $Type)

#===========================================
# END: LOGIC CODE
# NOTE: End with $NewComputername variable
#============================================
$ui_txtVersion.Text = 'v2.1.0'

#Change the display if device is already renamed
If ($env:COMPUTERNAME -ne $ui_inputTxtComputerName.Text)
{
    $ui_txtTitle.Text = 'Ready to use this device?'
    $ui_txtSubTitle.Text = 'This device needs to be rebooted before use'
    $ui_tabTitle.Header = 'Pending Reboot'
    $ui_btnReboot.Content = 'Reboot Now'
}
Else{
    $ui_txtTitle.Text = 'Ready to use this device?'
    $ui_txtSubTitle.Text = ''
    $ui_tabTitle.Header = 'Ready'
    $ui_btnReboot.Content = 'Ready'
}

# make the UI work
#==================
If ($Test)
{
    $ui_lblComputerName.Visibility = 'Visible'
    $ui_inputTxtComputerName.Visibility = 'Visible'
    $ui_inputTxtComputerName.IsEnabled = $True
}
ElseIf ($DebugPreference){
    $ui_lblComputerName.Visibility = 'Visible'
    $ui_inputTxtComputerName.Visibility = 'Visible'
    $ui_inputTxtComputerName.IsEnabled = $False
}
Else{
    $ui_inputTxtComputerName.Visibility = 'Hidden'
    $ui_lblComputerName.Visibility = 'Hidden'
}
$ui_txtError.Visibility = 'Hidden'
$ui_inputTxtComputerName.Text = $NewComputername

#dynamically build parameters
if ($NoCreds)
{
    $RenameParams = @{
        ComputerName=$env:ComputerName
        NewName=$ui_inputTxtComputerName.Text
        WhatIf=$Test
    }
}
Else
{
    $RenameParams = @{
        ComputerName=$env:ComputerName
        NewName=$ui_inputTxtComputerName.Text
        DomainCredential=$creds
        WhatIf=$Test
    }
}

#Build parameters
$UIControlParam = @{
    UIObject=$RebootUI
    UpdateStatusKeyHive=$RecordStatus
    Verbose=$VerbosePreference
    Debug=$DebugPreference
}

#when button is clicked: Rename and Reboot device
$ui_btnReboot.Add_Click({
    If ($env:COMPUTERNAME -eq $ui_inputTxtComputerName.Text)
    {
        #close the UI
        Stop-RenameUI @UIControlParam
    }
    ElseIf( (Test-ComputerName -Name $ui_inputTxtComputerName.Text -Outhost) ){
        #Attempt to Rename device
        Try{
            Rename-Computer @RenameParams -Force -ErrorAction Stop
            Invoke-UIMessage -Message ("Device has been renamed to: {0}" -f $ui_inputTxtComputerName.Text) -HighlightObject $ui_inputTxtComputerName -OutputErrorObject $ui_txtError -Type OK
            If($RecordStatus){
                Set-StatusKey -Name 'RenamedValue' -Value $ui_inputTxtComputerName.Text
                Set-StatusKey -Name 'Status' -Value 'Completed'
            }
            Write-LogEntry ("Device has been renamed to: {0}" -f $ui_inputTxtComputerName.Text) -Severity 1 -Outhost
        }
        Catch{
            Invoke-UIMessage -Message "Unable to rename the device!" -HighlightObject $ui_inputTxtComputerName -OutputErrorObject $ui_txtError -Type Error
            If($RecordStatus){
                Set-StatusKey -Name 'Status' -Value 'Failed'
            }
            Write-LogEntry ("{0}" -f $_.Exception.Message) -Severity 3 -Outhost
        }
        Finally{

            If($ForceReboot){
                If($RecordStatus){
                    Set-StatusKey -Name 'RebootDate' -Value (Get-Date)
                }
                Restart-Computer -Delay 1 -Force -AsJob -WhatIf:$Test
            }

            #close the UI
            Stop-RenameUI @UIControlParam

        }
    }

})

Start-RenameUI @UIControlParam
