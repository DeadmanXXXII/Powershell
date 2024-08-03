# Powershell
Here is an extensive list of PowerShell commands.

## Comprehensive List of PowerShell Commands

## System Information and Management

- **Get detailed system information:**
  ```powershell
  Get-ComputerInfo
  ```

- **Get hardware information:**
  ```powershell
  Get-CimInstance -ClassName Win32_Processor
  ```

- **Get BIOS information:**
  ```powershell
  Get-CimInstance -ClassName Win32_BIOS
  ```

- **List environment variables:**
  ```powershell
  Get-ChildItem Env:
  ```

- **Get the last boot time:**
  ```powershell
  (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
  ```

- **List installed hotfixes:**
  ```powershell
  Get-HotFix
  ```

- **List all installed programs:**
  ```powershell
  Get-WmiObject -Class Win32_Product
  ```

- **Check system drive space:**
  ```powershell
  Get-PSDrive -PSProvider FileSystem
  ```

## File and Directory Management

- **List files and directories:**
  ```powershell
  Get-ChildItem
  ```

- **Create a new directory:**
  ```powershell
  New-Item -Path "directoryname" -ItemType Directory
  ```

- **Delete a directory:**
  ```powershell
  Remove-Item -Path "directoryname" -Recurse -Force
  ```

- **Copy files:**
  ```powershell
  Copy-Item -Path "sourcefile" -Destination "destinationfile"
  ```

- **Move files:**
  ```powershell
  Move-Item -Path "sourcefile" -Destination "destinationfile"
  ```

- **Delete files:**
  ```powershell
  Remove-Item -Path "filename"
  ```

- **Search for files:**
  ```powershell
  Get-ChildItem -Recurse -Filter "filename"
  ```

- **Find files containing specific text:**
  ```powershell
  Select-String -Path *.* -Pattern "searchtext"
  ```

- **Get file or directory size:**
  ```powershell
  (Get-Item "filename").length
  ```

- **Get the last modified date of a file:**
  ```powershell
  (Get-Item "filename").LastWriteTime
  ```

- **Get the creation date of a file:**
  ```powershell
  (Get-Item "filename").CreationTime
  ```

- **Rename a file:**
  ```powershell
  Rename-Item -Path "oldname" -NewName "newname"
  ```

## Network Commands

- **Ping a host:**
  ```powershell
  Test-Connection -ComputerName hostname
  ```

- **Trace route to a host:**
  ```powershell
  Test-NetConnection -ComputerName hostname -TraceRoute
  ```

- **Test network connection to a port:**
  ```powershell
  Test-NetConnection -ComputerName hostname -Port port
  ```

- **View routing table:**
  ```powershell
  Get-NetRoute
  ```

- **Flush DNS cache:**
  ```powershell
  Clear-DnsClientCache
  ```

- **Display network shares:**
  ```powershell
  Get-SmbShare
  ```

- **Get network adapter configuration:**
  ```powershell
  Get-NetAdapter
  ```

- **Get detailed IP configuration:**
  ```powershell
  Get-NetIPAddress
  ```

- **List DNS servers:**
  ```powershell
  Get-DnsClientServerAddress
  ```

- **Get firewall rules:**
  ```powershell
  Get-NetFirewallRule
  ```

- **Add a new firewall rule:**
  ```powershell
  New-NetFirewallRule -DisplayName "RuleName" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80
  ```

## User and Group Management

- **List all users:**
  ```powershell
  Get-LocalUser
  ```

- **Add a new user:**
  ```powershell
  New-LocalUser -Name "username" -Password (ConvertTo-SecureString "password" -AsPlainText -Force) -FullName "User Full Name" -Description "User description"
  ```

- **Delete a user:**
  ```powershell
  Remove-LocalUser -Name "username"
  ```

- **Add a user to a group:**
  ```powershell
  Add-LocalGroupMember -Group "groupname" -Member "username"
  ```

- **Remove a user from a group:**
  ```powershell
  Remove-LocalGroupMember -Group "groupname" -Member "username"
  ```

- **Get local group members:**
  ```powershell
  Get-LocalGroupMember -Group "Administrators"
  ```

- **Change user password:**
  ```powershell
  $SecurePassword = ConvertTo-SecureString "NewPassword" -AsPlainText -Force
  Set-LocalUser -Name "username" -Password $SecurePassword
  ```

- **Set user account to expire:**
  ```powershell
  Set-LocalUser -Name "username" -AccountNeverExpires $false
  ```

## Security and Permissions

- **Check file permissions:**
  ```powershell
  Get-Acl -Path "filename"
  ```

- **Change file permissions:**
  ```powershell
  $acl = Get-Acl -Path "filename"
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("username", "FullControl", "Allow")
  $acl.SetAccessRule($rule)
  Set-Acl -Path "filename" -AclObject $acl
  ```

- **Check for permissions inheritance:**
  ```powershell
  (Get-Acl -Path "filename").AreAccessRulesProtected
  ```

- **View active network connections:**
  ```powershell
  Get-NetTCPConnection
  ```

- **Stop a process by PID:**
  ```powershell
  Stop-Process -Id pidnumber
  ```

- **Start a process:**
  ```powershell
  Start-Process -FilePath "processname.exe"
  ```

## System and Application Logs

- **View Windows Event Logs:**
  ```powershell
  Get-EventLog -LogName Application
  ```

- **Export Event Log to a file:**
  ```powershell
  Export-Clixml -Path "filename.xml" -InputObject (Get-EventLog -LogName Application)
  ```

- **View specific log entries:**
  ```powershell
  Get-EventLog -LogName Application -EntryType Error | Format-List
  ```

- **Clear event log:**
  ```powershell
  Clear-EventLog -LogName Application
  ```

- **Export specific log entries to CSV:**
  ```powershell
  Get-EventLog -LogName Application -EntryType Error | Export-Csv -Path "errors.csv"
  ```

## System Maintenance

- **Check system health:**
  ```powershell
  Get-HealthStatus
  ```

- **Repair Windows image:**
  ```powershell
  Repair-WindowsImage -Online -RestoreHealth
  ```

- **Optimize drives:**
  ```powershell
  Optimize-Volume -DriveLetter C -ReTrim -Verbose
  ```

- **Run system file checker:**
  ```powershell
  sfc /scannow
  ```

- **Update Windows Defender:**
  ```powershell
  MpCmdRun.exe -SignatureUpdate
  ```

## PowerShell Script Management

- **Run a PowerShell script:**
  ```powershell
  .\script.ps1
  ```

- **Check execution policy:**
  ```powershell
  Get-ExecutionPolicy
  ```

- **Set execution policy:**
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```

- **List all scheduled tasks:**
  ```powershell
  Get-ScheduledTask
  ```

- **Create a new scheduled task:**
  ```powershell
  $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\path\to\script.ps1"
  $trigger = New-ScheduledTaskTrigger -Daily -At "2:00AM"
  Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MyTask"
  ```

## Summary

This list covers an extensive range of PowerShell commands for system administration, file management, network diagnostics, security, and maintenance tasks. These commands provide robust functionality for managing and securing Windows environments effectively. Copy and paste these commands into your PowerShell console as needed.
