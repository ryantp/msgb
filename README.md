# msgb
Message Box -- cli password (or other sensitive information) storage tool

# HOW TO USE:
[Optional] Place the tool (msgb.bat and src/) in a dir that is listed in the PATH variable.
Create dir config (in appd), and run `msgb new-rsa` in this dir.
Create dir msgb (in appd), which is where the .db file will reside.

    C:\> msgb addUser
    >> Username: Example
    >> Password:
    >> Retype Password
    >> Password:
    
    C:\>msgb new-rsa
    ...
    >> Username: Example
    >> Password:
    ...
    
    C:\> msgb addMsg [KEY] [MSG]
    >> Username: Example
    >> Password:
    >> Entry 1 [KEY: [KEY]] added.

