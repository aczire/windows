ACL
===

### General information

* server.cpp - This program creates shared section in Global namespace and set permissions.
* client.cpp - This program try to open shared section (since not all users allow open it) and then simulate some work.
* get-dacl.cpp - This program print out the DACL of the named kernel objects (file, event, mutex, etc.).
* common.h - Some useful functions to get information from the DACL and some common constants.

### Usage example of the client-server program
Source computer has the following users:

![users on test computer](img/users_on_computer.png)

Shared section has the following permissions:

![shared section permissions](img/shared_section_permissions.png)

Bob runs the client:

![bob runs client](img/client_bob.png)

Alice runs the client:

![alice runs client](img/client_alice.png)

TestUser runs the client:

![testuser runs client](img/client_testuser.png)

As expect Alice wasn't allow to open shared section with any permissions, since Alice belongs to Power Users Group.

### Usage example of get-dacl program
Print out get DACL of the file kernel32.dll:

![dacl of the kernel32.dll](img/dacl_kernel32.png)

Print out the DACL of the ShellDesktopSwitchEvent:

![dacl of the explorer's event](img/dacl_explorers_event.png)
