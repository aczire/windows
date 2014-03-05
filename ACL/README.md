ACL
===

### General information
These simple client-server programs shows how to set up and install ACL (Access Control List). There are two files:

* server.cpp - This program creates shared section in Global namespace and set permissions.
* client.cpp - This program try to open shared section (since not all users allow open it) and then simulate some work.

### Usage example
Source computer has the following users:

![users on test computer](img\users_on_computer.png)

Shared section has the following permissions:

![shared section permissions](img\shared_section_permissions.png)

Bob runs the client:

![bob runs client](img\client_bob.png)

Alice runs the client:

![alice runs client](img\client_alice.png)

TestUser runs the client:

![testuser runs client](img\client_testuser.png)

As expect Alice wasn't allow to open shared section with any permissions, since Alice belongs to Power Users Group.
