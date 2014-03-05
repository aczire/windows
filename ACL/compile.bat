@echo off
echo ===================== 
echo Build UNICODE version
echo =====================
IF EXIST bin goto compile
mkdir bin
:compile
cl.exe /nologo /O2 /DUNICODE /D_UNICODE /c server-acl.cpp
link.exe /nologo /INCREMENTAL:NO /DYNAMICBASE server-acl.obj /OUT:bin\serverW.exe
cl.exe /nologo /O2 /DUNICODE /D_UNICODE /c client-acl.cpp
link.exe /nologo /INCREMENTAL:NO /DYNAMICBASE client-acl.obj /OUT:bin\clientW.exe
del server-acl.obj client-acl.obj
echo ===================== 
echo Build ANSI version
echo =====================
cl.exe /nologo /O2 /c server-acl.cpp
link.exe /nologo /INCREMENTAL:NO /DYNAMICBASE server-acl.obj /OUT:bin\serverA.exe
cl.exe /nologo /O2 /c client-acl.cpp
link.exe /nologo /INCREMENTAL:NO /DYNAMICBASE client-acl.obj /OUT:bin\clientA.exe
del server-acl.obj client-acl.obj
