name	win32s16
type	win16

1 stub WEP
2 pascal16 BootTask() BootTask
3 stub CREATEPROCESS
4 stub WAITFORDEBUGEVENT
5 pascal CONTINUEDEBUGEVENT(long long long) ContinueDebugEvent
6 pascal READPROCESSMEMORY(long ptr ptr long ptr) ReadProcessMemory
7 stub WRITEPROCESSMEMORY
8 stub GETTHREADCONTEXT
9 stub SETTHREADCONTEXT
10 pascal GETLASTERROR() GetLastError
11 pascal CLOSEHANDLE(long) CloseHandle
12 stub ALLOCCLBKTO32BDLL
13 pascal GETEXITCODETHREAD(long ptr) GetExitCodeThread
14 stub GETEXITCODEPROCESS
15 stub OPENPROCESS
16 stub OPENTHREAD
17 stub GETTHREADSELECTORENTRY
18 pascal VIRTUALQUERYEX(long ptr ptr long) VirtualQueryEx
19 pascal VIRTUALPROTECTEX(long ptr long long ptr) VirtualProtectEx
20 stub KGETTASKPPDB
21 stub KGETTHREADPTDB
22 stub FREECALLBACK
23 stub RELEASECSALIAS
24 stub EXCHANGEPFN32INSTUB
25 stub SELCBCS
26 stub DESTROYPEHEADER
27 stub SELCBDS
28 stub GETCSALIAS
29 stub SELFLATCODE
30 stub HUNITOANSIDBCS
31 stub ALLOCUTPROC32
32 stub FLATDATA
33 stub CODEDATA
34 stub MYGLOBALFREE
35 stub FREE32BDLLCBENTRIES
36 stub SETFS
37 stub PELOADRESOURCEHANDLER
38 stub CHECKDEBUG
39 stub REMOVEH32FROMWIN32S
40 stub RMEMCPY
41 stub INITRESLOADER
42 stub FREESELECTOROFFSET
43 pascal StackLinearToSegmented(word word) StackLinearToSegmented
44 stub GETMODULEFILENAME32S
45 stub FAPILOG16
46 stub ALLOCCALLBACK
47 stub LINEARTOHUGESELECTOROFFSET
48 pascal UTSelectorOffsetToLinear(ptr) UTSelectorOffsetToLinear
49 pascal UTLinearToSelectorOffset(ptr) UTLinearToSelectorOffset
50 stub SELFOREIGNTIB
51 stub MYGLOBALREALLOC
52 stub CREATEPEHEADER
53 stub FINDGLOBALHANDLE

#54-289 exist, but function names blanked out
143 equate win32s16_143  0x100
