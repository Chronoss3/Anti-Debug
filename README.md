# Codepulze Anti Debug

## Features (AntiDebug.go)

- Blocks over 50+ popular debugging software.
- Blocks IsDebuggerPresent.
- Prevents debuggers and traffic debuggers.
- Detects and kills blacklisted processes.
- Detects windows associated with debugging tools.
- Checks system uptime and running processes.
- Checks disk size, RAM, and number of processors.
- Verifies GPU information.
- Performs IP check against a blacklist.
- Lowers VirusTotal detection to 2/72.


## Features (AntiDebug1.go)
- + Check For RemoteDebugger (ADDED)
- + Hide Threads From Debugger (ADDED)
- + Check if GPU has VBOX / VM start
- Blocks over 50+ popular debugging software.
- Blocks IsDebuggerPresent.
- Prevents debuggers and traffic debuggers.
- Detects and kills blacklisted processes.
- Detects windows associated with debugging tools.
- Checks system uptime and running processes.
- Checks disk size, RAM, and number of processors.
- Verifies GPU information.
- Performs IP check against a blacklist.
- Lowers VirusTotal detection to 4/72.

## Todo (AntiDebug1.go) :
- TLS Callbacks ntdll.LdrpDoDebuggerBreak
- PEB
- Add CheckRemoteDebuggerPresent which calls NtQueryInformationProcess
- Flags and artifacts
- Detecting breakpoints by checking the code for changes
- Add HW Breakpoints through DR0 and DR3
- Execution time
## Disclaimer

This anti-debug solution is designed for educational purposes.

## Contact

For support, please reach out to Codepulze on Discord: godfathercodepulze.

## Detection Rate
## - After with AntiDebug ![image](https://github.com/EvilBytecode/Anti-Debug/assets/151552809/f642d746-6f2f-459f-afec-e4595abbb25d)
## - Blank Hello World File ![image](https://github.com/EvilBytecode/Anti-Debug/assets/151552809/bf174279-2e30-42eb-8e2c-dd4e1a360e4a)




![Codepulze Anti Debug Logo](https://cdn.discordapp.com/attachments/1221500386918142012/1221525647927677098/mystific.png?ex=6612e569&is=66007069&hm=9942a29d520fbb0eda11472a8f40d6d4747df37a43e54262db568e5fa6c71289&)

Very good Anti Debug for Go programs.

Made with ❤️ By Codepulze
