# Log Analyzer (C++ Authentication Log Parser)

This project is a **Linux authentication log analyzer** written in C++.  
It reads log files (such as `/var/log/auth.log`) and detects **suspicious login activity**, such as repeated failed login attempts within a short time window.  
The program supports flexible command-line options for threshold detection, window size, verbosity, and output file reporting.

---

## Instructions for Build and Use

### Steps to Build

1. Open a terminal and navigate to the project folder.
2. Compile the program using g++
2a.   g++ -std=c++17 -O2 -o log_analyzer log_analyzer.cpp
3. Confirm the executable was created with ls

### Steps to Run
1. Run the analyzer on a log file (example: auth.log):
1a.   ./log_analyzer --input auth.log --threshold 3 --window 5
2. Enable verbose mode to see details about what’s being processed:
2a.   ./log_analyzer --input auth.log --threshold 3 --window 5 --verbose
3. Output the results to a report file:
3a.   ./log_analyzer --input auth_burst.log --threshold 3 --window 5 --output report.txt
4. Try different log files to observe varying detection levels:

auth.log → normal background login activity

auth_burst.log → moderate bursts of failed logins

auth_attack.log → clear signs of an attack

## Development Environment 

To recreate the development environment, you need the following software and/or libraries with the specified versions:
Operating System: Linux, macOS, or Windows with WSL

Compiler: g++ 9.0 or newer (C++17 support required)

Libraries: Standard Template Library (STL), <regex>, <chrono>, <map>, <vector> (included by default in C++)

Text Editor / IDE: Visual Studio Code, CLion, or any text editor with C++ syntax highlighting

## Useful Websites to Learn More

I found these websites useful in developing this software:

* w3schools
* ChatGPT
* MinGw-w64

## Future Work

The following items I plan to fix, improve, and/or add to this project in the future:

 Add support for additional log formats (Windows Event Logs, web server logs, etc.)

 Implement color-coded console output for better readability

 Add JSON or CSV report export options
