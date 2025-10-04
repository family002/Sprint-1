#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <regex>

using namespace std;
using TimePoint = std::time_t;  // Alias for readability — used for timestamps

// =========================
// STRUCT: LogEntry
// Represents a single parsed log line from the auth log file
// =========================
struct LogEntry {
    TimePoint timestamp;  // Date and time of the log entry
    string host;          // Host machine name
    string service;       // The service (like sshd)
    int pid;              // Process ID
    string message;       // The full log message after header
    string user;          // Extracted username (if any)
    string ip;            // Extracted IP address (if any)
    string action;        // Action type (e.g., LOGIN_SUCCESS, LOGIN_FAILURE, etc.)
};

// =========================
// CLASS: Analyzer (Base Class)
// Abstract class defining the interface for log analyzers.
// Derived classes must implement ingest() and report().
// =========================
class Analyzer {
public:
    virtual ~Analyzer() = default;
    virtual void ingest(const LogEntry& entry) = 0; // Process a parsed log entry
    virtual void report(ostream& out) = 0;          // Generate a summary report
};

// =========================
// FUNCTION: parseTimestamp
// Converts a timestamp string like "Oct 3 10:15:42" into a std::time_t object.
// =========================
TimePoint parseTimestamp(const string& ts_str) {
    std::tm tm = {};
    std::istringstream ss(ts_str);
    ss >> std::get_time(&tm, "%b %d %H:%M:%S");
    time_t now = time(nullptr);
    std::tm* now_tm = std::localtime(&now);
    tm.tm_year = now_tm->tm_year;  // Assume current year
    tm.tm_isdst = now_tm->tm_isdst;
    return std::mktime(&tm);
}

// =========================
// FUNCTION: parseLogLine
// Uses regex to parse one line from the log file into a structured LogEntry object.
// Extracts timestamp, host, service, PID, and message.
// Then it identifies user, IP, and action from common SSH message patterns.
// =========================
bool parseLogLine(const string& line, LogEntry& out) {
    // Regex to match general log line format
    static const regex headerRe(R"(^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[]+)\[(\d+)\]:\s+(.*)$)");
    smatch m;
    if (!regex_match(line, m, headerRe)) {
        return false; // Skip lines that don't match the expected format
    }

    // Extract header components
    string ts_str = m[1].str();
    out.timestamp = parseTimestamp(ts_str);
    out.host = m[2].str();
    out.service = m[3].str();
    out.pid = stoi(m[4].str());
    out.message = m[5].str();

    // Define regex patterns for various SSH login events
    static const regex acceptedRe(R"(Accepted password for (\S+) from (\S+)(?:\s|$))");
    static const regex failedRe(R"(Failed password for (?:invalid user )?(\S+) from (\S+)(?:\s|$))");
    static const regex invalidUserRe(R"(Invalid user (\S+) from (\S+)(?:\s|$))");

    // Match message text to extract details
    smatch mm;
    if (regex_search(out.message, mm, acceptedRe)) {
        out.user = mm[1].str();
        out.ip = mm[2].str();
        out.action = "LOGIN_SUCCESS";
    } else if (regex_search(out.message, mm, failedRe)) {
        out.user = mm[1].str();
        out.ip = mm[2].str();
        out.action = "LOGIN_FAILURE";
    } else if (regex_search(out.message, mm, invalidUserRe)) {
        out.user = mm[1].str();
        out.ip = mm[2].str();
        out.action = "INVALID_USER";
    } else {
        out.user = "";
        out.ip = "";
        out.action = "OTHER"; // Anything not matching login activity
    }

    return true; // Parsing succeeded
}

// =========================
// FUNCTION: maxWithinWindow
// Given a list of timestamps, find the maximum number of events that occurred
// within a sliding time window (used to detect bursts of failed logins).
// =========================
int maxWithinWindow(vector<TimePoint>& times, int windowSeconds) {
    if (times.empty()) return 0;
    sort(times.begin(), times.end());
    int maxCount = 0;
    size_t left = 0;

    // Sliding window algorithm: move the right pointer through time points
    for (size_t right = 0; right < times.size(); ++right) {
        // Move left pointer until window fits within allowed seconds
        while (left <= right && difftime(times[right], times[left]) > windowSeconds) {
            ++left;
        }
        int curCount = static_cast<int>(right - left + 1);
        if (curCount > maxCount) maxCount = curCount;
    }
    return maxCount;
}

// =========================
// CLASS: FailedLoginAnalyzer
// Concrete implementation of Analyzer. Tracks failed/invalid login attempts.
// Uses maps to count failures per user and per IP and compares them to thresholds.
// =========================
class FailedLoginAnalyzer : public Analyzer {
public:
    FailedLoginAnalyzer(int threshold, int windowMinutes, bool verbose)
        : threshold_(threshold), windowSeconds_(windowMinutes * 60), verbose_(verbose) {}

    // =========================
    // ingest(): Store timestamps of failed logins by user and IP
    // Called for each parsed log entry.
    // =========================
    void ingest(const LogEntry& entry) override {
        if (entry.action == "LOGIN_FAILURE" || entry.action == "INVALID_USER") {
            if(!entry.user.empty()) {
                failures_by_user_[entry.user].push_back(entry.timestamp);
            }
            if (!entry.ip.empty()) {
                failures_by_ip_[entry.ip].push_back(entry.timestamp);
            }
            if (verbose_) {
                cerr << "[ingest] failure user=" << entry.user << " ip=" << entry.ip << " t=" << entry.timestamp << "\n";
            }
        }
    }

    // =========================
    // report(): Analyze stored data and output suspicious users/IPs
    // =========================
    void report(ostream& out) override {
        out << "=== Suspicious Activity Report ===\n";
        out << "Threshold: " << threshold_ << " failures within " << (windowSeconds_/60) << " minute(s)\n\n";

        // Analyze users
        out << "Users exceeding threshold:\n";
        bool found_any = false;
        for (auto& kv : failures_by_user_) {
            vector<TimePoint>& times = kv.second;
            int maxc = maxWithinWindow(times, windowSeconds_);
            if (maxc >= threshold_) {
                out << " user \"" << kv.first << "\" had " << maxc << " failures (max in window)\n";
                found_any = true;
            } else if (verbose_) {
                out << " (info) user \"" << kv.first << "\" max=" << maxc << "\n";
            }
        }
        if (!found_any) out << " none\n";
        out << "\n";

        // Analyze IPs
        out << "IPs exceeding threshold:\n";
        found_any = false;
        for (auto& kv : failures_by_ip_) {
            vector<TimePoint>& times = kv.second;
            int maxc = maxWithinWindow(times, windowSeconds_);
            if (maxc >= threshold_) {
                out << " ip " << kv.first << " had " << maxc << " failures (max in window)\n";
                found_any = true;
            } else if (verbose_) {
                out << " (info) ip " << kv.first << " max=" << maxc << "\n";
            }
        }
        if (!found_any) out << " none\n";
        out << "=================================\n";
    }

private:
    int threshold_;  // Max allowed failures before flagging
    int windowSeconds_;  // Time window in seconds
    bool verbose_;  // Verbose mode toggle for debugging
    map<string, vector<TimePoint>> failures_by_user_; // user → timestamps
    map<string, vector<TimePoint>> failures_by_ip_;   // ip → timestamps
};

// =========================
// STRUCT: Options
// Holds program configuration, set via command-line arguments
// =========================
struct Options {
    string input = "auth.log";
    string output = "";
    int threshold = 3;
    int windowMinutes = 5;
    bool verbose = false;
};

// =========================
// FUNCTION: parseArgs
// Parses command-line options such as --input, --threshold, and --verbose.
// Returns an Options struct filled with user preferences.
// =========================
Options parseArgs(int argc, char* argv[]) {
    Options opt;
    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if ((a == "--input" || a == "-i") && i + 1 < argc) {
            opt.input = argv[++i];
        } else if ((a == "--output" || a == "-o") && i + 1 < argc) {
            opt.output = argv[++i];
        } else if ((a == "--threshold" || a == "-t") && i + 1 < argc) {
            opt.threshold = stoi(argv[++i]);
        } else if ((a == "--window" || a == "-w") && i + 1 < argc) {
            opt.windowMinutes = stoi(argv[++i]);
        } else if (a == "--verbose" || a == "-v") {
            opt.verbose = true;
        } else if (a == "--help" || a == "-h") {
            cout << "Usage: log_analyzer [--input file] [--output file] [--threshold N] [--window minutes] [--verbose]\n";
            exit(0);
        } else {
            cerr << "Unknown option: " << a << "\n";
            cout << "Use --help for usage.\n";
            exit(1);
        }
    }
    return opt;
}

// =========================
// MAIN FUNCTION
// Controls overall program flow:
// 1. Parse arguments
// 2. Read log file
// 3. Parse and ingest each line
// 4. Generate and print report
// =========================
int main(int argc, char* argv[]) {
    // Step 1: Parse command-line options
    Options opts = parseArgs(argc, argv);

    if (opts.verbose) {
        cerr << "Options:\n  input=" << opts.input
             << "\n  output=" << (opts.output.empty() ? "stdout" : opts.output)
             << "\n  threshold=" << opts.threshold
             << "\n  windowMinutes=" << opts.windowMinutes << "\n";
    }

    // Step 2: Open the input log file
    ifstream infile(opts.input);
    if (!infile.is_open()) {
        cerr << "Error: could not open input file: " << opts.input << "\n";
        return 1;
    }

    // Step 3: Create analyzer instance dynamically (shows polymorphism)
    Analyzer* analyzer = new FailedLoginAnalyzer(opts.threshold, opts.windowMinutes, opts.verbose);

    // Step 4: Read and process each log line
    string line;
    int parsed = 0;
    while (getline(infile, line)) {
        if (line.empty()) continue;
        LogEntry entry;
        if (parseLogLine(line, entry)) {
            analyzer->ingest(entry); // Send structured entry to analyzer
            ++parsed;
        } else {
            if (opts.verbose) cerr << "[warn] could not parse line: " << line << "\n";
        }
    }
    infile.close();

    // Step 5: Generate report to console or output file
    if (opts.verbose) cerr << "[info] parsed lines: " << parsed << "\n";
    if (opts.output.empty()) {
        analyzer->report(cout);
    } else {
        ofstream outfile(opts.output);
        if (!outfile.is_open()) {
            cerr << "Error: could not open output file: " << opts.output << "\n";
            delete analyzer;
            return 1;
        }
        analyzer->report(outfile);
        outfile.close();
        if (opts.verbose) cerr << "Report written to " << opts.output << "\n";
    }

    // Step 6: Clean up dynamically allocated analyzer
    delete analyzer;

    return 0;
}
