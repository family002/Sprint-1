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
using TimePoint = std::time_t;

struct LogEntry {
    TimePoint timestamp;
    string host;
    string service;
    int pid;
    string message;
    string user;
    string ip;
    string action;
};

class Analyzer {
public:
    virtual ~Analyzer() = default;
    virtual void ingest(const LogEntry& entry) = 0;
    virtual void report(ostream& out) = 0;  
};

TimePoint parseTimestamp(const string& ts_str) {
    std::tm tm = {};
    std::istringstream ss(ts_str);
    ss >> std::get_time(&tm, "%b %d %H:%M:%S");
    time_t now = time(nullptr);
    std::tm* now_tm = std::localtime(&now);
    tm.tm_year = now_tm->tm_year;
    tm.tm_isdst = now_tm->tm_isdst;
    return std::mktime(&tm);
}

bool parseLogLine(const string& line, LogEntry& out) {
    static const regex headerRe(R"(^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[]+)\[(\d+)\]:\s+(.*)$)");
    smatch m;
    if (!regex_match(line, m, headerRe)) {
        return false;
    }

    string ts_str = m[1].str();
    out.timestamp = parseTimestamp(ts_str);
    out.host = m[2].str();
    out.service = m[3].str();
    out.pid = stoi(m[4].str());
    out.message = m[5].str();

    // Try to parse user/ip/action from the message using common patterns
    // 1) Accepted password for <user> from <ip>
    // 2) Failed password for <user> from <ip>
    // 3) Failed password for invalid user <user> from <ip>
    // 4) Invalid user <user> from <ip>
    static const regex acceptedRe(R"(Accepted password for (\S+) from (\S+)(?:\s|$))");
    static const regex failedRe(R"(Failed password for (?:invalid user )?(\S+) from (\S+)(?:\s|$))");
    static const regex invalidUserRe(R"(Invalid user (\S+) from (\S+)(?:\s|$))");

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
        out.action = "OTHER";
    }

    return true;
}

int maxWithinWindow(vector<TimePoint>& times, int windowSeconds) {
    if (times.empty()) return 0;
    sort(times.begin(), times.end());
    int maxCount = 0;
    size_t left = 0;
    for (size_t right = 0; right < times.size(); ++right) {
        while (left <= right && difftime(times[right], times[left]) > windowSeconds) {
            ++left;
        }
        int curCount = static_cast<int>(right - left + 1);
        if (curCount > maxCount) maxCount = curCount;
    }
    return maxCount;
}

class FailedLoginAnalyzer : public Analyzer {
public:
    FailedLoginAnalyzer(int threshold, int windowMinutes, bool verbose)
        : threshold_(threshold), windowSeconds_(windowMinutes * 60), verbose_(verbose) {}

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

    void report(ostream& out) override {
        out << "=== Suspicious Activity Report ===\n";
        out << "Threshold: " << threshold_ << " failures within " << (windowSeconds_/60) << " minute(s)\n\n";

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
    int threshold_;
    int windowSeconds_;
    bool verbose_;
    map<string, vector<TimePoint>> failures_by_user_;
    map<string, vector<TimePoint>> failures_by_ip_;
};

struct Options {
    string input = "auth.log";
    string output = "";
    int threshold = 3;
    int windowMinutes = 5;
    bool verbose = false;
};

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

int main(int argc, char* argv[]) {
    Options opts = parseArgs(argc, argv);

    if (opts.verbose) {
        cerr << "Options:\n  input=" << opts.input
             << "\n  output=" << (opts.output.empty() ? "stdout" : opts.output)
             << "\n  threshold=" << opts.threshold
             << "\n  windowMinutes=" << opts.windowMinutes << "\n";
    }

    ifstream infile(opts.input);
    if (!infile.is_open()) {
        cerr << "Error: could not open input file: " << opts.input << "\n";
        return 1;
    }

    Analyzer* analyzer = new FailedLoginAnalyzer(opts.threshold, opts.windowMinutes, opts.verbose);

    string line;
    int parsed = 0;
    while (getline(infile, line)) {
        if (line.empty()) continue;
        LogEntry entry;
        if (parseLogLine(line, entry)) {
            analyzer->ingest(entry);
            ++parsed;
        } else {
            if (opts.verbose) cerr << "[warn] could not parse line: " << line << "\n";
        }
    }
    infile.close();

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

    delete analyzer;

    return 0;
}