// SPDX-License-Identifier: MIT
// cpp-route-watch — Linux IPv4/IPv6 routing table monitor (/proc/net/route + ipv6_route)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o route-watch
// Usage: ./route-watch [--watch N] [--json] [--demo] [--no-color] [--selftest] [--ipv4|--ipv6]

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <expected>
#include <fstream>
#include <iostream>
#include <optional>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

// ── Types ──

struct Error {
  int code;
  std::string message;
};

template <typename T>
using Result = std::expected<T, Error>;

struct Route4 {
  std::string iface;
  std::string dest;     // dotted IPv4
  std::string gateway;  // dotted IPv4 or "*"
  std::string mask;     // dotted IPv4
  unsigned flags{0};
  unsigned metric{0};
  unsigned refcnt{0};
  unsigned use{0};
  int prefix_len{-1};   // computed from mask
  bool is_default{false};
  bool is_host{false};
  bool is_gateway{false};
  bool is_up{false};
};

struct Route6 {
  std::string iface;
  std::string dest;     // compressed-ish IPv6
  int prefix_len{0};
  std::string gateway;  // or "*"
  unsigned metric{0};
  unsigned refcnt{0};
  unsigned use{0};
  unsigned flags{0};
  bool is_default{false};
  bool is_gateway{false};
};

struct RouteSnapshot {
  std::vector<Route4> v4;
  std::vector<Route6> v6;
  int default4{0};
  int default6{0};
  int gateway4{0};
  int gateway6{0};
  int host4{0};
  double timestamp{0.0};
  // watch deltas
  int d_v4{0};
  int d_v6{0};
  int d_default4{0};
  bool has_delta{false};
};

// ── Mutable ANSI palette (--no-color empties every code) ──

bool g_color = true;
std::string C_RST, C_BOLD, C_DIM, C_CYAN, C_GREEN, C_YELLOW, C_RED, C_MAGENTA, C_BLUE;

void init_colors() {
  C_RST     = g_color ? "\033[0m"  : "";
  C_BOLD    = g_color ? "\033[1m"  : "";
  C_DIM     = g_color ? "\033[2m"  : "";
  C_CYAN    = g_color ? "\033[36m" : "";
  C_GREEN   = g_color ? "\033[32m" : "";
  C_YELLOW  = g_color ? "\033[33m" : "";
  C_RED     = g_color ? "\033[31m" : "";
  C_MAGENTA = g_color ? "\033[35m" : "";
  C_BLUE    = g_color ? "\033[34m" : "";
}

// ── Helpers ──

static double now_epoch() {
  using namespace std::chrono;
  return duration<double>(system_clock::now().time_since_epoch()).count();
}

static std::string trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
    s.remove_suffix(1);
  return std::string(s);
}

static unsigned parse_hex_u32(std::string_view s) {
  unsigned v = 0;
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, 16);
  (void)ptr;
  if (ec != std::errc{}) return 0;
  return v;
}

static unsigned parse_u32(std::string_view s) {
  unsigned v = 0;
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return 0;
  s.remove_prefix(start);
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, 10);
  (void)ptr;
  if (ec != std::errc{}) return 0;
  return v;
}

// /proc/net/route prints __be32 with %08X on LE host → reverse bytes for dotted form
static std::string hex_le_to_ipv4(std::string_view hex8) {
  if (hex8.size() < 8) return "0.0.0.0";
  unsigned w = parse_hex_u32(hex8.substr(0, 8));
  unsigned b0 = w & 0xFFu;
  unsigned b1 = (w >> 8) & 0xFFu;
  unsigned b2 = (w >> 16) & 0xFFu;
  unsigned b3 = (w >> 24) & 0xFFu;
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b0, b1, b2, b3);
  return buf;
}

static int mask_to_prefix(std::string_view mask_dotted) {
  // count leading 1-bits of dotted mask
  unsigned parts[4] = {0, 0, 0, 0};
  int idx = 0;
  std::string tmp(mask_dotted);
  std::istringstream iss(tmp);
  std::string tok;
  while (std::getline(iss, tok, '.') && idx < 4) {
    parts[idx++] = parse_u32(tok);
  }
  int bits = 0;
  bool seen_zero = false;
  for (int i = 0; i < 4; ++i) {
    for (int b = 7; b >= 0; --b) {
      bool one = (parts[i] >> b) & 1u;
      if (one) {
        if (seen_zero) return -1;  // non-contiguous
        ++bits;
      } else {
        seen_zero = true;
      }
    }
  }
  return bits;
}

// /proc/net/ipv6_route uses %pi6 — 32 hex chars in NETWORK byte order (unlike tcp6 LE words).
static std::string hex_be_to_ipv6(std::string_view hex32) {
  std::string h(hex32);
  if (h.size() < 32) h.append(32 - h.size(), '0');
  unsigned hextets[8]{};
  for (int i = 0; i < 8; ++i) {
    hextets[i] = parse_hex_u32(std::string_view(h).substr(static_cast<size_t>(i) * 4, 4));
  }

  // longest zero run for :: compression (min length 2)
  int best_start = -1, best_len = 0;
  int run_start = -1, run_len = 0;
  for (int i = 0; i < 8; ++i) {
    if (hextets[i] == 0) {
      if (run_start < 0) run_start = i;
      ++run_len;
    } else {
      if (run_len > best_len) {
        best_len = run_len;
        best_start = run_start;
      }
      run_start = -1;
      run_len = 0;
    }
  }
  if (run_len > best_len) {
    best_len = run_len;
    best_start = run_start;
  }
  if (best_len < 2) best_start = -1;

  std::string out;
  for (int i = 0; i < 8;) {
    if (best_start >= 0 && i == best_start) {
      out += "::";
      i += best_len;
      continue;
    }
    if (!out.empty() && out.back() != ':') out += ':';
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%x", hextets[i]);
    out += buf;
    ++i;
  }
  if (out.empty()) out = "::";
  // leading/trailing edge cases already handled by "::" injection
  if (out == ":") out = "::";
  return out;
}

// IPv4 route flags (linux/route.h style bits commonly shown in netstat -rn)
// 0x0001 RTF_UP, 0x0002 RTF_GATEWAY, 0x0004 RTF_HOST, 0x0008 RTF_REINSTATE,
// 0x0010 RTF_DYNAMIC, 0x0020 RTF_MODIFIED, 0x0100 RTF_REJECT ...
static std::string flags4_str(unsigned f) {
  std::string s;
  if (f & 0x0001) s += 'U';
  if (f & 0x0002) s += 'G';
  if (f & 0x0004) s += 'H';
  if (f & 0x0008) s += 'R';
  if (f & 0x0010) s += 'D';
  if (f & 0x0020) s += 'M';
  if (f & 0x0100) s += '!';
  if (s.empty()) s = "-";
  return s;
}

static std::string flags6_str(unsigned f) {
  // RTF_* from ipv6_route (subset)
  std::string s;
  if (f & 0x00000001) s += 'U';  // UP
  if (f & 0x00000002) s += 'G';  // GATEWAY
  if (f & 0x00000004) s += 'H';  // HOST
  if (f & 0x00010000) s += 'A';  // ADDRCONF
  if (f & 0x00040000) s += 'C';  // CACHE
  if (f & 0x00100000) s += 'n';  // NONEXTHOP
  if (f & 0x00200000) s += 'e';  // EXPIRES
  if (f & 0x01000000) s += 'i';  // LOCAL
  if (f & 0x02000000) s += 'a';  // ANYCAST
  if (f & 0x80000000) s += 'r';  // REJECT
  if (s.empty()) {
    char buf[12];
    std::snprintf(buf, sizeof(buf), "%08x", f);
    return buf;
  }
  return s;
}

static std::string json_escape(std::string_view s) {
  std::string o;
  o.reserve(s.size() + 8);
  for (char c : s) {
    switch (c) {
      case '"':  o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n"; break;
      case '\r': o += "\\r"; break;
      case '\t': o += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          o += buf;
        } else {
          o += c;
        }
    }
  }
  return o;
}

static std::string fmt_signed(int v) {
  char buf[24];
  if (v > 0) std::snprintf(buf, sizeof(buf), "+%d", v);
  else std::snprintf(buf, sizeof(buf), "%d", v);
  return buf;
}

// ── Parsers ──

static Result<std::vector<Route4>> parse_route4_text(std::string_view text) {
  std::vector<Route4> out;
  std::istringstream iss{std::string(text)};
  std::string line;
  bool first = true;
  while (std::getline(iss, line)) {
    if (line.empty()) continue;
    if (first) {
      first = false;
      // header: Iface Destination Gateway Flags ...
      if (line.find("Iface") != std::string::npos ||
          line.find("Destination") != std::string::npos)
        continue;
    }
    std::istringstream ls(line);
    std::string iface, dest_h, gw_h, flags_h, ref_s, use_s, metric_s, mask_h;
    if (!(ls >> iface >> dest_h >> gw_h >> flags_h >> ref_s >> use_s >> metric_s >> mask_h))
      continue;

    Route4 r;
    r.iface = iface;
    r.dest = hex_le_to_ipv4(dest_h);
    r.gateway = hex_le_to_ipv4(gw_h);
    r.mask = hex_le_to_ipv4(mask_h);
    r.flags = parse_hex_u32(flags_h);
    r.refcnt = parse_u32(ref_s);
    r.use = parse_u32(use_s);
    r.metric = parse_u32(metric_s);
    r.prefix_len = mask_to_prefix(r.mask);
    r.is_up = (r.flags & 0x0001) != 0;
    r.is_gateway = (r.flags & 0x0002) != 0;
    r.is_host = (r.flags & 0x0004) != 0;
    r.is_default = (r.dest == "0.0.0.0" && (r.prefix_len == 0 || r.mask == "0.0.0.0"));
    if (r.gateway == "0.0.0.0") r.gateway = "*";
    out.push_back(std::move(r));
  }
  return out;
}

static Result<std::vector<Route6>> parse_route6_text(std::string_view text) {
  std::vector<Route6> out;
  std::istringstream iss{std::string(text)};
  std::string line;
  while (std::getline(iss, line)) {
    if (line.empty()) continue;
    // dest pl src spl gw metric refcnt use flags iface
    std::istringstream ls(line);
    std::string dest_h, pl_h, src_h, spl_h, gw_h, metric_h, ref_h, use_h, flags_h, iface;
    if (!(ls >> dest_h >> pl_h >> src_h >> spl_h >> gw_h >> metric_h >> ref_h >> use_h >>
          flags_h >> iface))
      continue;
    if (dest_h.size() < 32) continue;

    Route6 r;
    r.dest = hex_be_to_ipv6(dest_h);
    r.prefix_len = static_cast<int>(parse_hex_u32(pl_h));
    r.gateway = hex_be_to_ipv6(gw_h);
    r.metric = parse_hex_u32(metric_h);
    r.refcnt = parse_hex_u32(ref_h);
    r.use = parse_hex_u32(use_h);
    r.flags = parse_hex_u32(flags_h);
    r.iface = trim(iface);
    r.is_gateway = (r.flags & 0x00000002) != 0;
    r.is_default = (r.prefix_len == 0);
    // zero gateway → *
    bool gw_zero = true;
    for (char c : gw_h)
      if (c != '0') {
        gw_zero = false;
        break;
      }
    if (gw_zero) r.gateway = "*";
    out.push_back(std::move(r));
  }
  return out;
}

static Result<RouteSnapshot> read_routes() {
  RouteSnapshot snap;
  snap.timestamp = now_epoch();

  {
    std::ifstream f("/proc/net/route");
    if (!f)
      return std::unexpected(Error{1, "cannot open /proc/net/route"});
    std::ostringstream ss;
    ss << f.rdbuf();
    auto r = parse_route4_text(ss.str());
    if (!r) return std::unexpected(r.error());
    snap.v4 = std::move(*r);
  }
  {
    std::ifstream f("/proc/net/ipv6_route");
    if (f) {
      std::ostringstream ss;
      ss << f.rdbuf();
      auto r = parse_route6_text(ss.str());
      if (r) snap.v6 = std::move(*r);
    }
  }

  for (auto& r : snap.v4) {
    if (r.is_default) ++snap.default4;
    if (r.is_gateway) ++snap.gateway4;
    if (r.is_host) ++snap.host4;
  }
  for (auto& r : snap.v6) {
    if (r.is_default) ++snap.default6;
    if (r.is_gateway) ++snap.gateway6;
  }

  // sort: defaults first, then by prefix desc (more specific first), then iface
  std::sort(snap.v4.begin(), snap.v4.end(), [](const Route4& a, const Route4& b) {
    if (a.is_default != b.is_default) return a.is_default > b.is_default;
    int pa = a.prefix_len < 0 ? 0 : a.prefix_len;
    int pb = b.prefix_len < 0 ? 0 : b.prefix_len;
    if (pa != pb) return pa > pb;
    if (a.metric != b.metric) return a.metric < b.metric;
    return a.iface < b.iface;
  });
  std::sort(snap.v6.begin(), snap.v6.end(), [](const Route6& a, const Route6& b) {
    if (a.is_default != b.is_default) return a.is_default > b.is_default;
    if (a.prefix_len != b.prefix_len) return a.prefix_len > b.prefix_len;
    if (a.metric != b.metric) return a.metric < b.metric;
    return a.iface < b.iface;
  });

  return snap;
}

static RouteSnapshot build_demo_snapshot() {
  RouteSnapshot s;
  s.timestamp = now_epoch();

  auto add4 = [&](const char* iface, const char* dest, const char* gw, const char* mask,
                  unsigned flags, unsigned metric) {
    Route4 r;
    r.iface = iface;
    r.dest = dest;
    r.gateway = (std::string(gw) == "0.0.0.0") ? "*" : gw;
    r.mask = mask;
    r.flags = flags;
    r.metric = metric;
    r.prefix_len = mask_to_prefix(mask);
    r.is_up = (flags & 1) != 0;
    r.is_gateway = (flags & 2) != 0;
    r.is_host = (flags & 4) != 0;
    r.is_default = (std::string(dest) == "0.0.0.0" && std::string(mask) == "0.0.0.0");
    s.v4.push_back(std::move(r));
  };

  add4("eth0", "0.0.0.0", "172.16.1.1", "0.0.0.0", 0x0003, 100);
  add4("eth0", "172.16.1.0", "0.0.0.0", "255.255.255.0", 0x0001, 0);
  add4("docker0", "172.17.0.0", "0.0.0.0", "255.255.0.0", 0x0001, 0);
  add4("br-lan", "10.0.0.0", "0.0.0.0", "255.0.0.0", 0x0001, 0);
  add4("wg0", "10.8.0.0", "0.0.0.0", "255.255.255.0", 0x0001, 0);
  add4("eth0", "192.168.100.50", "0.0.0.0", "255.255.255.255", 0x0005, 0);  // host
  add4("tun0", "0.0.0.0", "10.9.0.1", "0.0.0.0", 0x0003, 50);               // alt default

  auto add6 = [&](const char* iface, const char* dest, int pl, const char* gw, unsigned metric,
                  unsigned flags) {
    Route6 r;
    r.iface = iface;
    r.dest = dest;
    r.prefix_len = pl;
    r.gateway = (std::string(gw) == "::" || std::string(gw) == "0") ? "*" : gw;
    r.metric = metric;
    r.flags = flags;
    r.is_default = (pl == 0);
    r.is_gateway = (flags & 2) != 0;
    s.v6.push_back(std::move(r));
  };

  add6("eth0", "::", 0, "fe80::1", 1024, 0x00000003);
  add6("lo", "::1", 128, "*", 0, 0x80000001);
  add6("eth0", "2001:db8:1::", 64, "*", 256, 0x00010001);
  add6("eth0", "fe80::", 64, "*", 256, 0x00010001);
  add6("wg0", "fd00:8::", 48, "*", 100, 0x00000001);

  for (auto& r : s.v4) {
    if (r.is_default) ++s.default4;
    if (r.is_gateway) ++s.gateway4;
    if (r.is_host) ++s.host4;
  }
  for (auto& r : s.v6) {
    if (r.is_default) ++s.default6;
    if (r.is_gateway) ++s.gateway6;
  }
  return s;
}

// ── Output ──

static void print_header(const RouteSnapshot& s) {
  std::println(std::cout, "{}+================================================+{}", C_CYAN, C_RST);
  std::println(std::cout, "{}|     Linux Routing Table Monitor               |{}", C_CYAN, C_RST);
  std::println(std::cout, "{}+================================================+{}", C_CYAN, C_RST);

  std::time_t t = static_cast<std::time_t>(s.timestamp);
  char tbuf[64];
  std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
  std::println(std::cout, "  {}Source:{} /proc/net/route + ipv6_route", C_DIM, C_RST);
  std::println(std::cout, "  {}Snapshot:{} {}", C_DIM, C_RST, tbuf);
  std::println(std::cout);
}

static void print_summary(const RouteSnapshot& s) {
  std::println(std::cout, "  {}-- Aggregate --{}", C_BOLD, C_RST);
  auto row = [](const char* label, const std::string& val, const std::string& color) {
    std::println(std::cout, "  {}{:<14}{} {}{}{}", C_DIM, label, C_RST, color, val, C_RST);
  };
  row("IPv4 routes", std::to_string(s.v4.size()), C_CYAN);
  row("IPv6 routes", std::to_string(s.v6.size()), C_CYAN);
  row("Default v4", std::to_string(s.default4), s.default4 > 0 ? C_GREEN : C_YELLOW);
  row("Default v6", std::to_string(s.default6), s.default6 > 0 ? C_GREEN : C_YELLOW);
  row("Via gateway", std::to_string(s.gateway4 + s.gateway6), C_MAGENTA);
  row("Host routes", std::to_string(s.host4), C_BLUE);

  if (s.has_delta) {
    std::println(std::cout, "  {}Deltas:{} v4 {}{}{}  v6 {}{}{}  def4 {}{}{}", C_DIM, C_RST,
                 s.d_v4 >= 0 ? C_GREEN : C_RED, fmt_signed(s.d_v4), C_RST,
                 s.d_v6 >= 0 ? C_GREEN : C_RED, fmt_signed(s.d_v6), C_RST,
                 s.d_default4 >= 0 ? C_GREEN : C_RED, fmt_signed(s.d_default4), C_RST);
  }
  std::println(std::cout);
}

static void print_table4(const RouteSnapshot& s) {
  std::println(std::cout, "  {}-- IPv4 routes ({}) --{}", C_BOLD, s.v4.size(), C_RST);
  std::println(std::cout, "  {}{:<8} {:<18} {:<16} {:<4} {:>6} {:<10} {}{}", C_DIM, "Iface",
               "Destination", "Gateway", "Flg", "Metric", "Genmask", "Notes", C_RST);
  std::println(std::cout, "  {}{}", C_DIM,
               std::string(78, '-'), C_RST);

  for (const auto& r : s.v4) {
    std::string dest = r.dest;
    if (r.prefix_len >= 0 && !r.is_default)
      dest += "/" + std::to_string(r.prefix_len);
    else if (r.is_default)
      dest = "default";

    std::string notes;
    if (r.is_default) notes += "default ";
    if (r.is_host) notes += "host ";
    if (r.is_gateway) notes += "via-gw ";

    std::string fl = flags4_str(r.flags);
    std::string color = r.is_default ? C_GREEN : (r.is_host ? C_YELLOW : C_CYAN);
    std::println(std::cout, "  {}{:<8}{} {:<18} {:<16} {:<4} {:>6} {:<10} {}{}{}", color,
                 r.iface, C_RST, dest, r.gateway, fl, r.metric, r.mask, C_DIM, trim(notes),
                 C_RST);
  }
  std::println(std::cout);
}

static void print_table6(const RouteSnapshot& s) {
  std::println(std::cout, "  {}-- IPv6 routes ({}) --{}", C_BOLD, s.v6.size(), C_RST);
  std::println(std::cout, "  {}{:<8} {:<28} {:<18} {:<6} {:>6} {}{}", C_DIM, "Iface",
               "Destination", "Gateway", "Flags", "Metric", "Notes", C_RST);
  std::println(std::cout, "  {}{}", C_DIM, std::string(78, '-'), C_RST);

  for (const auto& r : s.v6) {
    std::string dest = r.is_default ? "default" : (r.dest + "/" + std::to_string(r.prefix_len));
    std::string notes;
    if (r.is_default) notes += "default ";
    if (r.is_gateway) notes += "via-gw ";
    std::string color = r.is_default ? C_GREEN : C_MAGENTA;
    std::println(std::cout, "  {}{:<8}{} {:<28} {:<18} {:<6} {:>6} {}{}{}", color, r.iface, C_RST,
                 dest, r.gateway, flags6_str(r.flags), r.metric, C_DIM, trim(notes), C_RST);
  }
  std::println(std::cout);
}

static void print_json(const RouteSnapshot& s) {
  std::ostringstream o;
  o << "{";
  o << "\"timestamp\":" << static_cast<long long>(s.timestamp) << ",";
  o << "\"summary\":{";
  o << "\"ipv4_routes\":" << s.v4.size() << ",";
  o << "\"ipv6_routes\":" << s.v6.size() << ",";
  o << "\"default_v4\":" << s.default4 << ",";
  o << "\"default_v6\":" << s.default6 << ",";
  o << "\"gateway_v4\":" << s.gateway4 << ",";
  o << "\"gateway_v6\":" << s.gateway6 << ",";
  o << "\"host_v4\":" << s.host4;
  o << "},";
  o << "\"ipv4\":[";
  for (size_t i = 0; i < s.v4.size(); ++i) {
    const auto& r = s.v4[i];
    if (i) o << ",";
    o << "{";
    o << "\"iface\":\"" << json_escape(r.iface) << "\",";
    o << "\"destination\":\"" << json_escape(r.dest) << "\",";
    o << "\"gateway\":\"" << json_escape(r.gateway) << "\",";
    o << "\"mask\":\"" << json_escape(r.mask) << "\",";
    o << "\"prefix_len\":" << r.prefix_len << ",";
    o << "\"flags\":" << r.flags << ",";
    o << "\"flags_str\":\"" << json_escape(flags4_str(r.flags)) << "\",";
    o << "\"metric\":" << r.metric << ",";
    o << "\"is_default\":" << (r.is_default ? "true" : "false") << ",";
    o << "\"is_gateway\":" << (r.is_gateway ? "true" : "false") << ",";
    o << "\"is_host\":" << (r.is_host ? "true" : "false");
    o << "}";
  }
  o << "],";
  o << "\"ipv6\":[";
  for (size_t i = 0; i < s.v6.size(); ++i) {
    const auto& r = s.v6[i];
    if (i) o << ",";
    o << "{";
    o << "\"iface\":\"" << json_escape(r.iface) << "\",";
    o << "\"destination\":\"" << json_escape(r.dest) << "\",";
    o << "\"prefix_len\":" << r.prefix_len << ",";
    o << "\"gateway\":\"" << json_escape(r.gateway) << "\",";
    o << "\"flags\":" << r.flags << ",";
    o << "\"flags_str\":\"" << json_escape(flags6_str(r.flags)) << "\",";
    o << "\"metric\":" << r.metric << ",";
    o << "\"is_default\":" << (r.is_default ? "true" : "false") << ",";
    o << "\"is_gateway\":" << (r.is_gateway ? "true" : "false");
    o << "}";
  }
  o << "]";
  if (s.has_delta) {
    o << ",\"delta\":{";
    o << "\"ipv4\":" << s.d_v4 << ",";
    o << "\"ipv6\":" << s.d_v6 << ",";
    o << "\"default_v4\":" << s.d_default4;
    o << "}";
  }
  o << "}\n";
  std::cout << o.str();
}

// ── Selftest ──

static int run_selftest() {
  int passed = 0, failed = 0;
  auto check = [&](const char* name, bool ok) {
    if (ok) {
      ++passed;
      std::println(std::cout, "  {}✓{} {}", C_GREEN, C_RST, name);
    } else {
      ++failed;
      std::println(std::cout, "  {}✗{} {}", C_RED, C_RST, name);
    }
  };

  std::println(std::cout, "{}route-watch selftest{}", C_BOLD, C_RST);
  std::println(std::cout);

  // IPv4 hex decode (known from this host / skill)
  check("hex 010110AC → 172.16.1.1", hex_le_to_ipv4("010110AC") == "172.16.1.1");
  check("hex 000110AC → 172.16.1.0", hex_le_to_ipv4("000110AC") == "172.16.1.0");
  check("hex 00000000 → 0.0.0.0", hex_le_to_ipv4("00000000") == "0.0.0.0");
  check("hex 00FFFFFF → 255.255.255.0", hex_le_to_ipv4("00FFFFFF") == "255.255.255.0");

  check("mask /24", mask_to_prefix("255.255.255.0") == 24);
  check("mask /0", mask_to_prefix("0.0.0.0") == 0);
  check("mask /32", mask_to_prefix("255.255.255.255") == 32);
  check("mask /16", mask_to_prefix("255.255.0.0") == 16);

  check("flags UG", flags4_str(0x0003) == "UG");
  check("flags U", flags4_str(0x0001) == "U");
  check("flags UH", flags4_str(0x0005) == "UH");

  // ::1 network-order encoding used by ipv6_route (%pi6)
  check("ipv6 ::1 decode", hex_be_to_ipv6("00000000000000000000000000000001") == "::1");
  check("ipv6 :: decode", hex_be_to_ipv6("00000000000000000000000000000000") == "::");
  check("ipv6 2001:db8:: decode",
        hex_be_to_ipv6("20010db8000000000000000000000000") == "2001:db8::");

  // parse sample IPv4 table
  {
    const char* sample =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t010110AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        "eth0\t000110AC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
    auto r = parse_route4_text(sample);
    check("parse4 ok", r.has_value() && r->size() == 2);
    if (r && r->size() == 2) {
      check("parse4 default dest", (*r)[0].is_default || (*r)[1].is_default);
      bool found_def = false, found_net = false;
      for (auto& x : *r) {
        if (x.is_default) {
          found_def = true;
          check("parse4 default gw", x.gateway == "172.16.1.1");
          check("parse4 default flags UG", (x.flags & 0x3) == 0x3);
        }
        if (x.dest == "172.16.1.0") {
          found_net = true;
          check("parse4 net mask /24", x.prefix_len == 24);
          check("parse4 net gw *", x.gateway == "*");
        }
      }
      check("parse4 found default+net", found_def && found_net);
    }
  }

  // parse sample IPv6
  {
    const char* sample6 =
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
        "00000000000000000000000000000000 00000400 00000001 00000000 00000003     eth0\n"
        "00000000000000000000000000000001 80 00000000000000000000000000000000 00 "
        "00000000000000000000000000000000 00000000 00000001 00000000 80000001       lo\n";
    auto r = parse_route6_text(sample6);
    check("parse6 ok", r.has_value() && r->size() == 2);
    if (r && r->size() == 2) {
      bool def = false, loop = false;
      for (auto& x : *r) {
        if (x.is_default) {
          def = true;
          check("parse6 default iface eth0", x.iface == "eth0");
          check("parse6 default metric 1024", x.metric == 0x400);
        }
        if (x.prefix_len == 128) {
          loop = true;
          check("parse6 ::1", x.dest == "::1");
          check("parse6 lo", x.iface == "lo");
        }
      }
      check("parse6 found default+loopback", def && loop);
    }
  }

  auto demo = build_demo_snapshot();
  check("demo has v4", !demo.v4.empty());
  check("demo has v6", !demo.v6.empty());
  check("demo default4 >= 1", demo.default4 >= 1);
  check("demo default6 >= 1", demo.default6 >= 1);
  check("demo gateway4 >= 1", demo.gateway4 >= 1);

  bool print_ok = true;
  try {
    print_header(demo);
    print_summary(demo);
    print_table4(demo);
    print_table6(demo);
  } catch (...) {
    print_ok = false;
  }
  check("demo print no crash", print_ok);

  std::string json_out;
  {
    std::ostringstream oss;
    auto* old = std::cout.rdbuf(oss.rdbuf());
    print_json(demo);
    std::cout.rdbuf(old);
    json_out = oss.str();
  }
  check("JSON starts with '{'", !json_out.empty() && json_out[0] == '{');
  check("JSON has ipv4", json_out.find("\"ipv4\":[") != std::string::npos);
  check("JSON has ipv6", json_out.find("\"ipv6\":[") != std::string::npos);
  check("JSON has summary", json_out.find("\"summary\"") != std::string::npos);
  check("JSON has is_default", json_out.find("\"is_default\"") != std::string::npos);

  auto real = read_routes();
  if (real.has_value()) {
    check("proc route read ok", true);
    check("real v4 countable", real->v4.size() < 100000);
    // most hosts have at least lo or eth route
    check("real has some routes", !real->v4.empty() || !real->v6.empty());
  } else {
    std::println(std::cout, "  {}ℹ{} /proc read failed ({}): restricted env — skipping", C_YELLOW,
                 C_RST, real.error().message);
  }

  g_color = true;
  init_colors();
  std::string colored = C_GREEN;
  g_color = false;
  init_colors();
  std::string plain = C_GREEN;
  check("--no-color clears ANSI", !colored.empty() && plain.empty());
  g_color = true;
  init_colors();

  check("fmt_signed(+3)", fmt_signed(3) == "+3");
  check("fmt_signed(-2)", fmt_signed(-2) == "-2");

  std::println(std::cout);
  std::println(std::cout, "{}  Results: {} passed, {} failed{}", failed == 0 ? C_GREEN : C_RED,
               passed, failed, C_RST);
  return failed == 0 ? 0 : 1;
}

// ── Main ──

int main(int argc, char** argv) {
  bool json_mode = false;
  bool watch_mode = false;
  bool demo_mode = false;
  bool selftest = false;
  bool only4 = false;
  bool only6 = false;
  int watch_secs = 2;

  for (int i = 1; i < argc; ++i) {
    std::string_view arg{argv[i]};
    if (arg == "--json") json_mode = true;
    else if (arg == "--no-color" || arg == "-c") g_color = false;
    else if (arg == "--demo") demo_mode = true;
    else if (arg == "--selftest") selftest = true;
    else if (arg == "--ipv4" || arg == "-4") only4 = true;
    else if (arg == "--ipv6" || arg == "-6") only6 = true;
    else if ((arg == "--watch" || arg == "-w") && i + 1 < argc) {
      watch_mode = true;
      ++i;
      std::from_chars(argv[i], argv[i] + std::strlen(argv[i]), watch_secs);
      if (watch_secs < 1) watch_secs = 1;
    } else if (arg == "--help" || arg == "-h") {
      init_colors();
      std::println(std::cout, "{}route-watch{} — Linux IPv4/IPv6 routing table monitor\n", C_BOLD,
                   C_RST);
      std::println(std::cout, "Usage: route-watch [options]\n");
      std::println(std::cout, "Options:");
      std::println(std::cout, "  -w, --watch N   Refresh every N seconds (default: 2)");
      std::println(std::cout, "  --json          Output JSON");
      std::println(std::cout, "  --no-color, -c  Disable ANSI colors");
      std::println(std::cout, "  --demo          Simulated multi-iface routing table");
      std::println(std::cout, "  --ipv4, -4      Show only IPv4 routes");
      std::println(std::cout, "  --ipv6, -6      Show only IPv6 routes");
      std::println(std::cout, "  --selftest      Run built-in tests");
      std::println(std::cout, "  -h, --help      Show this help\n");
      std::println(std::cout, "{}", C_DIM + "Reads: /proc/net/route, /proc/net/ipv6_route" + C_RST);
      std::println(std::cout, "{}",
                   C_DIM + "Decodes LE hex addrs, flags (UG/H), prefix from mask, defaults" +
                       C_RST);
      return 0;
    }
  }

  init_colors();
  if (selftest) return run_selftest();

  auto filter = [&](RouteSnapshot& s) {
    if (only4) {
      s.v6.clear();
      s.default6 = 0;
      s.gateway6 = 0;
    }
    if (only6) {
      s.v4.clear();
      s.default4 = 0;
      s.gateway4 = 0;
      s.host4 = 0;
    }
  };

  auto take = [&]() -> std::optional<RouteSnapshot> {
    if (demo_mode) {
      auto d = build_demo_snapshot();
      filter(d);
      return d;
    }
    auto r = read_routes();
    if (!r) {
      if (!json_mode)
        std::println(std::cerr, "{}Error:{} {}", C_RED, C_RST, r.error().message);
      return std::nullopt;
    }
    filter(*r);
    return *r;
  };

  if (watch_mode) {
    std::optional<RouteSnapshot> prev;
    bool first = true;
    while (true) {
      auto snap = take();
      if (!snap) return 1;

      if (prev) {
        snap->d_v4 = static_cast<int>(snap->v4.size()) - static_cast<int>(prev->v4.size());
        snap->d_v6 = static_cast<int>(snap->v6.size()) - static_cast<int>(prev->v6.size());
        snap->d_default4 = snap->default4 - prev->default4;
        snap->has_delta = true;
      }
      prev = snap;

      if (!json_mode && !first) std::cout << "\033[2J\033[H";
      first = false;

      if (json_mode) {
        print_json(*snap);
      } else {
        print_header(*snap);
        print_summary(*snap);
        if (!only6) print_table4(*snap);
        if (!only4) print_table6(*snap);
        std::println(std::cout, "{}  Refreshing every {}s — Ctrl+C to exit{}", C_DIM, watch_secs,
                     C_RST);
      }
      std::cout << std::flush;
      std::this_thread::sleep_for(std::chrono::seconds(watch_secs));
    }
  } else {
    auto snap = take();
    if (!snap) return 1;
    if (json_mode) {
      print_json(*snap);
    } else {
      print_header(*snap);
      print_summary(*snap);
      if (!only6) print_table4(*snap);
      if (!only4) print_table6(*snap);
    }
  }
  return 0;
}
