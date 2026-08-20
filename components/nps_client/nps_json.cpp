#include "nps_json.h"

#include <cctype>
#include <cstdlib>
#include <cstring>

namespace esphome::nps {
namespace {

void skip_ws(const char *&p) {
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
    p++;
}

// 解析 JSON 字符串（含转义），p 指向开引号。
bool parse_string(const char *&p, std::string &out) {
  if (*p != '"')
    return false;
  p++;
  out.clear();
  while (*p && *p != '"') {
    if (*p == '\\') {
      p++;
      switch (*p) {
        case '"':
          out += '"';
          break;
        case '\\':
          out += '\\';
          break;
        case '/':
          out += '/';
          break;
        case 'b':
          out += '\b';
          break;
        case 'f':
          out += '\f';
          break;
        case 'n':
          out += '\n';
          break;
        case 'r':
          out += '\r';
          break;
        case 't':
          out += '\t';
          break;
        case 'u': {
          unsigned code = 0;
          for (int i = 0; i < 4; i++) {
            char c = p[1 + i];
            code <<= 4;
            if (c >= '0' && c <= '9')
              code |= c - '0';
            else if (c >= 'a' && c <= 'f')
              code |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')
              code |= c - 'A' + 10;
            else
              return false;
          }
          p += 4;
          if (code < 0x80)
            out += static_cast<char>(code);
          else if (code < 0x800) {
            out += static_cast<char>(0xC0 | (code >> 6));
            out += static_cast<char>(0x80 | (code & 0x3F));
          } else {
            out += static_cast<char>(0xE0 | (code >> 12));
            out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (code & 0x3F));
          }
          break;
        }
        default:
          return false;
      }
      p++;
    } else {
      out += *p++;
    }
  }
  if (*p != '"')
    return false;
  p++;  // 越过结束引号
  return true;
}

// 跳过任意 JSON 值（p 指向值起点）。
void skip_value(const char *&p) {
  skip_ws(p);
  switch (*p) {
    case '"': {
      std::string ignored;
      parse_string(p, ignored);
      break;
    }
    case '{': {
      int depth = 0;
      do {
        if (*p == '{')
          depth++;
        else if (*p == '}')
          depth--;
        else if (*p == '"') {
          std::string ignored;
          parse_string(p, ignored);
          continue;
        }
        p++;
      } while (*p && depth > 0);
      break;
    }
    case '[': {
      int depth = 0;
      do {
        if (*p == '[')
          depth++;
        else if (*p == ']')
          depth--;
        else if (*p == '"') {
          std::string ignored;
          parse_string(p, ignored);
          continue;
        }
        p++;
      } while (*p && depth > 0);
      break;
    }
    default:
      while (*p && *p != ',' && *p != '}' && *p != ']')
        p++;
  }
}

// 在对象体内按 key 查找，返回值起点；找不到返回 nullptr。
const char *find_key(const char *p, const char *key) {
  skip_ws(p);
  if (*p != '{')
    return nullptr;
  p++;
  while (*p) {
    skip_ws(p);
    if (*p == '}')
      return nullptr;
    if (*p != '"')
      return nullptr;
    std::string k;
    if (!parse_string(p, k))
      return nullptr;
    skip_ws(p);
    if (*p != ':')
      return nullptr;
    p++;
    skip_ws(p);
    if (k == key)
      return p;
    skip_value(p);
    skip_ws(p);
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p == '}')
      return nullptr;
    return nullptr;
  }
  return nullptr;
}

const char *locate(const std::string &json, const char *path) {
  const char *p = json.c_str();
  skip_ws(p);
  if (*p != '{')
    return nullptr;
  const char *key = path;
  while (true) {
    const char *dot = strchr(key, '.');
    std::string segment;
    if (dot != nullptr)
      segment.assign(key, dot - key);
    else
      segment = key;
    p = find_key(p, segment.c_str());
    if (p == nullptr)
      return nullptr;
    if (dot == nullptr)
      return p;
    key = dot + 1;
    skip_ws(p);
    if (*p != '{' && *p != '[')
      return nullptr;
    p = *p == '{' ? p : p + 1;
  }
}

}  // namespace

std::string nps_json_string(const std::string &json, const char *path) {
  const char *p = locate(json, path);
  if (p == nullptr)
    return {};
  skip_ws(p);
  std::string out;
  if (!parse_string(p, out))
    return {};
  return out;
}

bool nps_json_bool(const std::string &json, const char *path, bool fallback) {
  const char *p = locate(json, path);
  if (p == nullptr)
    return fallback;
  skip_ws(p);
  if (strncmp(p, "true", 4) == 0)
    return true;
  if (strncmp(p, "false", 5) == 0)
    return false;
  return fallback;
}

int64_t nps_json_int64(const std::string &json, const char *path,
                       int64_t fallback) {
  const char *p = locate(json, path);
  if (p == nullptr)
    return fallback;
  skip_ws(p);
  char *end = nullptr;
  long long v = strtoll(p, &end, 10);
  if (end == p)
    return fallback;
  return static_cast<int64_t>(v);
}

}  // namespace esphome::nps
