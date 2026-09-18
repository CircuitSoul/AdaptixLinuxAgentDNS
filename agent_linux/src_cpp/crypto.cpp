#include "agent.hpp"
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <ctime>
#include <cerrno>
#include <algorithm>

// ---------------------------------------------------------------------------
// RNG
// ---------------------------------------------------------------------------

static bool fill_urandom(uint8_t* p, size_t n){
    while(n>0){
#ifdef SYS_getrandom
        ssize_t r = ::syscall(SYS_getrandom, p, n, 0);
        if(r>0){ p += (size_t)r; n -= (size_t)r; continue; }
        if(r<0 && errno==EINTR) continue;
#endif
        break;
    }
    if(n==0) return true;
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if(fd<0) return false;
    while(n>0){
        ssize_t r = ::read(fd, p, n);
        if(r>0){ p += (size_t)r; n -= (size_t)r; continue; }
        if(r<0 && errno==EINTR) continue;
        break;
    }
    ::close(fd);
    return n==0;
}

static uint64_t weak_seed(){
    uint64_t x = 0x9e3779b97f4a7c15ULL;
    x ^= (uint64_t)::time(nullptr);
    x ^= ((uint64_t)::getpid() << 32);
    uint8_t stackbyte = 0;
    x ^= (uint64_t)(uintptr_t)&stackbyte * 0x100000001b3ULL;
    return x;
}

static void weak_fill(uint8_t* p, size_t n){
    uint64_t s = weak_seed();
    for(size_t i=0;i<n;i++){
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        p[i] = (uint8_t)(s >> 56);
    }
}

static bool fill_random(uint8_t* p, size_t n){
    int fd = ::open("/dev/random", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if(fd<0) return false;
    while(n>0){
        ssize_t r = ::read(fd, p, n);
        if(r>0){ p += (size_t)r; n -= (size_t)r; continue; }
        if(r<0 && errno==EINTR) continue;
        if(r<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;
        break;
    }
    ::close(fd);
    return n==0;
}

void random_bytes(bytes& out, size_t n){
    out.resize(n);
    if(n==0) return;
    if(!fill_urandom(out.data(), n) && !fill_random(out.data(), n)) weak_fill(out.data(), n);
}

// ---------------------------------------------------------------------------
// AES-128/192/256 encryption (forward cipher only, used by GCM)
// ---------------------------------------------------------------------------

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rcon[15] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d};

struct AesCtx {
    uint8_t rk[240];
    int rounds;
};

static void aes_set_key(AesCtx& ctx, const uint8_t* key, int bits){
    int nk = bits / 32;
    int nr = nk + 6;
    int words = 4 * (nr + 1);
    memcpy(ctx.rk, key, (size_t)nk * 4);
    uint8_t temp[4];
    for(int i=nk;i<words;i++){
        for(int j=0;j<4;j++) temp[j] = ctx.rk[(i-1)*4 + j];
        if(i % nk == 0){
            uint8_t t = temp[0]; temp[0]=temp[1]; temp[1]=temp[2]; temp[2]=temp[3]; temp[3]=t;
            for(int j=0;j<4;j++) temp[j] = sbox[temp[j]];
            temp[0] ^= rcon[i / nk];
        } else if(nk > 6 && (i % nk) == 4){
            for(int j=0;j<4;j++) temp[j] = sbox[temp[j]];
        }
        for(int j=0;j<4;j++) ctx.rk[i*4 + j] = ctx.rk[(i-nk)*4 + j] ^ temp[j];
    }
    ctx.rounds = nr;
}

static void add_round_key(uint8_t* s, const uint8_t* w){
    for(int i=0;i<16;i++) s[i] ^= w[i];
}
static void sub_bytes(uint8_t* s){
    for(int i=0;i<16;i++) s[i] = sbox[s[i]];
}
static void shift_rows(uint8_t* s){
    uint8_t t;
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}
static uint8_t xtime(uint8_t a){
    return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
}
static void mix_columns(uint8_t* s){
    for(int c=0;c<4;c++){
        uint8_t* a = s + 4*c;
        uint8_t a0=a[0], a1=a[1], a2=a[2], a3=a[3];
        uint8_t t = a0 ^ a1 ^ a2 ^ a3;
        a[0] = a0 ^ t ^ xtime(a0 ^ a1);
        a[1] = a1 ^ t ^ xtime(a1 ^ a2);
        a[2] = a2 ^ t ^ xtime(a2 ^ a3);
        a[3] = a3 ^ t ^ xtime(a3 ^ a0);
    }
}
static void aes_encrypt_block(const AesCtx& ctx, const uint8_t in[16], uint8_t out[16]){
    uint8_t s[16]; memcpy(s, in, 16);
    add_round_key(s, ctx.rk);
    for(int r=1;r<ctx.rounds;r++){
        sub_bytes(s); shift_rows(s); mix_columns(s);
        add_round_key(s, ctx.rk + r*16);
    }
    sub_bytes(s); shift_rows(s);
    add_round_key(s, ctx.rk + ctx.rounds*16);
    memcpy(out, s, 16);
}

// ---------------------------------------------------------------------------
// GCM (12-byte IV, 16-byte tag, no AAD)
// ---------------------------------------------------------------------------

static void gf_mul(uint8_t* z, const uint8_t* x, const uint8_t* y){
    uint8_t v[16]; memcpy(v, y, 16);
    uint8_t r[16] = {0};
    for(int i=0;i<16;i++){
        uint8_t xi = x[i];
        for(int bit=0;bit<8;bit++){
            if(xi & (0x80 >> bit)){
                for(int j=0;j<16;j++) r[j] ^= v[j];
            }
            uint8_t lsb = v[15] & 1;
            for(int j=15;j>0;j--) v[j] = (uint8_t)((v[j] >> 1) | (v[j-1] << 7));
            v[0] >>= 1;
            if(lsb) v[0] ^= 0xe1;
        }
    }
    memcpy(z, r, 16);
}

static void put_be64(uint8_t* p, uint64_t v){
    for(int i=7;i>=0;i--){ p[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

static void gcm_ghash(const AesCtx& ctx, const uint8_t* h, const uint8_t* data, size_t len, uint8_t* out){
    (void)ctx;
    memset(out, 0, 16);
    for(size_t off=0; off<len; off += 16){
        size_t n = std::min<size_t>(16, len - off);
        uint8_t block[16] = {0};
        memcpy(block, data + off, n);
        for(int i=0;i<16;i++) out[i] ^= block[i];
        gf_mul(out, out, h);
    }
    uint8_t lb[16] = {0};
    put_be64(lb, 0);
    put_be64(lb + 8, (uint64_t)len * 8ULL);
    for(int i=0;i<16;i++) out[i] ^= lb[i];
    gf_mul(out, out, h);
}

static void inc32(uint8_t ctr[16]){
    for(int i=15;i>=12;i--){
        if(++ctr[i] != 0) break;
    }
}

static void gcm_encrypt(const AesCtx& ctx, const uint8_t* iv,
                        const uint8_t* pt, size_t plen,
                        uint8_t* ct, uint8_t tag[16]){
    uint8_t h[16] = {0};
    aes_encrypt_block(ctx, h, h);

    uint8_t j0[16]; memcpy(j0, iv, 12);
    j0[12]=j0[13]=j0[14]=0; j0[15]=1;
    uint8_t s0[16]; aes_encrypt_block(ctx, j0, s0);

    uint8_t ctr[16]; memcpy(ctr, j0, 16);
    inc32(ctr);
    for(size_t off=0; off<plen; off += 16){
        uint8_t ks[16]; aes_encrypt_block(ctx, ctr, ks);
        size_t n = std::min<size_t>(16, plen - off);
        for(size_t j=0;j<n;j++) ct[off+j] = pt[off+j] ^ ks[j];
        inc32(ctr);
    }

    uint8_t s[16];
    gcm_ghash(ctx, h, ct, plen, s);
    for(int i=0;i<16;i++) tag[i] = s0[i] ^ s[i];
}

static bool const_eq(const uint8_t* a, const uint8_t* b, size_t n){
    uint8_t d = 0;
    for(size_t i=0;i<n;i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

static bool gcm_decrypt(const AesCtx& ctx, const uint8_t* iv,
                        const uint8_t* ct, size_t ctlen, const uint8_t tag[16],
                        uint8_t* pt){
    uint8_t h[16] = {0};
    aes_encrypt_block(ctx, h, h);

    uint8_t j0[16]; memcpy(j0, iv, 12);
    j0[12]=j0[13]=j0[14]=0; j0[15]=1;
    uint8_t s0[16]; aes_encrypt_block(ctx, j0, s0);

    uint8_t ctr[16]; memcpy(ctr, j0, 16);
    inc32(ctr);
    for(size_t off=0; off<ctlen; off += 16){
        uint8_t ks[16]; aes_encrypt_block(ctx, ctr, ks);
        size_t n = std::min<size_t>(16, ctlen - off);
        for(size_t j=0;j<n;j++) pt[off+j] = ct[off+j] ^ ks[j];
        inc32(ctr);
    }

    uint8_t s[16];
    gcm_ghash(ctx, h, ct, ctlen, s);
    uint8_t expected[16];
    for(int i=0;i<16;i++) expected[i] = s0[i] ^ s[i];
    return const_eq(expected, tag, 16);
}

// ---------------------------------------------------------------------------
// Public crypto API
// ---------------------------------------------------------------------------

bytes rc4_crypt(const bytes& data, const bytes& key) {
    if (key.empty() || data.empty()) return {};
    std::vector<uint8_t> S(256);
    for (int i=0;i<256;i++) S[i]=(uint8_t)i;
    int j=0;
    for (int i=0;i<256;i++) {
        j=(j+S[i]+key[i%key.size()])&0xff;
        std::swap(S[i],S[j]);
    }
    bytes out(data.size());
    int i=0; j=0;
    for (size_t n=0;n<data.size();n++) {
        i=(i+1)&0xff;
        j=(j+S[i])&0xff;
        std::swap(S[i],S[j]);
        uint8_t k=S[(S[i]+S[j])&0xff];
        out[n]=data[n]^k;
    }
    return out;
}

bytes aes_gcm_encrypt(const bytes& plain, const bytes& key) {
    if (key.size()!=16 && key.size()!=24 && key.size()!=32) return {};
    AesCtx ctx; aes_set_key(ctx, key.data(), (int)key.size()*8);
    bytes iv; random_bytes(iv, 12);
    if(iv.size()!=12) return {};
    bytes out(12 + plain.size() + 16);
    memcpy(out.data(), iv.data(), 12);
    gcm_encrypt(ctx, iv.data(), plain.data(), plain.size(), out.data()+12, out.data()+12+plain.size());
    return out;
}

bool aes_gcm_decrypt(const bytes& cipher, const bytes& key, bytes& plain) {
    if (cipher.size() < 28) return false;
    if (key.size()!=16 && key.size()!=24 && key.size()!=32) return false;
    AesCtx ctx; aes_set_key(ctx, key.data(), (int)key.size()*8);
    size_t ctlen = cipher.size() - 28;
    bytes pt(ctlen);
    if(!gcm_decrypt(ctx, cipher.data(), cipher.data()+12, ctlen, cipher.data()+12+ctlen, pt.data())){
        plain.clear();
        return false;
    }
    plain.swap(pt);
    return true;
}

static const char B64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
bytes base64_encode(const bytes& data) {
    bytes out;
    size_t n=data.size();
    out.reserve(((n+2)/3)*4);
    for(size_t i=0;i<n;i+=3){
        uint32_t v=(uint32_t)data[i]<<16;
        if(i+1<n) v|=(uint32_t)data[i+1]<<8;
        if(i+2<n) v|=(uint32_t)data[i+2];
        out.push_back(B64[(v>>18)&63]);
        out.push_back(B64[(v>>12)&63]);
        out.push_back((i+1<n)?B64[(v>>6)&63]:'=');
        out.push_back((i+2<n)?B64[v&63]:'=');
    }
    return out;
}

bool base64_decode(const std::string& s, bytes& out) {
    auto val=[](char c)->int{
        if(c>='A'&&c<='Z') return c-'A';
        if(c>='a'&&c<='z') return c-'a'+26;
        if(c>='0'&&c<='9') return c-'0'+52;
        if(c=='+') return 62;
        if(c=='/') return 63;
        return -1;
    };
    out.clear();
    uint32_t acc=0; int bits=0;
    for(char ch:s){
        if(ch=='=') break;
        int v=val(ch); if(v<0) continue;
        acc=(acc<<6)|v; bits+=6;
        if(bits>=8){ bits-=8; out.push_back((uint8_t)((acc>>bits)&0xff)); }
    }
    return true;
}

static const char B32[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
bytes base32_encode_nopad(const bytes& data) {
    bytes out;
    uint32_t acc=0; int bits=0;
    for(uint8_t b:data){ acc=(acc<<8)|b; bits+=8; while(bits>=5){ bits-=5; out.push_back(B32[(acc>>bits)&31]); } }
    if(bits>0) out.push_back(B32[(acc<<(5-bits))&31]);
    return out;
}

bool base32_decode_nopad(const std::string& s, bytes& out) {
    out.clear();
    auto val=[](char c)->int{
        if(c>='A'&&c<='Z') return c-'A';
        if(c>='a'&&c<='z') return c-'a';
        if(c>='2'&&c<='7') return c-'2'+26;
        return -1;
    };
    uint32_t acc=0; int bits=0;
    for(char ch:s){
        int v=val(ch); if(v<0) continue;
        acc=(acc<<5)|v; bits+=5;
        if(bits>=8){ bits-=8; out.push_back((uint8_t)((acc>>bits)&0xff)); }
    }
    return true;
}

bytes hex_decode(const std::string& s) {
    if(s.size()%2) return {};
    bytes out; out.reserve(s.size()/2);
    auto nib=[](char c)->int{
        if(c>='0'&&c<='9') return c-'0';
        if(c>='a'&&c<='f') return c-'a'+10;
        if(c>='A'&&c<='F') return c-'A'+10;
        return -1;
    };
    for(size_t i=0;i+1<s.size();i+=2){
        int a=nib(s[i]), b=nib(s[i+1]);
        if(a<0||b<0) return {};
        out.push_back((a<<4)|b);
    }
    return out;
}
