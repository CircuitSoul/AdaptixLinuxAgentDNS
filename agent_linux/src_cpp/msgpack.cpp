#include "agent.hpp"
#include <stdexcept>
#include <cstring>

static constexpr size_t MAX_BIN_LEN = 64ULL*1024ULL*1024ULL;
static constexpr uint32_t MAX_ARRAY_MAP = 1000000;

static void append(bytes& out, const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    out.insert(out.end(), b, b + n);
}

static void put_u64(bytes& out, uint64_t v) {
    if (v <= 0x7f) out.push_back((uint8_t)v);
    else if (v <= 0xff) { out.push_back(0xcc); out.push_back((uint8_t)v); }
    else if (v <= 0xffff) { out.push_back(0xcd); out.push_back((uint8_t)(v>>8)); out.push_back((uint8_t)v); }
    else if (v <= 0xffffffffULL) { out.push_back(0xce); for(int i=3;i>=0;i--) out.push_back((uint8_t)(v>>(8*i))); }
    else { out.push_back(0xcf); for(int i=7;i>=0;i--) out.push_back((uint8_t)(v>>(8*i))); }
}

static void put_i64(bytes& out, int64_t v) {
    if (v >= 0) { put_u64(out, (uint64_t)v); return; }
    if (v >= -32) { out.push_back((uint8_t)(0xe0 | (v & 0x1f))); }
    else if (v >= -128) { out.push_back(0xd0); out.push_back((uint8_t)(int8_t)v); }
    else if (v >= -32768) { out.push_back(0xd1); uint16_t u=(uint16_t)v; out.push_back((uint8_t)(u>>8)); out.push_back((uint8_t)u); }
    else if (v >= -2147483648LL) { out.push_back(0xd2); uint32_t u=(uint32_t)v; for(int i=3;i>=0;i--) out.push_back((uint8_t)(u>>(8*i))); }
    else { out.push_back(0xd3); uint64_t u=(uint64_t)v; for(int i=7;i>=0;i--) out.push_back((uint8_t)(u>>(8*i))); }
}

static void put_str(bytes& out, const std::string& s) {
    size_t n=s.size();
    if(n<=31) out.push_back((uint8_t)(0xa0|n));
    else if(n<=255){ out.push_back(0xd9); out.push_back((uint8_t)n); }
    else if(n<=65535){ out.push_back(0xda); out.push_back((uint8_t)(n>>8)); out.push_back((uint8_t)n); }
    else { out.push_back(0xdb); for(int i=3;i>=0;i--) out.push_back((uint8_t)(n>>(8*i))); }
    append(out, s.data(), n);
}

static void put_bin(bytes& out, const bytes& b) {
    size_t n=b.size();
    if(n<=255){ out.push_back(0xc4); out.push_back((uint8_t)n); }
    else if(n<=65535){ out.push_back(0xc5); out.push_back((uint8_t)(n>>8)); out.push_back((uint8_t)n); }
    else { out.push_back(0xc6); for(int i=3;i>=0;i--) out.push_back((uint8_t)(n>>(8*i))); }
    if(n) append(out, b.data(), n);
}

bytes mp_u64(uint64_t v){ bytes o; put_u64(o,v); return o; }
bytes mp_i64(int64_t v){ bytes o; put_i64(o,v); return o; }
bytes mp_bool(bool v){ return bytes{v ? (uint8_t)0xc3 : (uint8_t)0xc2}; }
bytes mp_nil(){ return bytes{0xc0}; }
bytes mp_str(const std::string& s){ bytes o; put_str(o,s); return o; }
bytes mp_bin(const bytes& b){ bytes o; put_bin(o,b); return o; }
bytes mp_array(const std::vector<bytes>& items){ bytes o; if(items.size()<=15) o.push_back((uint8_t)(0x90|items.size())); else if(items.size()<=0xffff){ o.push_back(0xdc); o.push_back((uint8_t)(items.size()>>8)); o.push_back((uint8_t)items.size()); } else { o.push_back(0xdd); for(int i=3;i>=0;i--) o.push_back((uint8_t)(items.size()>>(8*i))); } for(auto& x:items) o.insert(o.end(), x.begin(), x.end()); return o; }
bytes mp_map(const std::vector<std::pair<std::string, bytes>>& kv){ bytes o; if(kv.size()<=15) o.push_back((uint8_t)(0x80|kv.size())); else if(kv.size()<=0xffff){ o.push_back(0xde); o.push_back((uint8_t)(kv.size()>>8)); o.push_back((uint8_t)kv.size()); } else { o.push_back(0xdf); for(int i=3;i>=0;i--) o.push_back((uint8_t)(kv.size()>>(8*i))); } for(auto& e:kv){ put_str(o,e.first); o.insert(o.end(), e.second.begin(), e.second.end()); } return o; }

// ---- reader ----
static inline void need(MpReader& r, size_t n) {
    if (r.pos + n > r.buf.size()) throw std::runtime_error("msgpack eof");
}
uint8_t MpReader::peek(){ need(*this,1); return buf[pos]; }
void MpReader::skip(){ need(*this,1); pos++; }
uint64_t MpReader::read_u64(){
    uint8_t c=peek(); skip();
    if(c<=0x7f) return c;
    if((c&0xe0)==0xe0) return (int64_t)(int8_t)c;
    switch(c){
        case 0xcc: need(*this,1); return buf[pos++];
        case 0xcd: need(*this,2); { uint16_t v=(buf[pos]<<8)|buf[pos+1]; pos+=2; return v; }
        case 0xce: need(*this,4); { uint64_t v=0; for(int i=0;i<4;i++) v=(v<<8)|buf[pos+i]; pos+=4; return v; }
        case 0xcf: need(*this,8); { uint64_t v=0; for(int i=0;i<8;i++) v=(v<<8)|buf[pos+i]; pos+=8; return v; }
        case 0xd0: need(*this,1); return (int64_t)(int8_t)buf[pos++];
        case 0xd1: need(*this,2); { int16_t v=(int16_t)((buf[pos]<<8)|buf[pos+1]); pos+=2; return (int64_t)v; }
        case 0xd2: need(*this,4); { int32_t v=0; for(int i=0;i<4;i++) v=(v<<8)|buf[pos+i]; pos+=4; return (int64_t)v; }
        case 0xd3: need(*this,8); { int64_t v=0; for(int i=0;i<8;i++) v=(v<<8)|buf[pos+i]; pos+=8; return v; }
        default: throw std::runtime_error("bad uint");
    }
}
int64_t MpReader::read_i64(){ uint8_t c=peek(); if(c<=0x7f){ skip(); return c; } if((c&0xe0)==0xe0){ skip(); return (int8_t)c; } switch(c){ case 0xcc: case 0xcd: case 0xce: case 0xcf: return (int64_t)read_u64(); case 0xd0: case 0xd1: case 0xd2: case 0xd3: return (int64_t)read_u64(); default: throw std::runtime_error("bad int"); } }
bool MpReader::read_bool(){ uint8_t c=peek(); if(c==0xc2){skip();return false;} if(c==0xc3){skip();return true;} throw std::runtime_error("bad bool"); }
bool MpReader::read_nil(){ uint8_t c=peek(); if(c==0xc0){skip();return true;} return false; }
std::string MpReader::read_str(){ uint8_t c=peek(); size_t n; skip();
    if((c&0xe0)==0xa0) n=c&0x1f;
    else if(c==0xd9){need(*this,1); n=buf[pos++];}
    else if(c==0xda){need(*this,2); n=(buf[pos]<<8)|buf[pos+1]; pos+=2;}
    else if(c==0xdb){need(*this,4); n=0; for(int i=0;i<4;i++) n=(n<<8)|buf[pos+i]; pos+=4;}
    else throw std::runtime_error("bad str");
    if(n>MAX_BIN_LEN) throw std::runtime_error("str too large");
    need(*this,n); std::string s(buf.begin()+(std::ptrdiff_t)pos, buf.begin()+(std::ptrdiff_t)(pos+n)); pos+=n; return s;
}
bytes MpReader::read_bin(){ uint8_t c=peek(); size_t n;
    if(c==0xc0){ skip(); return bytes{}; }
    skip();
    if(c==0xc4){need(*this,1); n=buf[pos++];}
    else if(c==0xc5){need(*this,2); n=(buf[pos]<<8)|buf[pos+1]; pos+=2;}
    else if(c==0xc6){need(*this,4); n=0; for(int i=0;i<4;i++) n=(n<<8)|buf[pos+i]; pos+=4;}
    else throw std::runtime_error("bad bin");
    if(n>MAX_BIN_LEN) throw std::runtime_error("bin too large");
    need(*this,n); bytes b(buf.begin()+pos, buf.begin()+pos+n); pos+=n; return b;
}
uint32_t MpReader::read_map(){ uint8_t c=peek(); skip(); uint32_t n;
    if((c&0xf0)==0x80) n=c&0x0f;
    else if(c==0xde){need(*this,2); n=(uint32_t)((buf[pos]<<8)|buf[pos+1]); pos+=2;}
    else if(c==0xdf){need(*this,4); n=0; for(int i=0;i<4;i++) n=(n<<8)|buf[pos+i]; pos+=4;}
    else throw std::runtime_error("bad map");
    if(n>MAX_ARRAY_MAP) throw std::runtime_error("map too large");
    return n;
}
uint32_t MpReader::read_array(){ uint8_t c=peek(); skip(); uint32_t n;
    if((c&0xf0)==0x90) n=c&0x0f;
    else if(c==0xdc){need(*this,2); n=(uint32_t)((buf[pos]<<8)|buf[pos+1]); pos+=2;}
    else if(c==0xdd){need(*this,4); n=0; for(int i=0;i<4;i++) n=(n<<8)|buf[pos+i]; pos+=4;}
    else throw std::runtime_error("bad array");
    if(n>MAX_ARRAY_MAP) throw std::runtime_error("array too large");
    return n;
}
static void skip_value_impl(MpReader& r, unsigned depth){
    if(depth > 64) throw std::runtime_error("msgpack nesting too deep");
    uint8_t c=r.peek(); r.skip();
    if(c<=0x7f || (c&0xe0)==0xe0) return;
    if(c>=0xa0 && c<=0xbf){ size_t n=c&0x1f; need(r,n); r.pos+=n; return; }
    if(c>=0x80 && c<=0x8f){ uint32_t n=c&0x0f; for(uint32_t i=0;i<n;i++){ skip_value_impl(r,depth+1); skip_value_impl(r,depth+1); } return; }
    if(c>=0x90 && c<=0x9f){ uint32_t n=c&0x0f; for(uint32_t i=0;i<n;i++) skip_value_impl(r,depth+1); return; }
    switch(c){
        case 0xc0: case 0xc2: case 0xc3: return;
        case 0xc4: { need(r,1); size_t n=r.buf[r.pos]; r.pos++; need(r,n); r.pos+=n; return; }
        case 0xc5: { need(r,2); size_t n=(r.buf[r.pos]<<8)|r.buf[r.pos+1]; r.pos+=2; need(r,n); r.pos+=n; return; }
        case 0xc6: { need(r,4); uint32_t n=0; for(int i=0;i<4;i++) n=(n<<8)|r.buf[r.pos+i]; r.pos+=4; need(r,(size_t)n); r.pos+=n; return; }
        case 0xcc: need(r,1); r.pos++; return;
        case 0xcd: need(r,2); r.pos+=2; return;
        case 0xce: need(r,4); r.pos+=4; return;
        case 0xcf: need(r,8); r.pos+=8; return;
        case 0xd0: need(r,1); r.pos++; return;
        case 0xd1: need(r,2); r.pos+=2; return;
        case 0xd2: need(r,4); r.pos+=4; return;
        case 0xd3: need(r,8); r.pos+=8; return;
        case 0xd9: { need(r,1); size_t n=r.buf[r.pos]; r.pos++; need(r,n); r.pos+=n; } return;
        case 0xda: { need(r,2); size_t n=(r.buf[r.pos]<<8)|r.buf[r.pos+1]; r.pos+=2; need(r,n); r.pos+=n; } return;
        case 0xdb: { need(r,4); uint32_t n=0; for(int i=0;i<4;i++) n=(n<<8)|r.buf[r.pos+i]; r.pos+=4; need(r,(size_t)n); r.pos+=n; } return;
        case 0xdc: { uint32_t n=r.read_array(); for(uint32_t i=0;i<n;i++) skip_value_impl(r,depth+1); return; }
        case 0xdd: { uint32_t n=r.read_array(); for(uint32_t i=0;i<n;i++) skip_value_impl(r,depth+1); return; }
        case 0xde: { uint32_t n=r.read_map(); for(uint32_t i=0;i<n;i++){ skip_value_impl(r,depth+1); skip_value_impl(r,depth+1); } return; }
        case 0xdf: { uint32_t n=r.read_map(); for(uint32_t i=0;i<n;i++){ skip_value_impl(r,depth+1); skip_value_impl(r,depth+1); } return; }
        case 0xc7: { need(r,2); uint32_t n=r.buf[r.pos]; r.pos+=2; need(r,(size_t)n); r.pos+=n; return; }
        case 0xc8: { need(r,3); uint32_t n=((uint32_t)r.buf[r.pos]<<8)|r.buf[r.pos+1]; r.pos+=3; need(r,(size_t)n); r.pos+=n; return; }
        case 0xc9: { need(r,5); uint32_t n=0; for(int i=0;i<4;i++) n=(n<<8)|r.buf[r.pos+i]; r.pos+=5; need(r,(size_t)n); r.pos+=n; return; }
        case 0xd4: need(r,2); r.pos+=2; return;
        case 0xd5: need(r,3); r.pos+=3; return;
        case 0xd6: need(r,5); r.pos+=5; return;
        case 0xd7: need(r,9); r.pos+=9; return;
        case 0xd8: need(r,17); r.pos+=17; return;
        default: throw std::runtime_error("bad value");
    }
}

void MpReader::skip_value(){
    skip_value_impl(*this, 0);
}
