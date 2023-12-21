package fake

import (
	"math/rand"
	"path/filepath"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/protoconv"
)

var (
	processAncestors = []*storage.ProcessSignal_LineageInfo{
		{
			ParentExecFilePath: "bash",
		},
	}

	goodProcessNames = []string{
		"ssl-tools",
		"ansible-tower-s",
		"apache2",
		"apache2-foregro",
		"arangod",
		"asd",
		"awk",
		"awx-manage",
		"basename",
		"beam.smp",
		"bootstrap.sh",
		"cadvisor",
		"calico-node",
		"calico-typha",
		"cat",
		"catalina.sh",
		"central",
		"cfssl",
		"cfssl-helper",
		"cfssljson",
		"chgrp",
		"child_setup",
		"chmod",
		"chown",
		"chpst",
		"chronograf",
		"cluster-proport",
		"collector",
		"compliance",
		"consul",
		"couchbase-serve",
		"cp",
		"cpu_sup",
		"cpvpa",
		"crate",
		"cut",
		"daphne",
		"date",
		"debconf-set-sel",
		"df",
		"dirname",
		"dnsmasq",
		"dnsmasq-nanny",
		"docker-entrypoi",
		"docker-php-entr",
		"egrep",
		"entrypoint.sh",
		"env",
		"epmd",
		"erl",
		"erl_child_setup",
		"erlexec",
		"etcd",
		"expr",
		"failure-event-h",
		"find",
		"free",
		"gateway.start",
		"generate_cert",
		"getconf",
		"getent",
		"getopt",
		"git",
		"gnatsd",
		"goport",
		"gosecrets",
		"gosu",
		"grafana-server",
		"grep",
		"gunicorn",
		"head",
		"heapster",
		"hostname",
		"id",
		"import-addition",
		"inet_gethost",
		"initctl",
		"install-cni.sh",
		"invoke-rc.d",
		"ip-masq-agent",
		"ipset",
		"java",
		"kube-dns",
		"kube-proxy",
		"kubernetes-sens",
		"ldapadd",
		"ldapmodify",
		"ldapsearch",
		"ldconfig",
		"ldconfig.real",
		"ln",
		"log-helper",
		"ls",
		"memsup",
		"metrics-server",
		"mkdir",
		"mktemp",
		"monitor",
		"mosquitto",
		"mv",
		"mysql",
		"mysql_ssl_rsa_s",
		"mysql_tzinfo_to",
		"mysqladmin",
		"mysqld",
		"nats-server",
		"nats-streaming-",
		"nginx",
		"node",
		"openssl",
		"perl",
		"pg_ctlcluster",
		"php",
		"pod_nanny",
		"policy-rc.d",
		"postgres",
		"postgresql",
		"ps",
		"psql",
		"pwgen",
		"python",
		"rabbitmq-server",
		"rabbitmqctl",
		"readlink",
		"redis-server",
		"restore-all-dir",
		"rm",
		"run",
		"run-parts",
		"run.sh",
		"runsv",
		"runsvdir",
		"runsvdir-start",
		"scanner",
		"schema-to-ldif.",
		"sed",
		"server",
		"service",
		"sidecar",
		"slapadd",
		"slapd",
		"slapd.config",
		"slapd.postinst",
		"slapd.prerm",
		"slappasswd",
		"slaptest",
		"sleep",
		"sort",
		"ssl-helper",
		"start-confluenc",
		"start-stop-daem",
		"stat",
		"su",
		"su-exec",
		"supervisor",
		"supervisord",
		"tail",
		"tar",
		"tini",
		"touch",
		"tr",
		"uname",
		"update-rc.d",
		"uwsgi",
		"wc",
		"webproc",
		"whoami",
	}

	badProcessNames = []string{
		"wget",
		"curl",
		"bash",
		"sh",
		"zsh",
		"nmap",
		"groupadd",
		"addgroup",
		"useradd",
		"adduser",
		"usermod",
		"apk",
		"apt-get",
		"apt",
		"chkconfig",
		"anacron",
		"cron",
		"crond",
		"crontab",
		"rpm",
		"dnf",
		"yum",
		"iptables",
		"make",
		"gcc",
		"llc",
		"llvm-gcc",
		"sgminer",
		"cgminer",
		"cpuminer",
		"minerd",
		"geth",
		"ethminer",
		"xmr-stak-cpu",
		"xmr-stak-amd",
		"xmr-stak-nvidia",
		"xmrminer",
		"cpuminer-multi",
		"ifrename",
		"ethtool",
		"ifconfig",
		"ipmaddr",
		"iptunnel",
		"route",
		"nameif",
		"mii-tool",
		"nc",
		"nmap",
		"scp",
		"sshfs",
		"ssh-copy-id",
		"rsync",
		"sshd",
		"systemctl",
		"systemd",
	}

	activeProcessNames = []string{
		"/bin/bash",
		"/bin/busybox",
		"/bin/cat",
		"/bin/chgrp",
		"/bin/chmod",
		"/bin/chown",
		"/bin/chvt",
		"/bin/cp",
		"/bin/cpio",
		"/bin/dash",
		"/bin/date",
		"/bin/dd",
		"/bin/df",
		"/bin/dir",
		"/bin/echo",
		"/bin/egrep",
		"/bin/false",
		"/bin/fgrep",
		"/bin/fusermount",
		"/bin/grep",
		"/bin/gunzip",
		"/bin/gzexe",
		"/bin/gzip",
		"/bin/hostname",
		"/bin/ip",
		"/bin/journalctl",
		"/bin/kill",
		"/bin/ln",
		"/bin/ls",
		"/bin/mkdir",
		"/bin/mknod",
		"/bin/mktemp",
		"/bin/mount",
		"/bin/mountpoint",
		"/bin/mv",
		"/bin/ping",
		"/bin/pwd",
		"/bin/readlink",
		"/bin/rm",
		"/bin/rmdir",
		"/bin/sed",
		"/bin/sleep",
		"/bin/stty",
		"/bin/su",
		"/bin/sync",
		"/bin/tar",
		"/bin/touch",
		"/bin/true",
		"/bin/uname",
		"/bin/uncompress",
		"/bin/vdir",
		"/bin/whiptail",
		"/bin/zcat",
		"/bin/zcmp",
		"/bin/zdiff",
		"/bin/zegrep",
		"/bin/zfgrep",
		"/bin/zforce",
		"/bin/zgrep",
		"/bin/zless",
		"/bin/zmore",
		"/bin/znew",
		"/etc/cron.daily/apt",
		"/etc/cron.daily/dpkg",
		"/etc/security/namespace.init",
		"/etc/ssl/misc/CA.pl",
		"/lib/ld-musl-x86_64.so.1",
		"/lib/libcrypto.so.1.0.0",
		"/lib/libcrypto.so.1.1",
		"/lib/libcrypto.so.42.0.0",
		"/lib/libssl.so.1.1",
		"/lib/libssl.so.45.0.1",
		"/lib/libtls.so.17.0.1",
		"/lib/libz.so.1.2.8",
		"/lib/libz.so.1.2.11",
		"/sbin/apk",
		"/sbin/badblocks",
		"/sbin/ldconfig",
		"/sbin/mkmntdirs",
		"/sbin/tini",
		"/sbin/xtables-multi",
		"/usr/bin/apt",
		"/usr/bin/arch",
		"/usr/bin/b2sum",
		"/usr/bin/base32",
		"/usr/bin/base64",
		"/usr/bin/basename",
		"/usr/bin/bash",
		"/usr/bin/cal",
		"/usr/bin/certutil",
		"/usr/bin/chcon",
		"/usr/bin/cksum",
		"/usr/bin/clear",
		"/usr/bin/cmp",
		"/usr/bin/cpio",
		"/usr/bin/comm",
		"/usr/bin/csplit",
		"/usr/bin/curl",
		"/usr/bin/cut",
		"/usr/bin/diff",
		"/usr/bin/diff3",
		"/usr/bin/dircolors",
		"/usr/bin/dirname",
		"/usr/bin/doveadm",
		"/usr/bin/dpkg",
		"/usr/bin/du",
		"/usr/bin/eject",
		"/usr/bin/env",
		"/usr/bin/expand",
		"/usr/bin/expr",
		"/usr/bin/factor",
		"/usr/bin/file",
		"/usr/bin/find",
		"/usr/bin/fmt",
		"/usr/bin/fold",
		"/usr/bin/gdbus",
		"/usr/bin/git",
		"/usr/bin/git-lfs",
		"/usr/bin/gpgv",
		"/usr/bin/groups",
		"/usr/bin/head",
		"/usr/bin/hostid",
		"/usr/bin/id",
		"/usr/bin/info",
		"/usr/bin/install",
		"/usr/bin/join",
		"/usr/bin/jq",
		"/usr/bin/ldd",
		"/usr/bin/less",
		"/usr/bin/link",
		"/usr/bin/logname",
		"/usr/bin/make",
		"/usr/bin/mawk",
		"/usr/bin/md5sum",
		"/usr/bin/mkfifo",
		"/usr/bin/nice",
		"/usr/bin/nl",
		"/usr/bin/nohup",
		"/usr/bin/nproc",
		"/usr/bin/numfmt",
		"/usr/bin/od",
		"/usr/bin/openssl",
		"/usr/bin/paste",
		"/usr/bin/pathchk",
		"/usr/bin/perl",
		"/usr/bin/php7",
		"/usr/bin/pinky",
		"/usr/bin/pip",
		"/usr/bin/pr",
		"/usr/bin/printenv",
		"/usr/bin/printf",
		"/usr/bin/ptx",
		"/usr/bin/realpath",
		"/usr/bin/rgrep",
		"/usr/bin/runcon",
		"/usr/bin/scanelf",
		"/usr/bin/seq",
		"/usr/bin/sdiff",
		"/usr/bin/sha1sum",
		"/usr/bin/sha224sum",
		"/usr/bin/sha256sum",
		"/usr/bin/sha384sum",
		"/usr/bin/sha512sum",
		"/usr/bin/shred",
		"/usr/bin/shuf",
		"/usr/bin/sort",
		"/usr/bin/split",
		"/usr/bin/ssl_client",
		"/usr/bin/sshfs",
		"/usr/bin/stat",
		"/usr/bin/stdbuf",
		"/usr/bin/sum",
		"/usr/bin/tac",
		"/usr/bin/tail",
		"/usr/bin/tee",
		"/usr/bin/test",
		"/usr/bin/timeout",
		"/usr/bin/tr",
		"/usr/bin/truncate",
		"/usr/bin/tsort",
		"/usr/bin/tty",
		"/usr/bin/unexpand",
		"/usr/bin/uniq",
		"/usr/bin/unlink",
		"/usr/bin/unzip",
		"/usr/bin/update-ca-trust",
		"/usr/bin/users",
		"/usr/bin/vi",
		"/usr/bin/wc",
		"/usr/bin/wget",
		"/usr/bin/who",
		"/usr/bin/whoami",
		"/usr/bin/xargs",
		"/usr/bin/yes",
		"/usr/bin/zip",
		"/usr/lib/libcurl.so.4.6.0",
		"/usr/lib/libsqlite3.so.0.8.6",
		"/usr/lib/node_modules/npm/bin/npm",
		"/usr/lib64/libpython2.7.so.1.0",
		"/usr/lib64/libz.so.1.2.7",
		"/usr/sbin/chroot",
		"/usr/sbin/rmt-tar",
		"/usr/sbin/sshd",
		"/usr/sbin/tarcat",
		"/usr/sbin/tzconfig",
		"/usr/sbin/update-ca-certificates",
	}
)

func getBadProcess(containerID string) *storage.ProcessSignal {
	name := badProcessNames[rand.Int()%len(badProcessNames)]
	return getProcess("/bin", name, containerID)
}

func getGoodProcess(containerID string) *storage.ProcessSignal {
	name := goodProcessNames[rand.Int()%len(goodProcessNames)]
	return getProcess("/bin", name, containerID)
}

func getActiveProcesses(containerID string) []*storage.ProcessSignal {
	processes := make([]*storage.ProcessSignal, 0, len(activeProcessNames))
	for _, process := range activeProcessNames {
		processes = append(processes, getProcess("", process, containerID))
	}
	return processes
}

func getProcess(path, name, containerID string) *storage.ProcessSignal {
	return &storage.ProcessSignal{
		ContainerId:  containerID[:12],
		Time:         protoconv.TimestampNow(),
		Name:         name,
		Args:         "abc def ghi jkl lmn op qrs tuv",
		ExecFilePath: filepath.Clean(path + "/" + name),
		LineageInfo:  processAncestors,
	}
}
