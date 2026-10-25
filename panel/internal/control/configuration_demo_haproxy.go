package control

import (
	"fmt"
	"net"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// Illustrative, in-process rendering. Never run system commands in Demo mode.
func demoHAConfig(b *strings.Builder, c model.Connection, value func(string) string) {
	fmt.Fprintln(b, "global")
	if value("maxconn") != "0" {
		fmt.Fprintf(b, "    maxconn %s\n", value("maxconn"))
	}
	if value("log") != "off" {
		fmt.Fprintln(b, "    log stdout format raw local0")
	}
	fmt.Fprintln(b, "defaults\n    mode tcp")
	if value("log") != "off" {
		fmt.Fprintln(b, "    log global\n    option tcplog")
		if value("log") == "errors" {
			fmt.Fprintln(b, "    option dontlog-normal")
		}
	}
	fmt.Fprintf(b, "    retries %s\n    timeout connect %ss\n    timeout client %ss\n    timeout server %ss\n    timeout queue %ss\n    timeout check %ss\n", value("retries"), value("connect"), value("idle"), value("idle"), value("queue"), value("check_timeout"))
	if value("fin") != "0" {
		fmt.Fprintf(b, "    timeout client-fin %ss\n    timeout server-fin %ss\n", value("fin"), value("fin"))
	}
	if value("tunnel") != "0" {
		fmt.Fprintf(b, "    timeout tunnel %ss\n", value("tunnel"))
	}
	fmt.Fprintf(b, "frontend entrance\n    bind %s\n", net.JoinHostPort(c.Bind, c.Ports))
	if value("maxconn") != "0" {
		fmt.Fprintf(b, "    maxconn %s\n", value("maxconn"))
	}
	algorithm := c.Strategy
	if oneOf(algorithm, "single", "failover") {
		algorithm = "roundrobin"
	}
	fmt.Fprintf(b, "    default_backend destinations\nbackend destinations\n    balance %s\n", algorithm)
	if algorithm == "source" {
		fmt.Fprintln(b, "    hash-type consistent")
	}
	if value("stick") == "source" && len(c.Targets) > 1 {
		fmt.Fprintf(b, "    stick-table type ipv6 size %s expire %ss\n    stick on src\n", value("stick_size"), value("stick_expire"))
	}
	if value("check_mode") == "http" {
		fmt.Fprintf(b, "    option httpchk\n    http-check send meth GET uri %s ver HTTP/1.1 hdr Host %s\n    http-check expect status %s\n", value("check_path"), value("check_host"), value("check_status"))
	}
	for i, t := range c.Targets {
		fmt.Fprintf(b, "    server target%d %s weight %d", i+1, net.JoinHostPort(t.IP, fmt.Sprint(t.Port)), t.Weight)
		if value("check_mode") != "off" {
			fmt.Fprintf(b, " check inter %ss fall %s rise %s", value("check_interval"), value("check_fall"), value("check_rise"))
			if value("check_port") != "0" {
				fmt.Fprintf(b, " port %s", value("check_port"))
			}
		}
		if value("server_maxconn") != "0" {
			fmt.Fprintf(b, " maxconn %s", value("server_maxconn"))
		}
		if value("slowstart") != "0" {
			fmt.Fprintf(b, " slowstart %ss", value("slowstart"))
		}
		if value("proxy") == "v1" {
			fmt.Fprint(b, " send-proxy")
		}
		if value("proxy") == "v2" {
			fmt.Fprint(b, " send-proxy-v2")
		}
		if c.Strategy == "failover" && i > 0 {
			fmt.Fprint(b, " backup")
		}
		fmt.Fprintln(b)
	}
}
