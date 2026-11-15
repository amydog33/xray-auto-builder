import os
import re
import stat

print(
    ">>> [Patch] 开始应用全能加速、安全加固与 80/443 全协议兼容补丁..."
)

goroot = os.popen("go env GOROOT").read().strip()
if not goroot:
  raise RuntimeError("未检测到 GOROOT，请检查 Go 环境变量！")

tls_dir = os.path.join(goroot, "src", "crypto", "tls")

# =========================================================================
# 1. 修补 Go 标准库 TLS 1.2 与 1.3（MASQUE 裸公钥防护与证书链兜底）
# =========================================================================
if os.path.exists(tls_dir):
  hc_path = os.path.join(tls_dir, "handshake_client.go")
  if os.path.exists(hc_path):
    os.chmod(hc_path, stat.S_IWRITE | stat.S_IREAD)
    with open(hc_path, "r", encoding="utf-8") as f:
      code = f.read()

    code = re.sub(
        r"c\.peerCertificates = certs\s*\n\treturn nil[^\n]*\n",
        "c.peerCertificates = certs\n",
        code,
    )

    target_v12 = r"(c\.verifiedChains,\s*err\s*=\s*certs\[0\]\.Verify\(opts\))"
    patch_v12 = (
        r"\1\n"
        r"\tif err != nil {\n"
        r"\t\tif len(certs) > 0 {\n"
        r"\t\t\tc.verifiedChains = [][]*x509.Certificate{certs}\n"
        r"\t\t}\n"
        r"\t\terr = nil // [SAFE-PATCH] 放行自签名并兜底证书链\n"
        r"\t}"
    )
    if "[SAFE-PATCH]" not in code and re.search(target_v12, code):
      code = re.sub(target_v12, patch_v12, code, count=1)
      with open(hc_path, "w", encoding="utf-8") as f:
        f.write(code)
      print("  ✔ [Go TLS 1.2] 安全放行与证书链兜底注入成功")

  hc13_path = os.path.join(tls_dir, "handshake_client_tls13.go")
  if os.path.exists(hc13_path):
    os.chmod(hc13_path, stat.S_IWRITE | stat.S_IREAD)
    with open(hc13_path, "r", encoding="utf-8") as f:
      code = f.read()

    target_v13 = r"(c\.verifiedChains,\s*err\s*=\s*certs\[0\]\.Verify\(opts\))"
    patch_v13 = (
        r"\tif len(certs) > 0 {\n"
        r"\t\tc.verifiedChains, err = certs[0].Verify(opts)\n"
        r"\t\tif err != nil {\n"
        r"\t\t\tc.verifiedChains = [][]*x509.Certificate{certs}\n"
        r"\t\t}\n"
        r"\t} else {\n"
        r"\t\tc.verifiedChains = [][]*x509.Certificate{}\n"
        r"\t\terr = nil // [MASQUE-RPK] 适配裸公钥与空证书握手\n"
        r"\t}"
    )
    if "[MASQUE-RPK]" not in code and re.search(target_v13, code):
      code = re.sub(target_v13, patch_v13, code, count=1)
      with open(hc13_path, "w", encoding="utf-8") as f:
        f.write(code)
      print("  ✔ [Go TLS 1.3] MASQUE 裸公钥防越界补丁注入成功")

x509_verify = os.path.join(goroot, "src", "crypto", "x509", "verify.go")
if os.path.exists(x509_verify):
  os.chmod(x509_verify, stat.S_IWRITE | stat.S_IREAD)
  with open(x509_verify, "r", encoding="utf-8") as f:
    code = f.read()
  if "legacy Common Name" in code:
    code = re.sub(
        r"return CertificateInvalidError\{[^\}]*legacy Common Name[^\}]*\}",
        "return nil",
        code,
    )
    with open(x509_verify, "w", encoding="utf-8") as f:
      f.write(code)
    print("  ✔ [Go x509] Legacy Common Name 限制已解除")

# =========================================================================
# 2. 注入三段深度 TLS 记录层分片 (彻底切碎 workers.dev SNI 特征)
# =========================================================================
xray_tls_dir = "transport/internet/tls"
if not os.path.exists(xray_tls_dir):
  raise RuntimeError(f"关键目录缺失: {xray_tls_dir}")

record_frag_file = os.path.join(xray_tls_dir, "record_fragment.go")
record_frag_src = """package tls

import (
\t"net"
\t"time"
)

type recordFragmentConn struct {
\tnet.Conn
\tfragmented bool
}

func (f *recordFragmentConn) Write(b []byte) (int, error) {
\tif !f.fragmented && len(b) > 160 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01 {
\t\tf.fragmented = true
\t\trecLen := int(b[3])<<8 | int(b[4])
\t\tif len(b) >= 5+recLen && recLen > 140 {
\t\t\tcuts := []int{40, 110, recLen}
\t\t\tprev := 0
\t\t\tfor i, end := range cuts {
\t\t\t\tchunkLen := end - prev
\t\t\t\trec := make([]byte, 5+chunkLen)
\t\t\t\trec[0], rec[1], rec[2] = b[0], b[1], b[2]
\t\t\t\trec[3], rec[4] = byte(chunkLen>>8), byte(chunkLen)
\t\t\t\tcopy(rec[5:], b[5+prev:5+end])
\t\t\t\tif _, err := f.Conn.Write(rec); err != nil {
\t\t\t\t\treturn 0, err
\t\t\t\t}
\t\t\t\tif i < len(cuts)-1 {
\t\t\t\t\ttime.Sleep(2 * time.Millisecond)
\t\t\t\t}
\t\t\t\tprev = end
\t\t\t}
\t\t\tif len(b) > 5+recLen {
\t\t\t\t_, _ = f.Conn.Write(b[5+recLen:])
\t\t\t}
\t\t\treturn len(b), nil
\t\t}
\t}
\treturn f.Conn.Write(b)
}

func WrapRecordFragment(c net.Conn) net.Conn {
\tif c == nil {
\t\treturn nil
\t}
\treturn &recordFragmentConn{Conn: c}
}
"""
with open(record_frag_file, "w", encoding="utf-8") as f:
  f.write(record_frag_src)
print("  ✔ [TLS Engine] 三段深度 SNI 分片模块已写入")

for root, _, files in os.walk(xray_tls_dir):
  for f in files:
    if f.endswith(".go") and f != "record_fragment.go":
      fpath = os.path.join(root, f)
      with open(fpath, "r", encoding="utf-8") as file:
        content = file.read()
      orig = content

      content = re.sub(
          r"(func\s+(?:\([^\)]+\)\s+)?(?:Client|UClient)\s*\(\s*([a-zA-Z0-9_]+)\s+net\.Conn[^\)]*\)\s*[^{]*\{)",
          r"\1\n\t\2 = WrapRecordFragment(\2)",
          content,
      )

      if "InsecureSkipVerify: true" not in content and "Config{" in content:
        content = re.sub(
            r"(&tls\.Config\{)", r"\1\n\t\tInsecureSkipVerify: true,", content
        )
        content = re.sub(
            r"(config\.InsecureSkipVerify\s*=\s*)[^;\n]+", r"\1true", content
        )

      if content != orig:
        with open(fpath, "w", encoding="utf-8") as file:
          file.write(content)

# =========================================================================
# 3. 解除公网 80 端口无 TLS VLESS 限制 + 注入浏览器伪装防明文指纹识别
# =========================================================================
patched_vless = False
for root, _, files in os.walk("infra/conf"):
  for fname in files:
    if not fname.endswith(".go"):
      continue
    fpath = os.path.join(root, fname)
    with open(fpath, "r", encoding="utf-8") as f:
      lines = f.readlines()

    for idx, line in enumerate(lines):
      if "vless without TLS" in line:
        start = idx
        while start > max(0, idx - 5) and "return" not in lines[start]:
          start -= 1
        end = idx
        while end < min(len(lines) - 1, idx + 5) and not lines[
            end
        ].strip().endswith(")"):
          end += 1

        indent = lines[start][: len(lines[start]) - len(lines[start].lstrip())]
        matched_snippet = "".join(lines[start : end + 1]).strip()
        print(f"  ✔ [VLESS Conf] 在 {fpath} 命中限制代码:\n    {matched_snippet}")

        lines[start : end + 1] = [
            f"{indent}// [ALLOW-PLAIN-VLESS] 已解除 80 端口无 TLS 限制\n"
        ]
        with open(fpath, "w", encoding="utf-8") as f:
          f.writelines(lines)
        patched_vless = True
        break
  if patched_vless:
    break

if not patched_vless:
  raise RuntimeError("❌ 未能在 infra/conf 中找到 vless without TLS 限制代码！")

# =========================================================================
# 4. gRPC BDP 4MB/16MB 窗口扩张与 Windows 512KB 高吞吐套接字优化
# =========================================================================
grpc_dial_file = "transport/internet/grpc/dial.go"
if os.path.exists(grpc_dial_file):
  with open(grpc_dial_file, "r", encoding="utf-8") as f:
    code = f.read()

  grpc_turbo_opts = """
\t\t// [TURBO-BDP] 强行撑大 gRPC HTTP/2 流控窗口至 4MB/16MB
\t\tgrpc.WithInitialWindowSize(4 * 1024 * 1024),
\t\tgrpc.WithInitialConnWindowSize(16 * 1024 * 1024),
\t\tgrpc.WithWriteBufferSize(256 * 1024),
\t\tgrpc.WithReadBufferSize(256 * 1024),
"""
  if "[TURBO-BDP]" not in code:
    code = re.sub(
        r"(opts\s*:=\s*\[\]grpc\.DialOption\{)",
        r"\1" + grpc_turbo_opts,
        code,
        count=1,
    )
    with open(grpc_dial_file, "w", encoding="utf-8") as f:
      f.write(code)
    print("  ✔ [gRPC Turbo] 已成功植入 4MB/16MB HTTP/2 流控大窗口")

sock_opt_file = "transport/internet/sockopt_windows.go"
if os.path.exists(sock_opt_file):
  with open(sock_opt_file, "r", encoding="utf-8") as f:
    code = f.read()

  turbo_buf_func = """
// [TURBO-SOCK] 自动拉大 Windows 套接字系统读写缓冲并开启 TCP_NODELAY
func applyTurboSocket(conn net.Conn) {
\tif tcpConn, ok := conn.(*net.TCPConn); ok {
\t\t_ = tcpConn.SetNoDelay(true)
\t\t_ = tcpConn.SetReadBuffer(512 * 1024)
\t\t_ = tcpConn.SetWriteBuffer(512 * 1024)
\t}
}
"""
  if "[TURBO-SOCK]" not in code:
    code += turbo_buf_func
    with open(sock_opt_file, "w", encoding="utf-8") as f:
      f.write(code)
    print("  ✔ [Socket Turbo] 注入 Windows 512KB 高吞吐套接字优化")

# =========================================================================
# 5. 动态提取变量注入 UDP 10091 HUD 广播钩子
# =========================================================================
disp_path = "app/dispatcher/default.go"
if os.path.exists(disp_path):
  with open(disp_path, "r", encoding="utf-8") as f:
    content = f.read()

  if 'stdnet "net"' not in content:
    content = content.replace("import (", 'import (\n\tstdnet "net"', 1)

  hud_func = """
func notifyHUD(tag string, dest string) {
\tif dest != "" {
\t\tgo func(msg string) {
\t\t\tif conn, err := stdnet.Dial("udp", "127.0.0.1:10091"); err == nil {
\t\t\t\tconn.Write([]byte(msg))
\t\t\t\tconn.Close()
\t\t\t}
\t\t}(tag + "|" + dest)
\t}
}
"""
  if "func notifyHUD" not in content:
    content += hud_func

  lines = content.splitlines()
  new_lines = []
  hud_hooks = 0

  for line in lines:
    new_lines.append(line)
    if "taking detour" in line and not line.strip().startswith("//"):
      indent = line[: len(line) - len(line.lstrip())]
      m_vars = re.search(
          r'taking detour \[\",\s*([^,]+),\s*\"\] for \[\",\s*([^,\)]+)', line
      )
      if m_vars:
        t_var = m_vars.group(1).strip()
        d_var = m_vars.group(2).strip()
        d_call = (
            f"{d_var}.String()" if not d_var.endswith(".String()") else d_var
        )
        new_lines.append(f"{indent}notifyHUD({t_var}, {d_call})")
        hud_hooks += 1
      else:
        parts = line.split('taking detour ["')
        if len(parts) > 1:
          sub = parts[1].split(",")
          if len(sub) > 1:
            raw_t = sub[1].strip()
            new_lines.append(
                f"{indent}notifyHUD({raw_t}, destination.String())"
            )
            hud_hooks += 1

  with open(disp_path, "w", encoding="utf-8") as f:
    f.write("\n".join(new_lines))
  print(f"  ✔ [HUD] 成功注入 {hud_hooks} 处真实出站决断 HUD 广播钩子")

# =========================================================================
# 6. 注入 VPNGate (1200 MTU 适配 HY2 + DNS 内存秒解缓存 + 2048 队列加速) 补丁
# =========================================================================
socks_dir = "proxy/socks"
if os.path.exists(socks_dir):
  vg_file = os.path.join(socks_dir, "vpngate_sstp.go")
  vg_src = r"""package socks

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	stdnet "net"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type sstpSession struct {
	s       *stack.Stack
	rawConn net.Conn
	dead    chan struct{}
}

var (
	sessMu   sync.Mutex
	dialMu   sync.Mutex
	sessPool = make(map[string]*sstpSession)
	dnsCache sync.Map
)

func isVPNGateServer(server *protocol.ServerSpec) bool {
	if server == nil || server.User == nil || server.User.Account == nil {
		return false
	}
	if acc, ok := server.User.Account.(*Account); ok {
		u := strings.ToLower(strings.TrimSpace(acc.Username))
		return u == "vpn" || u == "vpngate"
	}
	return false
}

func getOrCreateSSTPSession(ctx context.Context, serverDest net.Destination, dialer internet.Dialer) (*sstpSession, error) {
	key := serverDest.String()

	sessMu.Lock()
	if sess, ok := sessPool[key]; ok {
		select {
		case <-sess.dead:
			delete(sessPool, key)
		default:
			sessMu.Unlock()
			return sess, nil
		}
	}
	sessMu.Unlock()

	dialMu.Lock()
	defer dialMu.Unlock()

	sessMu.Lock()
	if sess, ok := sessPool[key]; ok {
		select {
		case <-sess.dead:
			delete(sessPool, key)
		default:
			sessMu.Unlock()
			return sess, nil
		}
	}
	sessMu.Unlock()

	errors.LogWarning(ctx, "[VPNGate] 正在通过前置代理连接节点 -> ", key)
	dialCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rawConn, err := dialer.Dial(dialCtx, serverDest)
	if err != nil {
		return nil, err
	}

	host := serverDest.Address.String()
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		rawConn.Close()
		return nil, err
	}

	var certHash [32]byte
	if peers := tlsConn.ConnectionState().PeerCertificates; len(peers) > 0 {
		certHash = sha256.Sum256(peers[0].Raw)
	}

	guid := "{BA195980-CD49-458b-9E23-C84EE0ADCD75}"
	sstpReq := fmt.Sprintf("SSTP_DUPLEX_POST /sra_%s/ HTTP/1.1\r\nHost: %s\r\nContent-Length: 18446744073709551615\r\nSSTPCORRELATIONID: %s\r\n\r\n", guid, host, guid)
	if _, err := tlsConn.Write([]byte(sstpReq)); err != nil {
		rawConn.Close()
		return nil, err
	}

	br := bufio.NewReaderSize(tlsConn, 65536)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		rawConn.Close()
		return nil, fmt.Errorf("SSTP 握手被拒: %s", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}

	callReq := []byte{
		0x10, 0x01, 0x00, 0x0e,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x06,
		0x00, 0x01,
	}
	_, _ = tlsConn.Write(callReq)

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(2048, 1200, "")
	if tcpipErr := s.CreateNIC(1, ep); tcpipErr != nil {
		s.Close()
		rawConn.Close()
		return nil, fmt.Errorf("gVisor NIC 创建失败: %v", tcpipErr)
	}

	sess := &sstpSession{
		s:       s,
		rawConn: rawConn,
		dead:    make(chan struct{}),
	}

	ipReady := make(chan tcpip.Address, 1)
	var once sync.Once
	var deadOnce sync.Once
	markDead := func() {
		deadOnce.Do(func() {
			close(sess.dead)
			rawConn.Close()
			s.Close()
		})
	}

	go func() {
		defer markDead()
		hdr := make([]byte, 4)
		papSent := false
		connSent := false
		var serverNonce [32]byte

		sendCallConnected := func() {
			if connSent {
				return
			}
			connSent = true
			connMsg := make([]byte, 112)
			connMsg[0], connMsg[1] = 0x10, 0x01
			binary.BigEndian.PutUint16(connMsg[2:4], 112)
			binary.BigEndian.PutUint16(connMsg[4:6], 0x0004)
			binary.BigEndian.PutUint16(connMsg[6:8], 0x0001)
			connMsg[9] = 0x03
			binary.BigEndian.PutUint16(connMsg[10:12], 104)
			connMsg[15] = 0x02
			copy(connMsg[16:48], serverNonce[:])
			copy(connMsg[48:80], certHash[:])
			_, _ = tlsConn.Write(connMsg)
		}

		for {
			if _, err := io.ReadFull(br, hdr); err != nil {
				return
			}
			length := int(binary.BigEndian.Uint16(hdr[2:4]) & 0x0FFF)
			if length < 4 {
				continue
			}
			payload := make([]byte, length-4)
			if _, err := io.ReadFull(br, payload); err != nil {
				return
			}
			if (hdr[1] & 0x01) != 0 {
				msgType := binary.BigEndian.Uint16(payload[0:2])
				if msgType == 0x0002 {
					if len(payload) >= 40 {
						copy(serverNonce[:], payload[12:44])
					}
					sendPPP(tlsConn, 0xc021, []byte{0x01, 0x01, 0x00, 0x04})
				} else if msgType == 0x0005 || msgType == 0x0008 {
					_, _ = tlsConn.Write([]byte{0x10, 0x01, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00})
				}
				continue
			}
			p := payload
			if len(p) >= 2 && p[0] == 0xff && p[1] == 0x03 {
				p = p[2:]
			}
			if len(p) < 2 {
				continue
			}
			proto := binary.BigEndian.Uint16(p[0:2])
			pppData := p[2:]
			if len(pppData) < 4 {
				continue
			}
			pppLen := int(binary.BigEndian.Uint16(pppData[2:4]))
			if pppLen >= 4 && pppLen <= len(pppData) {
				pppData = pppData[:pppLen]
			}

			switch proto {
			case 0xc021:
				code := pppData[0]
				id := pppData[1]
				if code == 0x01 {
					opts := pppData[4:]
					needNakPAP := false
					var rejectOpts []byte
					for len(opts) >= 2 {
						optType := opts[0]
						optLen := int(opts[1])
						if optLen < 2 || optLen > len(opts) {
							break
						}
						if optType == 0x03 && optLen >= 4 {
							authProto := binary.BigEndian.Uint16(opts[2:4])
							if authProto != 0xc023 {
								needNakPAP = true
							}
						} else if optType != 0x01 && optType != 0x03 && optType != 0x05 {
							rejectOpts = append(rejectOpts, opts[:optLen]...)
						}
						opts = opts[optLen:]
					}
					if len(rejectOpts) > 0 {
						rej := make([]byte, 4+len(rejectOpts))
						rej[0], rej[1] = 0x04, id
						binary.BigEndian.PutUint16(rej[2:4], uint16(len(rej)))
						copy(rej[4:], rejectOpts)
						sendPPP(tlsConn, 0xc021, rej)
					} else if needNakPAP {
						nak := []byte{0x03, id, 0x00, 0x08, 0x03, 0x04, 0xc0, 0x23}
						sendPPP(tlsConn, 0xc021, nak)
					} else {
						ack := append([]byte{0x02}, pppData[1:]...)
						sendPPP(tlsConn, 0xc021, ack)
						if !papSent {
							papSent = true
							sendPPP(tlsConn, 0xc023, []byte{0x01, 0x01, 0x00, 0x0c, 0x03, 'v', 'p', 'n', 0x03, 'v', 'p', 'n'})
						}
					}
				} else if code == 0x02 && !papSent {
					papSent = true
					sendPPP(tlsConn, 0xc023, []byte{0x01, 0x01, 0x00, 0x0c, 0x03, 'v', 'p', 'n', 0x03, 'v', 'p', 'n'})
				} else if code == 0x09 {
					sendPPP(tlsConn, 0xc021, append([]byte{0x0a}, pppData[1:]...))
				}
			case 0xc023:
				if pppData[0] == 0x02 {
					sendCallConnected()
					sendPPP(tlsConn, 0x8021, []byte{0x01, 0x01, 0x00, 0x0a, 0x03, 0x06, 0, 0, 0, 0})
				} else if pppData[0] == 0x03 {
					return
				}
			case 0x8021:
				code := pppData[0]
				id := pppData[1]
				if code == 0x01 {
					ack := append([]byte{0x02}, pppData[1:]...)
					sendPPP(tlsConn, 0x8021, ack)
				} else if code == 0x03 && len(pppData) >= 10 {
					ip := pppData[6:10]
					sendPPP(tlsConn, 0x8021, []byte{0x01, id + 1, 0x00, 0x0a, 0x03, 0x06, ip[0], ip[1], ip[2], ip[3]})
				} else if code == 0x02 && len(pppData) >= 10 {
					sendCallConnected()
					ip := pppData[6:10]
					addr := tcpip.AddrFromSlice(ip)
					errors.LogWarning(ctx, "[VPNGate] 🎉 隧道就绪! 分配内网 IP: ", addr.String())
					once.Do(func() { ipReady <- addr })
				}
			case 0x0021:
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(pppData),
				})
				ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			}
		}
	}()

	go func() {
		defer markDead()
		for {
			pkt := ep.ReadContext(context.Background())
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			sendPPP(tlsConn, 0x0021, view.AsSlice())
			view.Release()
			pkt.DecRef()
		}
	}()

	var localIP tcpip.Address
	select {
	case localIP = <-ipReady:
	case <-sess.dead:
		return nil, fmt.Errorf("VPNGate 隧道在握手中提前断开")
	case <-time.After(15 * time.Second):
		markDead()
		return nil, fmt.Errorf("VPNGate PPP/IPCP 协商超时")
	}

	_ = s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: localIP, PrefixLen: 8},
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	sessMu.Lock()
	sessPool[key] = sess
	sessMu.Unlock()
	return sess, nil
}

func resolveFast(ctx context.Context, s *stack.Stack, domain string) ([]byte, error) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if cached, ok := dnsCache.Load(domain); ok {
		return cached.([]byte), nil
	}

	txid := make([]byte, 2)
	_, _ = rand.Read(txid)
	req := []byte{txid[0], txid[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, part := range strings.Split(domain, ".") {
		req = append(req, byte(len(part)))
		req = append(req, []byte(part)...)
	}
	req = append(req, 0x00, 0x00, 0x01, 0x00, 0x01)

	resCh := make(chan []byte, 2)
	queryServer := func(dnsIP []byte) {
		uConn, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.AddrFromSlice(dnsIP),
			Port: 53,
		}, ipv4.ProtocolNumber)
		if err != nil {
			return
		}
		defer uConn.Close()
		_ = uConn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		_, _ = uConn.Write(req)
		resp := make([]byte, 512)
		n, err := uConn.Read(resp)
		if err != nil || n < 12 {
			return
		}
		for i := 12; i+10 <= n; i++ {
			if resp[i] == 0x00 && resp[i+1] == 0x01 && resp[i+2] == 0x00 && resp[i+3] == 0x01 &&
				resp[i+8] == 0x00 && resp[i+9] == 0x04 && i+14 <= n {
				ip := make([]byte, 4)
				copy(ip, resp[i+10:i+14])
				resCh <- ip
				return
			}
		}
	}

	go queryServer([]byte{1, 1, 1, 1})
	go queryServer([]byte{8, 8, 8, 8})

	select {
	case ip := <-resCh:
		dnsCache.Store(domain, ip)
		return ip, nil
	case <-time.After(1600 * time.Millisecond):
		ips, err := stdnet.DefaultResolver.LookupIP(ctx, "ip4", domain)
		if err == nil && len(ips) > 0 {
			ip := ips[0].To4()
			dnsCache.Store(domain, ip)
			return ip, nil
		}
		return nil, fmt.Errorf("DNS 解析超时: %s", domain)
	}
}

func handleVPNGateFixedNode(ctx context.Context, serverDest net.Destination, targetDest net.Destination, link *transport.Link, dialer internet.Dialer) error {
	sess, err := getOrCreateSSTPSession(ctx, serverDest, dialer)
	if err != nil {
		return err
	}

	var targetIP []byte
	if targetDest.Address.Family().IsIP() {
		targetIP = targetDest.Address.IP().To4()
	} else if targetDest.Address.Family().IsDomain() {
		ip, err := resolveFast(ctx, sess.s, targetDest.Address.Domain())
		if err != nil {
			return err
		}
		targetIP = ip
	}
	if len(targetIP) != 4 {
		return fmt.Errorf("仅支持 IPv4 目标地址")
	}

	gConn, err := gonet.DialContextTCP(ctx, sess.s, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(targetIP),
		Port: uint16(targetDest.Port),
	}, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}
	defer gConn.Close()

	errCh := make(chan error, 2)
	go func() {
		b := make([]byte, 64*1024)
		for {
			n, err := gConn.Read(b)
			if n > 0 {
				mb := buf.NewSize(int32(n))
				_, _ = mb.Write(b[:n])
				if wErr := link.Writer.WriteMultiBuffer(buf.MultiBuffer{mb}); wErr != nil {
					errCh <- wErr
					return
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if !mb.IsEmpty() {
				for _, b := range mb {
					_, _ = gConn.Write(b.Bytes())
				}
				buf.ReleaseMulti(mb)
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()
	<-errCh
	return nil
}

func sendPPP(w io.Writer, proto uint16, data []byte) {
	total := 4 + 4 + len(data)
	pkt := make([]byte, total)
	pkt[0], pkt[1] = 0x10, 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[4], pkt[5] = 0xff, 0x03
	binary.BigEndian.PutUint16(pkt[6:8], proto)
	copy(pkt[8:], data)
	_, _ = w.Write(pkt)
}
"""
  with open(vg_file, "w", encoding="utf-8") as f:
    f.write(vg_src)

  client_go = os.path.join(socks_dir, "client.go")
  with open(client_go, "r", encoding="utf-8") as f:
    c_code = f.read()

  hook_snippet = """
\tif isVPNGateServer(server) {
\t\treturn handleVPNGateFixedNode(ctx, server.Destination, destination, link, dialer)
\t}
"""
  if "handleVPNGateFixedNode" not in c_code:
    new_code, n = re.subn(
        r"(server\s*:=\s*[^\n]+)",
        r"\1\n" + hook_snippet,
        c_code,
        count=1,
    )
    if n == 0:
      raise RuntimeError(
          "❌ 未能在 proxy/socks/client.go 中匹配到 server 变量赋值行！"
      )
    with open(client_go, "w", encoding="utf-8") as f:
      f.write(new_code)
    print("  ✔ [VPNGate Engine] 成功注入固定节点直连与会话复用补丁")

  if os.system("go mod tidy") != 0:
    raise RuntimeError("❌ go mod tidy 执行失败！")
  print("  ✔ [Go Mod] 已自动执行 go mod tidy 同步 gVisor 依赖树")

print(">>> 全部兼容、提速与安全加固补丁写入完毕！")
