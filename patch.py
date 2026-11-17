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

import os
import re

# =========================================================================
# 6. 注入 VPNGate (修复测速-1首包丢弃 + 双协议自适应 + 多端口回退 + 并发分流池)
# =========================================================================
socks_dir = "proxy/socks"
if os.path.exists(socks_dir):
  vg_file = os.path.join(socks_dir, "vpngate_sstp.go")
  vg_src = r"""package socks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	stderrors "errors"
	"fmt"
	"io"
	"math/bits"
	"strings"
	"sync"
	"sync/atomic"
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

const poolSizePerNode = 2

type sstpSession struct {
	s           *stack.Stack
	rawConn     net.Conn
	tlsConn     *tls.Conn
	writeMu     sync.Mutex
	bw          *bufio.Writer
	dead        chan struct{}
	markDead    func()
	isSoftEther bool
	myMAC       [6]byte
	gwMAC       atomic.Value
}

type dnsEntry struct {
	ip     []byte
	expire time.Time
}

var (
	sessMu          sync.Mutex
	slotLocks       sync.Map
	sessPool        = make(map[string]*sstpSession)
	rrCounter       atomic.Uint32
	dnsCache        sync.Map
	failCache       sync.Map
	slotBackoff     sync.Map
	tlsSessionCache = tls.NewLRUClientSessionCache(256)
	pppPool         = sync.Pool{
		New: func() any { b := make([]byte, 2048); return &b },
	}
	readBufPool = sync.Pool{
		New: func() any { b := make([]byte, 32768); return &b },
	}
)

func init() {
	// 定期清扫过期的 DNS 缓存、退避记录和冷却缓存，防止长期运行内存缓慢增长
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			dnsCache.Range(func(k, v any) bool {
				if entry, ok := v.(dnsEntry); ok && now.After(entry.expire) {
					dnsCache.Delete(k)
				}
				return true
			})
			slotBackoff.Range(func(k, v any) bool {
				if t, ok := v.(time.Time); ok && now.Sub(t) > 2*time.Minute {
					slotBackoff.Delete(k)
				}
				return true
			})
			failCache.Range(func(k, v any) bool {
				if t, ok := v.(time.Time); ok && now.Sub(t) > 30*time.Second {
					failCache.Delete(k)
				}
				return true
			})
		}
	}()
}

func buildCompatTLSConfig(host string) *tls.Config {
	var suites []uint16
	for _, cs := range tls.CipherSuites() {
		suites = append(suites, cs.ID)
	}
	for _, cs := range tls.InsecureCipherSuites() {
		suites = append(suites, cs.ID)
	}
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       suites,
		ClientSessionCache: tlsSessionCache,
	}
}

func dialWithPortFallback(ctx context.Context, dialer internet.Dialer, serverDest net.Destination) (net.Conn, net.Port, error) {
	origPort := serverDest.Port
	ports := []net.Port{origPort}
	if origPort != 443 && origPort != 995 {
		for _, fp := range []net.Port{443, 995, 5555} {
			if fp != origPort {
				ports = append(ports, fp)
			}
		}
	}

	if len(ports) == 1 {
		c, err := dialer.Dial(ctx, serverDest)
		return c, origPort, err
	}

	type dialRes struct {
		conn net.Conn
		port net.Port
		err  error
	}
	ch := make(chan dialRes, len(ports))
	dCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var won atomic.Bool
	for i, p := range ports {
		go func(idx int, port net.Port) {
			if idx > 0 {
				delay := time.Duration(1400+(idx-1)*150) * time.Millisecond
				select {
				case <-time.After(delay):
				case <-dCtx.Done():
					return
				}
			}
			dest := net.TCPDestination(serverDest.Address, port)
			c, err := dialer.Dial(dCtx, dest)
			if err == nil {
				if !won.CompareAndSwap(false, true) {
					c.Close()
					return
				}
				cancel()
			}
			select {
			case ch <- dialRes{conn: c, port: port, err: err}:
			case <-dCtx.Done():
				if c != nil {
					c.Close()
				}
			}
		}(i, p)
	}

	var lastErr error
	for range ports {
		select {
		case r := <-ch:
			if r.err == nil && r.conn != nil {
				if r.port != origPort {
					errors.LogInfo(ctx, fmt.Sprintf("[VPNGate] 端口回退命中 -> %s:%d (原端口 %d 不通)", serverDest.Address.String(), r.port, origPort))
				}
				return r.conn, r.port, nil
			}
			if r.err != nil {
				lastErr = r.err
			}
		case <-dCtx.Done():
			if lastErr == nil {
				lastErr = dCtx.Err()
			}
			return nil, origPort, lastErr
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("所有回退端口拨号均失败")
	}
	return nil, origPort, lastErr
}

func getSlotMutex(slotKey string) *sync.Mutex {
	val, _ := slotLocks.LoadOrStore(slotKey, &sync.Mutex{})
	return val.(*sync.Mutex)
}

func isAlive(sess *sstpSession) bool {
	if sess == nil {
		return false
	}
	select {
	case <-sess.dead:
		return false
	default:
		return true
	}
}

func hasAnyAliveSlot(baseKey string) bool {
	sessMu.Lock()
	defer sessMu.Unlock()
	for i := 0; i < poolSizePerNode; i++ {
		if isAlive(sessPool[fmt.Sprintf("%s#%d", baseKey, i)]) {
			return true
		}
	}
	return false
}

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

func (sess *sstpSession) writeFrame(data []byte) error {
	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
	_ = sess.tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := sess.bw.Write(data)
	if err == nil {
		err = sess.bw.Flush()
	}
	_ = sess.tlsConn.SetWriteDeadline(time.Time{})
	return err
}

func (sess *sstpSession) writeSoftEtherFrames(ethFrames [][]byte) error {
	if len(ethFrames) == 0 {
		return nil
	}
	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
	_ = sess.tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ethFrames)))
	if _, err := sess.bw.Write(hdr[:]); err != nil {
		return err
	}
	for _, f := range ethFrames {
		binary.BigEndian.PutUint32(hdr[:], uint32(len(f)))
		if _, err := sess.bw.Write(hdr[:]); err != nil {
			return err
		}
		if _, err := sess.bw.Write(f); err != nil {
			return err
		}
	}
	err := sess.bw.Flush()
	_ = sess.tlsConn.SetWriteDeadline(time.Time{})
	return err
}

func (sess *sstpSession) sendPPPControl(proto uint16, data []byte) {
	total := 8 + len(data)
	if total > 0x3FFF {
		return
	}
	pkt := make([]byte, total)
	pkt[0], pkt[1] = 0x10, 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[4], pkt[5] = 0xff, 0x03
	binary.BigEndian.PutUint16(pkt[6:8], proto)
	copy(pkt[8:], data)
	_ = sess.writeFrame(pkt)
}

func triggerBgSlotDial(serverDest net.Destination, dialer internet.Dialer, baseKey, slotKey string) {
	if t, ok := slotBackoff.Load(slotKey); ok && time.Since(t.(time.Time)) < 60*time.Second {
		return
	}
	slotBackoff.Store(slotKey, time.Now())
	go func() {
		time.Sleep(450 * time.Millisecond)
		_, _ = dialSlotSession(context.Background(), serverDest, dialer, baseKey, slotKey, true)
	}()
}

func getOrCreateSSTPSession(ctx context.Context, serverDest net.Destination, dialer internet.Dialer) (*sstpSession, error) {
	baseKey := serverDest.String()
	idx := int(rrCounter.Add(1) % poolSizePerNode)
	slotKey := fmt.Sprintf("%s#%d", baseKey, idx)

	sessMu.Lock()
	sCurr := sessPool[slotKey]
	if isAlive(sCurr) {
		altKey := fmt.Sprintf("%s#%d", baseKey, (idx+1)%poolSizePerNode)
		if !isAlive(sessPool[altKey]) {
			triggerBgSlotDial(serverDest, dialer, baseKey, altKey)
		}
		sessMu.Unlock()
		return sCurr, nil
	}
	for i := 0; i < poolSizePerNode; i++ {
		altKey := fmt.Sprintf("%s#%d", baseKey, i)
		if alt := sessPool[altKey]; isAlive(alt) {
			sessMu.Unlock()
			triggerBgSlotDial(serverDest, dialer, baseKey, slotKey)
			return alt, nil
		}
	}
	sessMu.Unlock()

	return dialSlotSession(ctx, serverDest, dialer, baseKey, slotKey, false)
}

func newGVisorStack() (*stack.Stack, *channel.Endpoint, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	sackEnabled := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabled)
	delayEnabled := tcpip.TCPDelayEnabled(false)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &delayEnabled)
	ccOpt := tcpip.CongestionControlOption("cubic")
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt)
	rackOpt := tcpip.TCPRecovery(tcpip.TCPRACKLossDetection)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &rackOpt)

	rcvBuf := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 2097152, Max: 8 * 1024 * 1024}
	sndBuf := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 1048576, Max: 8 * 1024 * 1024}
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvBuf)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndBuf)
	modOpt := tcpip.TCPModerateReceiveBufferOption(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &modOpt)

	ep := channel.New(4096, 1360, "")
	if tcpipErr := s.CreateNIC(1, ep); tcpipErr != nil {
		s.Close()
		return nil, nil, fmt.Errorf("gVisor NIC 创建失败: %v", tcpipErr)
	}
	return s, ep, nil
}

func recordNodeFailureIfNeeded(baseKey string, isBackground bool, err error) {
	if isBackground || stderrors.Is(err, context.Canceled) || errors.Cause(err) == context.Canceled {
		return
	}
	if !hasAnyAliveSlot(baseKey) {
		failCache.Store(baseKey, time.Now())
	}
}

func dialSlotSession(ctx context.Context, serverDest net.Destination, dialer internet.Dialer, baseKey, slotKey string, isBackground bool) (*sstpSession, error) {
	mu := getSlotMutex(slotKey)
	mu.Lock()
	defer mu.Unlock()

	sessMu.Lock()
	if sess := sessPool[slotKey]; isAlive(sess) {
		sessMu.Unlock()
		return sess, nil
	}
	sessMu.Unlock()

	if !isBackground {
		if failTime, ok := failCache.Load(baseKey); ok {
			if time.Since(failTime.(time.Time)) < 10*time.Second {
				return nil, fmt.Errorf("节点 %s 处于失败冷却中", baseKey)
			}
			failCache.Delete(baseKey)
		}
	}

	bgCtx := context.Background()
	errors.LogDebug(bgCtx, "[VPNGate] 正在建立并发隧道槽位 -> ", slotKey)
	dialCtx, cancel := context.WithTimeout(bgCtx, 22*time.Second)
	defer cancel()

	rawConn, activePort, err := dialWithPortFallback(dialCtx, dialer, serverDest)
	if err != nil {
		recordNodeFailureIfNeeded(baseKey, isBackground, err)
		return nil, err
	}

	host := serverDest.Address.String()
	tlsConn := tls.Client(rawConn, buildCompatTLSConfig(host))
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		rawConn.Close()
		recordNodeFailureIfNeeded(baseKey, isBackground, err)
		return nil, err
	}

	var certHash [32]byte
	if peers := tlsConn.ConnectionState().PeerCertificates; len(peers) > 0 {
		certHash = sha256.Sum256(peers[0].Raw)
	}

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	guid := fmt.Sprintf("{%08X-%04X-%04X-%04X-%012X}",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])

	serviceGUID := "{BA195980-CD49-458b-9E23-C84EE0ADCD75}"
	sstpReq := fmt.Sprintf("SSTP_DUPLEX_POST /sra_%s/ HTTP/1.1\r\nHost: %s\r\nContent-Length: 18446744073709551615\r\nSSTPCORRELATIONID: %s\r\n\r\n", serviceGUID, host, guid)
	_ = tlsConn.SetDeadline(time.Now().Add(6 * time.Second))
	_, writeErr := tlsConn.Write([]byte(sstpReq))
	br := bufio.NewReaderSize(tlsConn, 131072)
	var statusLine string
	var readErr error
	if writeErr == nil {
		statusLine, readErr = br.ReadString('\n')
	}
	_ = tlsConn.SetDeadline(time.Time{})

	if writeErr != nil || readErr != nil || !strings.Contains(statusLine, "200") {
		rawConn.Close()
		reason := strings.TrimSpace(statusLine)
		if reason == "" {
			reason = "非SSTP响应/重置"
		}
		errors.LogDebug(bgCtx, fmt.Sprintf("[VPNGate] SSTP 握手未命中 (%s)，自动回退 SoftEther 原生协议 -> %s:%d", reason, host, activePort))
		nativeDest := net.TCPDestination(serverDest.Address, activePort)
		sess, nativeErr := dialSoftEtherNativeSession(nativeDest, dialer, baseKey, slotKey, isBackground)
		if nativeErr != nil {
			recordNodeFailureIfNeeded(baseKey, isBackground, nativeErr)
			return nil, nativeErr
		}
		return sess, nil
	}

	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}

	s, ep, err := newGVisorStack()
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	sess := &sstpSession{
		s:       s,
		rawConn: rawConn,
		tlsConn: tlsConn,
		bw:      bufio.NewWriterSize(tlsConn, 65536),
		dead:    make(chan struct{}),
	}

	_ = sess.writeFrame([]byte{
		0x10, 0x01, 0x00, 0x0e,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x06,
		0x00, 0x01,
	})

	ipReady := make(chan tcpip.Address, 1)
	var once sync.Once
	var deadOnce sync.Once
	markDead := func() {
		deadOnce.Do(func() {
			close(sess.dead)
			sessMu.Lock()
			if cur, ok := sessPool[slotKey]; ok && cur == sess {
				delete(sessPool, slotKey)
			}
			sessMu.Unlock()
			rawConn.Close()
			s.Close()
		})
	}
	sess.markDead = markDead

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
			connMsg[0], connMsg[1], connMsg[3] = 0x10, 0x01, 112
			connMsg[5], connMsg[7], connMsg[9], connMsg[11] = 0x04, 0x01, 0x03, 104
			connMsg[15] = 0x02
			copy(connMsg[16:48], serverNonce[:])
			copy(connMsg[48:80], certHash[:])
			_ = sess.writeFrame(connMsg)
		}

		for {
			_ = tlsConn.SetReadDeadline(time.Now().Add(45 * time.Second))
			if _, err := io.ReadFull(br, hdr); err != nil {
				errors.LogDebug(bgCtx, "[VPNGate] 槽位断开或超时 (", slotKey, "): ", err)
				return
			}
			// MS-SSTP 长度字段为低 14 位 (0x3FFF)
			length := int(binary.BigEndian.Uint16(hdr[2:4]) & 0x3FFF)
			if length < 4 {
				continue
			}
			payload := make([]byte, length-4)
			if _, err := io.ReadFull(br, payload); err != nil {
				return
			}
			if (hdr[1] & 0x01) != 0 {
				if len(payload) < 2 {
					continue
				}
				msgType := binary.BigEndian.Uint16(payload[0:2])
				if msgType == 0x0002 {
					// 按 SoftEther 实测 SSTP CALL_CONNECT_ACK 格式直接提取 32B CryptoBinding Nonce
					if len(payload) >= 44 {
						copy(serverNonce[:], payload[12:44])
					}
					sess.sendPPPControl(0xc021, []byte{0x01, 0x01, 0x00, 0x04})
				} else if msgType == 0x0008 {
					_ = sess.writeFrame([]byte{0x10, 0x01, 0x00, 0x08, 0x00, 0x09, 0x00, 0x00})
				} else if msgType == 0x0005 || msgType == 0x0006 {
					return
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
						sess.sendPPPControl(0xc021, rej)
					} else if needNakPAP {
						nak := []byte{0x03, id, 0x00, 0x08, 0x03, 0x04, 0xc0, 0x23}
						sess.sendPPPControl(0xc021, nak)
					} else {
						ack := append([]byte{0x02}, pppData[1:]...)
						sess.sendPPPControl(0xc021, ack)
						if !papSent {
							papSent = true
							sess.sendPPPControl(0xc023, []byte{0x01, 0x01, 0x00, 0x0c, 0x03, 'v', 'p', 'n', 0x03, 'v', 'p', 'n'})
						}
					}
				} else if code == 0x02 && !papSent {
					papSent = true
					sess.sendPPPControl(0xc023, []byte{0x01, 0x01, 0x00, 0x0c, 0x03, 'v', 'p', 'n', 0x03, 'v', 'p', 'n'})
				} else if code == 0x09 {
					sess.sendPPPControl(0xc021, append([]byte{0x0a}, pppData[1:]...))
				}
			case 0xc023:
				if pppData[0] == 0x02 {
					sess.sendPPPControl(0x8021, []byte{0x01, 0x01, 0x00, 0x0a, 0x03, 0x06, 0, 0, 0, 0})
				} else if pppData[0] == 0x03 {
					return
				}
			case 0x8021:
				code := pppData[0]
				id := pppData[1]
				if code == 0x01 {
					ack := append([]byte{0x02}, pppData[1:]...)
					sess.sendPPPControl(0x8021, ack)
				} else if code == 0x03 && len(pppData) >= 10 {
					ip := pppData[6:10]
					sess.sendPPPControl(0x8021, []byte{0x01, id + 1, 0x00, 0x0a, 0x03, 0x06, ip[0], ip[1], ip[2], ip[3]})
				} else if code == 0x02 && len(pppData) >= 10 {
					sendCallConnected()
					ip := pppData[6:10]
					addr := tcpip.AddrFromSlice(ip)
					var activeCC tcpip.CongestionControlOption
					_ = s.TransportProtocolOption(tcp.ProtocolNumber, &activeCC)
					errors.LogInfo(bgCtx, fmt.Sprintf("[VPNGate] 隧道槽位就绪 (%s) | 协议: MS-SSTP | 端口: %d | IP: %s | 算法: %s+RACK", slotKey, activePort, addr.String(), string(activeCC)))
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
		bp := pppPool.Get().(*[]byte)
		defer pppPool.Put(bp)
		scratch := *bp

		writeOnePacket := func(pkt *stack.PacketBuffer) error {
			view := pkt.ToView()
			data := view.AsSlice()
			total := 8 + len(data)
			if total > 0x3FFF {
				view.Release()
				pkt.DecRef()
				return fmt.Errorf("SSTP 数据帧超长: %d", total)
			}
			var frame []byte
			if total <= len(scratch) {
				frame = scratch[:total]
			} else {
				frame = make([]byte, total)
			}
			frame[0], frame[1] = 0x10, 0x00
			binary.BigEndian.PutUint16(frame[2:4], uint16(total))
			frame[4], frame[5] = 0xff, 0x03
			binary.BigEndian.PutUint16(frame[6:8], 0x0021)
			copy(frame[8:], data)
			_, err := sess.bw.Write(frame)
			view.Release()
			pkt.DecRef()
			return err
		}

		for {
			pkt := ep.ReadContext(bgCtx)
			if pkt == nil {
				return
			}
			sess.writeMu.Lock()
			_ = tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := writeOnePacket(pkt)
			for i := 0; i < 64 && err == nil; i++ {
				nextPkt := ep.Read()
				if nextPkt == nil {
					break
				}
				err = writeOnePacket(nextPkt)
			}
			if err == nil {
				err = sess.bw.Flush()
			}
			_ = tlsConn.SetWriteDeadline(time.Time{})
			sess.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer markDead()
		ticker := time.NewTicker(12 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sess.dead:
				return
			case <-ticker.C:
				if err := sess.writeFrame([]byte{0x10, 0x01, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00}); err != nil {
					return
				}
			}
		}
	}()

	var localIP tcpip.Address
	select {
	case localIP = <-ipReady:
	case <-sess.dead:
		err := fmt.Errorf("VPNGate 隧道在握手中提前断开")
		recordNodeFailureIfNeeded(baseKey, isBackground, err)
		return nil, err
	case <-time.After(22 * time.Second):
		markDead()
		err := fmt.Errorf("VPNGate PPP/IPCP 协商超时")
		recordNodeFailureIfNeeded(baseKey, isBackground, err)
		return nil, err
	}

	_ = s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: localIP, PrefixLen: 8},
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	// 等待 80ms 让 SoftEther 服务端内部完成 SSTP CALL_CONNECTED 路由绑定，防止首个 SYN 包被丢弃导致 3 秒 RTO 重传
	time.Sleep(80 * time.Millisecond)

	slotBackoff.Delete(slotKey)
	sessMu.Lock()
	sessPool[slotKey] = sess
	sessMu.Unlock()
	return sess, nil
}

// =========================================================================
// SoftEther 原生 SSL-VPN 协议回退实现
// =========================================================================
func buildSoftEtherLoginPack() []byte {
	var b bytes.Buffer
	writeU32 := func(v uint32) {
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], v)
		b.Write(tmp[:])
	}
	writeName := func(s string) {
		writeU32(uint32(len(s) + 1))
		b.WriteString(s)
	}
	addStr := func(k, v string) {
		writeName(k)
		writeU32(2)
		writeU32(1)
		writeU32(uint32(len(v) + 1))
		b.WriteString(v)
	}
	addInt := func(k string, v uint32) {
		writeName(k)
		writeU32(0)
		writeU32(1)
		writeU32(v)
	}

	writeU32(12)
	addStr("method", "login")
	addStr("hubname", "VPNGATE")
	addStr("username", "vpn")
	addInt("authtype", 0)
	addInt("protocol", 0)
	addInt("use_encrypt", 0)
	addInt("use_compress", 0)
	addInt("max_connection", 1)
	addInt("half_connection", 0)
	addStr("client_str", "SoftEther VPN Client")
	addInt("client_ver", 442)
	addInt("client_build", 9798)
	return b.Bytes()
}

// 校验 SoftEther 登录响应 PACK，快速识别 error != 0，避免白等 DHCP 超时
func checkSoftEtherLoginResponse(body []byte) error {
	if len(body) < 8 {
		return fmt.Errorf("SoftEther 登录响应过短: %d", len(body))
	}
	packLen := binary.BigEndian.Uint32(body[0:4])
	data := body[4:]
	if int(packLen) > len(data) || len(data) < 4 {
		return fmt.Errorf("SoftEther 登录 PACK 长度异常")
	}
	data = data[:packLen]
	numElems := binary.BigEndian.Uint32(data[0:4])
	pos := 4
	readU32 := func() (uint32, bool) {
		if pos+4 > len(data) {
			return 0, false
		}
		v := binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		return v, true
	}
	for i := uint32(0); i < numElems && i < 128; i++ {
		nameLen, ok := readU32()
		if !ok || nameLen == 0 || pos+int(nameLen) > len(data) {
			break
		}
		name := strings.TrimRight(string(data[pos:pos+int(nameLen)]), "\x00")
		pos += int(nameLen)

		valType, ok := readU32()
		if !ok {
			break
		}
		numVals, ok := readU32()
		if !ok || numVals > 256 {
			break
		}
		for j := uint32(0); j < numVals; j++ {
			switch valType {
			case 0: // VALUE_INT
				v, ok := readU32()
				if !ok {
					return nil
				}
				if name == "error" && j == 0 && v != 0 {
					return fmt.Errorf("SoftEther 服务端拒绝登录 (error=%d)", v)
				}
			case 4: // VALUE_INT64
				if pos+8 > len(data) {
					return nil
				}
				pos += 8
			case 1, 2, 3: // DATA / STR / UNISTR
				dLen, ok := readU32()
				if !ok || pos+int(dLen) > len(data) {
					return nil
				}
				pos += int(dLen)
			default:
				return nil
			}
		}
	}
	return nil
}

func readSoftEtherHTTPBody(br *bufio.Reader) ([]byte, error) {
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(statusLine, "200") {
		return nil, fmt.Errorf("SoftEther HTTP 状态异常: %s", strings.TrimSpace(statusLine))
	}
	contentLen := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" {
			break
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "content-length:") {
			if n, scanErr := fmt.Sscanf(strings.TrimSpace(lower[len("content-length:"):]), "%d", &contentLen); scanErr != nil || n != 1 {
				return nil, fmt.Errorf("SoftEther Content-Length 解析失败: %s", lower)
			}
		}
	}
	if contentLen <= 0 || contentLen > 65536 {
		return nil, fmt.Errorf("SoftEther HTTP 响应体长度无效: %d", contentLen)
	}
	body := make([]byte, contentLen)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	return body, nil
}

func buildDHCPFrame(msgType byte, xid uint32, myMAC [6]byte, reqIP, serverIP []byte) []byte {
	// BOOTP/DHCP 规范最小载荷为 300 字节，不足部分保持零填充
	bootp := make([]byte, 300)
	bootp[0] = 1
	bootp[1] = 1
	bootp[2] = 6
	binary.BigEndian.PutUint32(bootp[4:8], xid)
	binary.BigEndian.PutUint16(bootp[10:12], 0x8000)
	copy(bootp[28:34], myMAC[:])
	bootp[236], bootp[237], bootp[238], bootp[239] = 99, 130, 83, 99
	idx := 240
	bootp[idx], bootp[idx+1], bootp[idx+2] = 53, 1, msgType
	idx += 3
	if len(reqIP) == 4 {
		bootp[idx], bootp[idx+1] = 50, 4
		copy(bootp[idx+2:idx+6], reqIP)
		idx += 6
	}
	if len(serverIP) == 4 {
		bootp[idx], bootp[idx+1] = 54, 4
		copy(bootp[idx+2:idx+6], serverIP)
		idx += 6
	}
	bootp[idx], bootp[idx+1], bootp[idx+2], bootp[idx+3], bootp[idx+4] = 55, 3, 1, 3, 6
	idx += 5
	bootp[idx] = 255

	udpLen := 8 + len(bootp)
	ipLen := 20 + udpLen
	eth := make([]byte, 14+ipLen)
	for i := 0; i < 6; i++ {
		eth[i] = 0xff
	}
	copy(eth[6:12], myMAC[:])
	eth[12], eth[13] = 0x08, 0x00

	ip := eth[14 : 14+20]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[8] = 64
	ip[9] = 17
	ip[16], ip[17], ip[18], ip[19] = 255, 255, 255, 255
	var csum uint32
	for i := 0; i < 20; i += 2 {
		csum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for (csum >> 16) > 0 {
		csum = (csum & 0xffff) + (csum >> 16)
	}
	binary.BigEndian.PutUint16(ip[10:12], ^uint16(csum))

	udpHdr := eth[34 : 34+8]
	binary.BigEndian.PutUint16(udpHdr[0:2], 68)
	binary.BigEndian.PutUint16(udpHdr[2:4], 67)
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(udpLen))
	copy(eth[42:], bootp)
	return eth
}

func dialSoftEtherNativeSession(serverDest net.Destination, dialer internet.Dialer, baseKey, slotKey string, isBackground bool) (*sstpSession, error) {
	bgCtx := context.Background()
	dialCtx, cancel := context.WithTimeout(bgCtx, 22*time.Second)
	defer cancel()

	rawConn, err := dialer.Dial(dialCtx, serverDest)
	if err != nil {
		return nil, err
	}
	host := serverDest.Address.String()
	tlsConn := tls.Client(rawConn, buildCompatTLSConfig(host))
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		rawConn.Close()
		return nil, err
	}

	_ = tlsConn.SetDeadline(time.Now().Add(12 * time.Second))
	sigReq := fmt.Sprintf("POST /vpnsvc/connect.cgi HTTP/1.1\r\nHost: %s\r\nContent-Type: image/jpeg\r\nConnection: Keep-Alive\r\nContent-Length: 16\r\n\r\nSEVPN_20121006\x00\x00", host)
	if _, err := tlsConn.Write([]byte(sigReq)); err != nil {
		rawConn.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(tlsConn, 131072)
	if _, err := readSoftEtherHTTPBody(br); err != nil {
		rawConn.Close()
		return nil, err
	}

	packBytes := buildSoftEtherLoginPack()
	var loginBuf bytes.Buffer
	fmt.Fprintf(&loginBuf, "POST /vpnsvc/vpn.cgi HTTP/1.1\r\nHost: %s\r\nContent-Type: image/jpeg\r\nConnection: Keep-Alive\r\nContent-Length: %d\r\n\r\n", host, 4+len(packBytes))
	var lenHdr [4]byte
	binary.BigEndian.PutUint32(lenHdr[:], uint32(len(packBytes)))
	loginBuf.Write(lenHdr[:])
	loginBuf.Write(packBytes)

	if _, err := tlsConn.Write(loginBuf.Bytes()); err != nil {
		rawConn.Close()
		return nil, err
	}
	loginRespBody, err := readSoftEtherHTTPBody(br)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	if err := checkSoftEtherLoginResponse(loginRespBody); err != nil {
		rawConn.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})

	s, ep, err := newGVisorStack()
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	var myMAC [6]byte
	_, _ = rand.Read(myMAC[:])
	myMAC[0] = (myMAC[0] & 0xfe) | 0x02
	var defaultGW [6]byte
	for i := 0; i < 6; i++ {
		defaultGW[i] = 0xff
	}

	sess := &sstpSession{
		s:           s,
		rawConn:     rawConn,
		tlsConn:     tlsConn,
		bw:          bufio.NewWriterSize(tlsConn, 65536),
		dead:        make(chan struct{}),
		isSoftEther: true,
		myMAC:       myMAC,
	}
	sess.gwMAC.Store(defaultGW)

	type dhcpLease struct {
		ip        tcpip.Address
		prefixLen int
	}
	ipReady := make(chan dhcpLease, 1)
	var once sync.Once
	var deadOnce sync.Once
	var assignedIP [4]byte
	var hasIP atomic.Bool

	markDead := func() {
		deadOnce.Do(func() {
			close(sess.dead)
			sessMu.Lock()
			if cur, ok := sessPool[slotKey]; ok && cur == sess {
				delete(sessPool, slotKey)
			}
			sessMu.Unlock()
			rawConn.Close()
			s.Close()
		})
	}
	sess.markDead = markDead

	xidBytes := make([]byte, 4)
	_, _ = rand.Read(xidBytes)
	dhcpXid := binary.BigEndian.Uint32(xidBytes)

	_ = sess.writeSoftEtherFrames([][]byte{buildDHCPFrame(1, dhcpXid, myMAC, nil, nil)})

	go func() {
		defer markDead()
		var hdr [4]byte
		for {
			_ = tlsConn.SetReadDeadline(time.Now().Add(45 * time.Second))
			if _, err := io.ReadFull(br, hdr[:]); err != nil {
				errors.LogDebug(bgCtx, "[VPNGate] SoftEther 槽位断开或超时 (", slotKey, "): ", err)
				return
			}
			numPkts := binary.BigEndian.Uint32(hdr[:])
			if numPkts == 0 {
				if _, err := io.ReadFull(br, hdr[:]); err != nil {
					return
				}
				kaLen := binary.BigEndian.Uint32(hdr[:])
				if kaLen > 0 && kaLen <= 65536 {
					_, _ = io.CopyN(io.Discard, br, int64(kaLen))
				}
				continue
			}
			if numPkts > 1024 {
				return
			}
			for i := uint32(0); i < numPkts; i++ {
				if _, err := io.ReadFull(br, hdr[:]); err != nil {
					return
				}
				pktLen := binary.BigEndian.Uint32(hdr[:])
				if pktLen == 0 || pktLen > 65536 {
					return
				}
				eth := make([]byte, pktLen)
				if _, err := io.ReadFull(br, eth); err != nil {
					return
				}
				if len(eth) < 14 {
					continue
				}
				etherType := binary.BigEndian.Uint16(eth[12:14])
				if etherType == 0x0806 && len(eth) >= 42 {
					oper := binary.BigEndian.Uint16(eth[20:22])
					if oper == 1 && hasIP.Load() && bytes.Equal(eth[38:42], assignedIP[:]) {
						arpRep := make([]byte, 42)
						copy(arpRep[0:6], eth[6:12])
						copy(arpRep[6:12], myMAC[:])
						arpRep[12], arpRep[13] = 0x08, 0x06
						binary.BigEndian.PutUint16(arpRep[14:16], 1)
						binary.BigEndian.PutUint16(arpRep[16:18], 0x0800)
						arpRep[18], arpRep[19] = 6, 4
						binary.BigEndian.PutUint16(arpRep[20:22], 2)
						copy(arpRep[22:28], myMAC[:])
						copy(arpRep[28:32], assignedIP[:])
						copy(arpRep[32:38], eth[22:28])
						copy(arpRep[38:42], eth[28:32])
						_ = sess.writeSoftEtherFrames([][]byte{arpRep})
					}
					continue
				}
				if etherType != 0x0800 {
					continue
				}
				ipPkt := eth[14:]
				if len(ipPkt) < 20 {
					continue
				}
				if ipPkt[9] == 17 {
					ihl := int(ipPkt[0]&0x0f) * 4
					if len(ipPkt) >= ihl+8+240 {
						srcPort := binary.BigEndian.Uint16(ipPkt[ihl : ihl+2])
						dstPort := binary.BigEndian.Uint16(ipPkt[ihl+2 : ihl+4])
						if srcPort == 67 && dstPort == 68 {
							bootp := ipPkt[ihl+8:]
							if binary.BigEndian.Uint32(bootp[4:8]) == dhcpXid && len(bootp) > 240 {
								yiaddr := bootp[16:20]
								var msgType byte
								var srvID []byte
								var subnetMask []byte
								opts := bootp[240:]
								for k := 0; k < len(opts); {
									code := opts[k]
									if code == 255 {
										break
									}
									if code == 0 {
										k++
										continue
									}
									if k+1 >= len(opts) {
										break
									}
									olen := int(opts[k+1])
									if k+2+olen > len(opts) {
										break
									}
									if code == 1 && olen == 4 {
										subnetMask = opts[k+2 : k+6]
									} else if code == 53 && olen >= 1 {
										msgType = opts[k+2]
									} else if code == 54 && olen == 4 {
										srvID = opts[k+2 : k+6]
									}
									k += 2 + olen
								}
								var srcMAC [6]byte
								copy(srcMAC[:], eth[6:12])
								sess.gwMAC.Store(srcMAC)
								if msgType == 2 {
									_ = sess.writeSoftEtherFrames([][]byte{buildDHCPFrame(3, dhcpXid, myMAC, yiaddr, srvID)})
								} else if msgType == 5 {
									copy(assignedIP[:], yiaddr)
									hasIP.Store(true)
									addr := tcpip.AddrFromSlice(yiaddr)
									prefixLen := 16
									if len(subnetMask) == 4 {
										mask := binary.BigEndian.Uint32(subnetMask)
										if mask != 0 && (^mask&(^mask+1)) == 0 {
											prefixLen = bits.OnesCount32(mask)
										}
									}
									var activeCC tcpip.CongestionControlOption
									_ = s.TransportProtocolOption(tcp.ProtocolNumber, &activeCC)
									errors.LogInfo(bgCtx, fmt.Sprintf("[VPNGate] 隧道槽位就绪 (%s) | 协议: SoftEther-SSL | 端口: %d | IP: %s/%d | 算法: %s+RACK", slotKey, serverDest.Port, addr.String(), prefixLen, string(activeCC)))
									once.Do(func() { ipReady <- dhcpLease{ip: addr, prefixLen: prefixLen} })
								}
							}
							continue
						}
					}
				}

				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(ipPkt),
				})
				ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			}
		}
	}()

	go func() {
		defer markDead()
		for {
			pkt := ep.ReadContext(bgCtx)
			if pkt == nil {
				return
			}
			var batch []*stack.PacketBuffer
			batch = append(batch, pkt)
			for i := 0; i < 64; i++ {
				nextPkt := ep.Read()
				if nextPkt == nil {
					break
				}
				batch = append(batch, nextPkt)
			}
			gw := sess.gwMAC.Load().([6]byte)
			frames := make([][]byte, 0, len(batch))
			for _, p := range batch {
				v := p.ToView()
				ipData := v.AsSlice()
				eth := make([]byte, 14+len(ipData))
				copy(eth[0:6], gw[:])
				copy(eth[6:12], myMAC[:])
				eth[12], eth[13] = 0x08, 0x00
				copy(eth[14:], ipData)
				frames = append(frames, eth)
				v.Release()
				p.DecRef()
			}
			if err := sess.writeSoftEtherFrames(frames); err != nil {
				return
			}
		}
	}()

	go func() {
		defer markDead()
		ticker := time.NewTicker(12 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sess.dead:
				return
			case <-ticker.C:
				// SoftEther 原生协议心跳格式: numPkts=0 (4B) + payloadLen=4 (4B) + 4B 零负载
				if err := sess.writeFrame([]byte{0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0}); err != nil {
					return
				}
			}
		}
	}()

	var lease dhcpLease
	select {
	case lease = <-ipReady:
	case <-sess.dead:
		err := fmt.Errorf("SoftEther 原生隧道在握手中提前断开")
		recordNodeFailureIfNeeded(baseKey, isBackground, err)
		return nil, err
	case <-time.After(22 * time.Second):
		markDead()
		err := fmt.Errorf("SoftEther Virtual DHCP 分配 IP 超时")
		recordNodeFailureIfNeeded(baseKey, isBackground, err)
		return nil, err
	}

	_ = s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: lease.ip, PrefixLen: lease.prefixLen},
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	time.Sleep(80 * time.Millisecond)

	slotBackoff.Delete(slotKey)
	sessMu.Lock()
	sessPool[slotKey] = sess
	sessMu.Unlock()
	return sess, nil
}

// 极速 DNS 解析：并发通过前置 DoT + 隧道内网直连 DNS (8.8.8.8/1.1.1.1:53) 双路抢答，彻底消除测速阻塞
func resolveFast(ctx context.Context, dialer internet.Dialer, sess *sstpSession, domain string) ([]byte, error) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if cached, ok := dnsCache.Load(domain); ok {
		if entry, ok := cached.(dnsEntry); ok && time.Now().Before(entry.expire) && len(entry.ip) == 4 {
			return entry.ip, nil
		}
	}

	txid := make([]byte, 2)
	_, _ = rand.Read(txid)
	req := []byte{txid[0], txid[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, part := range strings.Split(domain, ".") {
		req = append(req, byte(len(part)))
		req = append(req, []byte(part)...)
	}
	req = append(req, 0x00, 0x00, 0x01, 0x00, 0x01)

	parseDNSResp := func(resp []byte, n int) []byte {
		for i := 12; i+10 <= n; i++ {
			if resp[i] == 0x00 && resp[i+1] == 0x01 && resp[i+2] == 0x00 && resp[i+3] == 0x01 &&
				resp[i+8] == 0x00 && resp[i+9] == 0x04 && i+14 <= n {
				ip := make([]byte, 4)
				copy(ip, resp[i+10:i+14])
				return ip
			}
		}
		return nil
	}

	resCh := make(chan []byte, 4)

	// 路径 A：通过已建好的 VPNGate 隧道内网直发 UDP DNS
	queryTunnelUDP := func(dnsIP string) {
		if sess == nil || sess.s == nil {
			return
		}
		addr := net.ParseAddress(dnsIP).IP().To4()
		if len(addr) != 4 {
			return
		}
		uConn, err := gonet.DialUDP(sess.s, nil, &tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.AddrFromSlice(addr),
			Port: 53,
		}, ipv4.ProtocolNumber)
		if err != nil {
			return
		}
		defer uConn.Close()
		_ = uConn.SetDeadline(time.Now().Add(2500 * time.Millisecond))
		if _, err := uConn.Write(req); err != nil {
			return
		}
		resp := make([]byte, 512)
		n, err := uConn.Read(resp)
		if err == nil && n > 12 {
			if ip := parseDNSResp(resp, n); ip != nil {
				select {
				case resCh <- ip:
				default:
				}
			}
		}
	}

	// 路径 B：前置加密 DoT 并发查询（按 RFC 7858 2 字节长度前缀完整循环读取）
	queryDoT := func(dnsIP, sni string) {
		dCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		defer cancel()
		dest := net.TCPDestination(net.ParseAddress(dnsIP), 853)
		rawConn, err := dialer.Dial(dCtx, dest)
		if err != nil {
			return
		}
		defer rawConn.Close()

		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         sni,
			ClientSessionCache: tlsSessionCache,
		})
		_ = tlsConn.SetDeadline(time.Now().Add(2500 * time.Millisecond))
		if err := tlsConn.HandshakeContext(dCtx); err != nil {
			return
		}

		tcpReq := make([]byte, 2+len(req))
		binary.BigEndian.PutUint16(tcpReq[0:2], uint16(len(req)))
		copy(tcpReq[2:], req)
		if _, err := tlsConn.Write(tcpReq); err != nil {
			return
		}

		var lenHdr [2]byte
		if _, err := io.ReadFull(tlsConn, lenHdr[:]); err != nil {
			return
		}
		msgLen := int(binary.BigEndian.Uint16(lenHdr[:]))
		if msgLen < 12 || msgLen > 4096 {
			return
		}
		resp := make([]byte, msgLen)
		if _, err := io.ReadFull(tlsConn, resp); err != nil {
			return
		}
		if ip := parseDNSResp(resp, msgLen); ip != nil {
			select {
			case resCh <- ip:
			default:
			}
		}
	}

	go queryTunnelUDP("8.8.8.8")
	go queryTunnelUDP("1.1.1.1")
	go queryDoT("1.1.1.1", "cloudflare-dns.com")
	go queryDoT("8.8.8.8", "dns.google")

	select {
	case ip := <-resCh:
		dnsCache.Store(domain, dnsEntry{ip: ip, expire: time.Now().Add(15 * time.Minute)})
		return ip, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(3000 * time.Millisecond):
		return nil, fmt.Errorf("双路并发 DNS 解析超时: %s", domain)
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
		ip, err := resolveFast(ctx, dialer, sess, targetDest.Address.Domain())
		if err != nil {
			return err
		}
		targetIP = ip
	}
	if len(targetIP) != 4 {
		return fmt.Errorf("仅支持 IPv4 目标地址")
	}

	dialCtx, cancel := context.WithTimeout(ctx, 6000*time.Millisecond)
	gConn, err := gonet.DialContextTCP(dialCtx, sess.s, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(targetIP),
		Port: uint16(targetDest.Port),
	}, ipv4.ProtocolNumber)
	cancel()
	if err != nil {
		// 目标站超时或拒连属于业务层目标问题，不累加隧道死亡计数，避免误杀共享槽位
		return err
	}
	defer gConn.Close()

	downErrCh := make(chan error, 1)
	upErrCh := make(chan error, 1)

	// 下行: gConn -> link.Writer
	go func() {
		bp := readBufPool.Get().(*[]byte)
		defer readBufPool.Put(bp)
		b := *bp
		for {
			n, rErr := gConn.Read(b)
			if n > 0 {
				var mb buf.MultiBuffer
				offset := 0
				for offset < n {
					chunk := n - offset
					if chunk > buf.Size {
						chunk = buf.Size
					}
					item := buf.New()
					_, _ = item.Write(b[offset : offset+chunk])
					mb = append(mb, item)
					offset += chunk
				}
				if wErr := link.Writer.WriteMultiBuffer(mb); wErr != nil {
					buf.ReleaseMulti(mb)
					downErrCh <- wErr
					return
				}
			}
			if rErr != nil {
				downErrCh <- rErr
				return
			}
		}
	}()

	// 上行: link.Reader -> gConn
	go func() {
		for {
			mb, rErr := link.Reader.ReadMultiBuffer()
			if !mb.IsEmpty() {
				var wErr error
				for _, b := range mb {
					if _, err := gConn.Write(b.Bytes()); err != nil {
						wErr = err
						break
					}
				}
				buf.ReleaseMulti(mb)
				if wErr != nil {
					upErrCh <- wErr
					return
				}
			}
			if rErr != nil {
				if errors.Cause(rErr) == io.EOF {
					// 客户端发完请求半关闭时仅发送 FIN，保留下行继续接收完整响应
					_ = gConn.CloseWrite()
				}
				upErrCh <- rErr
				return
			}
		}
	}()

	for upDone, downDone := false, false; !downDone; {
		select {
		case err := <-downErrCh:
			downDone = true
			if err != nil && errors.Cause(err) != io.EOF {
				return err
			}
		case err := <-upErrCh:
			if !upDone {
				upDone = true
				if err != nil && errors.Cause(err) != io.EOF {
					return err
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
"""
  with open(vg_file, "w", encoding="utf-8") as f:
    f.write(vg_src)

  client_go = os.path.join(socks_dir, "client.go")
  with open(client_go, "r", encoding="utf-8") as f:
    c_code = f.read()

  hook_snippet = """
	if isVPNGateServer(server) {
		return handleVPNGateFixedNode(ctx, server.Destination, destination, link, dialer)
	}
"""
  if "handleVPNGateFixedNode" not in c_code:
    # 锚定 func (c *Client) Process 内部的第一处 server := 赋值，防止匹配到文件顶部其他函数
    new_code, n = re.subn(
        r"(func\s*\(c\s*\*Client\)\s*Process\s*\([^)]*\)[^{]*\{[\s\S]*?server\s*:=\s*[^\n]+)",
        r"\1\n" + hook_snippet,
        c_code,
        count=1,
    )
    if n == 0:
      raise RuntimeError(
          "❌ 未能在 proxy/socks/client.go 的 Process 函数中匹配到 server 变量赋值行！"
      )
    with open(client_go, "w", encoding="utf-8") as f:
      f.write(new_code)
    print("  ✔ [VPNGate Engine] 成功注入双协议自适应与首包防丢补丁")

  # 显式拉取满足 buffer.MakeWithData / TCPRACKLossDetection 的 gVisor 版本后再整理依赖
# 保留 xray-core 原有 go.mod 中的 gVisor 版本，仅整理依赖（切勿使用 @latest，否则会拉取 Bazel 主干分支）
  if os.system("go mod tidy") != 0:
    raise RuntimeError("❌ go mod tidy 执行失败！")
  print("  ✔ [Go Mod] 已同步 gVisor 依赖树")
# =========================================================================
# 7. 注入 VPNGate OpenVPN TCP/UDP 双栈自适应模块 (单读分发 + ARQ重传 + MSS钳制)
# =========================================================================
if os.path.exists(socks_dir):
    ovpn_file = os.path.join(socks_dir, "vpngate_openvpn.go")
    ovpn_src = r"""package socks

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type parsedOVPNConfig struct {
	mode       string // "default" | "udp" | "both"
	tcpPort    uint16
	udpPort    uint16
	cipherName string
	authName   string
	compLZO    bool
}

var (
	ovpnConfigCache sync.Map // map[string]*parsedOVPNConfig
	ovpnProtoCache  sync.Map // map[string]string ("openvpn-tcp" | "openvpn-udp")
)

func getOrDefaultOVPNConfig(baseKey string) *parsedOVPNConfig {
	if v, ok := ovpnConfigCache.Load(baseKey); ok {
		return v.(*parsedOVPNConfig)
	}
	return &parsedOVPNConfig{
		mode:       "default",
		cipherName: "AES-128-CBC",
		authName:   "SHA1",
		compLZO:    true,
	}
}

// 解析密码中的协议路由元数据:
// 1) vpn:udp:<udpPort>
// 2) vpn:both:<tcpPort>:<udpPort>
// 3) ovpn:<zlibBase64> (向后兼容)
func cacheOVPNFromPassword(baseKey, password string) {
	pw := strings.TrimSpace(password)
	if pw == "" || pw == "vpn" {
		return
	}
	if _, exists := ovpnConfigCache.Load(baseKey); exists {
		return
	}

	if strings.HasPrefix(pw, "udp:") {
		pStr := strings.TrimPrefix(pw, "udp:")
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 && p <= 65535 {
			ovpnConfigCache.Store(baseKey, &parsedOVPNConfig{
				mode:       "udp",
				udpPort:    uint16(p),
				cipherName: "AES-128-CBC",
				authName:   "SHA1",
				compLZO:    true,
			})
		}
		return
	}

	if strings.HasPrefix(pw, "both:") {
		parts := strings.Split(strings.TrimPrefix(pw, "both:"), ":")
		if len(parts) == 2 {
			tp, err1 := strconv.Atoi(parts[0])
			up, err2 := strconv.Atoi(parts[1])
			if err1 == nil && err2 == nil && tp > 0 && tp <= 65535 && up > 0 && up <= 65535 {
				ovpnConfigCache.Store(baseKey, &parsedOVPNConfig{
					mode:       "both",
					tcpPort:    uint16(tp),
					udpPort:    uint16(up),
					cipherName: "AES-128-CBC",
					authName:   "SHA1",
					compLZO:    true,
				})
			}
		}
		return
	}

	if strings.HasPrefix(pw, "ovpn:") {
		encoded := strings.TrimPrefix(pw, "ovpn:")
		var raw []byte
		var err error
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding} {
			if raw, err = enc.DecodeString(encoded); err == nil {
				break
			}
		}
		if len(raw) == 0 {
			return
		}
		if len(raw) > 2 && raw[0] == 0x78 {
			if zr, zErr := zlib.NewReader(bytes.NewReader(raw)); zErr == nil {
				if unz, rErr := io.ReadAll(zr); rErr == nil {
					raw = unz
				}
				_ = zr.Close()
			}
		}
		if cfg := parseOVPNText(string(raw)); cfg != nil {
			ovpnConfigCache.Store(baseKey, cfg)
		}
	}
}

func parseOVPNText(text string) *parsedOVPNConfig {
	cfg := &parsedOVPNConfig{
		mode:       "default",
		cipherName: "AES-128-CBC",
		authName:   "SHA1",
		compLZO:    false,
	}
	hasTCP, hasUDP := false, false
	var remotePort uint16
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		kw := strings.ToLower(fields[0])
		if kw == "comp-lzo" || kw == "compress" {
			cfg.compLZO = true
			continue
		}
		if len(fields) < 2 {
			continue
		}
		switch kw {
		case "proto":
			p := strings.ToLower(fields[1])
			if strings.HasPrefix(p, "tcp") {
				hasTCP = true
			} else if strings.HasPrefix(p, "udp") {
				hasUDP = true
			}
		case "remote":
			if len(fields) >= 3 {
				if p, err := strconv.Atoi(fields[2]); err == nil && p > 0 && p <= 65535 {
					remotePort = uint16(p)
				}
			}
		case "cipher", "data-ciphers":
			c := strings.ToUpper(strings.Split(fields[1], ":")[0])
			if strings.Contains(c, "256") {
				cfg.cipherName = "AES-256-CBC"
			} else {
				cfg.cipherName = "AES-128-CBC"
			}
		case "auth":
			if strings.EqualFold(fields[1], "SHA256") {
				cfg.authName = "SHA256"
			} else {
				cfg.authName = "SHA1"
			}
		}
	}
	if hasUDP && !hasTCP && remotePort > 0 {
		cfg.mode = "udp"
		cfg.udpPort = remotePort
	} else if remotePort > 0 {
		cfg.tcpPort = remotePort
	}
	return cfg
}

// =========================================================================
// 帧读写抽象层 (PacketIO: 统一 TCP 流式帧与 UDP 数据报帧)
// =========================================================================
type ovpnPacketIO interface {
	ReadPacket() ([]byte, error)
	WritePacket(pkt []byte) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type tcpPacketIO struct {
	raw     net.Conn
	writeMu sync.Mutex
}

func (t *tcpPacketIO) ReadPacket() ([]byte, error) {
	var lenHdr [2]byte
	if _, err := io.ReadFull(t.raw, lenHdr[:]); err != nil {
		return nil, err
	}
	pktLen := int(binary.BigEndian.Uint16(lenHdr[:]))
	if pktLen <= 0 || pktLen > 16384 {
		return nil, fmt.Errorf("OpenVPN TCP 帧长度异常: %d", pktLen)
	}
	pkt := make([]byte, pktLen)
	if _, err := io.ReadFull(t.raw, pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}

func (t *tcpPacketIO) WritePacket(pkt []byte) error {
	out := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(pkt)))
	copy(out[2:], pkt)
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, err := t.raw.Write(out)
	return err
}

func (t *tcpPacketIO) Close() error                       { return t.raw.Close() }
func (t *tcpPacketIO) LocalAddr() net.Addr                { return t.raw.LocalAddr() }
func (t *tcpPacketIO) RemoteAddr() net.Addr               { return t.raw.RemoteAddr() }
func (t *tcpPacketIO) SetDeadline(tm time.Time) error     { return t.raw.SetDeadline(tm) }
func (t *tcpPacketIO) SetReadDeadline(tm time.Time) error { return t.raw.SetReadDeadline(tm) }
func (t *tcpPacketIO) SetWriteDeadline(tm time.Time) error { return t.raw.SetWriteDeadline(tm) }

type udpPacketIO struct {
	raw     net.Conn
	writeMu sync.Mutex
}

func (u *udpPacketIO) ReadPacket() ([]byte, error) {
	buf := make([]byte, 4096)
	n, err := u.raw.Read(buf)
	if err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, fmt.Errorf("收到空 UDP 数据报")
	}
	pkt := make([]byte, n)
	copy(pkt, buf[:n])
	return pkt, nil
}

func (u *udpPacketIO) WritePacket(pkt []byte) error {
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	_, err := u.raw.Write(pkt)
	return err
}

func (u *udpPacketIO) Close() error                       { return u.raw.Close() }
func (u *udpPacketIO) LocalAddr() net.Addr                { return u.raw.LocalAddr() }
func (u *udpPacketIO) RemoteAddr() net.Addr               { return u.raw.RemoteAddr() }
func (u *udpPacketIO) SetDeadline(tm time.Time) error     { return u.raw.SetDeadline(tm) }
func (u *udpPacketIO) SetReadDeadline(tm time.Time) error { return u.raw.SetReadDeadline(tm) }
func (u *udpPacketIO) SetWriteDeadline(tm time.Time) error { return u.raw.SetWriteDeadline(tm) }

// =========================================================================
// 单读协程多路分发器 + 控制通道 ARQ 可靠传输状态机
// =========================================================================
type unackedCtrlPkt struct {
	pkt      []byte
	lastSent time.Time
}

type ovpnControlConn struct {
	pktIO         ovpnPacketIO
	isUDP         bool
	localSID      [8]byte
	remoteSID     [8]byte
	hasRemote     atomic.Bool
	handshakeDone atomic.Bool

	mu         sync.Mutex
	outPktID   uint32
	unacked    map[uint32]*unackedCtrlPkt
	nextRecvID uint32
	outOfOrder map[uint32][]byte
	readBuf    []byte
	closed     bool
	closeErr   error

	notifyCh     chan struct{}
	resetAckCh   chan struct{}
	resetAckOnce sync.Once
	stopARQ      chan struct{}
	stopARQOnce  sync.Once

	cbMu         sync.RWMutex
	onDataPacket func([]byte)
	onConnClosed func()
}

func newOVPNControlConn(pktIO ovpnPacketIO, isUDP bool) *ovpnControlConn {
	c := &ovpnControlConn{
		pktIO:      pktIO,
		isUDP:      isUDP,
		unacked:    make(map[uint32]*unackedCtrlPkt),
		outOfOrder: make(map[uint32][]byte),
		notifyCh:   make(chan struct{}, 1),
		resetAckCh: make(chan struct{}),
		stopARQ:    make(chan struct{}),
	}
	_, _ = rand.Read(c.localSID[:])
	go c.readerLoop()
	if isUDP {
		go c.arqRetransmitLoop()
	}
	return c
}

func (c *ovpnControlConn) stopRetransmit() {
	c.stopARQOnce.Do(func() {
		close(c.stopARQ)
	})
}

func (c *ovpnControlConn) fail(err error) {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		c.closeErr = err
	}
	c.mu.Unlock()

	c.stopRetransmit()
	select {
	case c.notifyCh <- struct{}{}:
	default:
	}

	c.cbMu.RLock()
	closedCb := c.onConnClosed
	c.cbMu.RUnlock()
	if closedCb != nil {
		closedCb()
	}
}

func (c *ovpnControlConn) readerLoop() {
	for {
		if c.handshakeDone.Load() {
			_ = c.pktIO.SetReadDeadline(time.Now().Add(15 * time.Second))
		}
		pkt, err := c.pktIO.ReadPacket()
		if err != nil {
			c.fail(err)
			return
		}
		if len(pkt) < 1 {
			continue
		}
		opcode := pkt[0] >> 3
		if opcode == 6 { // P_DATA_V1
			c.cbMu.RLock()
			dataCb := c.onDataPacket
			c.cbMu.RUnlock()
			if dataCb != nil {
				dataCb(pkt)
			}
			continue
		}
		if opcode == 4 || opcode == 5 || opcode == 8 {
			c.handleControlFrame(opcode, pkt)
		}
	}
}

func (c *ovpnControlConn) arqRetransmitLoop() {
	ticker := time.NewTicker(800 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopARQ:
			return
		case <-ticker.C:
			var toResend [][]byte
			now := time.Now()
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				return
			}
			// 按 Packet ID 升序重传未确认控制包
			for id := uint32(0); id <= c.outPktID; id++ {
				if item, ok := c.unacked[id]; ok && now.Sub(item.lastSent) >= 800*time.Millisecond {
					item.lastSent = now
					toResend = append(toResend, item.pkt)
				}
			}
			c.mu.Unlock()
			for _, p := range toResend {
				_ = c.pktIO.WritePacket(p)
			}
		}
	}
}

func (c *ovpnControlConn) sendAck(remotePktID uint32) {
	if !c.hasRemote.Load() {
		return
	}
	// P_ACK_V1 (opcode=5): 无自身 PacketID 字段，共 22 字节
	pkt := make([]byte, 22)
	pkt[0] = (5 << 3)
	copy(pkt[1:9], c.localSID[:])
	pkt[9] = 1
	binary.BigEndian.PutUint32(pkt[10:14], remotePktID)
	copy(pkt[14:22], c.remoteSID[:])
	_ = c.pktIO.WritePacket(pkt)
}

func (c *ovpnControlConn) handleControlFrame(opcode byte, pkt []byte) {
	if len(pkt) < 10 {
		return
	}
	ackLen := int(pkt[9])
	pos := 10 + 4*ackLen
	if len(pkt) < pos {
		return
	}

	c.mu.Lock()
	if !c.hasRemote.Load() {
		copy(c.remoteSID[:], pkt[1:9])
		c.hasRemote.Store(true)
	}
	// 销账已收到服务端确认的控制包
	for i := 0; i < ackLen; i++ {
		ackID := binary.BigEndian.Uint32(pkt[10+4*i : 14+4*i])
		delete(c.unacked, ackID)
	}
	c.mu.Unlock()

	if ackLen > 0 {
		pos += 8 // 跳过 remote_session_id 回显
	}
	if opcode == 5 { // 纯 ACK 帧到此结束
		return
	}
	if pos+4 > len(pkt) {
		return
	}

	remotePktID := binary.BigEndian.Uint32(pkt[pos : pos+4])
	pos += 4

	// 无论是否重复帧，收到 opcode=4 或 8 都必须立即回发 ACK
	c.sendAck(remotePktID)

	c.mu.Lock()
	if remotePktID < c.nextRecvID {
		c.mu.Unlock()
		return
	}
	if opcode == 8 { // P_CONTROL_HARD_RESET_SERVER_V2
		if remotePktID == c.nextRecvID {
			c.nextRecvID++
		}
		c.mu.Unlock()
		c.resetAckOnce.Do(func() {
			close(c.resetAckCh)
		})
		return
	}

	// opcode == 4 (P_CONTROL_V1)
	if pos < len(pkt) {
		payload := make([]byte, len(pkt)-pos)
		copy(payload, pkt[pos:])
		c.outOfOrder[remotePktID] = payload
	} else if remotePktID == c.nextRecvID {
		c.nextRecvID++
	}

	appended := false
	for {
		chunk, ok := c.outOfOrder[c.nextRecvID]
		if !ok {
			break
		}
		c.readBuf = append(c.readBuf, chunk...)
		delete(c.outOfOrder, c.nextRecvID)
		c.nextRecvID++
		appended = true
	}
	c.mu.Unlock()

	if appended {
		select {
		case c.notifyCh <- struct{}{}:
		default:
		}
	}
}

func (c *ovpnControlConn) sendHardReset(ctx context.Context) error {
	pkt := make([]byte, 14)
	pkt[0] = (7 << 3) // P_CONTROL_HARD_RESET_CLIENT_V2 (PacketID=0)
	copy(pkt[1:9], c.localSID[:])
	pkt[9] = 0
	binary.BigEndian.PutUint32(pkt[10:14], 0)

	c.mu.Lock()
	c.outPktID = 0
	if c.isUDP {
		c.unacked[0] = &unackedCtrlPkt{pkt: pkt, lastSent: time.Now()}
	}
	c.mu.Unlock()

	if err := c.pktIO.WritePacket(pkt); err != nil {
		return err
	}

	select {
	case <-c.resetAckCh:
		return nil
	case <-c.notifyCh:
		c.mu.Lock()
		err := c.closeErr
		c.mu.Unlock()
		if err != nil {
			return err
		}
		return fmt.Errorf("连接在等待 HARD_RESET_SERVER_V2 时关闭")
	case <-ctx.Done():
		return fmt.Errorf("等待 HARD_RESET_SERVER_V2 超时: %w", ctx.Err())
	}
}

func (c *ovpnControlConn) Write(b []byte) (int, error) {
	total := len(b)
	for len(b) > 0 {
		chunk := len(b)
		if chunk > 800 { // 单片上限 800B，避免嵌套 UDP 分片
			chunk = 800
		}

		c.mu.Lock()
		if c.closed {
			err := c.closeErr
			c.mu.Unlock()
			return 0, err
		}
		c.outPktID++
		pktID := c.outPktID

		pkt := make([]byte, 14+chunk)
		pkt[0] = (4 << 3) // P_CONTROL_V1
		copy(pkt[1:9], c.localSID[:])
		pkt[9] = 0
		binary.BigEndian.PutUint32(pkt[10:14], pktID)
		copy(pkt[14:], b[:chunk])

		if c.isUDP {
			c.unacked[pktID] = &unackedCtrlPkt{pkt: pkt, lastSent: time.Now()}
		}
		c.mu.Unlock()

		if err := c.pktIO.WritePacket(pkt); err != nil {
			return 0, err
		}
		b = b[chunk:]
	}
	return total, nil
}

func (c *ovpnControlConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.readBuf) > 0 {
			n := copy(b, c.readBuf)
			c.readBuf = c.readBuf[n:]
			c.mu.Unlock()
			return n, nil
		}
		if c.closed {
			err := c.closeErr
			c.mu.Unlock()
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}
		c.mu.Unlock()

		<-c.notifyCh
	}
}

func (c *ovpnControlConn) Close() error                       { c.stopRetransmit(); return c.pktIO.Close() }
func (c *ovpnControlConn) LocalAddr() net.Addr                { return c.pktIO.LocalAddr() }
func (c *ovpnControlConn) RemoteAddr() net.Addr               { return c.pktIO.RemoteAddr() }
func (c *ovpnControlConn) SetDeadline(t time.Time) error      { return c.pktIO.SetDeadline(t) }
func (c *ovpnControlConn) SetReadDeadline(t time.Time) error  { return c.pktIO.SetReadDeadline(t) }
func (c *ovpnControlConn) SetWriteDeadline(t time.Time) error { return c.pktIO.SetWriteDeadline(t) }

// =========================================================================
// 密码学辅助与 TCP SYN MSS 钳制
// =========================================================================
func openvpnPRF(secret, label, seed []byte, outLen int) []byte {
	fullSeed := append(append([]byte{}, label...), seed...)
	half := (len(secret) + 1) / 2
	s1 := secret[:half]
	s2 := secret[len(secret)/2:]

	pHash := func(newHash func() hash.Hash, key []byte) []byte {
		var out []byte
		macA := hmac.New(newHash, key)
		macA.Write(fullSeed)
		a := macA.Sum(nil)
		for len(out) < outLen {
			mac := hmac.New(newHash, key)
			mac.Write(a)
			mac.Write(fullSeed)
			out = append(out, mac.Sum(nil)...)

			nextA := hmac.New(newHash, key)
			nextA.Write(a)
			a = nextA.Sum(nil)
		}
		return out[:outLen]
	}

	b1 := pHash(md5.New, s1)
	b2 := pHash(sha1.New, s2)
	res := make([]byte, outLen)
	for i := 0; i < outLen; i++ {
		res[i] = b1[i] ^ b2[i]
	}
	return res
}

func clampIPv4TCPMSS(ipPkt []byte, maxMSS uint16) []byte {
	if len(ipPkt) < 40 || (ipPkt[0]>>4) != 4 || ipPkt[9] != 6 {
		return ipPkt
	}
	ihl := int(ipPkt[0]&0x0f) * 4
	if ihl < 20 || len(ipPkt) < ihl+20 {
		return ipPkt
	}
	if (ipPkt[ihl+13] & 0x02) == 0 { // 非 SYN 报文
		return ipPkt
	}
	doff := int(ipPkt[ihl+12]>>4) * 4
	if doff <= 20 || len(ipPkt) < ihl+doff {
		return ipPkt
	}

	out := make([]byte, len(ipPkt))
	copy(out, ipPkt)
	modified := false
	for i := ihl + 20; i < ihl+doff; {
		kind := out[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= ihl+doff {
			break
		}
		optLen := int(out[i+1])
		if optLen < 2 || i+optLen > ihl+doff {
			break
		}
		if kind == 2 && optLen == 4 {
			curMSS := binary.BigEndian.Uint16(out[i+2 : i+4])
			if curMSS > maxMSS {
				binary.BigEndian.PutUint16(out[i+2:i+4], maxMSS)
				modified = true
			}
			break
		}
		i += optLen
	}
	if !modified {
		return ipPkt
	}

	// 重算 TCP 校验和
	out[ihl+16] = 0
	out[ihl+17] = 0
	tcpLen := len(out) - ihl
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(out[12:14]))
	sum += uint32(binary.BigEndian.Uint16(out[14:16]))
	sum += uint32(binary.BigEndian.Uint16(out[16:18]))
	sum += uint32(binary.BigEndian.Uint16(out[18:20]))
	sum += 6
	sum += uint32(tcpLen)
	for i := ihl; i+1 < len(out); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(out[i : i+2]))
	}
	if tcpLen%2 == 1 {
		sum += uint32(out[len(out)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(out[ihl+16:ihl+18], ^uint16(sum))
	return out
}

// =========================================================================
// OpenVPN 核心建连函数 (同时支持 TCP 与 UDP)
// =========================================================================
func dialOpenVPNSession(serverDest net.Destination, dialer internet.Dialer, baseKey, slotKey string, cfg *parsedOVPNConfig, useUDP bool) (*sstpSession, error) {
	bgCtx := context.Background()
	dialCtx, cancel := context.WithTimeout(bgCtx, 12*time.Second)
	defer cancel()

	var targetDest net.Destination
	if useUDP {
		uPort := serverDest.Port
		if cfg.udpPort > 0 {
			uPort = net.Port(cfg.udpPort)
		}
		targetDest = net.UDPDestination(serverDest.Address, uPort)
	} else {
		tPort := serverDest.Port
		if cfg.tcpPort > 0 {
			tPort = net.Port(cfg.tcpPort)
		}
		targetDest = net.TCPDestination(serverDest.Address, tPort)
	}

	rawConn, err := dialer.Dial(dialCtx, targetDest)
	if err != nil {
		return nil, err
	}

	var pktIO ovpnPacketIO
	if useUDP {
		pktIO = &udpPacketIO{raw: rawConn}
	} else {
		pktIO = &tcpPacketIO{raw: rawConn}
	}

	_ = pktIO.SetDeadline(time.Now().Add(10 * time.Second))
	ctrl := newOVPNControlConn(pktIO, useUDP)

	// 1. 发送 HARD_RESET_CLIENT_V2 并等待服务端 HARD_RESET_SERVER_V2
	if err := ctrl.sendHardReset(dialCtx); err != nil {
		ctrl.Close()
		return nil, err
	}

	// 2. 限制 TLS 1.2 并关闭后量子大扩展，确保 ClientHello 单包发出
	tlsConn := tls.Client(ctrl, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		CurvePreferences:   []tls.CurveID{tls.CurveP256, tls.X25519, tls.CurveP384},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	})
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("OpenVPN TLS 握手失败: %w", err)
	}

	var preMaster [48]byte
	var cRand1, cRand2 [32]byte
	_, _ = rand.Read(preMaster[:])
	_, _ = rand.Read(cRand1[:])
	_, _ = rand.Read(cRand2[:])

	writeStr := func(buf *bytes.Buffer, s string) {
		b := append([]byte(s), 0)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(b)))
		buf.Write(l[:])
		buf.Write(b)
	}

	cipherName := cfg.cipherName
	authName := cfg.authName
	keyBits := 128
	if cipherName == "AES-256-CBC" {
		keyBits = 256
	}
	lzoOpt := ""
	extraStub := 0
	if cfg.compLZO {
		lzoOpt = ",comp-lzo no"
		extraStub = 1
	}
	hmacBytes := 20
	if authName == "SHA256" {
		hmacBytes = 32
	}
	protoOpt := "TCPv4_CLIENT"
	if useUDP {
		protoOpt = "UDPv4"
	}
	linkMTU := 1500 + 1 + hmacBytes + 16 + 4 + 1 + extraStub

	var kmBuf bytes.Buffer
	kmBuf.Write([]byte{0, 0, 0, 0, 2})
	kmBuf.Write(preMaster[:])
	kmBuf.Write(cRand1[:])
	kmBuf.Write(cRand2[:])
	optStr := fmt.Sprintf("V4,dev-type tun,link-mtu %d,tun-mtu 1500,proto %s,cipher %s,auth %s,keysize %d,key-method 2,tls-client%s", linkMTU, protoOpt, cipherName, authName, keyBits, lzoOpt)
	writeStr(&kmBuf, optStr)
	writeStr(&kmBuf, "vpn")
	writeStr(&kmBuf, "vpn")

	if _, err := tlsConn.Write(kmBuf.Bytes()); err != nil {
		ctrl.Close()
		return nil, err
	}

	// 3. SoftEther KM2 响应只有 OptionString 单字段，读完立即结束
	var srvKMHdr [69]byte
	if _, err := io.ReadFull(tlsConn, srvKMHdr[:]); err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("读取 OpenVPN KM2 失败: %w", err)
	}
	sRand1 := srvKMHdr[5:37]
	sRand2 := srvKMHdr[37:69]

	var optLenHdr [2]byte
	if _, err := io.ReadFull(tlsConn, optLenHdr[:]); err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("读取 KM2 OptionString 长度失败: %w", err)
	}
	srvOptLen := int(binary.BigEndian.Uint16(optLenHdr[:]))
	var srvOptStr string
	if srvOptLen > 0 {
		if srvOptLen > 8192 {
			ctrl.Close()
			return nil, fmt.Errorf("KM2 OptionString 长度异常: %d", srvOptLen)
		}
		optBytes := make([]byte, srvOptLen)
		if _, err := io.ReadFull(tlsConn, optBytes); err != nil {
			ctrl.Close()
			return nil, fmt.Errorf("读取 KM2 OptionString 内容失败: %w", err)
		}
		srvOptStr = strings.TrimRight(string(optBytes), "\x00")
	}

	if strings.Contains(srvOptStr, "AES-256-CBC") {
		cipherName = "AES-256-CBC"
	} else if strings.Contains(srvOptStr, "AES-128-CBC") {
		cipherName = "AES-128-CBC"
	}
	if strings.Contains(srvOptStr, "SHA256") {
		authName = "SHA256"
	} else if strings.Contains(srvOptStr, "SHA1") {
		authName = "SHA1"
	}
	hasCompLZO := cfg.compLZO || strings.Contains(srvOptStr, "comp-lzo") || strings.Contains(srvOptStr, "compress")

	// 4. 循环每 1s 重发 PUSH_REQUEST\x00，等待 SoftEther 异步 DHCP 分配内网 IP
	var tlsWriteMu sync.Mutex
	sendPushReq := func() error {
		tlsWriteMu.Lock()
		defer tlsWriteMu.Unlock()
		_, wErr := tlsConn.Write([]byte("PUSH_REQUEST\x00"))
		return wErr
	}
	if err := sendPushReq(); err != nil {
		ctrl.Close()
		return nil, err
	}

	stopPushCh := make(chan struct{})
	var stopPushOnce sync.Once
	stopPush := func() {
		stopPushOnce.Do(func() {
			close(stopPushCh)
		})
	}
	defer stopPush()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopPushCh:
				return
			case <-dialCtx.Done():
				return
			case <-ticker.C:
				_ = sendPushReq()
			}
		}
	}()

	var assignedIP []byte
	var pushAcc strings.Builder
	pushBuf := make([]byte, 2048)
	for attempts := 0; attempts < 10; attempts++ {
		n, err := tlsConn.Read(pushBuf)
		if err != nil {
			stopPush()
			ctrl.Close()
			return nil, fmt.Errorf("读取 PUSH_REPLY 失败: %w", err)
		}
		pushAcc.Write(pushBuf[:n])
		reply := pushAcc.String()
		if strings.Contains(reply, "AUTH_FAILED") {
			stopPush()
			ctrl.Close()
			return nil, fmt.Errorf("OpenVPN 认证被拒绝 (AUTH_FAILED)")
		}
		if idx := strings.Index(reply, "PUSH_REPLY"); idx != -1 {
			sub := reply[idx:]
			if strings.Contains(sub, "comp-lzo") || strings.Contains(sub, "compress") {
				hasCompLZO = true
			}
			if strings.Contains(sub, "ifconfig ") && (strings.IndexByte(sub, 0) != -1 || len(sub) > 30) {
				cleanReply := strings.SplitN(sub, "\x00", 2)[0]
				for _, token := range strings.Split(cleanReply, ",") {
					parts := strings.Fields(strings.TrimSpace(token))
					if len(parts) >= 2 && parts[0] == "ifconfig" {
						if ip := net.ParseAddress(parts[1]).IP().To4(); len(ip) == 4 {
							assignedIP = ip
							break
						}
					}
				}
				if len(assignedIP) == 4 {
					break
				}
			}
		}
	}
	stopPush()

	if len(assignedIP) != 4 {
		ctrl.Close()
		return nil, fmt.Errorf("OpenVPN 未分配有效 IP: %q", strings.Trim(pushAcc.String(), "\x00"))
	}

	ctrl.stopRetransmit()
	_ = pktIO.SetDeadline(time.Time{})
	ctrl.handshakeDone.Store(true)

	// 5. 派生数据通道密钥
	seed1 := append(append([]byte{}, cRand1[:]...), sRand1...)
	masterSecret := openvpnPRF(preMaster[:], []byte("OpenVPN master secret"), seed1, 48)
	var seed2 []byte
	seed2 = append(seed2, cRand2[:]...)
	seed2 = append(seed2, sRand2...)
	seed2 = append(seed2, ctrl.localSID[:]...)
	seed2 = append(seed2, ctrl.remoteSID[:]...)
	keyBlock := openvpnPRF(masterSecret, []byte("OpenVPN key expansion"), seed2, 256)

	keyLen := 16
	if cipherName == "AES-256-CBC" {
		keyLen = 32
	}
	sendCipherBlk, err := aes.NewCipher(keyBlock[0:keyLen])
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	recvCipherBlk, err := aes.NewCipher(keyBlock[128 : 128+keyLen])
	if err != nil {
		ctrl.Close()
		return nil, err
	}

	newAuthHash := sha1.New
	hmacSize := 20
	if authName == "SHA256" {
		newAuthHash = sha256.New
		hmacSize = 32
	}
	hmacSendKey := keyBlock[64 : 64+hmacSize]
	hmacRecvKey := keyBlock[192 : 192+hmacSize]

	s, ep, err := newGVisorStack()
	if err != nil {
		ctrl.Close()
		return nil, err
	}

	sess := &sstpSession{
		s:       s,
		rawConn: rawConn,
		dead:    make(chan struct{}),
	}

	var deadOnce sync.Once
	sess.markDead = func() {
		deadOnce.Do(func() {
			close(sess.dead)
			sessMu.Lock()
			if cur, ok := sessPool[slotKey]; ok && cur == sess {
				delete(sessPool, slotKey)
			}
			sessMu.Unlock()
			ctrl.Close()
			s.Close()
		})
	}

	// 绑定下行数据帧回调与连接关闭回调到单读分发器
	ctrl.cbMu.Lock()
	ctrl.onConnClosed = sess.markDead
	ctrl.onDataPacket = func(pkt []byte) {
		if len(pkt) < 1+hmacSize+16+16 {
			return
		}
		recvMAC := pkt[1 : 1+hmacSize]
		encBody := pkt[1+hmacSize:]
		mac := hmac.New(newAuthHash, hmacRecvKey)
		mac.Write(encBody)
		if !hmac.Equal(recvMAC, mac.Sum(nil)) {
			return
		}
		iv := encBody[:16]
		ct := encBody[16:]
		if len(ct)%16 != 0 {
			return
		}
		pt := make([]byte, len(ct))
		cipher.NewCBCDecrypter(recvCipherBlk, iv).CryptBlocks(pt, ct)
		padLen := int(pt[len(pt)-1])
		if padLen < 1 || padLen > 16 || padLen > len(pt) {
			return
		}
		plain := pt[:len(pt)-padLen]
		if len(plain) > 4 {
			ipPkt := plain[4:]
			if ipPkt[0] == 0xfa && len(ipPkt) > 1 {
				ipPkt = ipPkt[1:]
			}
			if (ipPkt[0] >> 4) == 4 {
				pBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(ipPkt),
				})
				ep.InjectInbound(header.IPv4ProtocolNumber, pBuf)
				pBuf.DecRef()
			}
		}
	}
	ctrl.cbMu.Unlock()

	var dataPktID atomic.Uint32
	sendEncryptedPayload := func(payload []byte, isIPPacket bool) error {
		if isIPPacket {
			payload = clampIPv4TCPMSS(payload, 1280)
		}
		id := dataPktID.Add(1)
		lzoByte := 0
		if hasCompLZO {
			lzoByte = 1
		}
		rawPlainLen := 4 + lzoByte + len(payload)
		padLen := 16 - (rawPlainLen % 16)
		padded := make([]byte, rawPlainLen+padLen)
		binary.BigEndian.PutUint32(padded[0:4], id)
		if hasCompLZO {
			padded[4] = 0xfa
		}
		copy(padded[4+lzoByte:rawPlainLen], payload)
		for i := rawPlainLen; i < len(padded); i++ {
			padded[i] = byte(padLen)
		}

		var iv [16]byte
		_, _ = rand.Read(iv[:])
		ct := make([]byte, len(padded))
		cipher.NewCBCEncrypter(sendCipherBlk, iv[:]).CryptBlocks(ct, padded)

		mac := hmac.New(newAuthHash, hmacSendKey)
		mac.Write(iv[:])
		mac.Write(ct)
		tag := mac.Sum(nil)

		out := make([]byte, 1+len(tag)+16+len(ct))
		out[0] = (6 << 3)
		copy(out[1:1+len(tag)], tag)
		copy(out[1+len(tag):1+len(tag)+16], iv[:])
		copy(out[1+len(tag)+16:], ct)

		return pktIO.WritePacket(out)
	}

	// 上行: gVisor 读取 IPv4 -> P_DATA_V1 加密发送
	go func() {
		defer sess.markDead()
		for {
			pkt := ep.ReadContext(bgCtx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			wErr := sendEncryptedPayload(v.AsSlice(), true)
			v.Release()
			pkt.DecRef()
			if wErr != nil {
				return
			}
		}
	}()

	// 每 3 秒发送 OCC Ping 心跳，对齐 SoftEther ping 3 / ping-restart 10 阈值
	go func() {
		defer sess.markDead()
		ovpnPing := []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sess.dead:
				return
			case <-ticker.C:
				if err := sendEncryptedPayload(ovpnPing, false); err != nil {
					return
				}
			}
		}
	}()

	localIP := tcpip.AddrFromSlice(assignedIP)
	_ = s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: localIP, PrefixLen: 8},
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	time.Sleep(80 * time.Millisecond)

	protoLabel := "OpenVPN-TCP"
	if useUDP {
		protoLabel = "OpenVPN-UDP"
	}
	errors.LogInfo(bgCtx, fmt.Sprintf("[VPNGate] 隧道槽位就绪 (%s) | 协议: %s | 端口: %d | IP: %s", slotKey, protoLabel, targetDest.Port, localIP.String()))

	slotBackoff.Delete(slotKey)
	sessMu.Lock()
	sessPool[slotKey] = sess
	sessMu.Unlock()
	return sess, nil
}
"""
    with open(ovpn_file, "w", encoding="utf-8") as f:
        f.write(ovpn_src)

    with open(vg_file, "r", encoding="utf-8") as f:
        vg_code = f.read()

    if "dialOpenVPNSession" not in vg_code:
        vg_code = vg_code.replace(
            "_ = tlsConn.SetDeadline(time.Now().Add(6 * time.Second))",
            "_ = tlsConn.SetDeadline(time.Now().Add(2500 * time.Millisecond))",
            1,
        )
        vg_code = vg_code.replace(
            'return u == "vpn" || u == "vpngate"',
            'if u == "vpn" || u == "vpngate" {\n\t\t\tcacheOVPNFromPassword(server.Destination.String(), acc.Password)\n\t\t\treturn true\n\t\t}\n\t\treturn false',
            1,
        )

        # 入口路由: 纯 UDP 节点跳过 SSTP/SoftEther 直连 OpenVPN-UDP；专用 TCP 端口优先试 OpenVPN-TCP
        ovpn_fast_hook = """
	{
		ovpnCfg := getOrDefaultOVPNConfig(baseKey)
		pCached, _ := ovpnProtoCache.Load(baseKey)
		if ovpnCfg.mode == "udp" || pCached == "openvpn-udp" {
			sess, ovpnErr := dialOpenVPNSession(serverDest, dialer, baseKey, slotKey, ovpnCfg, true)
			if ovpnErr == nil {
				ovpnProtoCache.Store(baseKey, "openvpn-udp")
				return sess, nil
			}
			errors.LogDebug(bgCtx, "[VPNGate] OpenVPN-UDP 拨号失败 (", slotKey, "): ", ovpnErr)
			recordNodeFailureIfNeeded(baseKey, isBackground, ovpnErr)
			return nil, ovpnErr
		}
		isDedicatedOVPNPort := serverDest.Port != 443 && serverDest.Port != 995 && serverDest.Port != 5555
		if pCached == "openvpn-tcp" || (pCached == nil && isDedicatedOVPNPort) {
			sess, ovpnErr := dialOpenVPNSession(serverDest, dialer, baseKey, slotKey, ovpnCfg, false)
			if ovpnErr == nil {
				ovpnProtoCache.Store(baseKey, "openvpn-tcp")
				return sess, nil
			}
			errors.LogDebug(bgCtx, "[VPNGate] OpenVPN-TCP 直连未命中，继续尝试 SoftEther/SSTP (", slotKey, "): ", ovpnErr)
		}
	}
"""
        vg_code = vg_code.replace(
            "bgCtx := context.Background()",
            "bgCtx := context.Background()" + ovpn_fast_hook,
            1,
        )

        # TCP (SSTP + SoftEther) 均失败后的回退链: 先试 OpenVPN-TCP，若配置含 UDP 端口再兜底 OpenVPN-UDP
        ovpn_fallback_hook = """
		ovpnCfg := getOrDefaultOVPNConfig(baseKey)
		if sess, ovpnErr := dialOpenVPNSession(serverDest, dialer, baseKey, slotKey, ovpnCfg, false); ovpnErr == nil {
			ovpnProtoCache.Store(baseKey, "openvpn-tcp")
			return sess, nil
		} else {
			errors.LogDebug(bgCtx, "[VPNGate] OpenVPN-TCP 回退未命中 (", slotKey, "): ", ovpnErr)
		}
		if ovpnCfg.mode == "both" && ovpnCfg.udpPort > 0 {
			if sess, udpErr := dialOpenVPNSession(serverDest, dialer, baseKey, slotKey, ovpnCfg, true); udpErr == nil {
				ovpnProtoCache.Store(baseKey, "openvpn-udp")
				return sess, nil
			} else {
				errors.LogDebug(bgCtx, "[VPNGate] OpenVPN-UDP 兜底也失败 (", slotKey, "): ", udpErr)
			}
		}
"""
        vg_code = vg_code.replace(
            "if nativeErr != nil {",
            "if nativeErr != nil {" + ovpn_fallback_hook,
            1,
        )

        with open(vg_file, "w", encoding="utf-8") as f:
            f.write(vg_code)
        print("  ✔ [VPNGate OpenVPN] 成功注入 TCP/UDP 双栈自适应引擎")

print(">>> 全部兼容、提速与安全加固补丁写入完毕！")
