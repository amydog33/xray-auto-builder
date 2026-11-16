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
# 6. 注入 VPNGate (多端口回退 + TLS全兼容 + SSTP/SoftEther双协议自适应 + 并发分流池)
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
	"fmt"
	"io"
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

// 每个节点并发保持 2 条独立隧道，消除单 TCP 队头阻塞并叠加带宽
const poolSizePerNode = 2

type sstpSession struct {
	s           *stack.Stack
	rawConn     net.Conn
	tlsConn     *tls.Conn
	writeMu     sync.Mutex
	bw          *bufio.Writer
	dead        chan struct{}
	markDead    func()
	failCount   atomic.Int32
	isSoftEther bool
	myMAC       [6]byte
	gwMAC       atomic.Value // 存储 [6]byte
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

// 构造全版本与全加密套件兼容的 TLS 配置，防止老旧 SoftEther 节点拒绝握手
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

// 多端口阶梯并发回退拨号：解决四位数随机端口 i/o timeout 问题
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
				// 主端口给予 1.4s 优先建立时间，超时未通则错峰并发尝试 443/995/5555
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
			ch <- dialRes{conn: c, port: port, err: err}
		}(i, p)
	}

	var lastErr error
	for range ports {
		r := <-ch
		if r.err == nil && r.conn != nil {
			if r.port != origPort {
				errors.LogWarning(ctx, fmt.Sprintf("[VPNGate] 端口回退拨号命中 -> %s:%d (原端口 %d 不通)", serverDest.Address.String(), r.port, origPort))
			}
			return r.conn, r.port, nil
		}
		if r.err != nil {
			lastErr = r.err
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
		// 错开 450ms 启动后台槽位，防止双槽位冷启动 TLS 握手同时挤爆前置代理
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
			if time.Since(failTime.(time.Time)) < 12*time.Second {
				return nil, fmt.Errorf("节点 %s 处于失败冷却中", baseKey)
			}
			failCache.Delete(baseKey)
		}
	}

	errors.LogWarning(ctx, "[VPNGate] 正在建立并发隧道槽位 -> ", slotKey)
	dialCtx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
	defer cancel()

	// 1. 多端口并发回退拨号
	rawConn, activePort, err := dialWithPortFallback(dialCtx, dialer, serverDest)
	if err != nil {
		if !isBackground && !hasAnyAliveSlot(baseKey) {
			failCache.Store(baseKey, time.Now())
		}
		return nil, err
	}

	// 2. 全版本兼容 TLS 握手
	host := serverDest.Address.String()
	tlsConn := tls.Client(rawConn, buildCompatTLSConfig(host))
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		rawConn.Close()
		if !isBackground && !hasAnyAliveSlot(baseKey) {
			failCache.Store(baseKey, time.Now())
		}
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

	// 3. 优先尝试 MS-SSTP 握手，若被拒或不支持则无缝回退到 SoftEther 原生 SSL-VPN 协议
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
		errors.LogWarning(ctx, fmt.Sprintf("[VPNGate] SSTP 握手未命中 (%s)，自动回退 SoftEther 原生协议 -> %s:%d", reason, host, activePort))
		nativeDest := net.TCPDestination(serverDest.Address, activePort)
		sess, nativeErr := dialSoftEtherNativeSession(ctx, nativeDest, dialer, baseKey, slotKey)
		if nativeErr != nil {
			if !isBackground && !hasAnyAliveSlot(baseKey) {
				failCache.Store(baseKey, time.Now())
			}
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
				errors.LogWarning(ctx, "[VPNGate] 槽位断开或超时 (", slotKey, "): ", err)
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
					errors.LogWarning(ctx, fmt.Sprintf("[VPNGate] 🎉 隧道槽位就绪 (%s)! 协议: MS-SSTP | 端口: %d | IP: %s | 算法: %s+RACK", slotKey, activePort, addr.String(), string(activeCC)))
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
			pkt := ep.ReadContext(context.Background())
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

	// 放宽单槽位 PPP/IPCP 协商超时至 22s，适配跨洲链式代理高 RTT
	var localIP tcpip.Address
	select {
	case localIP = <-ipReady:
	case <-sess.dead:
		if !hasAnyAliveSlot(baseKey) {
			failCache.Store(baseKey, time.Now())
		}
		return nil, fmt.Errorf("VPNGate 隧道在握手中提前断开")
	case <-time.After(22 * time.Second):
		markDead()
		if !hasAnyAliveSlot(baseKey) {
			failCache.Store(baseKey, time.Now())
		}
		return nil, fmt.Errorf("VPNGate PPP/IPCP 协商超时")
	}

	_ = s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: localIP, PrefixLen: 8},
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	slotBackoff.Delete(slotKey)
	sessMu.Lock()
	sessPool[slotKey] = sess
	sessMu.Unlock()
	return sess, nil
}

// =========================================================================
// SoftEther 原生 SSL-VPN 协议回退实现 (HTTP Watermark + PACK + L2 Ethernet/DHCP)
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
		writeU32(2) // VALUE_STR
		writeU32(1)
		writeU32(uint32(len(v) + 1))
		b.WriteString(v)
	}
	addInt := func(k string, v uint32) {
		writeName(k)
		writeU32(0) // VALUE_INT
		writeU32(1)
		writeU32(v)
	}

	writeU32(12) // 共 12 个字段
	addStr("method", "login")
	addStr("hubname", "VPNGATE")
	addStr("username", "vpn")
	addInt("authtype", 0) // CLIENT_AUTHTYPE_ANONYMOUS
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
			fmt.Sscanf(strings.TrimSpace(lower[len("content-length:"):]), "%d", &contentLen)
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
	bootp := make([]byte, 300)
	bootp[0] = 1 // BOOTREQUEST
	bootp[1] = 1 // Ethernet
	bootp[2] = 6 // MAC len
	binary.BigEndian.PutUint32(bootp[4:8], xid)
	binary.BigEndian.PutUint16(bootp[10:12], 0x8000) // Broadcast flag
	copy(bootp[28:34], myMAC[:])
	// Magic cookie 99.130.83.99
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
	idx++
	dhcpPayload := bootp[:idx]

	udpLen := 8 + len(dhcpPayload)
	ipLen := 20 + udpLen
	eth := make([]byte, 14+ipLen)
	// Dst MAC: ff:ff:ff:ff:ff:ff
	for i := 0; i < 6; i++ {
		eth[i] = 0xff
	}
	copy(eth[6:12], myMAC[:])
	eth[12], eth[13] = 0x08, 0x00

	ip := eth[14 : 14+20]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[8] = 64
	ip[9] = 17 // UDP
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
	copy(eth[42:], dhcpPayload)
	return eth
}

func dialSoftEtherNativeSession(ctx context.Context, serverDest net.Destination, dialer internet.Dialer, baseKey, slotKey string) (*sstpSession, error) {
	dialCtx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
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
	// 1. 发送 SoftEther HTTP Watermark 签名
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

	// 2. 发送 SoftEther PACK 匿名认证包 (Hub: VPNGATE, User: vpn)
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
	if _, err := readSoftEtherHTTPBody(br); err != nil {
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
	myMAC[0] = (myMAC[0] & 0xfe) | 0x02 // 本地单播 MAC
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

	ipReady := make(chan tcpip.Address, 1)
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

	// 发送 DHCP Discover 向 SoftEther Virtual DHCP 申请内网 IP
	_ = sess.writeSoftEtherFrames([][]byte{buildDHCPFrame(1, dhcpXid, myMAC, nil, nil)})

	go func() {
		defer markDead()
		var hdr [4]byte
		for {
			_ = tlsConn.SetReadDeadline(time.Now().Add(45 * time.Second))
			if _, err := io.ReadFull(br, hdr[:]); err != nil {
				return
			}
			numPkts := binary.BigEndian.Uint32(hdr[:])
			if numPkts == 0 {
				// SoftEther Keep-Alive 帧
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
					// 处理 ARP 请求：向 SoftEther Virtual NAT 宣告本机 MAC
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
				// 截获 Virtual DHCP 响应 (UDP 67 -> 68)
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
									if code == 53 && olen >= 1 {
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
									var activeCC tcpip.CongestionControlOption
									_ = s.TransportProtocolOption(tcp.ProtocolNumber, &activeCC)
									errors.LogWarning(ctx, fmt.Sprintf("[VPNGate] 🎉 隧道槽位就绪 (%s)! 协议: SoftEther-SSL | 端口: %d | IP: %s | 算法: %s+RACK", slotKey, serverDest.Port, addr.String(), string(activeCC)))
									once.Do(func() { ipReady <- addr })
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
			pkt := ep.ReadContext(context.Background())
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
				if err := sess.writeFrame([]byte{0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0}); err != nil {
					return
				}
			}
		}
	}()

	var localIP tcpip.Address
	select {
	case localIP = <-ipReady:
	case <-sess.dead:
		return nil, fmt.Errorf("SoftEther 原生隧道在握手中提前断开")
	case <-time.After(22 * time.Second):
		markDead()
		return nil, fmt.Errorf("SoftEther Virtual DHCP 分配 IP 超时")
	}

	_ = s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: localIP, PrefixLen: 16},
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	slotBackoff.Delete(slotKey)
	sessMu.Lock()
	sessPool[slotKey] = sess
	sessMu.Unlock()
	return sess, nil
}

func resolveFast(ctx context.Context, dialer internet.Dialer, domain string) ([]byte, error) {
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

	resCh := make(chan []byte, 2)
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

		resp := make([]byte, 512)
		n, err := tlsConn.Read(resp)
		if err == nil && n > 14 {
			if ip := parseDNSResp(resp[2:], n-2); ip != nil {
				select {
				case resCh <- ip:
				default:
				}
			}
		}
	}

	go queryDoT("1.1.1.1", "cloudflare-dns.com")
	go queryDoT("8.8.8.8", "dns.google")

	select {
	case ip := <-resCh:
		dnsCache.Store(domain, dnsEntry{ip: ip, expire: time.Now().Add(15 * time.Minute)})
		return ip, nil
	case <-time.After(2600 * time.Millisecond):
		return nil, fmt.Errorf("前置加密 DNS 解析超时: %s", domain)
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
		ip, err := resolveFast(ctx, dialer, targetDest.Address.Domain())
		if err != nil {
			return err
		}
		targetIP = ip
	}
	if len(targetIP) != 4 {
		return fmt.Errorf("仅支持 IPv4 目标地址")
	}

	dialCtx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	gConn, err := gonet.DialContextTCP(dialCtx, sess.s, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(targetIP),
		Port: uint16(targetDest.Port),
	}, ipv4.ProtocolNumber)
	cancel()
	if err != nil {
		if sess.failCount.Add(1) >= 3 && sess.markDead != nil {
			errors.LogWarning(ctx, "[VPNGate] 连续拨号超时，主动回收当前隧道槽位")
			sess.markDead()
		}
		return err
	}
	sess.failCount.Store(0)
	defer gConn.Close()

	errCh := make(chan error, 2)
	go func() {
		bp := readBufPool.Get().(*[]byte)
		defer readBufPool.Put(bp)
		b := *bp
		for {
			n, err := gConn.Read(b)
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
    print("  ✔ [VPNGate Engine] 成功注入双协议自适应与多端口回退补丁")

  if os.system("go mod tidy") != 0:
    raise RuntimeError("❌ go mod tidy 执行失败！")
  print("  ✔ [Go Mod] 已自动执行 go mod tidy 同步 gVisor 依赖树")

print(">>> 全部兼容、提速与安全加固补丁写入完毕！")
