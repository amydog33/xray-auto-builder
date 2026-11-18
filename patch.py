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
# 6. 注入 VPNGate 核心主引擎 (禁用Go1.27后量子巨型包 + 全路径SSL回退 + 双模式PACK兼容 + 实时诊断日志)
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
	"runtime"
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
	fastSessMap     sync.Map
	dnsCache        sync.Map
	failCache       sync.Map
	slotBackoff     sync.Map
	tlsSessionCache = tls.NewLRUClientSessionCache(512)
	pppPool         = sync.Pool{
		New: func() any { b := make([]byte, 2048); return &b },
	}
	readBufPool = sync.Pool{
		New: func() any { b := make([]byte, 65536); return &b },
	}
)

func init() {
	prewarm := map[string][]byte{
		"dns.msftncsi.com":              {131, 107, 255, 255},
		"connectivitycheck.gstatic.com": {142, 250, 190, 78},
		"cp.cloudflare.com":             {104, 16, 132, 229},
		"captive.apple.com":             {17, 253, 144, 10},
	}
	farFuture := time.Now().Add(24 * time.Hour)
	for host, ip := range prewarm {
		dnsCache.Store(host, dnsEntry{ip: ip, expire: farFuture})
	}

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

// 修复 1：显式锁死经典椭圆曲线与 TLS 1.2，彻底禁用 Go 1.27 默认开启的 X25519MLKEM768 后量子巨型分片包
func buildCompatTLSConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		ClientSessionCache: tlsSessionCache,
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}
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

func tryReuseExistingSession(baseKey, slotKey string) *sstpSession {
	for _, k := range []string{slotKey, baseKey + "#0", baseKey + "#1"} {
		if v, ok := fastSessMap.Load(k); ok && v != nil {
			s := v.(*sstpSession)
			if isAlive(s) {
				fastSessMap.Store(slotKey, s)
				return s
			}
			fastSessMap.Delete(k)
		}
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	for _, k := range []string{slotKey, baseKey + "#0", baseKey + "#1"} {
		if existing, ok := sessPool[k]; ok && isAlive(existing) {
			sessPool[slotKey] = existing
			sessPool[baseKey+"#0"] = existing
			sessPool[baseKey+"#1"] = existing
			fastSessMap.Store(slotKey, existing)
			fastSessMap.Store(baseKey+"#0", existing)
			fastSessMap.Store(baseKey+"#1", existing)
			return existing
		}
		delete(sessPool, k)
	}
	return nil
}

func bindSessionAllSlots(baseKey, slotKey string, sess *sstpSession) {
	if sess == nil {
		return
	}
	sessMu.Lock()
	sessPool[slotKey] = sess
	sessPool[baseKey+"#0"] = sess
	sessPool[baseKey+"#1"] = sess
	sessMu.Unlock()
	fastSessMap.Store(slotKey, sess)
	fastSessMap.Store(baseKey+"#0", sess)
	fastSessMap.Store(baseKey+"#1", sess)
}

func unbindSessionAllSlots(baseKey, slotKey string, sess *sstpSession) {
	sessMu.Lock()
	for _, k := range []string{slotKey, baseKey + "#0", baseKey + "#1"} {
		if cur, ok := sessPool[k]; ok && cur == sess {
			delete(sessPool, k)
		}
		if cur, ok := fastSessMap.Load(k); ok && cur == sess {
			fastSessMap.Delete(k)
		}
	}
	sessMu.Unlock()
}

func hasAnyAliveSlot(baseKey string) bool {
	return tryReuseExistingSession(baseKey, baseKey+"#0") != nil
}

func isVPNGateServer(server *protocol.ServerSpec) bool {
	if server == nil || server.User == nil || server.User.Account == nil {
		return false
	}
	if acc, ok := server.User.Account.(*Account); ok {
		u := strings.ToLower(strings.TrimSpace(acc.Username))
		if u == "vpn" || u == "vpngate" {
			pw := strings.ToLower(strings.TrimSpace(acc.Password))
			baseKey := server.Destination.String()
			if pw == "ssl" || pw == "softether" || strings.HasPrefix(pw, "ssl:") {
				ovpnProtoCache.Store(baseKey, "softether-ssl")
			} else {
				cacheOVPNFromPassword(baseKey, acc.Password)
			}
			return true
		}
	}
	return false
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
				select {
				case <-time.After(time.Duration(1100+(idx-1)*150) * time.Millisecond):
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

func (sess *sstpSession) writeFrame(data []byte) error {
	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
	_, err := sess.bw.Write(data)
	if err == nil {
		err = sess.bw.Flush()
	}
	return err
}

func (sess *sstpSession) writeSoftEtherFrames(ethFrames [][]byte) error {
	if len(ethFrames) == 0 {
		return nil
	}
	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
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
	return sess.bw.Flush()
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

func getOrCreateSSTPSession(ctx context.Context, serverDest net.Destination, dialer internet.Dialer) (*sstpSession, error) {
	baseKey := serverDest.String()
	slotKey := baseKey + "#0"
	if existing := tryReuseExistingSession(baseKey, slotKey); existing != nil {
		return existing, nil
	}
	return ovpnDialSF.Do(baseKey+"|main", func() (*sstpSession, error) {
		if existing := tryReuseExistingSession(baseKey, slotKey); existing != nil {
			return existing, nil
		}
		return dialSlotSession(ctx, serverDest, dialer, baseKey, slotKey, false)
	})
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
	minRTO := tcpip.TCPMinRTOOption(250 * time.Millisecond)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &minRTO)

	rcvBuf := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 2 * 1024 * 1024, Max: 3584 * 1024}
	sndBuf := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 2 * 1024 * 1024, Max: 3584 * 1024}
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
	if existing := tryReuseExistingSession(baseKey, slotKey); existing != nil {
		return existing, nil
	}

	mu := getSlotMutex(slotKey)
	mu.Lock()
	defer mu.Unlock()

	if existing := tryReuseExistingSession(baseKey, slotKey); existing != nil {
		return existing, nil
	}

	if !isBackground {
		if failTime, ok := failCache.Load(baseKey); ok {
			if time.Since(failTime.(time.Time)) < 6*time.Second {
				return nil, fmt.Errorf("节点 %s 处于失败冷却中", baseKey)
			}
			failCache.Delete(baseKey)
		}
	}

	bgCtx := context.Background()
	pCached, _ := ovpnProtoCache.Load(baseKey)

	{
		ovpnCfg := getOrDefaultOVPNConfig(baseKey)
		if ovpnCfg.mode == "tcp" {
			sess, ovpnErr := dialOpenVPNSession(serverDest, dialer, baseKey, slotKey, ovpnCfg, false)
			if ovpnErr == nil {
				ovpnProtoCache.Store(baseKey, "openvpn-tcp")
				return sess, nil
			}
			recordNodeFailureIfNeeded(baseKey, isBackground, ovpnErr)
			return nil, ovpnErr
		}
		if ovpnCfg.mode == "udp" || pCached == "openvpn-udp" {
			sess, ovpnErr := dialOpenVPNSession(serverDest, dialer, baseKey, slotKey, ovpnCfg, true)
			if ovpnErr == nil {
				ovpnProtoCache.Store(baseKey, "openvpn-udp")
				return sess, nil
			}
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
			if ovpnCfg.udpPort > 0 {
				if udpSess, udpErr := dialOpenVPNSession(serverDest, dialer, baseKey, slotKey, ovpnCfg, true); udpErr == nil {
					ovpnProtoCache.Store(baseKey, "openvpn-udp")
					return udpSess, nil
				}
			}
			if isDedicatedOVPNPort {
				recordNodeFailureIfNeeded(baseKey, isBackground, ovpnErr)
				return nil, ovpnErr
			}
		}
	}

	// 1. 优先直接走 SoftEther-SSL 原生协议 (第 1 条连接直接秒连，不等 SSTP 超时)
	if pCached != "ms-sstp" {
		sess, seErr := dialSoftEtherNativeSession(serverDest, dialer, baseKey, slotKey, isBackground)
		if seErr == nil {
			ovpnProtoCache.Store(baseKey, "softether-ssl")
			return sess, nil
		}
		errors.LogInfo(bgCtx, fmt.Sprintf("[VPNGate] SoftEther-SSL 未命中 (%v)，回退尝试 MS-SSTP -> %s", seErr, serverDest.String()))
	}

	// 2. 回退尝试 MS-SSTP 协议
	if sstpSess, sstpErr := dialMSSSTPSession(serverDest, dialer, baseKey, slotKey, isBackground); sstpErr == nil {
		ovpnProtoCache.Store(baseKey, "ms-sstp")
		return sstpSess, nil
	} else if pCached == "ms-sstp" {
		if sess, seErr := dialSoftEtherNativeSession(serverDest, dialer, baseKey, slotKey, isBackground); seErr == nil {
			ovpnProtoCache.Store(baseKey, "softether-ssl")
			return sess, nil
		}
	}

	// 3. 最终兜底尝试 OpenVPN (TCP / UDP)
	ovpnCfg := getOrDefaultOVPNConfig(baseKey)
	if ovpnSess, ovpnErr := dialOpenVPNSession(serverDest, dialer, baseKey, slotKey, ovpnCfg, false); ovpnErr == nil {
		ovpnProtoCache.Store(baseKey, "openvpn-tcp")
		return ovpnSess, nil
	}
	if ovpnCfg.udpPort > 0 {
		if udpSess, udpErr := dialOpenVPNSession(serverDest, dialer, baseKey, slotKey, ovpnCfg, true); udpErr == nil {
			ovpnProtoCache.Store(baseKey, "openvpn-udp")
			return udpSess, nil
		}
	}

	err := fmt.Errorf("节点 %s 全协议 (SSL/SSTP/OVPN) 握手均未就绪", baseKey)
	recordNodeFailureIfNeeded(baseKey, isBackground, err)
	return nil, err
}

func dialMSSSTPSession(serverDest net.Destination, dialer internet.Dialer, baseKey, slotKey string, isBackground bool) (*sstpSession, error) {
	bgCtx := context.Background()
	// 持久化 connCtx：绝不在函数 return 时触发 cancel 掐断底层前置 VLESS 管道
	connCtx, connCancel := context.WithCancel(bgCtx)
	var handshakeSucceeded atomic.Bool
	stopWatch := make(chan struct{})
	defer func() {
		close(stopWatch)
		if !handshakeSucceeded.Load() {
			connCancel()
		}
	}()
	go func() {
		select {
		case <-time.After(10 * time.Second):
			if !handshakeSucceeded.Load() {
				connCancel()
			}
		case <-stopWatch:
		}
	}()

	rawConn, activePort, err := dialWithPortFallback(connCtx, dialer, serverDest)
	if err != nil {
		return nil, err
	}

	host := serverDest.Address.String()
	tlsConn := tls.Client(rawConn, buildCompatTLSConfig(host))
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.HandshakeContext(connCtx); err != nil {
		rawConn.Close()
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
	_ = tlsConn.SetDeadline(time.Now().Add(1800 * time.Millisecond))
	_, writeErr := tlsConn.Write([]byte(sstpReq))
	br := bufio.NewReaderSize(tlsConn, 131072)
	var statusLine string
	var readErr error
	if writeErr == nil {
		statusLine, readErr = br.ReadString('\n')
	}
	if writeErr != nil || readErr != nil || !strings.Contains(statusLine, "200") {
		rawConn.Close()
		return nil, fmt.Errorf("SSTP HTTP 非 200")
	}

	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	_ = rawConn.SetDeadline(time.Time{})
	_ = tlsConn.SetDeadline(time.Time{})

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

	var lastRxNano, lastActiveNano atomic.Int64
	nowNano := time.Now().UnixNano()
	lastRxNano.Store(nowNano)
	lastActiveNano.Store(nowNano)

	ipReady := make(chan tcpip.Address, 1)
	var once sync.Once
	var deadOnce sync.Once
	markDead := func() {
		deadOnce.Do(func() {
			close(sess.dead)
			unbindSessionAllSlots(baseKey, slotKey, sess)
			connCancel()
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
			if _, err := io.ReadFull(br, hdr); err != nil {
				return
			}
			lastRxNano.Store(time.Now().UnixNano())
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
							if binary.BigEndian.Uint16(opts[2:4]) != 0xc023 {
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
						sess.sendPPPControl(0xc021, []byte{0x03, id, 0x00, 0x08, 0x03, 0x04, 0xc0, 0x23})
					} else {
						sess.sendPPPControl(0xc021, append([]byte{0x02}, pppData[1:]...))
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
					sess.sendPPPControl(0x8021, append([]byte{0x02}, pppData[1:]...))
				} else if code == 0x03 && len(pppData) >= 10 {
					ip := pppData[6:10]
					sess.sendPPPControl(0x8021, []byte{0x01, id + 1, 0x00, 0x0a, 0x03, 0x06, ip[0], ip[1], ip[2], ip[3]})
				} else if code == 0x02 && len(pppData) >= 10 {
					sendCallConnected()
					addr := tcpip.AddrFromSlice(pppData[6:10])
					errors.LogInfo(bgCtx, fmt.Sprintf("[VPNGate] 隧道就绪 (%s) | 协议: MS-SSTP | 端口: %d | IP: %s", slotKey, activePort, addr.String()))
					once.Do(func() { ipReady <- addr })
				}
			case 0x0021:
				if len(pppData) >= 20 {
					if tot := int(binary.BigEndian.Uint16(pppData[2:4])); tot >= 20 && tot <= len(pppData) {
						pppData = pppData[:tot]
					}
					lastActiveNano.Store(time.Now().UnixNano())
					clampIPv4TCPMSSInPlace(pppData, 1240)
					pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
						Payload: buffer.MakeWithData(pppData),
					})
					ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
					pkt.DecRef()
				}
			}
		}
	}()

	go func() {
		defer markDead()
		var sstpHdr [8]byte
		sstpHdr[0], sstpHdr[1] = 0x10, 0x00
		sstpHdr[4], sstpHdr[5] = 0xff, 0x03
		sstpHdr[6], sstpHdr[7] = 0x00, 0x21

		writeOnePacket := func(pkt *stack.PacketBuffer) error {
			view := pkt.ToView()
			data := view.AsSlice()
			total := 8 + len(data)
			if total > 0x3FFF {
				view.Release()
				pkt.DecRef()
				return nil
			}
			clampIPv4TCPMSSInPlace(data, 1240)
			binary.BigEndian.PutUint16(sstpHdr[2:4], uint16(total))
			_, err := sess.bw.Write(sstpHdr[:])
			if err == nil {
				_, err = sess.bw.Write(data)
			}
			view.Release()
			pkt.DecRef()
			return err
		}

		for {
			pkt := ep.ReadContext(bgCtx)
			if pkt == nil {
				return
			}
			lastActiveNano.Store(time.Now().UnixNano())
			sess.writeMu.Lock()
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
			sess.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer markDead()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sess.dead:
				return
			case <-ticker.C:
				now := time.Now().UnixNano()
				if now-lastRxNano.Load() > int64(45*time.Second) || now-lastActiveNano.Load() > int64(600*time.Second) {
					return
				}
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
		markDead()
		return nil, fmt.Errorf("SSTP 握手中被服务端断开")
	case <-time.After(3500 * time.Millisecond):
		markDead()
		return nil, fmt.Errorf("SSTP PPP/IPCP 协商超时")
	}

	_ = s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: localIP, PrefixLen: 8},
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	handshakeSucceeded.Store(true)
	slotBackoff.Delete(slotKey)
	bindSessionAllSlots(baseKey, slotKey, sess)
	return sess, nil
}

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
		writeU32(uint32(len(v)))
		b.WriteString(v)
	}
	addInt := func(k string, v uint32) {
		writeName(k)
		writeU32(0)
		writeU32(1)
		writeU32(v)
	}
	// 同时兼容 Cedar/Protocol.c 的 hello/version/build/client_id 与 client_str/client_ver/client_build
	writeU32(16)
	addStr("method", "login")
	addStr("hubname", "VPNGATE")
	addStr("username", "vpn")
	addInt("authtype", 0)
	addInt("protocol", 0)
	addStr("hello", "SoftEther VPN Client")
	addInt("version", 442)
	addInt("build", 9798)
	addInt("client_id", 1)
	addInt("use_encrypt", 0)
	addInt("use_compress", 0)
	addInt("max_connection", 1)
	addInt("half_connection", 0)
	addStr("client_str", "SoftEther VPN Client")
	addInt("client_ver", 442)
	addInt("client_build", 9798)
	return b.Bytes()
}

func checkSoftEtherLoginResponse(body []byte) error {
	if len(body) < 4 {
		return fmt.Errorf("SoftEther 登录响应过短: %d", len(body))
	}
	data := body
	firstU32 := binary.BigEndian.Uint32(data[0:4])
	if firstU32 > 256 && int(firstU32) <= len(data)-4 && len(data) >= 8 {
		data = data[4 : 4+int(firstU32)]
	}
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
		if !ok || nameLen == 0 {
			break
		}
		actualNameBytes := int(nameLen) - 1
		if actualNameBytes < 0 || pos+actualNameBytes > len(data) {
			break
		}
		name := strings.TrimRight(string(data[pos:pos+actualNameBytes]), "\x00")
		pos += actualNameBytes

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
			case 0:
				v, ok := readU32()
				if !ok {
					return nil
				}
				if name == "error" && j == 0 && v != 0 {
					return fmt.Errorf("SoftEther 拒绝登录 (error=%d)", v)
				}
			case 4:
				if pos+8 > len(data) {
					return nil
				}
				pos += 8
			case 1, 2, 3:
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
			_, _ = fmt.Sscanf(strings.TrimSpace(lower[len("content-length:"):]), "%d", &contentLen)
		}
	}
	if contentLen <= 0 || contentLen > 65536 {
		return nil, fmt.Errorf("SoftEther 响应体长度无效: %d", contentLen)
	}
	body := make([]byte, contentLen)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	return body, nil
}

func buildDHCPFrame(msgType byte, xid uint32, myMAC [6]byte, reqIP, serverIP []byte) []byte {
	bootp := make([]byte, 300)
	bootp[0], bootp[1], bootp[2] = 1, 1, 6
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
	bootp[idx+5] = 255

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
	ip[8], ip[9] = 64, 17
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
	// 持久化 connCtx：保证握手返回后底层前置 VLESS 管道绝不被 defer cancel 杀死
	connCtx, connCancel := context.WithCancel(bgCtx)
	var handshakeSucceeded atomic.Bool
	stopWatch := make(chan struct{})
	defer func() {
		close(stopWatch)
		if !handshakeSucceeded.Load() {
			connCancel()
		}
	}()
	go func() {
		select {
		case <-time.After(11 * time.Second):
			if !handshakeSucceeded.Load() {
				connCancel()
			}
		case <-stopWatch:
		}
	}()

	rawConn, activePort, err := dialWithPortFallback(connCtx, dialer, serverDest)
	if err != nil {
		return nil, err
	}

	host := serverDest.Address.String()
	tlsConn := tls.Client(rawConn, buildCompatTLSConfig(host))
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.HandshakeContext(connCtx); err != nil {
		rawConn.Close()
		return nil, err
	}

	_ = rawConn.SetDeadline(time.Time{})
	_ = tlsConn.SetDeadline(time.Now().Add(4 * time.Second))
	sigReq := fmt.Sprintf("POST /vpnsvc/connect.cgi HTTP/1.1\r\nHost: %s\r\nContent-Type: image/jpeg\r\nConnection: Keep-Alive\r\nContent-Length: 10\r\n\r\nVPNCONNECT", host)
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
	fmt.Fprintf(&loginBuf, "POST /vpnsvc/vpn.cgi HTTP/1.1\r\nHost: %s\r\nContent-Type: image/jpeg\r\nConnection: Keep-Alive\r\nContent-Length: %d\r\n\r\n", host, len(packBytes))
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

func inspectSoftEtherHelloPack(body []byte) (strPlusOne bool) {
	data := body
	if len(data) >= 8 {
		first := binary.BigEndian.Uint32(data[0:4])
		if first > 256 && int(first) <= len(data)-4 {
			data = data[4 : 4+int(first)]
		}
	}
	if len(data) < 20 {
		return false
	}
	pos := 4
	nameLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if nameLen <= 1 || pos+nameLen-1+12 > len(data) {
		return false
	}
	pos += nameLen - 1
	valType := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 8 // skip type + num_values
	if valType == 2 && pos+4 <= len(data) {
		sLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if sLen > 0 && pos+sLen-1 < len(data) && data[pos+sLen-1] == 0 {
			return true
		}
	}
	return false
}

func buildSoftEtherLoginPack(strPlusOne bool) []byte {
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
		if strPlusOne {
			writeU32(uint32(len(v) + 1))
		} else {
			writeU32(uint32(len(v)))
		}
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

func checkSoftEtherLoginResponse(body []byte, strPlusOne bool) error {
	if len(body) < 4 {
		return fmt.Errorf("SoftEther 登录响应过短: %d", len(body))
	}
	data := body
	firstU32 := binary.BigEndian.Uint32(data[0:4])
	if firstU32 > 256 && int(firstU32) <= len(data)-4 && len(data) >= 8 {
		data = data[4 : 4+int(firstU32)]
	}
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
		if !ok || nameLen == 0 {
			break
		}
		actualNameBytes := int(nameLen) - 1
		if actualNameBytes < 0 || pos+actualNameBytes > len(data) {
			break
		}
		name := strings.TrimRight(string(data[pos:pos+actualNameBytes]), "\x00")
		pos += actualNameBytes

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
			case 0:
				v, ok := readU32()
				if !ok {
					return nil
				}
				if name == "error" && j == 0 && v != 0 {
					return fmt.Errorf("SoftEther 拒绝登录 (error=%d)", v)
				}
			case 4:
				if pos+8 > len(data) {
					return nil
				}
				pos += 8
			case 2:
				dLen, ok := readU32()
				if !ok {
					return nil
				}
				adv := int(dLen)
				if strPlusOne && adv > 0 {
					adv--
				}
				if adv < 0 || pos+adv > len(data) {
					return nil
				}
				pos += adv
			case 1, 3:
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

// 自适应读取：同时兼容 HTTP/1.1 200 OK 封装与纯二进制 RecvPack 流
func readSoftEtherPackOrHTTP(br *bufio.Reader) ([]byte, error) {
	peek, err := br.Peek(4)
	if err != nil {
		return nil, err
	}
	if string(peek) != "HTTP" {
		rawLen := int(binary.BigEndian.Uint32(peek))
		if rawLen <= 0 || rawLen > 65536 {
			return nil, fmt.Errorf("SoftEther 非HTTP响应首字异常: %x", peek)
		}
		_, _ = br.Discard(4)
		body := make([]byte, rawLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, err
		}
		return body, nil
	}

	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(statusLine, "200") {
		return nil, fmt.Errorf("HTTP状态异常: %s", strings.TrimSpace(statusLine))
	}
	contentLen := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "content-length:") {
			_, _ = fmt.Sscanf(strings.TrimSpace(lower[len("content-length:"):]), "%d", &contentLen)
		}
	}
	if contentLen <= 0 || contentLen > 65536 {
		return nil, fmt.Errorf("HTTP响应体长度无效: %d", contentLen)
	}
	body := make([]byte, contentLen)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	return body, nil
}

func buildDHCPFrame(msgType byte, xid uint32, myMAC [6]byte, reqIP, serverIP []byte) []byte {
	bootp := make([]byte, 300)
	bootp[0], bootp[1], bootp[2] = 1, 1, 6
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
	bootp[idx+5] = 255

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
	ip[8], ip[9] = 64, 17
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
	connCtx, connCancel := context.WithCancel(bgCtx)
	var handshakeSucceeded atomic.Bool
	var rawConn net.Conn
	var stage atomic.Value
	stage.Store("0-前置拨号")

	// 用真实定时器关闭管道，解决 Xray 链式代理 cnc.Connection 下 SetDeadline 空函数失效问题
	abortTimer := time.AfterFunc(6500*time.Millisecond, func() {
		if !handshakeSucceeded.Load() {
			connCancel()
			if rawConn != nil {
				_ = rawConn.Close()
			}
		}
	})
	defer func() {
		abortTimer.Stop()
		if !handshakeSucceeded.Load() {
			connCancel()
		}
	}()

	var activePort net.Port
	var err error
	rawConn, activePort, err = dialWithPortFallback(connCtx, dialer, serverDest)
	if err != nil {
		return nil, fmt.Errorf("阶段[%s]: %w", stage.Load().(string), err)
	}

	stage.Store("1-TLS握手")
	host := serverDest.Address.String()
	sniHost := host
	if serverDest.Address.Family().IsIP() {
		sniHost = "www.microsoft.com"
	}
	tlsConn := tls.Client(rawConn, buildCompatTLSConfig(sniHost))
	if err := tlsConn.HandshakeContext(connCtx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("阶段[%s]: %w", stage.Load().(string), err)
	}

	// TLS 握手已通，重置定时器给 HTTP/PACK 握手与 DHCP 留足 5 秒
	abortTimer.Reset(5000 * time.Millisecond)
	stage.Store("2-connect.cgi签名")
	sigReq := fmt.Sprintf("POST /vpnsvc/connect.cgi HTTP/1.1\r\nHost: %s\r\nContent-Type: image/jpeg\r\nConnection: Keep-Alive\r\nContent-Length: 10\r\n\r\nVPNCONNECT", host)
	if _, err := tlsConn.Write([]byte(sigReq)); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("阶段[%s写]: %w", stage.Load().(string), err)
	}
	br := bufio.NewReaderSize(tlsConn, 131072)
	helloBody, err := readSoftEtherPackOrHTTP(br)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("阶段[%s读]: %w", stage.Load().(string), err)
	}

	stage.Store("3-vpn.cgi登录")
	strPlusOne := inspectSoftEtherHelloPack(helloBody)
	packBytes := buildSoftEtherLoginPack(strPlusOne)
	var loginBuf bytes.Buffer
	fmt.Fprintf(&loginBuf, "POST /vpnsvc/vpn.cgi HTTP/1.1\r\nHost: %s\r\nContent-Type: image/jpeg\r\nConnection: Keep-Alive\r\nContent-Length: %d\r\n\r\n", host, len(packBytes))
	loginBuf.Write(packBytes)

	if _, err := tlsConn.Write(loginBuf.Bytes()); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("阶段[%s写]: %w", stage.Load().(string), err)
	}
	loginRespBody, err := readSoftEtherPackOrHTTP(br)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("阶段[%s读]: %w", stage.Load().(string), err)
	}
	if err := checkSoftEtherLoginResponse(loginRespBody, strPlusOne); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("阶段[%s验]: %w", stage.Load().(string), err)
	}

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

	var lastRxNano, lastActiveNano atomic.Int64
	nowNano := time.Now().UnixNano()
	lastRxNano.Store(nowNano)
	lastActiveNano.Store(nowNano)

	type dhcpLease struct {
		ip        tcpip.Address
		prefixLen int
	}
	ipReady := make(chan dhcpLease, 1)
	var once sync.Once
	var deadOnce sync.Once
	var assignedIP [4]byte
	var hasIP, offerReceived atomic.Bool

	markDead := func() {
		deadOnce.Do(func() {
			close(sess.dead)
			unbindSessionAllSlots(baseKey, slotKey, sess)
			connCancel()
			rawConn.Close()
			s.Close()
		})
	}
	sess.markDead = markDead

	xidBytes := make([]byte, 4)
	_, _ = rand.Read(xidBytes)
	dhcpXid := binary.BigEndian.Uint32(xidBytes)
	discoverFrame := buildDHCPFrame(1, dhcpXid, myMAC, nil, nil)
	_ = sess.writeSoftEtherFrames([][]byte{discoverFrame})

	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for i := 0; i < 12; i++ {
			select {
			case <-sess.dead:
				return
			case <-ticker.C:
				if hasIP.Load() || offerReceived.Load() {
					return
				}
				_ = sess.writeSoftEtherFrames([][]byte{discoverFrame})
			}
		}
	}()

	go func() {
		defer markDead()
		var hdr [4]byte
		for {
			if _, err := io.ReadFull(br, hdr[:]); err != nil {
				return
			}
			lastRxNano.Store(time.Now().UnixNano())
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
					if binary.BigEndian.Uint16(eth[20:22]) == 1 && hasIP.Load() && bytes.Equal(eth[38:42], assignedIP[:]) {
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
				if tot := int(binary.BigEndian.Uint16(ipPkt[2:4])); tot >= 20 && tot <= len(ipPkt) {
					ipPkt = ipPkt[:tot]
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
								var srvID, subnetMask []byte
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
									offerReceived.Store(true)
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
									errors.LogInfo(bgCtx, fmt.Sprintf("[VPNGate] 隧道就绪 (%s) | 协议: SoftEther-SSL | 端口: %d | IP: %s/%d", slotKey, activePort, addr.String(), prefixLen))
									once.Do(func() { ipReady <- dhcpLease{ip: addr, prefixLen: prefixLen} })
								}
							}
							continue
						}
					}
				}

				lastActiveNano.Store(time.Now().UnixNano())
				clampIPv4TCPMSSInPlace(ipPkt, 1240)
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
		var batch [64]*stack.PacketBuffer
		var countBuf [4]byte
		var frameHdr [18]byte
		copy(frameHdr[10:16], myMAC[:])
		frameHdr[16], frameHdr[17] = 0x08, 0x00

		for {
			pkt := ep.ReadContext(bgCtx)
			if pkt == nil {
				return
			}
			lastActiveNano.Store(time.Now().UnixNano())
			batch[0] = pkt
			nBatch := 1
			for nBatch < 64 {
				nextPkt := ep.Read()
				if nextPkt == nil {
					break
				}
				batch[nBatch] = nextPkt
				nBatch++
			}

			gw := sess.gwMAC.Load().([6]byte)
			copy(frameHdr[4:10], gw[:])
			binary.BigEndian.PutUint32(countBuf[:], uint32(nBatch))

			sess.writeMu.Lock()
			_, wErr := sess.bw.Write(countBuf[:])
			for i := 0; i < nBatch; i++ {
				p := batch[i]
				batch[i] = nil
				v := p.ToView()
				ipData := v.AsSlice()
				clampIPv4TCPMSSInPlace(ipData, 1240)
				binary.BigEndian.PutUint32(frameHdr[0:4], uint32(14+len(ipData)))
				if wErr == nil {
					_, wErr = sess.bw.Write(frameHdr[:])
				}
				if wErr == nil {
					_, wErr = sess.bw.Write(ipData)
				}
				v.Release()
				p.DecRef()
			}
			if wErr == nil {
				wErr = sess.bw.Flush()
			}
			sess.writeMu.Unlock()
			if wErr != nil {
				return
			}
		}
	}()

	go func() {
		defer markDead()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sess.dead:
				return
			case <-ticker.C:
				now := time.Now().UnixNano()
				if now-lastRxNano.Load() > int64(45*time.Second) || now-lastActiveNano.Load() > int64(600*time.Second) {
					return
				}
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
		markDead()
		return nil, fmt.Errorf("SoftEther 隧道在握手中提前断开")
	case <-time.After(4500 * time.Millisecond):
		markDead()
		return nil, fmt.Errorf("SoftEther Virtual DHCP 分配 IP 超时")
	}

	_ = s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: lease.ip, PrefixLen: lease.prefixLen},
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	handshakeSucceeded.Store(true)
	slotBackoff.Delete(slotKey)
	bindSessionAllSlots(baseKey, slotKey, sess)
	return sess, nil
}

func resolveFast(ctx context.Context, dialer internet.Dialer, sess *sstpSession, domain string) ([]byte, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if cached, ok := dnsCache.Load(domain); ok {
		if entry, ok := cached.(dnsEntry); ok && time.Now().Before(entry.expire) && len(entry.ip) == 4 {
			return entry.ip, nil
		}
	}
	return ovpnFastResolveIPv4(ctx, dialer, sess, domain)
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
		return err
	}
	defer gConn.Close()

	downErrCh := make(chan error, 1)
	upErrCh := make(chan error, 1)

	go func() {
		bp := readBufPool.Get().(*[]byte)
		defer readBufPool.Put(bp)
		b := *bp
		var totalDown int64
		for {
			rSlice := b
			if totalDown > 1536*1024 {
				rSlice = b[:16384]
				runtime.Gosched()
			}
			n, rErr := gConn.Read(rSlice)
			totalDown += int64(n)
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
        new_code, n = re.subn(
            r"(func\s*\(c\s*\*Client\)\s*Process\s*\([^)]*\)[^{]*\{[\s\S]*?server\s*:=\s*[^\n]+)",
            r"\1\n" + hook_snippet,
            c_code,
            count=1,
        )
        if n == 0:
            raise RuntimeError("❌ 未能在 proxy/socks/client.go 的 Process 函数中匹配到 server 变量赋值行！")
        with open(client_go, "w", encoding="utf-8") as f:
            f.write(new_code)
        print("  ✔ [VPNGate 主引擎] 成功注入无锁单槽、SoftEther/SSTP零拷贝流与多路DNS抢答")

# =========================================================================
# 7. 注入 VPNGate 爆发+稳定双兼顾引擎 (QoS小包插队 + 3.5MB黄金BDP + 僵尸隧道秒级熔断 + Google DoT)
# =========================================================================
if os.path.exists(socks_dir):
    ovpn_file = os.path.join(socks_dir, "vpngate_openvpn.go")
    ovpn_src = r"""package socks

import (
	"bufio"
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
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type parsedOVPNConfig struct {
	mode       string
	tcpPort    uint16
	udpPort    uint16
	cipherName string
	authName   string
	compLZO    bool
}

var (
	ovpnConfigCache sync.Map
	ovpnProtoCache  sync.Map

	ovpnBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 4096)
			return &b
		},
	}
	ovpnBatchPool = sync.Pool{
		New: func() any {
			b := make([]byte, 32768)
			return &b
		},
	}
)

type ovpnSFCall[T any] struct {
	wg  sync.WaitGroup
	val T
	err error
}

type ovpnSingleflight[T any] struct {
	mu sync.Mutex
	m  map[string]*ovpnSFCall[T]
}

func (g *ovpnSingleflight[T]) Do(key string, fn func() (T, error)) (T, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*ovpnSFCall[T])
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := new(ovpnSFCall[T])
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return c.val, c.err
}

var (
	ovpnDialSF ovpnSingleflight[*sstpSession]
	ovpnDNSSF  ovpnSingleflight[[]byte]
)

func pickAnyLiveSession() *sstpSession {
	var found *sstpSession
	fastSessMap.Range(func(key, value any) bool {
		if s, ok := value.(*sstpSession); ok && isAlive(s) && s.s != nil {
			found = s
			return false
		}
		fastSessMap.Delete(key)
		return true
	})
	if found != nil {
		return found
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	for _, s := range sessPool {
		if isAlive(s) && s.s != nil {
			return s
		}
	}
	return nil
}

func buildDNSQueryA(domain string) ([]byte, uint16, error) {
	var txIDBuf [2]byte
	_, _ = rand.Read(txIDBuf[:])
	txID := binary.BigEndian.Uint16(txIDBuf[:])
	var buf bytes.Buffer
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], txID)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	buf.Write(hdr[:])
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, fmt.Errorf("bad domain: %s", domain)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.Write([]byte{0x00, 0x00, 0x01, 0x00, 0x01})
	return buf.Bytes(), txID, nil
}

func parseDNSResponseIPv4(pkt []byte, expectedTxID uint16) ([]byte, uint32, error) {
	if len(pkt) < 12 || binary.BigEndian.Uint16(pkt[0:2]) != expectedTxID {
		return nil, 0, fmt.Errorf("bad dns header")
	}
	qdcount := int(binary.BigEndian.Uint16(pkt[4:6]))
	ancount := int(binary.BigEndian.Uint16(pkt[6:8]))
	if ancount == 0 {
		return nil, 0, fmt.Errorf("no answer")
	}
	pos := 12
	skipName := func(p int) (int, bool) {
		for p < len(pkt) {
			l := int(pkt[p])
			if l == 0 {
				return p + 1, true
			}
			if (l & 0xc0) == 0xc0 {
				return p + 2, p+1 < len(pkt)
			}
			p += 1 + l
		}
		return 0, false
	}
	var ok bool
	for i := 0; i < qdcount; i++ {
		if pos, ok = skipName(pos); !ok || pos+4 > len(pkt) {
			return nil, 0, fmt.Errorf("bad qd")
		}
		pos += 4
	}
	for i := 0; i < ancount; i++ {
		if pos, ok = skipName(pos); !ok || pos+10 > len(pkt) {
			return nil, 0, fmt.Errorf("bad an")
		}
		rtype := binary.BigEndian.Uint16(pkt[pos : pos+2])
		rclass := binary.BigEndian.Uint16(pkt[pos+2 : pos+4])
		ttl := binary.BigEndian.Uint32(pkt[pos+4 : pos+8])
		rdlen := int(binary.BigEndian.Uint16(pkt[pos+8 : pos+10]))
		pos += 10
		if pos+rdlen > len(pkt) {
			return nil, 0, fmt.Errorf("bad rdata")
		}
		if rtype == 1 && rclass == 1 && rdlen == 4 {
			ip := make([]byte, 4)
			copy(ip, pkt[pos:pos+4])
			return ip, ttl, nil
		}
		pos += rdlen
	}
	return nil, 0, fmt.Errorf("no ipv4")
}

func queryUDP53OnStack(ctx context.Context, s *stack.Stack, dnsIP [4]byte, query []byte, txID uint16) ([]byte, uint32, error) {
	conn, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(dnsIP), Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	dl := time.Now().Add(1500 * time.Millisecond)
	if ctxDL, ok := ctx.Deadline(); ok && ctxDL.Before(dl) {
		dl = ctxDL
	}
	_ = conn.SetDeadline(dl)
	if _, err := conn.Write(query); err != nil {
		return nil, 0, err
	}
	var resp [512]byte
	n, err := conn.Read(resp[:])
	if err != nil {
		return nil, 0, err
	}
	return parseDNSResponseIPv4(resp[:n], txID)
}

func queryTCP53OnStack(ctx context.Context, s *stack.Stack, dnsIP [4]byte, query []byte, txID uint16) ([]byte, uint32, error) {
	dCtx, cancel := context.WithTimeout(ctx, 1600*time.Millisecond)
	defer cancel()
	conn, err := gonet.DialContextTCP(dCtx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(dnsIP), Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1600 * time.Millisecond))
	tcpReq := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpReq[0:2], uint16(len(query)))
	copy(tcpReq[2:], query)
	if _, err := conn.Write(tcpReq); err != nil {
		return nil, 0, err
	}
	var lenHdr [2]byte
	if _, err := io.ReadFull(conn, lenHdr[:]); err != nil {
		return nil, 0, err
	}
	msgLen := int(binary.BigEndian.Uint16(lenHdr[:]))
	if msgLen < 12 || msgLen > 4096 {
		return nil, 0, fmt.Errorf("bad tcp53 len")
	}
	resp := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, 0, err
	}
	return parseDNSResponseIPv4(resp, txID)
}

func queryOuterDoT(ctx context.Context, dialer internet.Dialer, dnsIP, sni string, query []byte, txID uint16) ([]byte, uint32, error) {
	if dialer == nil {
		return nil, 0, fmt.Errorf("nil dialer")
	}
	dCtx, cancel := context.WithTimeout(ctx, 1800*time.Millisecond)
	defer cancel()
	rawConn, err := dialer.Dial(dCtx, net.TCPDestination(net.ParseAddress(dnsIP), 853))
	if err != nil {
		return nil, 0, err
	}
	defer rawConn.Close()
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		ClientSessionCache: tlsSessionCache,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(1800 * time.Millisecond))
	if err := tlsConn.HandshakeContext(dCtx); err != nil {
		return nil, 0, err
	}
	tcpReq := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpReq[0:2], uint16(len(query)))
	copy(tcpReq[2:], query)
	if _, err := tlsConn.Write(tcpReq); err != nil {
		return nil, 0, err
	}
	var lenHdr [2]byte
	if _, err := io.ReadFull(tlsConn, lenHdr[:]); err != nil {
		return nil, 0, err
	}
	msgLen := int(binary.BigEndian.Uint16(lenHdr[:]))
	if msgLen < 12 || msgLen > 4096 {
		return nil, 0, fmt.Errorf("bad dot len")
	}
	resp := make([]byte, msgLen)
	if _, err := io.ReadFull(tlsConn, resp); err != nil {
		return nil, 0, err
	}
	return parseDNSResponseIPv4(resp, txID)
}

// 内层三路 UDP53 + 180ms 触发 TCP53 与 Google DoT (8.8.8.8:853) + 僵尸隧道秒级熔断器
func ovpnFastResolveIPv4(ctx context.Context, dialer internet.Dialer, sess *sstpSession, host string) ([]byte, error) {
	return ovpnDNSSF.Do(host, func() ([]byte, error) {
		if cached, ok := dnsCache.Load(host); ok {
			if entry, ok := cached.(dnsEntry); ok && time.Now().Before(entry.expire) && len(entry.ip) == 4 {
				return entry.ip, nil
			}
		}
		activeSess := sess
		if !isAlive(activeSess) || activeSess.s == nil {
			activeSess = pickAnyLiveSession()
		}
		if activeSess == nil || activeSess.s == nil {
			return nil, fmt.Errorf("no active tunnel stack for dns: %s", host)
		}
		query, txID, err := buildDNSQueryA(host)
		if err != nil {
			return nil, err
		}
		type dnsRes struct {
			ip      []byte
			ttl     uint32
			isOuter bool
			err     error
		}
		resCh := make(chan dnsRes, 6)
		innerAliveCh := make(chan struct{}, 5)
		probeCtx, probeCancel := context.WithTimeout(context.Background(), 1600*time.Millisecond)

		for _, srv := range [][4]byte{{8, 8, 8, 8}, {1, 1, 1, 1}, {9, 9, 9, 9}} {
			go func(ip [4]byte) {
				resIP, ttl, qErr := queryUDP53OnStack(probeCtx, activeSess.s, ip, query, txID)
				if qErr == nil && len(resIP) == 4 {
					select {
					case innerAliveCh <- struct{}{}:
					default:
					}
				}
				resCh <- dnsRes{ip: resIP, ttl: ttl, isOuter: false, err: qErr}
			}(srv)
		}

		go func() {
			select {
			case <-time.After(180 * time.Millisecond):
				go func() {
					resIP, ttl, qErr := queryTCP53OnStack(probeCtx, activeSess.s, [4]byte{8, 8, 8, 8}, query, txID)
					if qErr == nil && len(resIP) == 4 {
						select {
						case innerAliveCh <- struct{}{}:
						default:
						}
					}
					resCh <- dnsRes{ip: resIP, ttl: ttl, isOuter: false, err: qErr}
				}()
				go func() {
					resIP, ttl, qErr := queryTCP53OnStack(probeCtx, activeSess.s, [4]byte{1, 1, 1, 1}, query, txID)
					if qErr == nil && len(resIP) == 4 {
						select {
						case innerAliveCh <- struct{}{}:
						default:
						}
					}
					resCh <- dnsRes{ip: resIP, ttl: ttl, isOuter: false, err: qErr}
				}()
				// 改为 8.8.8.8 (dns.google)，彻底避开 Cloudflare Worker 禁连 1.1.1.1 的防火墙限制
				go func() {
					resIP, ttl, qErr := queryOuterDoT(probeCtx, dialer, "8.8.8.8", "dns.google", query, txID)
					resCh <- dnsRes{ip: resIP, ttl: ttl, isOuter: true, err: qErr}
				}()
			case <-probeCtx.Done():
			}
		}()

		var lastErr error
		for i := 0; i < 6; i++ {
			select {
			case <-ctx.Done():
				probeCancel()
				return nil, ctx.Err()
			case <-probeCtx.Done():
				probeCancel()
				if activeSess.markDead != nil {
					activeSess.markDead()
				}
				return nil, fmt.Errorf("tunnel dns timeout, zombie session purged")
			case r := <-resCh:
				if r.err == nil && len(r.ip) == 4 {
					dnsCache.Store(host, dnsEntry{ip: r.ip, expire: time.Now().Add(30 * time.Minute)})
					if r.isOuter {
						// 若外层 DoT 抢先返回，后台再给内层隧道 1.2s 宽限期；若 5 路内层查询全死，立即斩杀僵尸隧道
						go func(s *sstpSession) {
							defer probeCancel()
							select {
							case <-innerAliveCh:
							case <-time.After(1200 * time.Millisecond):
								if s.markDead != nil {
									s.markDead()
								}
							}
						}(activeSess)
					} else {
						probeCancel()
					}
					return r.ip, nil
				}
				lastErr = r.err
			}
		}
		probeCancel()
		if activeSess.markDead != nil {
			activeSess.markDead()
		}
		return nil, lastErr
	})
}

func getOrDefaultOVPNConfig(baseKey string) *parsedOVPNConfig {
	if v, ok := ovpnConfigCache.Load(baseKey); ok {
		return v.(*parsedOVPNConfig)
	}
	return &parsedOVPNConfig{mode: "default", cipherName: "AES-128-CBC", authName: "SHA1"}
}

func cacheOVPNFromPassword(baseKey, password string) {
	pw := strings.TrimSpace(password)
	if pw == "" || pw == "vpn" {
		return
	}
	if _, exists := ovpnConfigCache.Load(baseKey); exists {
		return
	}
	if strings.HasPrefix(pw, "tcp:") {
		if p, err := strconv.Atoi(strings.TrimPrefix(pw, "tcp:")); err == nil && p > 0 && p <= 65535 {
			ovpnConfigCache.Store(baseKey, &parsedOVPNConfig{mode: "tcp", tcpPort: uint16(p), cipherName: "AES-128-CBC", authName: "SHA1"})
		}
		return
	}
	if strings.HasPrefix(pw, "udp:") {
		if p, err := strconv.Atoi(strings.TrimPrefix(pw, "udp:")); err == nil && p > 0 && p <= 65535 {
			ovpnConfigCache.Store(baseKey, &parsedOVPNConfig{mode: "udp", udpPort: uint16(p), cipherName: "AES-128-CBC", authName: "SHA1"})
		}
		return
	}
	if strings.HasPrefix(pw, "both:") {
		parts := strings.Split(strings.TrimPrefix(pw, "both:"), ":")
		if len(parts) == 2 {
			tp, e1 := strconv.Atoi(parts[0])
			up, e2 := strconv.Atoi(parts[1])
			if e1 == nil && e2 == nil && tp > 0 && tp <= 65535 && up > 0 && up <= 65535 {
				ovpnConfigCache.Store(baseKey, &parsedOVPNConfig{mode: "both", tcpPort: uint16(tp), udpPort: uint16(up), cipherName: "AES-128-CBC", authName: "SHA1"})
			}
		}
		return
	}
	if strings.HasPrefix(pw, "ovpn:") {
		encoded := strings.TrimPrefix(pw, "ovpn:")
		var raw []byte
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding} {
			if b, err := enc.DecodeString(encoded); err == nil {
				raw = b
				break
			}
		}
		if len(raw) > 2 && raw[0] == 0x78 {
			if zr, zErr := zlib.NewReader(bytes.NewReader(raw)); zErr == nil {
				if unz, rErr := io.ReadAll(zr); rErr == nil {
					raw = unz
				}
				_ = zr.Close()
			}
		}
		if len(raw) > 0 {
			if cfg := parseOVPNText(string(raw)); cfg != nil {
				ovpnConfigCache.Store(baseKey, cfg)
			}
		}
	}
}

func parseOVPNText(text string) *parsedOVPNConfig {
	cfg := &parsedOVPNConfig{mode: "default", cipherName: "AES-128-CBC", authName: "SHA1"}
	hasTCP, hasUDP := false, false
	var remotePort uint16
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "proto":
			p := strings.ToLower(f[1])
			hasTCP = hasTCP || strings.HasPrefix(p, "tcp")
			hasUDP = hasUDP || strings.HasPrefix(p, "udp")
		case "remote":
			if len(f) >= 3 {
				if p, err := strconv.Atoi(f[2]); err == nil && p > 0 && p <= 65535 {
					remotePort = uint16(p)
				}
			}
		case "cipher", "data-ciphers":
			if strings.Contains(f[1], "256") {
				cfg.cipherName = "AES-256-CBC"
			}
		case "auth":
			if strings.EqualFold(f[1], "SHA256") {
				cfg.authName = "SHA256"
			}
		}
	}
	if hasUDP && !hasTCP && remotePort > 0 {
		cfg.mode, cfg.udpPort = "udp", remotePort
	} else if remotePort > 0 {
		cfg.tcpPort = remotePort
	}
	return cfg
}

type ovpnPacketIO interface {
	ReadPacket() ([]byte, error)
	WritePacket(pkt []byte) error
	WriteRawStream(raw []byte) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type tcpPacketIO struct {
	raw     net.Conn
	br      *bufio.Reader
	writeMu sync.Mutex
}

func (t *tcpPacketIO) ReadPacket() ([]byte, error) {
	var lenHdr [2]byte
	if _, err := io.ReadFull(t.br, lenHdr[:]); err != nil {
		return nil, err
	}
	pktLen := int(binary.BigEndian.Uint16(lenHdr[:]))
	if pktLen <= 0 || pktLen > 16384 {
		return nil, fmt.Errorf("bad tcp pkt len: %d", pktLen)
	}
	pkt := make([]byte, pktLen)
	if _, err := io.ReadFull(t.br, pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}

func (t *tcpPacketIO) WritePacket(pkt []byte) error {
	totalLen := 2 + len(pkt)
	if totalLen <= 4096 {
		bufPtr := ovpnBufPool.Get().(*[]byte)
		defer ovpnBufPool.Put(bufPtr)
		out := (*bufPtr)[:totalLen]
		binary.BigEndian.PutUint16(out[0:2], uint16(len(pkt)))
		copy(out[2:], pkt)
		t.writeMu.Lock()
		defer t.writeMu.Unlock()
		_, err := t.raw.Write(out)
		return err
	}
	out := make([]byte, totalLen)
	binary.BigEndian.PutUint16(out[0:2], uint16(len(pkt)))
	copy(out[2:], pkt)
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, err := t.raw.Write(out)
	return err
}

func (t *tcpPacketIO) WriteRawStream(raw []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, err := t.raw.Write(raw)
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
	bufPtr := ovpnBufPool.Get().(*[]byte)
	defer ovpnBufPool.Put(bufPtr)
	n, err := u.raw.Read(*bufPtr)
	if err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, fmt.Errorf("empty udp packet")
	}
	pkt := make([]byte, n)
	copy(pkt, (*bufPtr)[:n])
	return pkt, nil
}

func (u *udpPacketIO) WritePacket(pkt []byte) error {
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	_, err := u.raw.Write(pkt)
	return err
}

func (u *udpPacketIO) WriteRawStream(raw []byte) error    { return u.WritePacket(raw) }
func (u *udpPacketIO) Close() error                       { return u.raw.Close() }
func (u *udpPacketIO) LocalAddr() net.Addr                { return u.raw.LocalAddr() }
func (u *udpPacketIO) RemoteAddr() net.Addr               { return u.raw.RemoteAddr() }
func (u *udpPacketIO) SetDeadline(tm time.Time) error     { return u.raw.SetDeadline(tm) }
func (u *udpPacketIO) SetReadDeadline(tm time.Time) error { return u.raw.SetReadDeadline(tm) }
func (u *udpPacketIO) SetWriteDeadline(tm time.Time) error { return u.raw.SetWriteDeadline(tm) }
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
	lastRxNano    atomic.Int64

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
	c.lastRxNano.Store(time.Now().UnixNano())
	_, _ = rand.Read(c.localSID[:])
	go c.readerLoop()
	if isUDP {
		go c.arqRetransmitLoop()
	}
	return c
}

func (c *ovpnControlConn) stopRetransmit() {
	c.stopARQOnce.Do(func() { close(c.stopARQ) })
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
		pkt, err := c.pktIO.ReadPacket()
		if err != nil {
			c.fail(err)
			return
		}
		c.lastRxNano.Store(time.Now().UnixNano())
		if len(pkt) < 1 {
			continue
		}
		opcode := pkt[0] >> 3
		if opcode == 6 || opcode == 9 {
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
	ticker := time.NewTicker(500 * time.Millisecond)
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
			for id := uint32(0); id <= c.outPktID; id++ {
				if item, ok := c.unacked[id]; ok && now.Sub(item.lastSent) >= 500*time.Millisecond {
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
	for i := 0; i < ackLen; i++ {
		delete(c.unacked, binary.BigEndian.Uint32(pkt[10+4*i:14+4*i]))
	}
	c.mu.Unlock()

	if ackLen > 0 {
		pos += 8
	}
	if opcode == 5 || pos+4 > len(pkt) {
		return
	}
	remotePktID := binary.BigEndian.Uint32(pkt[pos : pos+4])
	pos += 4
	c.sendAck(remotePktID)

	c.mu.Lock()
	if remotePktID < c.nextRecvID {
		c.mu.Unlock()
		return
	}
	if opcode == 8 {
		if remotePktID == c.nextRecvID {
			c.nextRecvID++
		}
		c.mu.Unlock()
		c.resetAckOnce.Do(func() { close(c.resetAckCh) })
		return
	}
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
	pkt[0] = (7 << 3)
	copy(pkt[1:9], c.localSID[:])
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
		return fmt.Errorf("closed before reset ack")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *ovpnControlConn) Write(b []byte) (int, error) {
	total := len(b)
	for len(b) > 0 {
		chunk := len(b)
		if chunk > 800 {
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
		pkt[0] = (4 << 3)
		copy(pkt[1:9], c.localSID[:])
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

func (c *ovpnControlConn) Close() error {
	c.fail(io.ErrClosedPipe)
	return c.pktIO.Close()
}
func (c *ovpnControlConn) LocalAddr() net.Addr                { return c.pktIO.LocalAddr() }
func (c *ovpnControlConn) RemoteAddr() net.Addr               { return c.pktIO.RemoteAddr() }
func (c *ovpnControlConn) SetDeadline(t time.Time) error      { return c.pktIO.SetDeadline(t) }
func (c *ovpnControlConn) SetReadDeadline(t time.Time) error  { return c.pktIO.SetReadDeadline(t) }
func (c *ovpnControlConn) SetWriteDeadline(t time.Time) error { return c.pktIO.SetWriteDeadline(t) }

func openvpnPRF(secret, label, seed []byte, outLen int) []byte {
	fullSeed := append(append([]byte{}, label...), seed...)
	half := (len(secret) + 1) / 2
	s1, s2 := secret[:half], secret[len(secret)/2:]
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
	b1, b2 := pHash(md5.New, s1), pHash(sha1.New, s2)
	res := make([]byte, outLen)
	for i := 0; i < outLen; i++ {
		res[i] = b1[i] ^ b2[i]
	}
	return res
}

func clampIPv4TCPMSSInPlace(ipPkt []byte, maxMSS uint16) {
	if len(ipPkt) < 40 || (ipPkt[0]>>4) != 4 || ipPkt[9] != 6 {
		return
	}
	totLen := int(binary.BigEndian.Uint16(ipPkt[2:4]))
	if totLen < 40 || totLen > len(ipPkt) {
		return
	}
	ipPkt = ipPkt[:totLen]
	ihl := int(ipPkt[0]&0x0f) * 4
	if ihl < 20 || totLen < ihl+20 || (ipPkt[ihl+13]&0x02) == 0 {
		return
	}
	doff := int(ipPkt[ihl+12]>>4) * 4
	if doff <= 20 || totLen < ihl+doff {
		return
	}
	modified := false
	for i := ihl + 20; i < ihl+doff; {
		kind := ipPkt[i]
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
		optLen := int(ipPkt[i+1])
		if optLen < 2 || i+optLen > ihl+doff {
			break
		}
		if kind == 2 && optLen == 4 {
			if binary.BigEndian.Uint16(ipPkt[i+2:i+4]) > maxMSS {
				binary.BigEndian.PutUint16(ipPkt[i+2:i+4], maxMSS)
				modified = true
			}
			break
		}
		i += optLen
	}
	if !modified {
		return
	}
	ipPkt[ihl+16], ipPkt[ihl+17] = 0, 0
	tcpLen := totLen - ihl
	var sum uint32
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ipPkt[i : i+2]))
	}
	sum += 6 + uint32(tcpLen)
	for i := ihl; i+1 < totLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ipPkt[i : i+2]))
	}
	if tcpLen%2 == 1 {
		sum += uint32(ipPkt[totLen-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ipPkt[ihl+16:ihl+18], ^uint16(sum))
}

func dialOpenVPNSession(serverDest net.Destination, dialer internet.Dialer, baseKey, slotKey string, cfg *parsedOVPNConfig, useUDP bool) (*sstpSession, error) {
	if existing := tryReuseExistingSession(baseKey, slotKey); existing != nil {
		return existing, nil
	}
	protoTag := "tcp"
	if useUDP {
		protoTag = "udp"
	}
	return ovpnDialSF.Do(baseKey+"|"+protoTag, func() (*sstpSession, error) {
		if existing := tryReuseExistingSession(baseKey, slotKey); existing != nil {
			return existing, nil
		}
		return dialOpenVPNSessionCore(serverDest, dialer, baseKey, slotKey, cfg, useUDP)
	})
}

func dialOpenVPNSessionCore(serverDest net.Destination, dialer internet.Dialer, baseKey, slotKey string, cfg *parsedOVPNConfig, useUDP bool) (*sstpSession, error) {
	bgCtx := context.Background()
	connCtx, connCancel := context.WithCancel(bgCtx)
	var handshakeSucceeded atomic.Bool
	defer func() {
		if !handshakeSucceeded.Load() {
			connCancel()
		}
	}()

	handshakeCtx, handshakeCancel := context.WithTimeout(bgCtx, 12*time.Second)
	defer handshakeCancel()

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

	var ctrlMu sync.Mutex
	var ctrl *ovpnControlConn
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-handshakeCtx.Done():
			if !handshakeSucceeded.Load() {
				connCancel()
				ctrlMu.Lock()
				c := ctrl
				ctrlMu.Unlock()
				if c != nil {
					_ = c.Close()
				}
			}
		case <-stopWatch:
		}
	}()

	rawConn, err := dialer.Dial(connCtx, targetDest)
	if err != nil {
		return nil, err
	}

	var pktIO ovpnPacketIO
	if useUDP {
		pktIO = &udpPacketIO{raw: rawConn}
	} else {
		pktIO = &tcpPacketIO{raw: rawConn, br: bufio.NewReaderSize(rawConn, 65536)}
	}

	_ = pktIO.SetDeadline(time.Now().Add(10 * time.Second))
	cInstance := newOVPNControlConn(pktIO, useUDP)
	ctrlMu.Lock()
	ctrl = cInstance
	ctrlMu.Unlock()

	if err := ctrl.sendHardReset(handshakeCtx); err != nil {
		ctrl.Close()
		return nil, err
	}

	tlsConn := tls.Client(ctrl, &tls.Config{
		InsecureSkipVerify: true,
		ClientSessionCache: tlsSessionCache,
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
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		ctrl.Close()
		return nil, err
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

	cipherName, authName := cfg.cipherName, cfg.authName
	keyBits, hmacBytes := 128, 20
	if cipherName == "AES-256-CBC" {
		keyBits = 256
	}
	if authName == "SHA256" {
		hmacBytes = 32
	}
	protoOpt := "TCPv4_CLIENT"
	if useUDP {
		protoOpt = "UDPv4"
	}
	linkMTU := 1500 + 1 + hmacBytes + 16 + 4 + 1

	var kmBuf bytes.Buffer
	kmBuf.Write([]byte{0, 0, 0, 0, 2})
	kmBuf.Write(preMaster[:])
	kmBuf.Write(cRand1[:])
	kmBuf.Write(cRand2[:])
	optStr := fmt.Sprintf("V4,dev-type tun,link-mtu %d,tun-mtu 1500,proto %s,cipher %s,auth %s,keysize %d,key-method 2,tls-client", linkMTU, protoOpt, cipherName, authName, keyBits)
	writeStr(&kmBuf, optStr)
	writeStr(&kmBuf, "vpn")
	writeStr(&kmBuf, "vpn")
	writeStr(&kmBuf, "IV_VER=2.4.12\nIV_PLAT=win\nIV_NCP=2\nIV_CIPHERS=AES-128-GCM:AES-256-GCM\n")

	if _, err := tlsConn.Write(kmBuf.Bytes()); err != nil {
		ctrl.Close()
		return nil, err
	}

	var srvKMHdr [69]byte
	if _, err := io.ReadFull(tlsConn, srvKMHdr[:]); err != nil {
		ctrl.Close()
		return nil, err
	}
	sRand1, sRand2 := srvKMHdr[5:37], srvKMHdr[37:69]

	var optLenHdr [2]byte
	if _, err := io.ReadFull(tlsConn, optLenHdr[:]); err != nil {
		ctrl.Close()
		return nil, err
	}
	srvOptLen := int(binary.BigEndian.Uint16(optLenHdr[:]))
	var srvOptStr string
	if srvOptLen > 0 {
		if srvOptLen > 8192 {
			ctrl.Close()
			return nil, fmt.Errorf("opt len overflow")
		}
		optBytes := make([]byte, srvOptLen)
		if _, err := io.ReadFull(tlsConn, optBytes); err != nil {
			ctrl.Close()
			return nil, err
		}
		srvOptStr = strings.TrimRight(string(optBytes), "\x00")
	}

	for _, c := range []string{"AES-256-GCM", "AES-128-GCM", "AES-256-CBC", "AES-128-CBC"} {
		if strings.Contains(srvOptStr, c) {
			cipherName = c
			break
		}
	}
	if strings.Contains(srvOptStr, "SHA256") {
		authName = "SHA256"
	} else if strings.Contains(srvOptStr, "SHA1") {
		authName = "SHA1"
	}
	hasCompLZO := strings.Contains(srvOptStr, "comp-lzo") || strings.Contains(srvOptStr, "compress")

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
	stopPush := func() { stopPushOnce.Do(func() { close(stopPushCh) }) }
	defer stopPush()

	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopPushCh:
				return
			case <-handshakeCtx.Done():
				return
			case <-ticker.C:
				_ = sendPushReq()
			}
		}
	}()

	var assignedIP []byte
	var usePDataV2 bool
	var peerID uint32
	var pushAcc strings.Builder
	pushBuf := make([]byte, 2048)
	for attempts := 0; attempts < 30; attempts++ {
		n, err := tlsConn.Read(pushBuf)
		if err != nil {
			stopPush()
			ctrl.Close()
			return nil, err
		}
		pushAcc.Write(pushBuf[:n])
		reply := pushAcc.String()
		if strings.Contains(reply, "AUTH_FAILED") {
			stopPush()
			ctrl.Close()
			return nil, fmt.Errorf("AUTH_FAILED")
		}
		if idx := strings.Index(reply, "PUSH_REPLY"); idx != -1 {
			sub := reply[idx:]
			if strings.IndexByte(sub, 0) != -1 {
				cleanReply := strings.SplitN(sub, "\x00", 2)[0]
				for _, token := range strings.Split(cleanReply, ",") {
					parts := strings.Fields(strings.TrimSpace(token))
					if len(parts) == 0 {
						continue
					}
					switch parts[0] {
					case "ifconfig":
						if len(parts) >= 2 {
							if ip := net.ParseAddress(parts[1]).IP().To4(); len(ip) == 4 {
								assignedIP = ip
							}
						}
					case "cipher":
						if len(parts) >= 2 {
							c := strings.ToUpper(parts[1])
							if c == "AES-128-GCM" || c == "AES-256-GCM" || c == "AES-128-CBC" || c == "AES-256-CBC" {
								cipherName = c
							}
						}
					case "peer-id":
						if len(parts) >= 2 {
							if pid, pErr := strconv.Atoi(parts[1]); pErr == nil && pid >= 0 {
								usePDataV2 = true
								peerID = uint32(pid) & 0x00FFFFFF
							}
						}
					case "comp-lzo", "compress":
						if len(parts) < 2 || (parts[1] != "no" && parts[1] != "stub-v2") {
							hasCompLZO = true
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
		return nil, fmt.Errorf("no ip assigned")
	}

	ctrl.stopRetransmit()
	_ = pktIO.SetDeadline(time.Time{})
	ctrl.lastRxNano.Store(time.Now().UnixNano())
	ctrl.handshakeDone.Store(true)

	seed1 := append(append([]byte{}, cRand1[:]...), sRand1...)
	masterSecret := openvpnPRF(preMaster[:], []byte("OpenVPN master secret"), seed1, 48)
	var seed2 []byte
	seed2 = append(seed2, cRand2[:]...)
	seed2 = append(seed2, sRand2...)
	seed2 = append(seed2, ctrl.localSID[:]...)
	seed2 = append(seed2, ctrl.remoteSID[:]...)
	keyBlock := openvpnPRF(masterSecret, []byte("OpenVPN key expansion"), seed2, 256)

	isAEAD := strings.HasSuffix(cipherName, "-GCM")
	keyLen := 16
	if strings.Contains(cipherName, "256") {
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

	var sendAEAD, recvAEAD cipher.AEAD
	var sendImplicitIV, recvImplicitIV [8]byte
	if isAEAD {
		if sendAEAD, err = cipher.NewGCM(sendCipherBlk); err != nil {
			ctrl.Close()
			return nil, err
		}
		if recvAEAD, err = cipher.NewGCM(recvCipherBlk); err != nil {
			ctrl.Close()
			return nil, err
		}
		copy(sendImplicitIV[:], keyBlock[64:72])
		copy(recvImplicitIV[:], keyBlock[192:200])
	}

	newAuthHash := sha1.New
	hmacSize := 20
	if authName == "SHA256" {
		newAuthHash = sha256.New
		hmacSize = 32
	}
	hmacSendKey := append([]byte{}, keyBlock[64:64+hmacSize]...)
	hmacRecvKey := append([]byte{}, keyBlock[192:192+hmacSize]...)

	hmacSendPool := sync.Pool{New: func() any { return hmac.New(newAuthHash, hmacSendKey) }}
	hmacRecvPool := sync.Pool{New: func() any { return hmac.New(newAuthHash, hmacRecvKey) }}

	s, ep, err := newGVisorStack()
	if err != nil {
		ctrl.Close()
		return nil, err
	}

	sess := &sstpSession{s: s, rawConn: rawConn, dead: make(chan struct{})}

	var lastActiveNano atomic.Int64
	lastActiveNano.Store(time.Now().UnixNano())

	var deadOnce sync.Once
	sess.markDead = func() {
		deadOnce.Do(func() {
			close(sess.dead)
			unbindSessionAllSlots(baseKey, slotKey, sess)
			connCancel()
			ctrl.Close()
			s.Close()
		})
	}

	injectIPv4ZeroCopy := func(ipPkt []byte) {
		if (ipPkt[0] == 0xfa || ipPkt[0] == 0xfb) && len(ipPkt) > 1 {
			ipPkt = ipPkt[1:]
		}
		if len(ipPkt) >= 20 && (ipPkt[0]>>4) == 4 {
			totLen := int(binary.BigEndian.Uint16(ipPkt[2:4]))
			if totLen < 20 || totLen > len(ipPkt) {
				return
			}
			ipPkt = ipPkt[:totLen]
			lastActiveNano.Store(time.Now().UnixNano())
			clampIPv4TCPMSSInPlace(ipPkt, 1240)
			pBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(ipPkt),
			})
			ep.InjectInbound(header.IPv4ProtocolNumber, pBuf)
			pBuf.DecRef()
		}
	}

	ctrl.cbMu.Lock()
	ctrl.onConnClosed = sess.markDead
	ctrl.onDataPacket = func(pkt []byte) {
		if len(pkt) < 6 {
			return
		}
		opcode := pkt[0] >> 3
		if isAEAD {
			hdrLen := 5
			var pktIDBytes []byte
			if opcode == 9 {
				if len(pkt) < 8+16+1 {
					return
				}
				hdrLen, pktIDBytes = 8, pkt[4:8]
			} else if opcode == 6 {
				if len(pkt) < 5+16+1 {
					return
				}
				hdrLen, pktIDBytes = 5, pkt[1:5]
			} else {
				return
			}
			ctLen := len(pkt) - hdrLen - 16
			if ctLen <= 0 {
				return
			}
			var nonce [12]byte
			copy(nonce[0:4], pktIDBytes)
			copy(nonce[4:12], recvImplicitIV[:])

			var tag [16]byte
			copy(tag[:], pkt[hdrLen:hdrLen+16])
			copy(pkt[hdrLen:hdrLen+ctLen], pkt[hdrLen+16:hdrLen+16+ctLen])
			copy(pkt[hdrLen+ctLen:hdrLen+ctLen+16], tag[:])

			if plain, decErr := recvAEAD.Open(pkt[hdrLen:hdrLen], nonce[:], pkt[hdrLen:hdrLen+ctLen+16], pkt[0:hdrLen]); decErr == nil && len(plain) > 0 {
				injectIPv4ZeroCopy(plain)
			}
			return
		}

		if opcode != 6 || len(pkt) < 1+hmacSize+16+16 {
			return
		}
		recvMAC, encBody := pkt[1:1+hmacSize], pkt[1+hmacSize:]
		h := hmacRecvPool.Get().(hash.Hash)
		h.Reset()
		h.Write(encBody)
		var macSum [32]byte
		computedMAC := h.Sum(macSum[:0])
		hmacRecvPool.Put(h)
		if !hmac.Equal(recvMAC, computedMAC) {
			return
		}
		iv, ct := encBody[:16], encBody[16:]
		if len(ct)%16 != 0 {
			return
		}
		cipher.NewCBCDecrypter(recvCipherBlk, iv).CryptBlocks(ct, ct)
		padLen := int(ct[len(ct)-1])
		if padLen < 1 || padLen > 16 || padLen > len(ct) {
			return
		}
		if plain := ct[:len(ct)-padLen]; len(plain) > 4 {
			injectIPv4ZeroCopy(plain[4:])
		}
	}
	ctrl.cbMu.Unlock()

	var dataPktID atomic.Uint32
	encodeEncryptedFrame := func(dst []byte, payload []byte, isIPPacket bool) int {
		if isIPPacket {
			lastActiveNano.Store(time.Now().UnixNano())
		}
		id := dataPktID.Add(1)
		lzoByte := 0
		if hasCompLZO {
			lzoByte = 1
		}
		if isAEAD {
			hdrLen := 5
			if usePDataV2 {
				hdrLen = 8
			}
			plainLen := lzoByte + len(payload)
			totalLen := hdrLen + 16 + plainLen
			if totalLen > len(dst) {
				return 0
			}
			out := dst[:totalLen]
			if usePDataV2 {
				out[0] = (9 << 3)
				out[1], out[2], out[3] = byte(peerID>>16), byte(peerID>>8), byte(peerID)
				binary.BigEndian.PutUint32(out[4:8], id)
			} else {
				out[0] = (6 << 3)
				binary.BigEndian.PutUint32(out[1:5], id)
			}
			var nonce [12]byte
			binary.BigEndian.PutUint32(nonce[0:4], id)
			copy(nonce[4:12], sendImplicitIV[:])
			plainStart := hdrLen + 16
			if hasCompLZO {
				out[plainStart] = 0xfa
			}
			ipSlice := out[plainStart+lzoByte : totalLen]
			copy(ipSlice, payload)
			if isIPPacket {
				clampIPv4TCPMSSInPlace(ipSlice, 1240)
			}
			sealed := sendAEAD.Seal(out[plainStart:plainStart], nonce[:], out[plainStart:totalLen], out[0:hdrLen])
			copy(out[hdrLen:hdrLen+16], sealed[plainLen:plainLen+16])
			return totalLen
		}

		rawPlainLen := 4 + lzoByte + len(payload)
		padLen := 16 - (rawPlainLen % 16)
		ctLen := rawPlainLen + padLen
		totalLen := 1 + hmacSize + 16 + ctLen
		if totalLen > len(dst) {
			return 0
		}
		out := dst[:totalLen]
		out[0] = (6 << 3)
		ivStart := 1 + hmacSize
		ctStart := ivStart + 16
		_, _ = rand.Read(out[ivStart:ctStart])
		plainSlice := out[ctStart : ctStart+ctLen]
		binary.BigEndian.PutUint32(plainSlice[0:4], id)
		if hasCompLZO {
			plainSlice[4] = 0xfa
		}
		ipSlice := plainSlice[4+lzoByte : rawPlainLen]
		copy(ipSlice, payload)
		if isIPPacket {
			clampIPv4TCPMSSInPlace(ipSlice, 1240)
		}
		for i := rawPlainLen; i < ctLen; i++ {
			plainSlice[i] = byte(padLen)
		}
		cipher.NewCBCEncrypter(sendCipherBlk, out[ivStart:ctStart]).CryptBlocks(plainSlice, plainSlice)
		h := hmacSendPool.Get().(hash.Hash)
		h.Reset()
		h.Write(out[ivStart:totalLen])
		h.Sum(out[1:1])
		hmacSendPool.Put(h)
		return totalLen
	}

	sendEncryptedPayload := func(payload []byte, isIPPacket bool) error {
		bufPtr := ovpnBufPool.Get().(*[]byte)
		defer ovpnBufPool.Put(bufPtr)
		n := encodeEncryptedFrame(*bufPtr, payload, isIPPacket)
		if n <= 0 {
			return fmt.Errorf("encode ovpn frame failed")
		}
		return pktIO.WritePacket((*bufPtr)[:n])
	}

	if useUDP {
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
	} else {
		// QoS 大小包双轨插队：小包/DNS/握手包走 highCh 0ms 优先插队，大包走 lowCh
		highCh := make(chan *stack.PacketBuffer, 64)
		lowCh := make(chan *stack.PacketBuffer, 64)
		go func() {
			for {
				pkt := ep.ReadContext(bgCtx)
				if pkt == nil {
					close(highCh)
					close(lowCh)
					return
				}
				if pkt.Size() <= 420 {
					select {
					case highCh <- pkt:
					case <-sess.dead:
						pkt.DecRef()
						return
					}
				} else {
					select {
					case lowCh <- pkt:
					case <-sess.dead:
						pkt.DecRef()
						return
					}
				}
			}
		}()
		go func() {
			defer sess.markDead()
			for {
				var firstPkt *stack.PacketBuffer
				var ok bool
				select {
				case firstPkt, ok = <-highCh:
				default:
					select {
					case firstPkt, ok = <-highCh:
					case firstPkt, ok = <-lowCh:
					case <-sess.dead:
						return
					}
				}
				if !ok || firstPkt == nil {
					return
				}
				batchPtr := ovpnBatchPool.Get().(*[]byte)
				batchBuf := *batchPtr
				offset := 0

				appendPkt := func(p *stack.PacketBuffer) {
					v := p.ToView()
					n := encodeEncryptedFrame(batchBuf[offset+2:], v.AsSlice(), true)
					v.Release()
					p.DecRef()
					if n > 0 {
						binary.BigEndian.PutUint16(batchBuf[offset:offset+2], uint16(n))
						offset += 2 + n
					}
				}

				appendPkt(firstPkt)
			drainLoop:
				for i := 0; i < 15 && offset < 24000; i++ {
					select {
					case hp, ok2 := <-highCh:
						if !ok2 || hp == nil {
							break drainLoop
						}
						appendPkt(hp)
					default:
						select {
						case hp, ok2 := <-highCh:
							if !ok2 || hp == nil {
								break drainLoop
							}
							appendPkt(hp)
						case lp, ok2 := <-lowCh:
							if !ok2 || lp == nil {
								break drainLoop
							}
							appendPkt(lp)
						default:
							break drainLoop
						}
					}
				}

				var wErr error
				if offset > 0 {
					wErr = pktIO.WriteRawStream(batchBuf[:offset])
				}
				ovpnBatchPool.Put(batchPtr)
				if wErr != nil {
					return
				}
			}
		}()
	}

	// 10 分钟长效保活，彻底告别 90 秒断流重握
	go func() {
		defer sess.markDead()
		ovpnPing := []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}
		ticker := time.NewTicker(4 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sess.dead:
				return
			case <-ticker.C:
				now := time.Now().UnixNano()
				if now-ctrl.lastRxNano.Load() > int64(20*time.Second) || now-lastActiveNano.Load() > int64(600*time.Second) {
					return
				}
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

	handshakeSucceeded.Store(true)

	protoLabel := "OpenVPN-TCP"
	if useUDP {
		protoLabel = "OpenVPN-UDP"
	}
	vLabel := "P_DATA_V1"
	if usePDataV2 {
		vLabel = "P_DATA_V2"
	}
	errors.LogInfo(bgCtx, fmt.Sprintf("[VPNGate] 隧道就绪 (%s) | 协议: %s (%s/%s) | 端口: %d | IP: %s", slotKey, protoLabel, cipherName, vLabel, targetDest.Port, localIP.String()))

	slotBackoff.Delete(slotKey)
	bindSessionAllSlots(baseKey, slotKey, sess)

	return sess, nil
}
"""
    with open(ovpn_file, "w", encoding="utf-8") as f:
        f.write(ovpn_src)

    # 同步将第 6 部分 (vpngate_sstp.go) 升级为 3.5MB 黄金 BDP 窗口 + 10 分钟长效保活 + 大流平滑呼吸
    with open(vg_file, "r", encoding="utf-8") as f:
        vg_code = f.read()
    vg_code = vg_code.replace("Max: 16 * 1024 * 1024", "Max: 3584 * 1024")
    vg_code = vg_code.replace("Default: 4 * 1024 * 1024", "Default: 2 * 1024 * 1024")
    vg_code = vg_code.replace("int64(90*time.Second)", "int64(600*time.Second)")
    if '"runtime"' not in vg_code:
        vg_code = vg_code.replace('"io"', '"io"\n\t"runtime"', 1)
        vg_code = vg_code.replace(
            "b := *bp\n\t\tfor {\n\t\t\tn, rErr := gConn.Read(b)",
            "b := *bp\n\t\tvar totalDown int64\n\t\tfor {\n\t\t\trSlice := b\n\t\t\tif totalDown > 1536*1024 {\n\t\t\t\trSlice = b[:16384]\n\t\t\t\truntime.Gosched()\n\t\t\t}\n\t\t\tn, rErr := gConn.Read(rSlice)\n\t\t\ttotalDown += int64(n)",
            1,
        )
    with open(vg_file, "w", encoding="utf-8") as f:
        f.write(vg_code)

    print("  ✔ [VPNGate 爆发+稳定引擎] 成功注入 (QoS小包插队 + 3.5MB黄金BDP + 僵尸秒级自愈 + 10分钟保活)")

    if os.system("go mod tidy") != 0:
        raise RuntimeError("❌ go mod tidy 执行失败！")
    print("  ✔ [Go Mod] 已同步 gVisor 与全协议依赖树")

# =========================================================================
# 8. 突破口 1：直接爆改 $GOMODCACHE 中的 gVisor TCP 源码 (InitialCwnd=64 + 0.82 稳态抗丢包)
# =========================================================================
gvisor_dir = os.popen('go list -m -f "{{.Dir}}" gvisor.dev/gvisor').read().strip()
if gvisor_dir and os.path.exists(gvisor_dir):
    gvisor_tcp_dir = os.path.join(gvisor_dir, "pkg", "tcpip", "transport", "tcp")
    if os.path.exists(gvisor_tcp_dir):
        patched_cwnd = 0
        patched_cc = 0
        for fname in os.listdir(gvisor_tcp_dir):
            if not fname.endswith(".go"):
                continue
            fpath = os.path.join(gvisor_tcp_dir, fname)
            try:
                os.chmod(fpath, stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass
            with open(fpath, "r", encoding="utf-8") as f:
                tc_code = f.read()
            orig_tc = tc_code

            # 将 gVisor TCP 初始拥塞窗口提至 64 (首轮 RTT 直接并发 80KB，网页瞬间秒开)
            tc_code, n1 = re.subn(r"\bInitialCwnd\s*=\s*\d+\b", "InitialCwnd = 64", tc_code)
            patched_cwnd += n1

            # 将 cubic.go 丢包降窗系数精准设定在 0.82 (兼顾抗丢包与防 Bufferbloat 堵车)
            if fname == "cubic.go":
                tc_code, n2 = re.subn(r"0\.[789]\d*\b", "0.82", tc_code)
                tc_code, n3 = re.subn(r"\*\s*[789]\s*/\s*10\b", "* 82 / 100", tc_code)
                patched_cc += (n2 + n3)

            if tc_code != orig_tc:
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(tc_code)
        print(f"  ✔ [gVisor 内核调优] InitialCwnd=64 ({patched_cwnd} 处)，Cubic 0.82 黄金抗丢包 ({patched_cc} 处)")

print("🎉 Xray 核心所有定制补丁注入完成！")
