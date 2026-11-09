import os
import re
import stat

print(">>> [Patch] 开始对编译环境执行精准深度修复...")

goroot = os.popen("go env GOROOT").read().strip()
if not goroot:
    raise RuntimeError("未检测到 GOROOT，请检查 Go 环境变量！")

tls_dir = os.path.join(goroot, "src", "crypto", "tls")

# =========================================================================
# 1. 深度修补 Go TLS 1.2 与 TLS 1.3 证书验证链（彻底解决 Panic 并放行自签）
# =========================================================================
if os.path.exists(tls_dir):
    # --- A. 修补 TLS 1.2 (handshake_client.go) ---
    hc_path = os.path.join(tls_dir, "handshake_client.go")
    if os.path.exists(hc_path):
        os.chmod(hc_path, stat.S_IWRITE | stat.S_IREAD)
        with open(hc_path, "r", encoding="utf-8") as f:
            code = f.read()

        # 清除旧补丁的截断注入
        code = re.sub(
            r"c\.peerCertificates = certs\s*\n\treturn nil[^\n]*\n",
            "c.peerCertificates = certs\n",
            code
        )

        # 在 Verify 报错或 InsecureSkipVerify 时，安全填充 verifiedChains 且吞掉错误
        target_v12 = r"(c\.verifiedChains,\s*err\s*=\s*certs\[0\]\.Verify\(opts\))"
        patch_v12 = (
            r"\1\n"
            r"\tif err != nil {\n"
            r"\t\tif len(certs) > 0 {\n"
            r"\t\t\tc.verifiedChains = [][]*x509.Certificate{certs}\n"
            r"\t\t}\n"
            r"\t\terr = nil // [SAFE-PATCH] 放行自签并兜底证书链\n"
            r"\t}"
        )
        if "[SAFE-PATCH]" not in code and re.search(target_v12, code):
            code = re.sub(target_v12, patch_v12, code, count=1)
            with open(hc_path, "w", encoding="utf-8") as f:
                f.write(code)
            print("  ✔ [TLS 1.2] handshake_client.go 安全放行注入成功")

    # --- B. 修补 TLS 1.3 (handshake_client_tls13.go) [关键！] ---
    hc13_path = os.path.join(tls_dir, "handshake_client_tls13.go")
    if os.path.exists(hc13_path):
        os.chmod(hc13_path, stat.S_IWRITE | stat.S_IREAD)
        with open(hc13_path, "r", encoding="utf-8") as f:
            code = f.read()

        # 防御 MASQUE 空证书越界，并在 TLS 1.3 下兜底填充 verifiedChains
        target_v13 = r"(c\.verifiedChains,\s*err\s*=\s*certs\[0\]\.Verify\(opts\))"
        patch_v13 = (
            r"\tif len(certs) > 0 {\n"
            r"\t\tc.verifiedChains, err = certs[0].Verify(opts)\n"
            r"\t\tif err != nil {\n"
            r"\t\t\tc.verifiedChains = [][]*x509.Certificate{certs}\n"
            r"\t\t\terr = nil // [SAFE-PATCH-13] TLS 1.3 兜底自签证书链\n"
            r"\t\t}\n"
            r"\t}"
        )
        if "[SAFE-PATCH-13]" not in code and re.search(target_v13, code):
            code = re.sub(target_v13, patch_v13, code, count=1)
            with open(hc13_path, "w", encoding="utf-8") as f:
                f.write(code)
            print("  ✔ [TLS 1.3] handshake_client_tls13.go 证书验证与防越界补丁注入成功")

# 解除 Legacy Common Name 校验限制
x509_verify = os.path.join(goroot, "src", "crypto", "x509", "verify.go")
if os.path.exists(x509_verify):
    os.chmod(x509_verify, stat.S_IWRITE | stat.S_IREAD)
    with open(x509_verify, "r", encoding="utf-8") as f:
        code = f.read()
    if "legacy Common Name" in code:
        code = re.sub(
            r"return CertificateInvalidError\{[^\}]*legacy Common Name[^\}]*\}",
            "return nil",
            code
        )
        with open(x509_verify, "w", encoding="utf-8") as f:
            f.write(code)
        print("  ✔ Go x509 Legacy Common Name 限制已解除")

# =========================================================================
# 2. Xray-core TLS 工厂放行配置
# =========================================================================
tls_conf_path = "transport/internet/tls/config.go"
if os.path.exists(tls_conf_path):
    with open(tls_conf_path, "r", encoding="utf-8") as f:
        code = f.read()
    if "InsecureSkipVerify: true" not in code:
        code = re.sub(r"(&tls\.Config\{)", r"\1\n\t\tInsecureSkipVerify: true,", code)
        code = re.sub(r"config\.InsecureSkipVerify = [^;\n]+", "config.InsecureSkipVerify = true", code)
        with open(tls_conf_path, "w", encoding="utf-8") as f:
            f.write(code)
        print(f"  ✔ Xray TLS 工厂已配置放行: {tls_conf_path}")

# =========================================================================
# 3. 动态提取变量注入 UDP 10091 HUD 广播钩子
# =========================================================================
disp_path = "app/dispatcher/default.go"
if os.path.exists(disp_path):
    with open(disp_path, "r", encoding="utf-8") as f:
        content = f.read()

    if 'stdnet "net"' not in content:
        content = content.replace("import (", 'import (\n\tstdnet "net"', 1)

    hud_func = """
// notifyHUD 内存广播钩子
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
    hook_count = 0

    for line in lines:
        new_lines.append(line)
        if "taking detour" in line and not line.strip().startswith("//"):
            indent = line[: len(line) - len(line.lstrip())]
            m_vars = re.search(r'taking detour \[\",\s*([^,]+),\s*\"\] for \[\",\s*([^,\)]+)', line)
            if m_vars:
                t_var = m_vars.group(1).strip()
                d_var = m_vars.group(2).strip()
                d_call = f"{d_var}.String()" if not d_var.endswith(".String()") else d_var
                new_lines.append(f"{indent}notifyHUD({t_var}, {d_call})")
                hook_count += 1
            else:
                parts = line.split('taking detour ["')
                if len(parts) > 1:
                    sub = parts[1].split(',')
                    if len(sub) > 1:
                        raw_t = sub[1].strip()
                        new_lines.append(f"{indent}notifyHUD({raw_t}, destination.String())")
                        hook_count += 1

    with open(disp_path, "w", encoding="utf-8") as f:
        f.write("\n".join(new_lines))
    print(f"  ✔ 成功注入 {hook_count} 处真实出站决断 HUD 广播钩子")

print(">>> 全部补丁写入完成！")
