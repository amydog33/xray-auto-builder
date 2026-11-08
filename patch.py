import os
import re
import stat

print(">>> 开始注入底层补丁...")

# 1. 终极放行：短路 Go 标准库底层 TLS 与 x509 校验（自签/无 SAN 证书直接放行）
goroot = os.popen("go env GOROOT").read().strip()

# 1.1 遍历 crypto/tls 目录下的所有客户端握手逻辑，强制 verifyServerCertificate 返回 nil
tls_dir = os.path.join(goroot, "src", "crypto", "tls")
if os.path.exists(tls_dir):
  for root, _, files in os.walk(tls_dir):
    for f in files:
      if f.startswith("handshake_client") and f.endswith(".go"):
        fpath = os.path.join(root, f)
        os.chmod(fpath, stat.S_IWRITE | stat.S_IREAD)
        with open(fpath, "r", encoding="utf-8") as file:
          code = file.read()

        pattern = (
            r"(func \([a-zA-Z0-9_* ]+\) verifyServerCertificate\([^\)]*\)"
            r" error \{)"
        )
        if re.search(pattern, code):
          code = re.sub(
              pattern,
              r"\1\n\treturn nil // Force allow all self-signed certs\n",
              code,
              count=1,
          )
          with open(fpath, "w", encoding="utf-8") as file:
            file.write(code)
          print(f"[Patch 1/3] Go TLS 放行成功: {f}")

# 1.2 放行 crypto/x509 中对 legacy Common Name / SAN 缺失的拦截报错
x509_verify = os.path.join(goroot, "src", "crypto", "x509", "verify.go")
if os.path.exists(x509_verify):
  os.chmod(x509_verify, stat.S_IWRITE | stat.S_IREAD)
  with open(x509_verify, "r", encoding="utf-8") as file:
    code = file.read()
  code = re.sub(
      r"return CertificateInvalidError\{[^\}]*legacy Common Name[^\}]*\}",
      "return nil",
      code,
  )
  with open(x509_verify, "w", encoding="utf-8") as file:
    file.write(code)
  print("[Patch 1/3] Go x509: Legacy Common Name 校验限制已解除！")

# 2. 移除 Xray 源码内部对 allowInsecure 的报错拦截，全局强制 InsecureSkipVerify = true
tls_conf_path = "transport/internet/tls/config.go"
if os.path.exists(tls_conf_path):
  with open(tls_conf_path, "r", encoding="utf-8") as file:
    code = file.read()
  code = re.sub(
      r"(&tls\.Config\{)", r"\1\n\t\tInsecureSkipVerify: true,", code
  )
  code = re.sub(
      r"config\.InsecureSkipVerify = [^;\n]+",
      "config.InsecureSkipVerify = true",
      code,
  )
  with open(tls_conf_path, "w", encoding="utf-8") as file:
    file.write(code)
  print(f"[Patch 2/3] Xray-core TLS 工厂强制放行: {tls_conf_path}")

for root, _, files in os.walk("."):
  for f in files:
    if f.endswith(".go"):
      fpath = os.path.join(root, f)
      with open(fpath, "r", encoding="utf-8", errors="ignore") as file:
        c = file.read()
      orig = c
      if "allowInsecure" in c and "has been removed" in c:
        c = re.sub(
            r'return nil, newError\([^\)]*allowInsecure[^\)]*\)',
            "config.InsecureSkipVerify = true",
            c,
        )
      if "InsecureSkipVerify:" in c:
        c = re.sub(
            r"InsecureSkipVerify:\s*(?:false|c\.AllowInsecure|config\.AllowInsecure|c\.InsecureSkipVerify)",
            "InsecureSkipVerify: true",
            c,
        )
      if c != orig:
        with open(fpath, "w", encoding="utf-8") as file:
          file.write(c)

# 3. 注入带真实出站标签 (tag) 的 UDP 127.0.0.1:10091 内存广播钩子
disp_path = "app/dispatcher/default.go"
if os.path.exists(disp_path):
  with open(disp_path, "r", encoding="utf-8") as file:
    disp = file.read()

  # 纯净注入，绝不引入多余的 fmt 包，避免 Go 编译未使用报错
  if 'stdnet "net"' not in disp:
    disp = disp.replace("import (", 'import (\n\tstdnet "net"', 1)

  hud_func = """

// notifyHUD 内存广播钩子 (接收 interface{} 类型的 tag，无需外部转换)
func notifyHUD(tag interface{}, dest net.Destination) {
	if dest.Address != nil {
		go func(tStr, target string) {
			if conn, err := stdnet.Dial("udp", "127.0.0.1:10091"); err == nil {
				conn.Write([]byte(tStr + "|" + target))
				conn.Close()
			}
		}(net.Destination{}.String() + "" + toTagStr(tag), dest.String())
	}
}

func toTagStr(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	default:
		return "proxy"
	}
}
"""
  if "func notifyHUD" not in disp:
    disp += hud_func

  # 1. 优先挂钩 detour 决策位置（taking detour [tag] for [dest]）
  if 'taking detour [' in disp:
    # 只要在 newError("taking detour [", ... 这一行下面直接插调用
    lines = disp.splitlines()
    new_lines = []
    detour_injected = False
    for line in lines:
      new_lines.append(line)
      if 'newError("taking detour [' in line and not detour_injected:
        # 提取当前上下文变量名，通常是 destination.Tag 或 tag
        indent = line[:len(line) - len(line.lstrip())]
        if 'destination.Tag' in line:
          new_lines.append(f"{indent}notifyHUD(destination.Tag, destination)")
          detour_injected = True
        elif 'tag' in line:
          new_lines.append(f"{indent}notifyHUD(tag, destination)")
          detour_injected = True
        else:
          new_lines.append(f'{indent}notifyHUD("detour", destination)')
          detour_injected = True
    disp = "\n".join(new_lines)
    if detour_injected:
      print("[Patch 3/3] 成功精准挂钩 detour 决断行！")

  # 2. 如果没挂上 detour，挂钩 Dispatch 入口作为备用
  if "notifyHUD" not in disp.split("func (d *DefaultDispatcher) Dispatch")[1].split("func (d *DefaultDispatcher) DispatchLink")[0]:
    match_disp = re.search(r"func \(d \*DefaultDispatcher\) Dispatch\([^,]+,\s*([a-zA-Z0-9_]+)\s+net\.Destination", disp)
    if match_disp:
      pname = match_disp.group(1)
      disp = re.sub(
          r"(func \(d \*DefaultDispatcher\) Dispatch\([^{]+\{)",
          r'\1\n\tnotifyHUD("direct_or_proxy", ' + pname + ")",
          disp,
          count=1,
      )
      print("[Patch 3/3] 挂钩 Dispatch 入口完成！")

  with open(disp_path, "w", encoding="utf-8") as file:
    file.write(disp)
  print("[Patch 3/3] UDP 10091 带标签内存广播注入完成！")

print(">>> 全部补丁写入完成！")
