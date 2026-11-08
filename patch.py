import os
import re

print(">>> 正在应用针对 v2rayN 结构锁定的全局放行补丁...")

# 1. 暴力修改 Xray TLS 配置工厂函数 (transport/internet/tls/config.go)
# 只要是客户端发起的 TLS 握手，无条件强制 InsecureSkipVerify = true
tls_conf_path = "transport/internet/tls/config.go"
if os.path.exists(tls_conf_path):
  with open(tls_conf_path, "r", encoding="utf-8") as f:
    code = f.read()

  # 将 ParseConfig / GetTLSConfig 中构造的 client tls.Config 强制注入 InsecureSkipVerify: true
  code = re.sub(
      r"(&tls\.Config\{)", r"\1\n\t\tInsecureSkipVerify: true,", code
  )
  code = re.sub(r"config\.InsecureSkipVerify = [^;\n]+", "config.InsecureSkipVerify = true", code)

  with open(tls_conf_path, "w", encoding="utf-8") as f:
    f.write(code)
  print(f"[Patch 1/3] 核心 TLS 工厂注入成功: {tls_conf_path}")

# 2. 全局扫描所有 .go 文件，杜绝任何漏网之鱼
for root, _, files in os.walk("."):
  for f in files:
    if f.endswith(".go"):
      fpath = os.path.join(root, f)
      with open(fpath, "r", encoding="utf-8", errors="ignore") as file:
        c = file.read()
      orig = c

      # 消除可能存在的 allowInsecure 废弃阻断
      if "allowInsecure" in c and "has been removed" in c:
        c = re.sub(
            r'return nil, newError\([^\)]*allowInsecure[^\)]*\)',
            "config.InsecureSkipVerify = true",
            c,
        )

      # 强制覆盖所有现有的 InsecureSkipVerify 赋值
      if "InsecureSkipVerify:" in c:
        c = re.sub(
            r"InsecureSkipVerify:\s*(?:false|c\.AllowInsecure|config\.AllowInsecure|c\.InsecureSkipVerify)",
            "InsecureSkipVerify: true",
            c,
        )

      if c != orig:
        with open(fpath, "w", encoding="utf-8") as file:
          file.write(c)
        print(f"[Patch 2/3] 全局 TLS 放行: {fpath}")

# 3. 注入 UDP 127.0.0.1:10091 内存广播钩子
disp_path = "app/dispatcher/default.go"
if os.path.exists(disp_path):
  with open(disp_path, "r", encoding="utf-8") as file:
    disp = file.read()

  if 'stdnet "net"' not in disp:
    disp = disp.replace("import (", 'import (\n\tstdnet "net"', 1)

  if "func notifyHUD" not in disp:
    hud_func = """

// notifyHUD 内存域名广播钩子
func notifyHUD(dest net.Destination) {
	if dest.Address != nil {
		go func(target string) {
			if conn, err := stdnet.Dial("udp", "127.0.0.1:10091"); err == nil {
				conn.Write([]byte(target))
				conn.Close()
			}
		}(dest.String())
	}
}
"""
    disp += hud_func

  match_dispatch = re.search(
      r"func \(d \*DefaultDispatcher\) Dispatch\([^,]+,\s*([a-zA-Z0-9_]+)\s+net\.Destination",
      disp,
  )
  if match_dispatch:
    pname = match_dispatch.group(1)
    if (
        "notifyHUD("
        not in disp.split("func (d *DefaultDispatcher) Dispatch")[1].split("}")[
            0
        ]
    ):
      disp = re.sub(
          r"(func \(d \*DefaultDispatcher\) Dispatch\([^{]+\{)",
          r"\1\n\tnotifyHUD(" + pname + ")",
          disp,
          count=1,
      )
      print(f"[Patch 3/3] 成功挂钩 Dispatch (参数: {pname})")

  match_link = re.search(
      r"func \(d \*DefaultDispatcher\) DispatchLink\([^,]+,\s*([a-zA-Z0-9_]+)\s+net\.Destination",
      disp,
  )
  if match_link:
    pname_link = match_link.group(1)
    if (
        "notifyHUD("
        not in disp.split("func (d *DefaultDispatcher) DispatchLink")[1].split(
            "}"
        )[0]
    ):
      disp = re.sub(
          r"(func \(d \*DefaultDispatcher\) DispatchLink\([^{]+\{)",
          r"\1\n\tnotifyHUD(" + pname_link + ")",
          disp,
          count=1,
      )
      print(f"[Patch 3/3] 成功挂钩 DispatchLink (参数: {pname_link})")

  with open(disp_path, "w", encoding="utf-8") as file:
    file.write(disp)
  print("[Patch 3/3] UDP 127.0.0.1:10091 内存广播注入完成！")

print(">>> 全部补丁更新完成！")
