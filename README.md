# Bwjspace

Notes, drawings and a weekly to-do planner that sync between your computer and phone.
No email, no password: your devices share a private **sync key**.

---

## 设定步骤（照顺序做，大概 15 分钟）

### 第 1 步：Supabase（放资料的云端）

1. 到 **supabase.com** 注册，按 **New project**
   - Name：`bwjspace`
   - Database Password：自己设一个，记下来，**不要给任何人**
   - Region：**Southeast Asia (Singapore)**
   - Security：**Enable Data API** 打勾、**Automatically expose new tables** 不打勾、**Enable automatic RLS** 打勾
2. 等它建好（1–2 分钟）
3. 左边 **SQL Editor** → **New query** → 把 `supabase-setup.sql` 整份内容贴进去 → **Run**，看到 Success 就好
4. 左边 **Project Settings** → **API**，复制这两个：
   - **Project URL**（像 `https://abcdefgh.supabase.co`）
   - **anon public** key（很长的一串）

   不要复制 **service_role** key。

### 第 2 步：GitHub（放网页）

1. 到 **github.com** → 右上角 **+** → **New repository**
   - 名字：`bwjspace`
   - 选 **Public**（免费的 GitHub Pages 需要 Public。别人看得到的只是程式，看不到你的资料）
   - 按 **Create repository**
2. 按 **uploading an existing file**，把这个资料夹里**全部档案**拖进去 → **Commit changes**
3. 如果 `config.js` 还是空的：点 `config.js` → 右上角铅笔 ✏️，把第 1 步的两个值贴进引号里 → **Commit changes**
   ```js
   supabaseUrl: "https://abcdefgh.supabase.co",
   supabaseAnonKey: "eyJ......"
   ```
4. **Settings** → 左边 **Pages** → Source 选 **Deploy from a branch** → Branch 选 **main**、资料夹 **/(root)** → **Save**
5. 等 1–2 分钟，上面会出现你的网址，像 `https://你的帐号.github.io/bwjspace/`

### 第 3 步：电脑（第一台装置）

1. 打开你的 GitHub 网址
2. 左边下面按 **Set up sync** → **This is my first device**
3. 画面会出现你的**同步密钥**（像 `bwj-k7q9x-p2mlr-4t9vw-cn3hd-8fj2a`）和一个 QR code
4. 按 **Copy key**，把密钥存到备忘录或密码管理器
5. 左下角变成 **Synced** 就完成了

### 第 4 步：手机

1. 用手机打开同一个网址
2. **先加到主画面**：
   - iPhone（Safari）：分享按钮 → **加入主画面**
   - Android（Chrome）：右上角 ⋮ → **加到主画面 / 安装应用程式**
3. **从主画面的 Bwjspace 图示打开**，按 **Set up sync** → **I already have a key**
4. 按 **Scan QR code** 扫电脑上的 QR code，或者把密钥贴进去 → **Connect**
   （在电脑上再看到 QR code：左下角同步状态 → **Show sync key / add a device**）
5. 手机会自动拿掉自己的范例，换成电脑上的资料

之后每台装置都会一直连着，不用再输入。

### 换密钥

觉得密钥可能被别人看到：任何一台装置 → 左下角同步状态 → **Change sync key**（按两次确认）。
旧密钥马上失效，资料不会动。其他装置会显示 **Sync key changed**，按它再扫一次新的 QR code 就好。

### 分享一页给别人

1. 打开要分享的那一页，按右上角 **Share**
2. 打开 **Share with a link**
3. **Anyone with the link can**：选 **View**（只能看）或 **Edit**（可以改、可以加内容）
4. 要不要连底下的子页面一起分享：勾或不勾 **Include sub-pages**
5. 按 **Copy**，把连结传给对方

- 对方不用装 App、不用密钥，打开连结就能用
- 对方**看不到你其他的页面，也拿不到你的同步密钥**
- 选 Edit 时，对方可以改和加内容，但**不能删除或移动整页**，也不能新增页面（Supabase 那边会挡住）
- 你随时可以改成 View 或 Edit，对方重新整理就会生效
- 关掉 **Share with a link**，连结马上失效。再打开会是一个新的连结
- 分享中的页面，在 sidebar 会有一个小小的人像图示
- 两个人可以同时编辑：改不同段落会自动合并，改到同一段会两个版本都留着让你挑

---

## 资料是怎么保护的

- **一笔一笔同步，不会整份盖掉**：每一页笔记、每一个 to-do、每一个重复设定都是分开的一笔
- **只有你亲手改的才算「新」**：App 打开时自动做的整理（更新旧格式、把没做完的 to-do 搬到今天、产生重复的 to-do）不会改「最后修改时间」，也不会上传。所以很久没开的手机或旧分页，不会假装自己是最新的
- **旧装置不能盖掉新资料**：每一笔都记得自己是从云端哪个版本改出来的。云端如果已经被别的装置改过，旧装置上传会被拒绝
- **两边同时改同一页**：会一段一段自动合并。你改第 1 段、对方改第 5 段，两边的修改都会保留；两边新加的段落也都会保留
- **两边同时改同一段**：那一段的两个版本都会留在页面上，用黄色标出来。按其中一个的 **Keep this one**，另一个就会拿掉
- **分享的页面开着时，每 5 秒自动更新一次**，你会看到对方刚改的内容，打字的时候不会被打断
- **两边都改了同一个 to-do**：以真正最后一次修改的为准
- **删掉的不会复活**：删除会被记住
- **没网路也能用**：先存在装置上，有网路时自动上传
- **每天自动备份**：每台装置每天存一份，保留 7 天。⚙ Settings → **Automatic backups** 可以还原
- **Start over（清除资料）只清这台装置**，这台装置会停止同步，云端的资料不会被删
- **密钥不会存在云端**：资料库只存密钥的「指纹」。就算有人看到资料库，也拿不到你的密钥，而且没有密钥就读不到任何资料

## 要知道的事

- **密钥要保管好**：有密钥的人就能打开你的 Bwjspace。如果所有装置同时弄丢，又没有存密钥，资料就拿不回来
- Supabase 免费方案的 project 如果大约一个星期完全没人用会暂停，资料不会不见，到 Supabase 后台按 **Restore** 就好。每天在用就不会遇到
- 以后要更新 App：到 GitHub 用新的档案取代旧的就好（`config.js` 不用换）。如果 `supabase-setup.sql` 也有更新，到 SQL Editor 整份再跑一次（可以重复跑，资料不会受影响）

## 档案说明

| 档案 | 用途 |
|---|---|
| `index.html` | App 本身 |
| `config.js` | 你的 Supabase 网址和 key |
| `supabase.js`, `591.supabase.js` | 连接 Supabase 的程式库 |
| `qr.js` | 产生和扫描 QR code |
| `sw.js` | 让 App 没网路也能打开 |
| `manifest.webmanifest`, `icon-192.png`, `icon-512.png`, `apple-touch-icon.png`, `favicon.png` | 主画面和浏览器分页的名字和图示 |
| `supabase-setup.sql` | 在 Supabase 跑一次，建立资料表和安全规则 |
