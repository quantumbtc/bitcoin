#include <bits/stdc++.h>
using namespace std;

/* ====================== 简要设计说明 ==========================
 * 我们实现一个近似 SIS 求解器：给定 (n,m,q)、权重 w、残差阈值 r、可选 L2 阈值 T，
 * 从种子导出 A ∈ Z_q^{n×m}，搜索三元稀疏向量 x ∈ {-1,0,+1}^m, ||x||0 = w，
 * 使得 ||A x mod q||_∞ ≤ r 且（可选）||x||_2^2 ≤ T。
 *
 * 重要接口：
 *  - DeriveMatrixA(seed, n, m, q)   从 32B 种子导出 A
 *  - PackTernary(x)                 把 {-1,0,1}^m 打包为 2bit/coef 的 vchPowSolution
 *  - CheckSolution(A,x,q,r,T)       校验近似SIS
 *  - Miner 多线程：每个线程循环：
 *      1) 由 (seed || nonce) 派生 PRNG
 *      2) 采样稀疏三元 x
 *      3) 检查残差与范数
 *      4) 满足则输出并退出
 *
 * 你可以把 seed 替换为 区块头哈希（如：sha256(header-with-nonce)），
 * 并在验证端用同样逻辑重建 A 与 PRNG 路径（或仅 seed->A，x 来自区块头携带的 vchPowSolution）。
 * ============================================================ */

struct Params {
    int n = 256;
    int m = 512;
    int q = 12289;
    int w = 64;                  // 稀疏权重：非零个数
    int r = 8;                   // 允许的无穷范残差阈值（0 表示严格 SIS）
    uint64_t l2max = 0;          // 可选 L2² 阈值（0 表示不启用）
    uint32_t nBits = 0x1e0ffff0; // 可选：与 PoW 难度耦合（此处主要用于展示）
    int threads = 0;             // 0 = auto
    array<uint8_t, 32> seed{};   // 32B 种子（建议来自区块头）
};

static inline uint64_t now_ms()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// 简单的 xoshiro 风格 PRNG（不可用于密码学，仅用于 PoW 采样）
struct PRNG {
    uint64_t s0, s1, s2, s3;
    static inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
    PRNG(const array<uint8_t, 32>& seed, uint64_t nonce = 0)
    {
        // 用 seed 和 nonce 扩展初始化
        array<uint8_t, 40> buf{};
        memcpy(buf.data(), seed.data(), 32);
        memcpy(buf.data() + 32, &nonce, 8);
        // 简单搅拌
        std::array<uint64_t, 5> v{};
        memcpy(&v[0], buf.data(), 40);
        auto mix1 = [&](uint64_t a, uint64_t b) { a ^= rotl(b,13); b ^= rotl(a,7); return a+b; };
        for (int i = 0; i < 12; i++) {
            v[0] = mix1(v[0], v[1]);
            v[1] = mix1(v[1], v[2]);
            v[2] = mix1(v[2], v[3]);
            v[3] = mix1(v[3], v[4]);
            v[4] = mix1(v[4], v[0]);
        }
        s0 = v[0] ^ 0x9E3779B97F4A7C15ULL;
        s1 = v[1] ^ 0xD1B54A32D192ED03ULL;
        s2 = v[2] ^ 0x94D049BB133111EBULL;
        s3 = v[3] ^ 0xBF58476D1CE4E5B9ULL;
    }
    uint64_t next()
    {
        uint64_t result = s0 + s3;
        uint64_t t = s1 << 17;
        s2 ^= s0;
        s3 ^= s1;
        s1 ^= s2;
        s0 ^= s3;
        s2 ^= t;
        s3 = rotl(s3, 45);
        return result;
    }
    uint32_t next_u32() { return uint32_t(next() & 0xffffffffu); }
    int uniform_int(int lo, int hi)
    { // inclusive
        uint64_t r = next();
        return lo + int(r % uint64_t(hi - lo + 1));
    }
};

// 从 seed 导出 A: n×m，元素 ∈ [0,q)
static vector<uint16_t> DeriveMatrixA(const array<uint8_t, 32>& seed, int n, int m, int q)
{
    vector<uint16_t> A(size_t(n) * m);
    PRNG g(seed, /*nonce*/ 0xA5A5A5A5ULL);
    for (size_t i = 0; i < A.size(); ++i) {
        A[i] = uint16_t(g.next_u32() % q);
    }
    return A;
}

// 计算 y = A x mod q，A: n×m 按行存储，x ∈ {-1,0,+1}
static void MatVecMod(const vector<uint16_t>& A, const vector<int8_t>& x, int n, int m, int q, vector<int>& y)
{
    y.assign(n, 0);
    for (int i = 0; i < n; ++i) {
        int32_t acc = 0;
        const uint16_t* row = &A[size_t(i) * m];
        for (int j = 0; j < m; ++j) {
            int8_t v = x[j];
            if (!v) continue;
            acc += (v == 1 ? row[j] : (q - row[j])); // -a ≡ q-a (mod q)
            if (acc >= q) acc -= q;
            if (acc >= q) acc -= q;
        }
        y[i] = acc % q;
    }
}

// ||y||_∞ over centered residue: map to [-q/2,q/2]
static int LinfCentered(const vector<int>& y, int q)
{
    int half = q / 2;
    int m = 0;
    for (int v : y) {
        int c = v;
        if (c > half) c = c - q; // center
        if (c < -half) c = c + q;
        int a = std::abs(c);
        if (a > m) m = a;
    }
    return m;
}

// L2^2 of x
static uint64_t L2Squared(const vector<int8_t>& x)
{
    uint64_t s = 0;
    for (int8_t v : x)
        if (v) s += 1; // since entries ∈ {-1,0,1}
    return s;          // = ||x||_0 for ternary
}

// 采样稀疏三元向量，||x||0 = w
static void SampleSparseTernary(vector<int8_t>& x, int m, int w, PRNG& g)
{
    x.assign(m, 0);
    // 选 w 个不同位置
    vector<int> idx(m);
    iota(idx.begin(), idx.end(), 0);
    // 局部 shuffle w 位置
    for (int i = 0; i < w; ++i) {
        int j = g.uniform_int(i, m - 1);
        std::swap(idx[i], idx[j]);
    }
    for (int k = 0; k < w; ++k) {
        int pos = idx[k];
        x[pos] = (g.next() & 1) ? int8_t(+1) : int8_t(-1);
    }
}

// 打包 {-1,0,1} 到 2bit：00=0, 01=+1, 11=-1（10保留未用）
static vector<uint8_t> PackTernary(const vector<int8_t>& x)
{
    size_t bits = x.size() * 2;
    size_t nbytes = (bits + 7) / 8;
    vector<uint8_t> out(nbytes, 0);
    size_t bitpos = 0;
    for (int8_t v : x) {
        uint8_t code = 0;
        if (v == 0)
            code = 0; // 00
        else if (v == 1)
            code = 1; // 01
        else if (v == -1)
            code = 3; // 11
        else
            throw runtime_error("invalid ternary coef");
        size_t byte_idx = bitpos >> 3;
        int shift = bitpos & 7;
        out[byte_idx] |= (code << shift);
        if (shift > 6) { // 跨字节
            out[byte_idx + 1] |= (code >> (8 - shift));
        }
        bitpos += 2;
    }
    return out;
}

static string HexStr(const vector<uint8_t>& v)
{
    static const char* hexd = "0123456789abcdef";
    string s;
    s.resize(v.size() * 2);
    for (size_t i = 0; i < v.size(); ++i) {
        s[2 * i] = hexd[v[i] >> 4];
        s[2 * i + 1] = hexd[v[i] & 0xF];
    }
    return s;
}

struct FoundSolution {
    bool ok = false;
    uint64_t nonce = 0;
    vector<int8_t> x;
    vector<uint8_t> packed;
    int linf = 0;
    uint64_t l2 = 0;
};

struct MinerState {
    atomic<bool> stop{false};
    atomic<uint64_t> total_tries{0};
    atomic<uint64_t> best_nonce{0};
    atomic<int> best_linf{INT_MAX};
};

// 搜索：给定 seed 与参数，遍历不同 nonce → PRNG → 采样 x → 检查
static FoundSolution SearchSIS(const Params& P)
{
    vector<uint16_t> A = DeriveMatrixA(P.seed, P.n, P.m, P.q);

    MinerState S;
    FoundSolution result;
    int nthreads = P.threads > 0 ? P.threads : int(thread::hardware_concurrency());
    if (nthreads <= 0) nthreads = 1;

    auto t0 = now_ms();

    mutex out_mu;
    vector<thread> pool;

    auto worker = [&](int tid) {
        // 每线程自己的 nonce 扫描序列：tid, tid+T, tid+2T,...
        for (uint64_t nonce = tid; !S.stop.load(memory_order_relaxed); nonce += nthreads) {
            PRNG g(P.seed, nonce);
            vector<int8_t> x;
            SampleSparseTernary(x, P.m, P.w, g);

            vector<int> y;
            MatVecMod(A, x, P.n, P.m, P.q, y);
            int linf = LinfCentered(y, P.q);
            uint64_t l2 = L2Squared(x);

            S.total_tries.fetch_add(1, memory_order_relaxed);

            // 更新进度（非必要，仅记录“最好”的残差）
            int cur_best = S.best_linf.load();
            if (linf < cur_best) {
                S.best_linf.store(linf);
                S.best_nonce.store(nonce);
            }

            // 判定：近似 SIS
            if (linf <= P.r && (P.l2max == 0 || l2 <= P.l2max)) {
                vector<uint8_t> packed = PackTernary(x);
                lock_guard<mutex> lk(out_mu);
                if (!S.stop.exchange(true)) {
                    result.ok = true;
                    result.nonce = nonce;
                    result.x = std::move(x);
                    result.packed = std::move(packed);
                    result.linf = linf;
                    result.l2 = l2;
                }
                return;
            }
        }
    };

    for (int i = 0; i < nthreads; i++)
        pool.emplace_back(worker, i);

    // 进度/ETA
    while (!S.stop.load()) {
        this_thread::sleep_for(chrono::seconds(3));
        uint64_t tried = S.total_tries.load();
        int best = S.best_linf.load();
        uint64_t nonce = S.best_nonce.load();
        double sec = double(now_ms() - t0) / 1000.0;
        double rate = tried / max(1e-6, sec); // samples/s

        // 粗糙 ETA：假设 linf 的达成概率 ~ p，未知时用指数等待近似 1/rate
        // 这里无法准确估计 p（取决于参数/分布），仅打印速率。
        cerr << "[progress] tries=" << tried
             << " rate=" << fixed << setprecision(2) << rate << " samp/s"
             << " bestLinf=" << best
             << " bestNonce=" << nonce
             << " elapsed=" << int(sec) << "s\r" << flush;
    }
    cerr << "\n";

    for (auto& t : pool)
        t.join();
    return result;
}

static bool ParseHex32(const string& hex, array<uint8_t, 32>& out)
{
    if (hex.size() != 64) return false;
    for (int i = 0; i < 32; i++) {
        auto hexval = [&](char c) -> int {
            if ('0' <= c && c <= '9') return c - '0';
            if ('a' <= c && c <= 'f') return c - 'a' + 10;
            if ('A' <= c && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hexval(hex[2 * i]);
        int lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = uint8_t((hi << 4) | lo);
    }
    return true;
}

int main(int argc, char** argv)
{
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    Params P;
    // 默认 l2max=0（不启用），r=8（接近 SIS 的严格度可自行调为 0）
    string seed_hex;

    // 简易参数解析
    for (int i = 1; i < argc; i++) {
        string a = argv[i];
        auto need = [&](const char* name) {
            if (i + 1 >= argc) {
                cerr << "missing arg for " << name << "\n";
                exit(1);
            }
            return string(argv[++i]);
        };
        if (a == "--n")
            P.n = stoi(need("--n"));
        else if (a == "--m")
            P.m = stoi(need("--m"));
        else if (a == "--q")
            P.q = stoi(need("--q"));
        else if (a == "--w")
            P.w = stoi(need("--w"));
        else if (a == "--r")
            P.r = stoi(need("--r"));
        else if (a == "--l2")
            P.l2max = stoull(need("--l2"));
        else if (a == "--bits") {
            string s = need("--bits");
            if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0)
                P.nBits = stoul(s, nullptr, 16);
            else
                P.nBits = stoul(s);
        } else if (a == "--threads")
            P.threads = stoi(need("--threads"));
        else if (a == "--seed")
            seed_hex = need("--seed");
        else if (a == "--help" || a == "-h") {
            cout << "Usage:\n"
                 << "  " << argv[0] << " --n 256 --m 512 --q 12289 --w 64 --r 8 --bits 0x1e0ffff0 --seed <64 hex> --threads 0\n";
            return 0;
        } else {
            cerr << "Unknown arg: " << a << "\n";
            return 1;
        }
    }

    if (!seed_hex.empty()) {
        if (!ParseHex32(seed_hex, P.seed)) {
            cerr << "Invalid --seed, need 64 hex chars\n";
            return 1;
        }
    } else {
        // 默认种子（示例）：建议用 区块头哈希 替代
        const char* default_msg = "Entangle value, not control";
        // 简单 hash32（非加密）
        array<uint8_t, 32> tmp{};
        for (size_t i = 0; i < strlen(default_msg); ++i) {
            tmp[i % 32] ^= uint8_t(default_msg[i]);
            tmp[(i * 7) % 32] ^= uint8_t(default_msg[i] * 31);
        }
        P.seed = tmp;
    }

    // 参数打印
    cout << "SIS-PoW parameters:\n";
    cout << "  n=" << P.n << " m=" << P.m << " q=" << P.q << " w=" << P.w << " r=" << P.r << "\n";
    if (P.l2max) cout << "  L2^2 max=" << P.l2max << "\n";
    cout << "  nBits=0x" << hex << uppercase << P.nBits << nouppercase << dec << "\n";
    cout << "  threads=" << (P.threads ? P.threads : thread::hardware_concurrency()) << "\n";

    auto res = SearchSIS(P);

    if (!res.ok) {
        cout << "\nNo solution found in current run.\n";
        cout << "提示：增大搜索时间/线程数，或放宽 r（例如 r=16/32），或减小 w（例如 w=48）。\n";
        return 2;
    }

    // 输出结果
    cout << "\n=== FOUND SIS SOLUTION ===\n";
    cout << "nonce          : " << res.nonce << "\n";
    cout << "||x||_0 (L2^2) : " << res.l2 << "\n";
    cout << "||A x||_inf    : " << res.linf << "\n";
    auto packed = std::move(res.packed);
    cout << "vchPowSolution : " << HexStr(packed) << "\n";
    cout << "packed_size    : " << packed.size() << " bytes (expected " << ((size_t)P.m * 2 + 7) / 8 << ")\n";

    // 你可以把 vchPowSolution 直接塞到创世区块头，并在验证端用同样 A=Derive(seed) 重算残差。
    return 0;
}
