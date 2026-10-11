#include "vault.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <set>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>
#include <utility>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <poll.h>
#include <chrono>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <sys/stdio.h>
#endif

namespace securevault::vault {
namespace {
constexpr std::array<unsigned char, 8> magic_v1{'S','V','L','T','0','0','1','\0'};
constexpr std::array<unsigned char, 8> magic{'S','V','L','T','0','0','2','\0'};
constexpr std::array<unsigned char, 8> tree_magic{'S','V','T','R','E','E','0','1'};
constexpr std::size_t salt_size = 16, nonce_size = 12, tag_size = 16;
// One AES-GCM invocation must stay strictly below the GCM per-nonce limit.
constexpr std::uint64_t max_bytes = (1ULL << 35);
constexpr std::uint32_t max_path = 4096;
using Ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

[[noreturn]] void fail(std::string_view why) { throw std::runtime_error(std::string(why)); }
void write_all(int fd, std::span<const unsigned char> input) {
    while (!input.empty()) {
        ssize_t n = ::write(fd, input.data(), input.size());
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail("Unable to write encrypted snapshot");
        input = input.subspan(static_cast<std::size_t>(n));
    }
}
void read_all(int fd, std::span<unsigned char> output) {
    while (!output.empty()) {
        ssize_t n = ::read(fd, output.data(), output.size());
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail("Snapshot was truncated");
        output = output.subspan(static_cast<std::size_t>(n));
    }
}
void seek_to(int fd, off_t offset) {
    if (lseek(fd, offset, SEEK_SET) < 0) fail("Cannot seek in snapshot");
}
struct Fd {
    int value{-1};
    explicit Fd(int n = -1) : value(n) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value(other.value) { other.value = -1; }
    ~Fd() { if (value >= 0) close(value); }
};
struct TempFile {
    fs::path name;
    Fd fd;
    explicit TempFile(const fs::path& parent, std::string_view prefix) {
        std::string pattern = (parent / (std::string(prefix) + "XXXXXX")).string();
        std::vector<char> chars(pattern.begin(), pattern.end());
        chars.push_back('\0');
        fd.value = mkstemp(chars.data());
        if (fd.value < 0) fail("Cannot create private temporary file");
        name = chars.data();
    }
    ~TempFile() {
        std::error_code ec;
        if (!name.empty()) fs::remove(name, ec);
    }
};
struct TempDir {
    fs::path name;
    explicit TempDir(const fs::path& parent) {
        std::string pattern = (parent / ".securevault-restore-XXXXXX").string();
        std::vector<char> chars(pattern.begin(), pattern.end());
        chars.push_back('\0');
        if (!mkdtemp(chars.data())) fail("Cannot create private restore stage");
        name = chars.data();
    }
    ~TempDir() {
        if (!name.empty()) { std::error_code ec; fs::remove_all(name, ec); }
    }
};
std::array<unsigned char, 32> key_from(const fs::path& pass_file,
                                         std::span<const unsigned char, salt_size> salt) {
    if (!pass_file.is_absolute()) fail("Password file must be an absolute path");
    Fd fd(open(pass_file.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if (fd.value < 0) fail("Cannot open password file");
    struct stat st{};
    if (fstat(fd.value, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & 077) != 0 || st.st_size < 16 || st.st_size > 4096)
        fail("Password must be a private regular file (0600, 16..4096 bytes)");
    std::vector<unsigned char> secret(static_cast<std::size_t>(st.st_size));
    read_all(fd.value, secret);
    std::array<unsigned char, 32> key{};
    // EVP_PBE_scrypt is OpenSSL's audited, memory-hard KDF.
    const int ok = EVP_PBE_scrypt(
        reinterpret_cast<const char*>(secret.data()), secret.size(),
        salt.data(), salt.size(), 32768, 8, 1, 64ULL * 1024 * 1024,
        key.data(), key.size());
    OPENSSL_cleanse(secret.data(), secret.size());
    if (ok != 1) fail("Scrypt key derivation failed");
    return key;
}
std::array<unsigned char, salt_size + nonce_size + magic.size()> header_new() {
    std::array<unsigned char, salt_size + nonce_size + magic.size()> h{};
    std::copy(magic.begin(), magic.end(), h.begin());
    if (RAND_bytes(h.data() + magic.size(), salt_size + nonce_size) != 1)
        fail("Cryptographic random generator unavailable");
    return h;
}
std::array<unsigned char, 32> derive(const fs::path& pass,
                                      const std::array<unsigned char, 36>& header) {
    return key_from(pass,
        std::span<const unsigned char, salt_size>(header.data() + magic.size(), salt_size));
}
class Writer {
    Fd& output;
    Ctx ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
    std::uint64_t plaintext_bytes = 0;
public:
    Writer(Fd& file, const fs::path& pass) : output(file) {
        if (!ctx) fail("AES-GCM initialization failed");
        const auto h = header_new();
        auto k = derive(pass, h);
        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonce_size, nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, k.data(),
                               h.data() + magic.size() + salt_size) != 1)
            fail("AES-GCM initialization failed");
        OPENSSL_cleanse(k.data(), k.size());
        int count = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &count, h.data(), h.size()) != 1)
            fail("Unable to authenticate snapshot header");
        write_all(output.value, h);
    }
    void push(std::span<const unsigned char> plaintext) {
        if (plaintext.size() > max_bytes - plaintext_bytes)
            fail("Encrypted snapshot exceeds SVLT v1 per-nonce size limit");
        plaintext_bytes += plaintext.size();
        std::array<unsigned char, 65536 + 16> ciphertext{};
        while (!plaintext.empty()) {
            const auto n = std::min<std::size_t>(65536, plaintext.size());
            int produced = 0;
            if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &produced,
                                  plaintext.data(), static_cast<int>(n)) != 1)
                fail("AES-GCM encryption failed");
            write_all(output.value, std::span(ciphertext.data(), produced));
            plaintext = plaintext.subspan(n);
        }
    }
    void done() {
        int length = 0;
        std::array<unsigned char, 16> remaining{};
        if (EVP_EncryptFinal_ex(ctx.get(), remaining.data(), &length) != 1)
            fail("AES-GCM finalization failed");
        write_all(output.value, std::span(remaining.data(), length));
        std::array<unsigned char, tag_size> tag{};
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1)
            fail("AES-GCM tag generation failed");
        write_all(output.value, tag);
        if (fsync(output.value) != 0) fail("Snapshot fsync failed");
    }
};
class Reader {
    Fd input;
    Ctx ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
    std::array<unsigned char, 36> header{};
    std::array<unsigned char, tag_size> tag{};
    std::array<unsigned char, 65552> data{};
    std::size_t used = 0, cursor = 0;
    std::uint64_t remaining = 0;
public:
    Reader(const fs::path& archive, const fs::path& pass) :
        input(open(archive.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) {
        if (input.value < 0 || !ctx) fail("Cannot open encrypted archive");
        struct stat st{};
        if (fstat(input.value, &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_nlink != 1 || st.st_size < 36 + static_cast<off_t>(tag_size) ||
            static_cast<std::uint64_t>(st.st_size) > max_bytes + 52)
            fail("Invalid encrypted archive file");
        remaining = static_cast<std::uint64_t>(st.st_size) - 36 - tag_size;
        read_all(input.value, header);
        if (!std::equal(magic.begin(), magic.end(), header.begin()) &&
            !std::equal(magic_v1.begin(), magic_v1.end(), header.begin()))
            fail("Unrecognized snapshot format or version");
        seek_to(input.value, st.st_size - tag_size);
        read_all(input.value, tag);
        seek_to(input.value, header.size());
        auto k = derive(pass, header);
        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonce_size, nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, k.data(),
                               header.data() + magic.size() + salt_size) != 1)
            fail("AES-GCM reader initialization failed");
        OPENSSL_cleanse(k.data(), k.size());
        int count = 0;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &count, header.data(), header.size()) != 1)
            fail("Invalid authenticated header");
    }
    void fill() {
        if (remaining == 0) { used = cursor = 0; return; }
        std::array<unsigned char, 65536> ciphertext{};
        const auto n = std::min<std::uint64_t>(remaining, ciphertext.size());
        read_all(input.value, std::span(ciphertext.data(), static_cast<std::size_t>(n)));
        remaining -= n;
        int length = 0;
        if (EVP_DecryptUpdate(ctx.get(), data.data(), &length,
                              ciphertext.data(), static_cast<int>(n)) != 1)
            fail("Snapshot decryption failed");
        used = static_cast<std::size_t>(length);
        cursor = 0;
    }
    void take(std::span<unsigned char> out) {
        while (!out.empty()) {
            if (cursor == used) fill();
            if (cursor == used) fail("Truncated authenticated payload");
            const auto n = std::min(out.size(), used - cursor);
            std::copy_n(data.data() + cursor, n, out.data());
            cursor += n;
            out = out.subspan(n);
        }
    }
    unsigned char byte() {
        std::array<unsigned char, 1> b{};
        take(b);
        return b[0];
    }
    void end() {
        if (cursor != used || remaining != 0)
            fail("Unexpected trailing archive bytes");
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(),
                                tag.data()) != 1) fail("AES-GCM tag invalid");
        int produced = 0;
        std::array<unsigned char, 16> tail{};
        if (EVP_DecryptFinal_ex(ctx.get(), tail.data(), &produced) != 1)
            fail("Snapshot authentication failed (tampering or incorrect password)");
    }
    void authenticate() {
        while (remaining > 0 || cursor != used) {
            if (cursor == used) fill();
            cursor = used;
        }
        end();
    }
};
void enc_raw(Writer& w, std::string_view text) {
    w.push(std::span(reinterpret_cast<const unsigned char*>(text.data()), text.size()));
}
template <typename T> void enc_num(Writer& w, T n) {
    std::array<unsigned char, sizeof(T)> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<unsigned char>((n >> (8*i)) & 0xff);
    w.push(bytes);
}
template <typename T> T dec_num(Reader& r) {
    T out = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i)
        out |= static_cast<T>(r.byte()) << (8*i);
    return out;
}
std::string text(Reader& r, std::uint32_t n) {
    if (n == 0 || n > max_path) fail("Unsafe archive path length");
    std::string out(n, '\0');
    r.take(std::span(reinterpret_cast<unsigned char*>(out.data()), n));
    if (out.find('\0') != std::string::npos) fail("Embedded NUL archive path");
    return out;
}
bool safe_rel(const fs::path& p) {
    if (p.empty() || p.is_absolute() || p == "." || p.generic_string().size() > max_path)
        return false;
    for (const auto& part : p)
        if (part == "." || part == ".." || part.empty()) return false;
    return true;
}
void encode_tree(Writer& out, const fs::path& source) {
    enc_raw(out, std::string_view(reinterpret_cast<const char*>(tree_magic.data()), tree_magic.size()));
    std::error_code ec;
    const auto status = fs::symlink_status(source, ec);
    if (ec || fs::is_symlink(status) ||
        !(fs::is_regular_file(status) || fs::is_directory(status)))
        fail("Source must be a real regular file or directory");
    std::vector<std::pair<fs::path, fs::path>> entries;
    if (fs::is_regular_file(status)) entries.emplace_back(source, source.filename());
    else {
        for (fs::recursive_directory_iterator it(source, fs::directory_options::none, ec), end;
             it != end; it.increment(ec)) {
            if (ec) fail("Cannot scan entire source tree");
            auto rel = it->path().lexically_relative(source);
            if (!safe_rel(rel)) fail("Unsafe source relative path");
            entries.emplace_back(it->path(), rel);
        }
        if (ec) fail("Cannot scan entire source tree");
    }
    for (const auto& [abs, rel] : entries) {
        const auto meta = fs::symlink_status(abs, ec);
        if (ec) fail("Cannot stat a source entry");
        const auto path = rel.generic_string();
        if (path.size() > max_path) fail("Source path too long");
        const bool regular = fs::is_regular_file(meta);
        const bool directory = fs::is_directory(meta);
        const bool symlink = fs::is_symlink(meta);
        if (!regular && !directory && !symlink)
            fail("Special files are not allowed in native snapshots");
        out.push(std::array<unsigned char, 1>{static_cast<unsigned char>(regular ? 1 : directory ? 2 : 3)});
        enc_num<std::uint32_t>(out, static_cast<std::uint32_t>(path.size()));
        enc_raw(out, path);
        if (regular) {
            Fd fd(open(abs.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
            struct stat st{};
            if (fd.value < 0 || fstat(fd.value, &st) != 0 ||
                !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size < 0 ||
                static_cast<std::uint64_t>(st.st_size) > max_bytes)
                fail("Unreadable or hardlinked source file");
            auto size = static_cast<std::uint64_t>(st.st_size);
            enc_num<std::uint64_t>(out, size);
            std::array<unsigned char, 65536> chunk{};
            while (size) {
                const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(chunk.size(), size));
                read_all(fd.value, std::span(chunk.data(), n));
                out.push(std::span(chunk.data(), n));
                size -= n;
            }
            struct stat after{};
            if (fstat(fd.value, &after) != 0 || after.st_size != st.st_size)
                fail("Source was modified during backup");
#ifdef __APPLE__
            if (after.st_mtimespec.tv_sec != st.st_mtimespec.tv_sec ||
                after.st_mtimespec.tv_nsec != st.st_mtimespec.tv_nsec)
#else
            if (after.st_mtim.tv_sec != st.st_mtim.tv_sec ||
                after.st_mtim.tv_nsec != st.st_mtim.tv_nsec)
#endif
                fail("Source was modified during backup");
        }
        if (symlink) {
            auto link = fs::read_symlink(abs, ec);
            if (ec || link.empty() || link.is_absolute()) fail("Unsafe source symlink");
            const auto target = (rel.parent_path() / link).lexically_normal();
            if (!safe_rel(target)) fail("Symlink escapes the backup root");
            const std::string value = link.generic_string();
            if (value.size() > max_path) fail("Symlink target too long");
            enc_num<std::uint32_t>(out, static_cast<std::uint32_t>(value.size()));
            enc_raw(out, value);
        }
    }
    out.push(std::array<unsigned char, 1>{0});
}
void make_private_parents(const fs::path& stage, const fs::path& relative) {
    fs::path current = stage;
    for (const auto& part : relative) {
        current /= part;
        if (mkdir(current.c_str(), 0700) != 0 && errno != EEXIST)
            fail("Cannot create a private restore parent");
        struct stat st{};
        if (lstat(current.c_str(), &st) != 0 ||
            !S_ISDIR(st.st_mode) || (st.st_mode & 077) != 0)
            fail("Unsafe or non-private restore parent directory");
    }
}
void decode_tree(Reader& in, const fs::path& stage) {
    std::array<unsigned char, 8> prefix{};
    in.take(prefix);
    if (!std::equal(prefix.begin(), prefix.end(), tree_magic.begin()))
        fail("Unrecognized encrypted archive content");
    std::set<std::string> seen;
    std::vector<std::pair<fs::path, std::string>> links;
    for (std::uint64_t count = 0;; ++count) {
        if (count > 1000000) fail("Too many archive entries");
        const auto kind = in.byte();
        if (kind == 0) break;
        if (kind < 1 || kind > 4) fail("Invalid archive entry type");
        const fs::path rel = text(in, dec_num<std::uint32_t>(in));
        if (!safe_rel(rel) || !seen.insert(rel.generic_string()).second)
            fail("Duplicate or escaping archive path");
        auto target = stage / rel;
        // Materialize only real private 0700 parents. No restored symlink
        // can be followed because symlinks are created only at the end.
        make_private_parents(stage, rel.parent_path());
        if (kind == 2) {
            if (mkdir(target.c_str(), 0700) != 0 && errno != EEXIST)
                fail("Cannot restore private directory");
            struct stat st{};
            if (lstat(target.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) ||
                (st.st_mode & 077) != 0)
                fail("Restored directory is not a private real directory");
        } else if (kind == 1) {
            auto remaining = dec_num<std::uint64_t>(in);
            if (remaining > max_bytes) fail("Archive entry exceeds maximum size");
            Fd out(open(target.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
            if (out.value < 0) fail("Cannot create private recovered file");
            std::array<unsigned char, 65536> chunk{};
            while (remaining) {
                const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, chunk.size()));
                in.take(std::span(chunk.data(), n));
                write_all(out.value, std::span(chunk.data(), n));
                remaining -= n;
            }
            if (fsync(out.value) != 0) fail("Restored data cannot be synchronized");
        } else if (kind == 4) {
            // Chunked logical database stream. A zero-length chunk terminates
            // the record. The enclosing AES-GCM tag authenticates all chunks.
            Fd out(open(target.c_str(), O_WRONLY | O_CREAT | O_EXCL |
                        O_NOFOLLOW | O_CLOEXEC, 0600));
            if (out.value < 0) fail("Cannot create private recovered SQL file");
            std::uint64_t total = 0;
            std::array<unsigned char, 65536> bytes{};
            for (;;) {
                const auto length = dec_num<std::uint32_t>(in);
                if (length == 0) break;
                if (length > bytes.size() || length > max_bytes - total)
                    fail("Invalid encrypted database dump chunk");
                in.take(std::span(bytes.data(), length));
                write_all(out.value, std::span(bytes.data(), length));
                total += length;
            }
            if (total == 0 || fsync(out.value) != 0)
                fail("Empty or unsynchronized recovered SQL export");
        } else {
            std::string link = text(in, dec_num<std::uint32_t>(in));
            const auto pointed = (rel.parent_path() / link).lexically_normal();
            if (!safe_rel(pointed)) fail("Restored symlink escapes recovery directory");
            links.emplace_back(target, std::move(link));
        }
    }
    in.end();  // Do not expose the tree until AES-GCM validates the entire payload.
    for (const auto& [link, value] : links) {
        if (fs::exists(link) || fs::is_symlink(fs::symlink_status(link)))
            fail("Duplicate or colliding symlink");
        fs::create_symlink(value, link);
    }
}
void publish(const fs::path& from, const fs::path& target) {
#if defined(__linux__)
    if (syscall(SYS_renameat2, AT_FDCWD, from.c_str(), AT_FDCWD, target.c_str(), 1) != 0)
        fail("Atomic exclusive snapshot publication failed");
#elif defined(__APPLE__)
    if (renamex_np(from.c_str(), target.c_str(), RENAME_EXCL) != 0)
        fail("Atomic exclusive snapshot publication failed");
#else
    fail("Native vault requires macOS or Linux atomic no-replace rename");
#endif
}
void sync_parent(const fs::path& p) {
    Fd dir(open(p.c_str(), O_RDONLY | O_CLOEXEC));
    if (dir.value < 0 || fsync(dir.value) != 0)
        fail("Cannot synchronize snapshot parent directory");
}
bool valid_repo(const fs::path& root) {
    std::error_code ec;
    const auto st = fs::symlink_status(root, ec);
    return !ec && root.is_absolute() && fs::is_directory(st) &&
           !fs::is_symlink(st) &&
           (static_cast<unsigned>(st.permissions()) & 077) == 0;
}
template <typename F> auto guarded(F&& fn) {
    using Return = decltype(fn());
    try { return fn(); }
    catch (const std::exception& e) { return Return(std::unexpected(e.what())); }
}
} // namespace

std::expected<std::string, std::string> ciphertext_digest(const fs::path& archive) {
    return guarded([&]() -> std::expected<std::string, std::string> {
        Fd file(open(archive.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
        if (file.value < 0) fail("Cannot open encrypted snapshot for fingerprint");
        struct stat st{};
        if (fstat(file.value, &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_nlink != 1 || st.st_size < 52)
            fail("Snapshot fingerprint requires a regular, non-hardlinked archive");
        using Digest = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
        Digest context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
            fail("SHA-256 digest initialization failed");
        std::array<unsigned char, 65536> bytes{};
        while (true) {
            const ssize_t n = read(file.value, bytes.data(), bytes.size());
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) fail("Cannot read snapshot fingerprint");
            if (n == 0) break;
            if (EVP_DigestUpdate(context.get(), bytes.data(),
                                 static_cast<std::size_t>(n)) != 1)
                fail("SHA-256 digest failed");
        }
        std::array<unsigned char, 32> checksum{};
        unsigned int actual = 0;
        if (EVP_DigestFinal_ex(context.get(), checksum.data(), &actual) != 1 ||
            actual != checksum.size())
            fail("SHA-256 digest finalization failed");
        constexpr char hex[] = "0123456789abcdef";
        std::string id;
        id.reserve(64);
        for (auto byte : checksum) {
            id += hex[byte >> 4];
            id += hex[byte & 15];
        }
        return id;
    });
}

Status initialize(const fs::path& repository) {
    return guarded([&]() -> Status {
        if (!repository.is_absolute() || repository.filename().empty())
            fail("Repository must be an absolute non-root path");
        // mkdir(0700) avoids the exposure window of create_directory + chmod.
        if (mkdir(repository.c_str(), 0700) != 0)
            fail("Repository must be a newly created, private directory");
        if (!valid_repo(repository)) fail("Cannot protect vault repository");
        sync_parent(repository.parent_path());
        return {};
    });
}
Snapshot create(const fs::path& repository, const fs::path& source,
                const fs::path& password_file) {
    return guarded([&]() -> Snapshot {
        if (!valid_repo(repository)) fail("Repository must be an existing private directory");
        if (!source.is_absolute() || source == source.root_path())
            fail("Source must be a non-root absolute path");
        std::error_code ec;
        const auto real_repo = fs::weakly_canonical(repository, ec);
        if (ec) fail("Cannot inspect repository path");
        const auto real_source = fs::weakly_canonical(source, ec);
        if (ec) fail("Cannot inspect source path");
        const auto repo_path = real_repo.string();
        const auto source_path = real_source.string();
        if (repo_path == source_path ||
            repo_path.starts_with(source_path + "/") ||
            source_path.starts_with(repo_path + "/"))
            fail("Source and vault repository must be independent directories");
        const auto actual_pass = fs::weakly_canonical(password_file, ec);
        if (ec) fail("Cannot inspect password file placement");
        const auto key_path = actual_pass.string();
        if (key_path == source_path || key_path.starts_with(source_path + "/") ||
            key_path.starts_with(repo_path + "/"))
            fail("Password file must not be inside the source or repository");
        TempFile temp(repository, ".securevault-write-");
        Writer writer(temp.fd, password_file);
        encode_tree(writer, source);
        writer.done();
        const auto fingerprint = ciphertext_digest(temp.name);
        if (!fingerprint) fail(fingerprint.error());
        const auto dest = repository / (*fingerprint + ".svlt");
        publish(temp.name, dest);
        temp.name.clear();
        sync_parent(repository);
        return dest;
    });
}
Snapshot create_logical_dump(const fs::path& repository,
                             const fs::path& password_file,
                             const std::string& database,
                             const fs::path& executable) {
    return guarded([&]() -> Snapshot {
        if (!valid_repo(repository))
            fail("Logical dump requires an existing private Vault repository");
        std::error_code ec;
        const auto real_repo = fs::weakly_canonical(repository, ec);
        if (ec) fail("Cannot inspect logical backup repository");
        const auto real_key = fs::weakly_canonical(password_file, ec);
        if (ec || real_key.string().starts_with(real_repo.string() + "/"))
            fail("Database backup password file must be outside the repository");
        std::vector<std::string> arguments;
        std::string filename;
        if (database == "postgresql") {
            arguments = {"pg_dumpall"};
            filename = "postgresql-all.sql";
        } else if (database == "mariadb") {
            arguments = {"mariadb-dump", "--all-databases",
                         "--single-transaction", "--quick", "--routines",
                         "--events", "--triggers"};
            filename = "mariadb-all.sql";
        } else {
            fail("Only PostgreSQL and MariaDB logical backups are supported");
        }
        // Integration tests pass an explicit absolute fixture executable.
        // No environment/PATH override is used to resolve a mock dumper.
        if (!executable.empty()) {
            if (!executable.is_absolute() || !fs::exists(executable))
                fail("Explicit database executable must be an existing absolute path");
            arguments[0] = executable.string();
        }
        int ends[2] = {-1, -1};
        if (pipe(ends) != 0) fail("Cannot create encrypted database stream");
        const pid_t pid = fork();
        if (pid < 0) {
            close(ends[0]); close(ends[1]);
            fail("Cannot start database dump process");
        }
        if (pid == 0) {
            setpgid(0, 0);
            close(ends[0]);
            if (dup2(ends[1], STDOUT_FILENO) < 0) _exit(127);
            close(ends[1]);
            const int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
            if (null_fd < 0 ||
                dup2(null_fd, STDIN_FILENO) < 0 ||
                dup2(null_fd, STDERR_FILENO) < 0) _exit(127);
            close(null_fd);
            std::vector<char*> argv;
            for (auto& arg : arguments) argv.push_back(arg.data());
            argv.push_back(nullptr);
            execvp(argv[0], argv.data());
            _exit(127);
        }
        close(ends[1]);
        setpgid(pid, pid);
        struct Producer {
            pid_t pid;
            Fd pipe;
            bool reaped = false;
            explicit Producer(pid_t child, int read_fd): pid(child), pipe(read_fd) {}
            ~Producer() {
                if (!reaped) {
                    kill(-pid, SIGKILL);
                    kill(pid, SIGKILL);
                    int status = 0;
                    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
                }
            }
            void finish() {
                const int read_fd = std::exchange(pipe.value, -1);
                // The read end is no longer required; it cannot be leaked.
                if (read_fd >= 0) close(read_fd);
                int status = 0;
                pid_t result;
                do { result = waitpid(pid, &status, 0); }
                while (result < 0 && errno == EINTR);
                if (result == pid) reaped = true;
                if (result != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
                    fail("Database dump exited unsuccessfully; no snapshot published");
            }
        } producer(pid, ends[0]);
        TempFile stage(repository, ".securevault-db-");
        Writer writer(stage.fd, password_file);
        enc_raw(writer, std::string_view(
            reinterpret_cast<const char*>(tree_magic.data()), tree_magic.size()));
        writer.push(std::array<unsigned char, 1>{4});
        enc_num<std::uint32_t>(writer, static_cast<std::uint32_t>(filename.size()));
        enc_raw(writer, filename);
        std::array<unsigned char, 65536> buf{};
        const auto start = std::chrono::steady_clock::now();
        auto last_progress = start;
        std::uint64_t produced = 0;
        while (true) {
            const auto now = std::chrono::steady_clock::now();
            if (now - start > std::chrono::hours(12) ||
                now - last_progress > std::chrono::minutes(2))
                fail("Database dump stalled or exceeded the time limit");
            pollfd waiting{producer.pipe.value, static_cast<short>(POLLIN | POLLHUP), 0};
            const int ready = poll(&waiting, 1, 1000);
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0) fail("Cannot read encrypted database stream");
            if (ready == 0) continue;
            const ssize_t length = read(producer.pipe.value, buf.data(), buf.size());
            if (length < 0 && errno == EINTR) continue;
            if (length < 0) fail("Database dump stream read failed");
            if (length == 0) break;
            produced += static_cast<std::uint64_t>(length);
            enc_num<std::uint32_t>(writer, static_cast<std::uint32_t>(length));
            writer.push(std::span(buf.data(), static_cast<std::size_t>(length)));
            last_progress = std::chrono::steady_clock::now();
        }
        if (produced == 0) fail("Refusing to publish empty database backup");
        enc_num<std::uint32_t>(writer, 0);
        writer.push(std::array<unsigned char, 1>{0});
        writer.done();
        producer.finish();
        const auto fingerprint = ciphertext_digest(stage.name);
        if (!fingerprint) fail(fingerprint.error());
        const auto dest = repository / (*fingerprint + ".svlt");
        publish(stage.name, dest);
        stage.name.clear();
        sync_parent(repository);
        return dest;
    });
}
// The generation marker is itself an authenticated SVLT snapshot. Its
// plaintext contains only component IDs, never exported database records.
Snapshot create_generation(const fs::path& repository, const fs::path& source,
                           const fs::path& password_file,
                           const fs::path& pg_executable,
                           const fs::path& mariadb_executable) {
    return guarded([&]() -> Snapshot {
        if (!valid_repo(repository))
            fail("Native generation requires an existing private repository");
        const auto files = create(repository, source, password_file);
        if (!files) fail("File generation component failed: " + files.error());
        const auto postgres = create_logical_dump(
            repository, password_file, "postgresql", pg_executable);
        if (!postgres) fail("PostgreSQL generation component failed: " +
                            postgres.error());
        const auto mariadb = create_logical_dump(
            repository, password_file, "mariadb", mariadb_executable);
        if (!mariadb) fail("MariaDB generation component failed: " +
                          mariadb.error());

        const auto valid_id = [](const fs::path& file) {
            const std::string id = file.stem().string();
            return id.size() == 64 && std::all_of(
                id.begin(), id.end(), [](unsigned char c) {
                    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                });
        };
        if (!valid_id(*files) || !valid_id(*postgres) || !valid_id(*mariadb))
            fail("Generation cannot commit non-content-addressed snapshots");
        TempDir temp(fs::temp_directory_path());
        const auto marker_file = temp.name / "manifest.svgen";
        Fd fd(open(marker_file.c_str(),
                   O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (fd.value < 0) fail("Cannot allocate private generation manifest");
        const std::string record = "SVGEN02\n" + files->stem().string() + "\n" +
            postgres->stem().string() + "\n" + mariadb->stem().string() + "\n";
        write_all(fd.value, std::span(
            reinterpret_cast<const unsigned char*>(record.data()), record.size()));
        if (fsync(fd.value) != 0) fail("Cannot flush generation manifest");
        const auto committed = create(repository, marker_file, password_file);
        if (!committed) fail("Cannot encrypt generation commit marker: " +
                              committed.error());
        return *committed;
    });
}
Status verify_generation(const fs::path& repository,
                         const fs::path& manifest_snapshot,
                         const fs::path& password_file) {
    return guarded([&]() -> Status {
        if (!valid_repo(repository))
            fail("Generation validation requires a private repository");
        std::error_code ec;
        const auto real_repo = fs::weakly_canonical(repository, ec);
        if (ec) fail("Cannot resolve native generation repository");
        const auto real_marker = fs::weakly_canonical(manifest_snapshot, ec);
        if (ec || real_marker.parent_path() != real_repo)
            fail("Generation marker must reside in the specified repository");
        const auto marker_digest = ciphertext_digest(manifest_snapshot);
        if (!marker_digest ||
            manifest_snapshot.filename().string() != *marker_digest + ".svlt")
            fail("Generation marker has an invalid content address");
        TempDir scratch(fs::temp_directory_path());
        const auto unpack = scratch.name / "validated";
        const auto extracted = restore(manifest_snapshot, unpack, password_file);
        if (!extracted) fail("Cannot authenticate generation manifest: " +
                             extracted.error());
        const auto file = unpack / "manifest.svgen";
        const auto stat = fs::symlink_status(file, ec);
        if (ec || !fs::is_regular_file(stat) || fs::file_size(file, ec) > 512 || ec)
            fail("Generation manifest must be a short regular file");
        std::ifstream stream(file, std::ios::binary);
        if (!stream) fail("Cannot inspect decrypted generation marker");
        std::string header, files, postgres, mariadb, extra;
        if (!std::getline(stream, header) || !std::getline(stream, files) ||
            !std::getline(stream, postgres) || !std::getline(stream, mariadb) ||
            std::getline(stream, extra) || header != "SVGEN02")
            fail("Invalid native generation manifest structure");
        auto safe_id = [](const std::string& id) {
            return id.size() == 64 && std::all_of(
                id.begin(), id.end(), [](unsigned char c) {
                    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                });
        };
        if (!safe_id(files) || !safe_id(postgres) || !safe_id(mariadb) ||
            files == postgres || files == mariadb || postgres == mariadb)
            fail("Missing, duplicate or malformed generation snapshot identities");
        for (const auto& id : {files, postgres, mariadb}) {
            const auto member = repository / (id + ".svlt");
            const auto hash = ciphertext_digest(member);
            if (!hash || *hash != id)
                fail("Required generation component is missing or modified");
            const auto valid = verify(member, password_file);
            if (!valid)
                fail("Generation component failed AES-GCM authentication");
        }
        return {};
    });
}
Status verify(const fs::path& archive, const fs::path& password_file) {
    return guarded([&]() -> Status {
        Reader reader(archive, password_file);
        reader.authenticate();
        return {};
    });
}
Status restore(const fs::path& archive, const fs::path& target,
               const fs::path& password_file) {
    return guarded([&]() -> Status {
        if (!target.is_absolute() || target.filename().empty() ||
            target == target.root_path())
            fail("Restore destination must be an absolute, non-root new directory");
        for (const auto& p : target) if (p == "..") fail("Restore destination escapes directory");
        std::error_code ec;
        if (fs::exists(target, ec) || fs::is_symlink(fs::symlink_status(target, ec)))
            fail("Restore target exists or is a symlink");
        const auto parent_status = fs::symlink_status(target.parent_path(), ec);
        if (ec || !fs::is_directory(parent_status) || fs::is_symlink(parent_status))
            fail("Restore parent must be an existing real directory");
        { Reader validation(archive, password_file); validation.authenticate(); }
        TempDir stage(target.parent_path());
        Reader reader(archive, password_file);
        decode_tree(reader, stage.name);
        publish(stage.name, target);
        stage.name.clear();
        sync_parent(target.parent_path());
        return {};
    });
}
std::expected<std::vector<fs::path>, std::string> list(const fs::path& repository) {
    return guarded([&]() -> std::expected<std::vector<fs::path>, std::string> {
        if (!valid_repo(repository)) fail("Repository must be private and non-symlink");
        std::vector<fs::path> result;
        const auto valid = [](std::string s) {
            if (!s.ends_with(".svlt") || (s.size() != 37 && s.size() != 69))
                return false;
            const auto count = s.size() - 5;
            return std::all_of(s.begin(), s.begin() + count, [](unsigned char ch) {
                return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
            });
        };
        for (const auto& entry : fs::directory_iterator(repository)) {
            if (valid(entry.path().filename().string()) &&
                fs::is_regular_file(entry.symlink_status()))
                result.push_back(entry.path());
        }
        std::sort(result.begin(), result.end());
        return result;
    });
}
} // namespace securevault::vault
