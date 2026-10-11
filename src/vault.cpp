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
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <sys/stdio.h>
#endif

namespace securevault::vault {
namespace {
constexpr std::array<unsigned char, 8> magic{'S','V','L','T','0','0','1','\0'};
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
            static_cast<std::uint64_t>(st.st_size) > max_bytes)
            fail("Invalid encrypted archive file");
        remaining = static_cast<std::uint64_t>(st.st_size) - 36 - tag_size;
        read_all(input.value, header);
        if (!std::equal(magic.begin(), magic.end(), header.begin()))
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
        if (kind < 1 || kind > 3) fail("Invalid archive entry type");
        const fs::path rel = text(in, dec_num<std::uint32_t>(in));
        if (!safe_rel(rel) || !seen.insert(rel.generic_string()).second)
            fail("Duplicate or escaping archive path");
        auto target = stage / rel;
        std::error_code ec;
        const auto parent = target.parent_path();
        // Symlinks are materialized only after data and authentication.
        fs::create_directories(parent, ec);
        if (ec) fail("Cannot create restore directory");
        if (kind == 2) {
            if (!fs::create_directory(target, ec) && ec) fail("Cannot restore directory");
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
std::string random_id() {
    std::array<unsigned char, 16> id{};
    if (RAND_bytes(id.data(), id.size()) != 1) fail("Cannot generate snapshot ID");
    constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(32);
    for (auto c : id) { out += hex[c >> 4]; out += hex[c & 15]; }
    return out;
}
template <typename F> auto guarded(F&& fn) {
    using Return = decltype(fn());
    try { return fn(); }
    catch (const std::exception& e) { return Return(std::unexpected(e.what())); }
}
} // namespace

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
        TempFile temp(repository, ".securevault-write-");
        Writer writer(temp.fd, password_file);
        encode_tree(writer, source);
        writer.done();
        auto dest = repository / (random_id() + ".svlt");
        publish(temp.name, dest);
        temp.name.clear();
        sync_parent(repository);
        return dest;
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
        if (!fs::is_directory(target.parent_path(), ec) || ec)
            fail("Restore parent must already exist");
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
            if (s.size() != 37 || !s.ends_with(".svlt")) return false;
            return std::all_of(s.begin(), s.begin() + 32, [](unsigned char ch) {
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
