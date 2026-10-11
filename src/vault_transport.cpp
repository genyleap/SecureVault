#include "vault.hpp"
#include <curl/curl.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <regex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <sys/stdio.h>
#endif

namespace securevault::vault {
namespace {
struct Fd {
    int fd = -1;
    explicit Fd(int n = -1): fd(n) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    ~Fd() { if (fd >= 0) close(fd); }
};
using Easy = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>;
using Headers = std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)>;
[[noreturn]] void fail(std::string_view message) {
    throw std::runtime_error(std::string(message));
}
void require(bool ok, std::string_view message) { if (!ok) fail(message); }

std::string private_url(const fs::path& path) {
    require(path.is_absolute(), "URL file must be absolute");
    Fd file(open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    require(file.fd >= 0, "Cannot open private HTTPS URL file");
    struct stat statbuf{};
    require(fstat(file.fd, &statbuf) == 0 && S_ISREG(statbuf.st_mode) &&
            statbuf.st_nlink == 1 && (statbuf.st_mode & 077) == 0 &&
            statbuf.st_size >= 16 && statbuf.st_size < 8192,
            "HTTPS URL file must be private, non-symlink, and <=8192 bytes");
    std::string url(static_cast<std::size_t>(statbuf.st_size), '\0');
    std::size_t count = 0;
    while (count < url.size()) {
        const ssize_t n = read(file.fd, url.data() + count, url.size() - count);
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, "Failed reading private URL file");
        count += static_cast<std::size_t>(n);
    }
    if (!url.empty() && url.back() == '\n') url.pop_back();
    require(!url.empty() && url.starts_with("https://") &&
            url.find_first_of("\r\n\t <>") == std::string::npos,
            "Only a single HTTPS URL without whitespace is supported");
    // Deliberately reject embedded user:pass credentials; signed query URLs
    // are read from a restricted file instead of public CLI arguments.
    const auto slash = url.find('/', 8);
    const auto authority = url.substr(8, slash == std::string::npos
                                                ? std::string::npos : slash - 8);
    require(!authority.empty() && authority.find('@') == std::string::npos,
            "HTTPS endpoint cannot contain URL user credentials");
    return url;
}
void set_common(CURL* curl, const std::string& url, const fs::path& ca_bundle) {
    require(curl != nullptr, "Cannot create HTTP client");
    require(curl_easy_setopt(curl, CURLOPT_URL, url.c_str()) == CURLE_OK,
            "Invalid HTTPS URL");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (!ca_bundle.empty()) {
        require(ca_bundle.is_absolute() && fs::is_regular_file(ca_bundle),
                "Custom certificate bundle path must name a regular file");
        require(curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle.c_str()) == CURLE_OK,
                "Custom certificate bundle unavailable");
    }
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 43200L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 120L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "SecureVault-native-C++23/1.0");
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_NONE);
    curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_NONE);
    curl_easy_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, 0L);
}
void check_response(CURL* curl, CURLcode result, bool upload) {
    long status = 0;
    const auto info = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    // Avoid including libcurl error messages, which can contain signed URLs.
    require(info == CURLE_OK && result == CURLE_OK,
            upload ? "Encrypted HTTPS upload failed" : "Encrypted HTTPS download failed");
    require(status == 200 || status == 201 || status == 204,
            "Remote HTTPS endpoint returned an unexpected response status");
}
bool valid_name(std::string_view name) {
    if (name.size() != 64) return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}
bool private_repo(const fs::path& repo) {
    std::error_code ec;
    const auto st = fs::symlink_status(repo, ec);
    return !ec && repo.is_absolute() && fs::is_directory(st) &&
           !fs::is_symlink(st) &&
           (static_cast<unsigned>(st.permissions()) & 077) == 0;
}
void no_replace(const fs::path& from, const fs::path& to) {
#ifdef __linux__
    require(syscall(SYS_renameat2, AT_FDCWD, from.c_str(), AT_FDCWD,
                    to.c_str(), 1) == 0,
            "Downloaded snapshot already exists or cannot be published");
#elif defined(__APPLE__)
    require(renamex_np(from.c_str(), to.c_str(), RENAME_EXCL) == 0,
            "Downloaded snapshot already exists or cannot be published");
#else
    fail("Atomic no-replace publication unsupported on this platform");
#endif
}
std::size_t read_callback(char* out, std::size_t size, std::size_t n,
                          void* data) {
    if (size && n > SIZE_MAX / size) return CURL_READFUNC_ABORT;
    const auto count = size * n;
    if (count == 0) return 0;
    const auto fd = *static_cast<int*>(data);
    const ssize_t result = read(fd, out, count);
    if (result < 0) return CURL_READFUNC_ABORT;
    return static_cast<std::size_t>(result);
}
struct WriteState {
    int fd;
    std::uint64_t total = 0;
};
std::size_t write_callback(char* input, std::size_t size, std::size_t count,
                           void* opaque) {
    if (size && count > SIZE_MAX / size) return 0;
    const std::size_t length = size * count;
    auto& state = *static_cast<WriteState*>(opaque);
    constexpr std::uint64_t max_size = (1ULL << 35) + 64;
    if (length > max_size - state.total) return 0;
    std::size_t used = 0;
    while (used < length) {
        ssize_t n = write(state.fd, input + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        used += static_cast<std::size_t>(n);
    }
    state.total += length;
    return length;
}
std::size_t discard_callback(char*, std::size_t size, std::size_t count, void*) {
    if (size && count > SIZE_MAX / size) return 0;
    return size * count;
}
template<class F> auto guarded(F&& function) {
    using Ret = decltype(function());
    try { return function(); }
    catch(const std::exception& e) { return Ret(std::unexpected(e.what())); }
}
}
Status upload_https(const fs::path& archive, const fs::path& password_file,
                    const fs::path& url_file, const fs::path& ca_bundle) {
    return guarded([&]() -> Status {
        auto auth = verify(archive, password_file);
        require(auth.has_value(), "Cannot upload unauthenticated snapshot");
        const auto hash = ciphertext_digest(archive);
        require(hash && archive.filename().string() == *hash + ".svlt",
                "Upload requires a SHA-256 content-addressed snapshot");
        const std::string url = private_url(url_file);
        Fd input(open(archive.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
        struct stat st{};
        require(input.fd >= 0 && fstat(input.fd, &st) == 0 &&
                S_ISREG(st.st_mode) && st.st_size > 52 && st.st_nlink == 1,
                "Encrypted upload source must be a private regular snapshot file");
        Easy easy(curl_easy_init(), curl_easy_cleanup);
        require(easy != nullptr, "HTTPS transport unavailable");
        set_common(easy.get(), url, ca_bundle);
        Headers headers(nullptr, curl_slist_free_all);
        auto raw = curl_slist_append(nullptr, "If-None-Match: *");
        require(raw != nullptr, "Cannot allocate conditional upload headers");
        headers.reset(raw);
        raw = curl_slist_append(headers.get(), "Content-Type: application/octet-stream");
        require(raw != nullptr, "Cannot allocate content upload header");
        headers.release();
        headers.reset(raw);
        raw = curl_slist_append(headers.get(), "Expect:");
        require(raw != nullptr, "Cannot disable HTTP Expect handshake");
        headers.release();
        headers.reset(raw);
        curl_easy_setopt(easy.get(), CURLOPT_HTTPHEADER, headers.get());
        curl_easy_setopt(easy.get(), CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(easy.get(), CURLOPT_READFUNCTION, read_callback);
        curl_easy_setopt(easy.get(), CURLOPT_READDATA, &input.fd);
        curl_easy_setopt(easy.get(), CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size));
        curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION, discard_callback);
        const auto result = curl_easy_perform(easy.get());
        check_response(easy.get(), result, true);
        return {};
    });
}
Snapshot download_https(const fs::path& repository,
                        const std::string& snapshot_id,
                        const fs::path& password_file,
                        const fs::path& url_file, const fs::path& ca_bundle) {
    return guarded([&]() -> Snapshot {
        require(private_repo(repository), "Private repository required for download");
        require(valid_name(snapshot_id), "Invalid requested snapshot ID");
        const auto dest = repository / (snapshot_id + ".svlt");
        std::error_code ec;
        if (fs::exists(dest, ec) || fs::is_symlink(fs::symlink_status(dest, ec)))
            fail("Requested snapshot already exists");
        const std::string url = private_url(url_file);
        std::string pattern = (repository / ".securevault-download-XXXXXX").string();
        std::vector<char> name(pattern.begin(), pattern.end());
        name.push_back('\0');
        Fd file(mkstemp(name.data()));
        require(file.fd >= 0, "Cannot create private encrypted download stage");
        const fs::path stage = name.data();
        struct Cleanup {
            fs::path path;
            ~Cleanup() { if (!path.empty()) { std::error_code ec; fs::remove(path, ec); } }
        } cleanup{stage};
        Easy easy(curl_easy_init(), curl_easy_cleanup);
        require(easy != nullptr, "HTTPS transport unavailable");
        set_common(easy.get(), url, ca_bundle);
        WriteState writer{file.fd};
        curl_easy_setopt(easy.get(), CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &writer);
        curl_easy_setopt(easy.get(), CURLOPT_MAXFILESIZE_LARGE,
                         static_cast<curl_off_t>((1ULL << 35) + 64));
        const auto result = curl_easy_perform(easy.get());
        check_response(easy.get(), result, false);
        require(fsync(file.fd) == 0, "Cannot flush downloaded ciphertext");
        const auto hash = ciphertext_digest(stage);
        require(hash && *hash == snapshot_id,
                "Downloaded encrypted content does not match requested SHA-256 ID");
        const auto check = verify(stage, password_file);
        require(check.has_value(), "Downloaded encrypted snapshot failed authentication");
        no_replace(stage, dest);
        cleanup.path.clear();
        Fd dir(open(repository.c_str(), O_RDONLY | O_CLOEXEC));
        require(dir.fd >= 0 && fsync(dir.fd) == 0,
                "Cannot synchronize received snapshot metadata");
        return dest;
    });
}
}
