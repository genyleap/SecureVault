#include "vault.hpp"
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <iostream>
#include <utility>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
namespace {
void require(bool valid, const char* why) {
    if (!valid) throw std::runtime_error(why);
}
struct Temp {
    fs::path path;
    Temp() {
        std::string text = (fs::temp_directory_path() / "securevault-tls-test-XXXXXX").string();
        std::vector<char> buffer(text.begin(), text.end());
        buffer.push_back('\0');
        require(mkdtemp(buffer.data()) != nullptr, "Temporary TLS test directory unavailable");
        path = buffer.data();
    }
    ~Temp() { std::error_code ec; fs::remove_all(path, ec); }
};
void put(const fs::path& path, const std::string& contents, bool private_file = false) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    require(static_cast<bool>(stream), "Cannot write HTTPS fixture");
    if (private_file) require(chmod(path.c_str(), 0600) == 0, "Cannot protect HTTPS fixture");
}
std::string get(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    require(static_cast<bool>(stream), "Cannot read HTTPS fixture");
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}
void make_ca(const fs::path& certificate, SSL_CTX* context) {
    EVP_PKEY* key = EVP_RSA_gen(2048);
    require(key != nullptr, "Cannot generate temporary TLS key");
    X509* cert = X509_new();
    require(cert != nullptr, "Cannot generate temporary TLS certificate");
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_set_pubkey(cert, key);
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509V3_CTX extension_ctx{};
    X509V3_set_ctx(&extension_ctx, cert, cert, nullptr, nullptr, 0);
    for (const auto& extension : std::array<std::pair<int, const char*>,2>{
            std::pair{NID_basic_constraints, "critical,CA:TRUE"},
            std::pair{NID_subject_alt_name, "DNS:localhost"}}) {
        X509_EXTENSION* extra = X509V3_EXT_conf_nid(nullptr, &extension_ctx,
                                                   extension.first, const_cast<char*>(extension.second));
        require(extra != nullptr, "Cannot create TLS certificate extension");
        require(X509_add_ext(cert, extra, -1) == 1, "Cannot attach TLS extension");
        X509_EXTENSION_free(extra);
    }
    require(X509_sign(cert, key, EVP_sha256()) > 0, "Cannot sign ephemeral certificate");
    FILE* pem = fopen(certificate.c_str(), "wb");
    require(pem != nullptr && PEM_write_X509(pem, cert) == 1, "Cannot write temporary CA bundle");
    fclose(pem);
    require(SSL_CTX_use_certificate(context, cert) == 1 &&
            SSL_CTX_use_PrivateKey(context, key) == 1,
            "Cannot configure ephemeral TLS server");
    EVP_PKEY_free(key);
    X509_free(cert);
}
void send_all(SSL* connection, const std::string& bytes) {
    std::size_t sent = 0;
    while (sent < bytes.size()) {
        const int n = SSL_write(connection, bytes.data() + sent,
                                static_cast<int>(std::min<std::size_t>(bytes.size() - sent, 16384)));
        require(n > 0, "Cannot write loopback HTTPS reply");
        sent += static_cast<std::size_t>(n);
    }
}
enum class Mode { Upload, Download, RejectUpload, RejectDownload };
void serve_once(int listener, SSL_CTX* context, Mode mode,
                const fs::path& captured, const std::string& body) {
    const int client = accept(listener, nullptr, nullptr);
    require(client >= 0, "No loopback HTTPS connection");
    timeval timeout{20, 0};
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    SSL* ssl = SSL_new(context);
    require(ssl != nullptr, "Cannot allocate ephemeral TLS connection");
    SSL_set_fd(ssl, client);
    require(SSL_accept(ssl) == 1, "Local TLS handshake failed");
    std::string request;
    std::array<char,8192> buf{};
    const auto boundary = std::string("\r\n\r\n");
    while (request.find(boundary) == std::string::npos) {
        const int n = SSL_read(ssl, buf.data(), buf.size());
        require(n > 0 && request.size() < 65536, "HTTPS request header incomplete");
        request.append(buf.data(), n);
    }
    const auto index = request.find(boundary);
    const auto headers = request.substr(0, index);
    if (mode == Mode::Upload || mode == Mode::RejectUpload) {
        require(headers.starts_with("PUT ") &&
                headers.find("If-None-Match: *") != std::string::npos,
                "Conditional PUT header missing");
        const std::string marker = "Content-Length: ";
        const auto position = headers.find(marker);
        require(position != std::string::npos, "Expected explicit upload content length");
        const auto last = headers.find("\r\n", position);
        const auto length = std::stoull(headers.substr(position + marker.size(),
                            last - position - marker.size()));
        require(length > 50 && length < 10000000, "Invalid encrypted upload size");
        std::string received = request.substr(index + 4);
        while (received.size() < length) {
            const int n = SSL_read(ssl, buf.data(), buf.size());
            require(n > 0, "HTTPS upload truncated");
            received.append(buf.data(), n);
        }
        require(received.size() == length, "Unexpected extra HTTPS upload bytes");
        if (mode == Mode::RejectUpload)
            send_all(ssl, "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        else {
            put(captured, received);
            send_all(ssl, "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    } else {
        require(headers.starts_with("GET "), "Expected a TLS GET request");
        if (mode == Mode::RejectDownload)
            send_all(ssl, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        else {
            send_all(ssl, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
                      std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n");
            send_all(ssl, body);
        }
    }
    SSL_free(ssl);
    close(client);
    close(listener);
}
struct Loopback {
    int socket_fd = -1;
    pid_t child = -1;
    int port = 0;
    Loopback(SSL_CTX* context, Mode mode, const fs::path& captured, std::string body = {}) {
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        require(socket_fd >= 0, "Cannot open temporary TLS loopback");
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        require(bind(socket_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
                listen(socket_fd, 1) == 0,
                "Cannot bind temporary TLS loopback");
        socklen_t size = sizeof(address);
        require(getsockname(socket_fd, reinterpret_cast<sockaddr*>(&address), &size) == 0,
                "Cannot discover HTTPS fixture port");
        port = ntohs(address.sin_port);
        child = fork();
        require(child >= 0, "Cannot start local TLS fixture");
        if (child == 0) {
            try { serve_once(socket_fd, context, mode, captured, body); _exit(0); }
            catch(const std::exception& e) {
                std::cerr << "Loopback TLS fixture: " << e.what() << '\n';
                _exit(3);
            }
        }
    }
    bool finish() {
        int status = 0;
        const auto waited = waitpid(child, &status, 0);
        child = -1;
        return waited > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    ~Loopback() {
        if (socket_fd >= 0) close(socket_fd);
        if (child > 0) {
            kill(child, SIGKILL);
            int status = 0;
            waitpid(child, &status, 0);
        }
    }
};
} // namespace

int main() {
    try {
        Temp tmp;
        SSL_CTX* context = SSL_CTX_new(TLS_server_method());
        require(context != nullptr, "Cannot create TLS fixture context");
        const auto cert = tmp.path / "ca.pem";
        make_ca(cert, context);
        const auto repo = tmp.path / "repository";
        const auto source = tmp.path / "data";
        const auto password = tmp.path / "password";
        const auto url_file = tmp.path / "signed-url";
        fs::create_directory(source);
        put(source / "example.txt", "TEST-SENSITIVE-HTTPS-ROUNDTRIP-4589235\n");
        put(password, "unit-test-secret-32-bytes-generated!", true);
        require(securevault::vault::initialize(repo).has_value(), "Cannot initialize local repository");
        const auto snapshot = securevault::vault::create(repo, source, password);
        require(snapshot.has_value(), "Cannot create encrypted fixture snapshot");
        setenv("NO_PROXY", "localhost,127.0.0.1", 1);
        setenv("no_proxy", "localhost,127.0.0.1", 1);
        Loopback put_server(context, Mode::Upload, tmp.path / "received");
        put(url_file, "https://localhost:" + std::to_string(put_server.port) + "/one-object\n", true);
        const auto uploaded = securevault::vault::upload_https(*snapshot, password, url_file, cert);
        require(uploaded.has_value(), "Native conditional HTTPS upload failed");
        require(put_server.finish(), "Loopback conditional HTTPS PUT failed");
        require(get(tmp.path / "received") == get(*snapshot),
                "Uploaded encrypted ciphertext differs from native archive");

        // Object storage must reject conditional overwrites. A 412 must
        // never be reported as a successful off-site backup.
        Loopback conflict_server(context, Mode::RejectUpload, tmp.path / "must-not-exist");
        put(url_file, "https://localhost:" + std::to_string(conflict_server.port) + "/existing\n", true);
        const auto conflict = securevault::vault::upload_https(
            *snapshot, password, url_file, cert);
        require(!conflict && !fs::exists(tmp.path / "must-not-exist"),
                "Precondition-failed HTTP 412 must reject an upload");
        require(conflict_server.finish(), "TLS 412 response fixture failed");

        const auto original = get(*snapshot);
        const auto replica_repo = tmp.path / "replica-repository";
        require(securevault::vault::initialize(replica_repo).has_value(),
                "Cannot initialize independent local receiver");
        const auto object_id = snapshot->stem().string();
        require(object_id.size() == 64, "Native snapshot ID must be SHA-256");
        Loopback get_server(context, Mode::Download, tmp.path / "unused", original);
        put(url_file, "https://localhost:" + std::to_string(get_server.port) + "/one-object\n", true);
        const auto retrieved = securevault::vault::download_https(
            replica_repo, object_id, password, url_file, cert);
        require(retrieved.has_value(), "Authenticated HTTPS download failed");
        require(get_server.finish(), "Loopback HTTPS GET failed");
        require(get(*retrieved) == original, "Downloaded encrypted blob changed in transit");
        require(securevault::vault::verify(*retrieved, password).has_value(),
                "Downloaded snapshot cannot be authenticated");
        const auto target = tmp.path / "restored";
        require(securevault::vault::restore(*retrieved, target, password).has_value(),
                "Downloaded HTTPS snapshot cannot be restored");
        require(get(target / "example.txt") ==
                "TEST-SENSITIVE-HTTPS-ROUNDTRIP-4589235\n",
                "Restored encrypted HTTPS payload mismatch");

        // Expired or forbidden pre-signed GET URLs cannot publish anything.
        Loopback forbidden_server(context, Mode::RejectDownload, tmp.path / "unused");
        put(url_file, "https://localhost:" + std::to_string(forbidden_server.port) + "/expired\n", true);
        const auto forbidden_repo = tmp.path / "forbidden-repository";
        require(securevault::vault::initialize(forbidden_repo).has_value(),
                "Cannot prepare private expired-token recipient");
        const auto forbidden = securevault::vault::download_https(
            forbidden_repo, object_id, password, url_file, cert);
        require(!forbidden && !fs::exists(forbidden_repo / (object_id + ".svlt")),
                "HTTP 403 cannot publish a remote snapshot");
        require(forbidden_server.finish(), "TLS 403 response fixture failed");

        // Even a perfectly valid, authenticated SVLT archive must match
        // the particular SHA-256 content ID the caller requested.
        Loopback identity_server(context, Mode::Download, tmp.path / "unused", original);
        put(url_file, "https://localhost:" + std::to_string(identity_server.port) + "/wrong-object\n", true);
        const auto mismatched_id = std::string(64, 'f');
        const auto mismatch = securevault::vault::download_https(
            forbidden_repo, mismatched_id, password, url_file, cert);
        require(!mismatch && !fs::exists(forbidden_repo / (mismatched_id + ".svlt")),
                "Authenticated but wrong ciphertext identity must fail closed");
        require(identity_server.finish(), "TLS wrong-identity fixture failed");

        auto tampered = original;
        tampered[100] ^= 0x20;
        Loopback bad_server(context, Mode::Download, tmp.path / "unused", tampered);
        put(url_file, "https://localhost:" + std::to_string(bad_server.port) + "/malicious\n", true);
        const auto bad_repo = tmp.path / "tampered-repository";
        require(securevault::vault::initialize(bad_repo).has_value(),
                "Cannot prepare isolated tampering recipient");
        const auto bad_id = object_id;
        const auto invalid = securevault::vault::download_https(
            bad_repo, bad_id, password, url_file, cert);
        require(!invalid && !fs::exists(bad_repo / (bad_id + ".svlt")),
                "Tampered HTTPS download was published");
        require(bad_server.finish(), "Loopback negative HTTPS GET failed");
        SSL_CTX_free(context);
        std::cout << "Native C++23 HTTPS: conditional PUT, authenticated GET, restore, "
                     "and tampering refusal passed\n";
        return 0;
    } catch(const std::exception& e) {
        std::cerr << "Native HTTPS integration failed: " << e.what() << '\n';
        return 1;
    }
}
