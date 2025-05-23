# SecureVault Backup System

**SecureVault** is a robust, cross-platform backup solution designed for automated, secure, and efficient backups of files and databases. Written in modern C++23, it supports Linux, Windows, and macOS, offering flexible scheduling, incremental backups, database support (MySQL, PostgreSQL), remote transfers via SFTP, and notifications via Telegram or email. SecureVault is ideal for system administrators and developers needing a reliable backup tool for critical data.

## Features

- **Cross-Platform**: Runs on Linux (Ubuntu), Windows, and macOS with platform-specific default directories and configurations.
- **File Backups**: Performs full or incremental backups of specified directories using tar.gz compression, with customizable file exclusion by extension.
- **Database Backups**: Supports MySQL and PostgreSQL, backing up all databases to compressed `.sql.gz` files.
- **Scheduling**: Configurable backup schedules (daily, weekly, monthly) with precise timing and day-of-week/month options.
- **Remote Transfers**: Securely transfers backups to remote servers via SFTP.
- **Notifications**: Sends success or failure notifications via Telegram or email (email currently simulated; SMTP support planned).
- **Retention Policy**: Automatically cleans up old backups based on a configurable retention period.
- **Logging**: Detailed logging of backup operations and errors to dedicated log files.
- **Verification**: Validates backup integrity using `libarchive` to ensure reliability.
- **Modern C++23**: Leverages C++23 features for performance and maintainability, with strict compiler requirements (GCC 13+, Clang 16+, MSVC 19.29+).

## Prerequisites

### Dependencies
- **C++ Compiler**: GCC 13+, Clang 16+, or MSVC 19.29+ with C++23 support.
- **Libraries**:
  - `libarchive` (file compression and verification)
  - `libssh` (SFTP transfers)
  - `libcurl` (Telegram notifications)
  - `zlib` (compression)
  - `jsoncpp` (configuration parsing)

### Platform-Specific Requirements
- **Linux (Ubuntu 24.04)**:
  - Install dependencies: `sudo apt install -y libarchive-dev libssh-dev libcurl4-openssl-dev zlib1g-dev libjsoncpp-dev cmake g++`
- **Windows**:
  - Install vcpkg: `git clone https://github.com/microsoft/vcpkg && cd vcpkg && bootstrap-vcpkg.bat`
  - Install dependencies: `vcpkg install libarchive libssh libcurl jsoncpp zlib`
- **macOS**:
  - Install Homebrew: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
  - Install dependencies: `brew install libarchive libssh libcurl jsoncpp zlib cmake`

## Installation

### Clone the Repository
```bash
git clone https://github.com/genyleap/securevault.git
cd securevault
```

### Build on Linux
```bash
mkdir build && cd build
cmake ..
make
sudo make install
```

### Build on Windows
```bash
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
cmake --install .
```

### Build on macOS
```bash
mkdir build && cd build
cmake ..
make
sudo make install
```

## Configuration

SecureVault uses a JSON configuration file (`backup_config.json`) to define backup settings. The default paths are:
- **Linux**: `/var/www/genyleap.com/public_html/app/backup_system/backup_config.json`
- **Windows**: `C:/Backups/SecureVault/backup_config.json`
- **macOS**: `/Users/Shared/Backups/SecureVault/backup_config.json`

### Example Configuration
```json
{
    "backup_base": "/var/backups/securevault/",
    "backup_dirs": ["/var/www/", "/etc/nginx/"],
    "exclude_extensions": [".tmp", ".bak", ".log", ".cache"],
    "retention_days": 7,
    "databases": [
        {
            "type": "mysql",
            "user": "root",
            "password": "your_mysql_password",
            "host": "localhost",
            "port": 3306
        },
        {
            "type": "postgresql",
            "user": "postgres",
            "password": "your_postgres_password",
            "host": "localhost",
            "port": 5432
        }
    ],
    "schedule": {
        "type": "daily",
        "time": "15:25:00",
        "day_of_week": "monday",
        "day_of_month": 1
    },
    "sftp": {
        "host": "remote.example.com",
        "user": "sftp_user",
        "password": "sftp_password",
        "port": 22,
        "remote_dir": "/backups/"
    },
    "telegram": {
        "bot_token": "your_bot_token",
        "chat_id": "your_chat_id"
    },
    "email": {
        "email_to": "admin@example.com",
        "smtp_server": "smtp.example.com"
    }
}
```

### Configuration Fields
- `backup_base`: Base directory for backup files (e.g., `/var/backups/securevault/`).
- `backup_dirs`: List of directories to back up.
- `exclude_extensions`: File extensions to exclude from backups.
- `retention_days`: Number of days to retain backups.
- `databases`: Array of database configurations (MySQL or PostgreSQL).
- `schedule`: Backup schedule (`daily`, `weekly`, `monthly`) with time and day settings.
- `sftp`: Remote server details for SFTP transfers (optional).
- `telegram`: Telegram notification settings (optional).
- `email`: Email notification settings (optional, simulated).

## Usage

### Run a Backup
```bash
backup [--config <path>] [--full] {daily|monthly|yearly}
```
- `--config <path>`: Specify a custom configuration file path.
- `--full`: Perform a full backup (default is incremental).
- `daily|monthly|yearly`: Backup type.

Example:
```bash
backup daily
```

### Run in Daemon Mode
Run SecureVault as a background process with scheduled backups:
```bash
backup --daemon [--config <path>]
```
Example:
```bash
backup --daemon
```

### Logs
- Backup logs: `<backup_base>/backup.log`
- Error logs: `<backup_base>/errors.log`
- Last backup timestamp: `<backup_base>/last_backup.txt`

Example:
```bash
cat /var/backups/securevault/backup.log
```

## Directory Structure
```
securevault/
├── src/                  # Source files
│   ├── backup.cpp
│   ├── database_backup.cpp
│   ├── file_backup.cpp
│   ├── remote_transfer.cpp
│   ├── notification.cpp
│   ├── backup_config.cpp
│   ├── backup_api.cpp
├── include/              # Header files
│   ├── backup.hpp
│   ├── file_backup.hpp
│   ├── remote_transfer.hpp
│   ├── notification.hpp
│   ├── backup_config.hpp
│   ├── backup_api.hpp
├── cmake/                # Custom CMake modules
│   ├── FindLibssh.cmake
│   ├── FindJsonCpp.cmake
├── backup_config.json    # Default configuration file
├── CMakeLists.txt        # CMake build configuration
├── README.md             # This file
```

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Commit changes: `git commit -m "Add your feature"`.
4. Push to the branch: `git push origin feature/your-feature`.
5. Open a pull request.

Please ensure code follows C++23 standards and includes appropriate documentation.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments
- Built with modern C++23 for performance and maintainability.
- Leverages industry-standard libraries: `libarchive`, `libssh`, `libcurl`, `zlib`, `jsoncpp`.
- Inspired by the need for a reliable, cross-platform backup solution.

## Contact
For issues, feature requests, or questions, please open an issue on the [GitHub repository](https://github.com/genyleap/securevault/issues) or contact [dev@genyleap.com](mailto:dev@genyleap.com).
