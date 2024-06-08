
# Simple HTTP Server

This repository contains a custom-built proxy server designed to filter HTTP requests based on IP addresses and hostnames. The server supports a configurable thread pool to efficiently manage incoming connections and provides robust error handling for non-compliant HTTP requests.

## Key Features

- **HTTP Version Compliance**: Only processes requests compliant with HTTP/1.0 and HTTP/1.1 protocols.
- **Selective Host Filtering**: Blocks or allows requests based on a configurable list of IPs and hostnames.
- **Concurrent Connection Management**: Uses a thread pool to handle multiple client connections simultaneously.
- **Error Management**: Generates comprehensive error responses for unsupported HTTP methods, versions, and blocked hosts.

## Getting Started

### Prerequisites

- Linux environment
- GCC compiler
- Standard C library

### Installation

1. Clone this repository:
   ```bash
   git clone [Your Repository URL]
   ```
2. Navigate to the cloned directory:
   ```bash
   cd proxyserver
   ```

### Compilation

Compile the server using:
```bash
gcc -o proxyserver proxyServer.c threadpool.c -lpthread
```

## Usage

Run the proxy server with the following command:
```bash
./proxyserver <port> <pool-size> <max-number-of-requests> <filter-file>
```
Parameters:
- `port`: The port number the server listens on.
- `pool-size`: The number of threads in the pool.
- `max-number-of-requests`: The maximum requests the server handles before termination.
- `filter-file`: The path to the blacklist file.

### Example
```bash
./proxyserver 8080 4 100 filter.txt
```

## Configuration

To configure the server's filter settings, modify the `filter.txt` file. Enter IPs/hostnames to block, one per line:
```
104.154.64.64/17
www.example.com
```

## Contributing

Contributions to this project are welcome! Please feel free to fork the repository, make changes, and submit a pull request.


