# Sultan The Renter

**Advanced Hash Cracker with Identification & Dictionary Attack**

A multi-threaded Python tool that detects common hash types (MD5, NTLM, SHA family) and performs dictionary attacks to crack them. Ideal for pentesting, CTFs, and cybersecurity enthusiasts.

## Features

* **Automatic Hash Type Detection**: Identifies MD5, NTLM, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 based on regex heuristic and MD5/NTLM prefix analysis.
* **Multi-threaded Dictionary Attack**: Speeds up cracking by dividing the wordlist across multiple threads.
* **Robust Error Handling**: Gracefully handles missing files, permission errors, and hashing exceptions.
* **Customizable Thread Count**: Adjust the number of worker threads to match your CPU capacity.
* **Clean, Informative Banner**: Displays tool version, date, environment info, and supported algorithms at launch.

## Requirements

* Python 3.6+
* Standard libraries: `hashlib`, `binascii`, `argparse`, `re`, `os`, `threading`, `queue`, `time`, `platform`, `datetime`

## Installation

Clone the repository:

   ```bash
   git clone https://github.com/SultanAhmmed/SultanTheRenter.git
   cd SultanTheRenter
   ```
## Usage

```bash
python SultanTheRenter.py -H <TARGET_HASH> -w <WORDLIST> [-t <THREADS>] [-a <ALGORITHM>]
```

### Arguments

* `-H, --hash` **(required)**: The target hash to crack.
* `-w, --wordlist` **(required)**: Path to the dictionary file (e.g., `rockyou.txt`).
* `-t, --threads` **(optional)**: Number of worker threads for the dictionary attack. Default: 4.
* `-a, --algorithm` **(optional)**: Force a specific algorithm (`md5`, `sha1`, `sha256`, `sha512`, `ntlm`, etc.). If omitted, the tool will attempt auto-detection.

### Examples

* **Auto-detect and crack an MD5 hash**:

  ```bash
  python SultanTheRenter.py -H 5d41402abc4b2a76b9719d911017c592 -w ./wordlists/rockyou.txt
  ```

* **Specify algorithm and threads**:

  ```bash
  python SultanTheRenter.py -H fcea920f7412b5da7be0cf42b8c93759 -w ./wordlists/rockyou.txt -a md5 -t 8
  ```

* **Crack an NTLM hash**:

  ```bash
  python SultanTheRenter.py -H 8846f7eaee8fb117ad06bdd830b7586c -w ./wordlists/rockyou.txt -a ntlm
  ```

## Supported Algorithms & Formats

| Algorithm | Regex Pattern     | Notes                           |
| --------- | ----------------- | ------------------------------- |
| MD5       | `^[a-f0-9]{32}$`  | Common checksum & legacy hashes |
| NTLM      | `^[a-f0-9]{32}$`  | MD4-based Windows hash          |
| SHA-1     | `^[a-f0-9]{40}$`  | Deprecated collision-wise       |
| SHA-224   | `^[a-f0-9]{56}$`  | NIST Standard                   |
| SHA-256   | `^[a-f0-9]{64}$`  | Modern security workhorse       |
| SHA-384   | `^[a-f0-9]{96}$`  | Larger SHA-2 output             |
| SHA-512   | `^[a-f0-9]{128}$` | Largest SHA-2 digest            |

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to open a pull request or issue.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m 'Add YourFeature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a pull request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

**Sultan Ahmmed**
GitHub: [@SultanRenter](https://github.com/SultanAhmmed)

---

*Happy cracking!*
