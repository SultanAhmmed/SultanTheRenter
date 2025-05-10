#====================================================
# Author: Sultan Ahmmed
# Version: 1.0.0
# Date: 10 May 2025 
# Description: Advanced Hash Cracker with Identification & Dictionary Attack
# License: MIT
#====================================================

# Import necessary libraries
import hashlib
import binascii
import argparse
import re
import os
import sys
from threading import Thread, Lock
from queue import Queue
import time
import platform
from datetime import datetime


def show_banner():
    banner = f"""
\033[1;35m
   ▄▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▄
   █░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░█
   █░╔╦╦╦═╦═╦═╦═╗╔═╦═╦╗░█  \033[1;36m╔═╗╦ ╦╔═╗╔╗╔╔╦╗╦╔╦╗
   █░║║║║╩╣║╣║║║╚╣║║║║║░█  \033[1;36m╠═╝╠═╣║╣ ║║║ ║ ║║║║
   █░╚═══╩╩═╩╩═╩═╝╚═╩╩╩╝░█  \033[1;36m╩  ╩ ╩╚═╝╝╚╝ ╩ ╩╩ ╩
   ▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀
\033[1;33m
        ✦  \033[1;37m𝓢𝓾𝓵𝓽𝓪𝓷 𝓽𝓱𝓮 𝓡𝓮𝓷𝓽𝓮𝓻  ✦
\033[0;36m
╔════════════════════════════════════════════╗
║ \033[1;34m» Version: 1.0.0      \033[0;36m» Date: {datetime.now().strftime('%d %b %Y')}  ║
║ \033[1;34m» System: {platform.system()} {platform.release().split('.')[0]}     \033[0;36m» Python: {platform.python_version()}     ║
╠════════════════════════════════════════════╣
║ \033[1;32m ✦  MD5 Hash \033[0;36m|\033[1;32m SHA ALL Hash \033[0;36m|\033[1;32m NTLM Hash\033[1;32m ✦ \033[0;36m ║
╚════════════════════════════════════════════╝
\033[1;35m
      「 https://github.com/SultanAhmmed 」
\033[0m
"""
    print(banner)

#============================Start From Here=====================================================

# Hash identification patterns
HASH_REGEX = {
    'md5': r'^[a-f0-9]{32}$',
    'sha1': r'^[a-f0-9]{40}$',
    'sha224': r'^[a-f0-9]{56}$',
    'sha256': r'^[a-f0-9]{64}$',
    'sha384': r'^[a-f0-9]{96}$',
    'sha512': r'^[a-f0-9]{128}$',
    'ntlm': r'^[a-f0-9]{32}$',  # Same length as MD5 but different usage
}

class HashCracker:
    def __init__(self, threads=4):
        self.threads = threads
        self.found = False
        self.result = None
        self.lock = Lock()  # Thread-safe lock for shared variables
        self.processed = 0  # Track number of attempted passwords
        self.start_time = time.time()

    def detect_hash_type(self, hash_str):
        """Identify hash algorithm based on length and pattern"""
        hash_lower = hash_str.lower()
        for algo, pattern in HASH_REGEX.items():
            if re.match(pattern, hash_lower):
                # Special case for NTLM vs MD5 (same length)
                if algo == 'ntlm' and not self.is_probably_md5(hash_lower):
                    return 'ntlm'
                elif algo == 'md5':
                    return 'md5'
                return algo
        return None

    def is_probably_md5(self, hash_str):
        """Heuristic to distinguish MD5 from NTLM"""
        # MD5 hashes often start with common patterns
        common_md5_prefixes = ('0e', '1a', '5f', 'd4', 'c4')
        return hash_str.startswith(common_md5_prefixes)

    def hash_generator(self, word, algorithm):
        """Generate hash for a given word and algorithm"""
        word = word.encode('utf-8')
        
        try:
            if algorithm.lower() == 'ntlm':
                # Handle NTLM separately
                return binascii.hexlify(hashlib.new('md4', word).digest()).decode()
            else:
                # Handle other algorithms
                return hashlib.new(algorithm, word).hexdigest()
        except ValueError as e:
            print(f"\n[!] Error with {algorithm.upper()} hashing: {str(e)}")
            return None

    def dictionary_attack(self, target_hash, algorithm, wordlist):
        """Perform dictionary attack using wordlist"""
        try:
            with open(wordlist, 'r', errors='ignore') as f:
                for word in f:
                    if self.found:
                        return
                    word = word.strip()
                    if not word:
                        continue
                    if self.hash_generator(word, algorithm) == target_hash:
                        with self.lock:
                            self.result = word
                            self.found = True
                        return
        except Exception as e:
            print(f"\n[!] Error: {str(e)}")
            return

    def threaded_attack(self, target_hash, algorithm, wordlist):
        """Run dictionary attack with multiple threads"""
        threads = []
        word_queue = Queue()

        # Fill queue with words from wordlist
        try:
            with open(wordlist, 'r', errors='ignore') as f:
                for word in f:
                    word_queue.put(word.strip())
        except Exception as e:
            print(f"[!] Error reading wordlist: {str(e)}")
            return None

        # Create and start worker threads
        for _ in range(self.threads):
            t = Thread(target=self.worker, args=(target_hash, algorithm, word_queue))
            t.daemon = True
            t.start()
            threads.append(t)

        # Wait for completion
        for t in threads:
            t.join()

        return self.result

    def worker(self, target_hash, algorithm, word_queue):
        """Worker thread for processing words from queue"""
        while not word_queue.empty() and not self.found:
            word = word_queue.get()
            try:
                generated_hash = self.hash_generator(word, algorithm)
                if generated_hash and generated_hash == target_hash:
                    with self.lock:
                        self.result = word
                        self.found = True
                    return
            except Exception as e:
                print(f"\n[!] Error processing {word}: {str(e)}")
            finally:
                word_queue.task_done()

def main():
    show_banner()

    # Argument parser
    parser = argparse.ArgumentParser(
        description="Advanced Hash Cracker with Identification & Dictionary Attack",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  python SultanRenter.py -H 5d41402abc4b2a76b9719d911017c592 -w ./rockyou.txt\n"
               "  python SultanRenter.py -H 5d41402abc4b2a76b9719d911017c592 -w ./rockyou.txt -t 8\n"
               "  python SultanRenter.py -H 5d41402abc4b2a76b9719d911017c592 -w ./rockyou.txt -t 8 -a md5\n"
    )
    parser.add_argument("-H", "--hash", required=True, help="Target hash to crack")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads (default: 4)")
    parser.add_argument("-a", "--algorithm", help="Specify hash algorithm (auto-detected if not specified)")

    args = parser.parse_args()

    cracker = HashCracker(threads=args.threads)

    # Hash identification")
    print("═══════════ Hash Information ══════════\n")
    if not args.algorithm:
        algorithm = cracker.detect_hash_type(args.hash)
        if not algorithm:
            print("[!] Could not identify hash type. Please specify with -a")
            return
        print(f"[*] Identified hash type: {algorithm.upper()}")
    else:
        algorithm = args.algorithm.lower()
        if algorithm not in HASH_REGEX:
            print(f"[!] Unsupported algorithm: {algorithm}")
            return

    # Verify wordlist exists
    if not os.path.isfile(args.wordlist):
        print(f"[!] Wordlist not found: {args.wordlist}")
        return

    print(f"[*] Starting attack on {algorithm.upper()} hash with {args.threads} threads...")
    result = cracker.threaded_attack(args.hash, algorithm, args.wordlist)

    if result:
        print(f"\n[+] SUCCESS! Hash Cracked: {result}")
    else:
        print("\n[-] Hash unable to Break!")
    print("\n═══════════════════════════════════════")
if __name__ == "__main__":
    if sys.platform.startswith('win'):
        os.system('cls')
    else:
        os.system('clear')
    main()