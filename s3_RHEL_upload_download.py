#!/usr/bin/env python3
"""
S3 CLI File Manager - Command line interface for S3 uploads/downloads
Supports proxy settings and SSL verification bypass for corporate environments.

Usage:
    python3 s3_cli.py                          # Interactive mode
    python3 s3_cli.py upload file.txt bucket   # Quick upload
    python3 s3_cli.py download bucket/file.txt # Quick download
    python3 s3_cli.py list bucket              # List bucket contents
    python3 s3_cli.py --help                   # Show help
"""

import argparse
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from botocore.config import Config
import os
import sys
import configparser
from pathlib import Path
import urllib3
from datetime import datetime
import threading
import time

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class S3CLIManager:
    def __init__(self):
        self.s3_client = None
        self.session = None
        self.current_profile = 'default'
        self.use_proxy = self.check_proxy_settings()
        self.disable_ssl = True  # Default for corporate environments
        self.available_profiles = []
        self.current_bucket = None
        self.current_folder = ""
        
    def check_proxy_settings(self):
        """Check if proxy environment variables are set"""
        proxy_vars = ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']
        return any(os.environ.get(var) for var in proxy_vars)
    
    def set_proxy_environment(self):
        """Set proxy environment variables"""
        proxy_url = 'http://127.0.0.1:9000'
        os.environ['http_proxy'] = proxy_url
        os.environ['https_proxy'] = proxy_url
        os.environ['HTTP_PROXY'] = proxy_url
        os.environ['HTTPS_PROXY'] = proxy_url
        print(f"[OK] Proxy set to {proxy_url}")
    
    def load_aws_profiles(self):
        """Load available AWS profiles"""
        try:
            aws_dir = os.path.expanduser('~/.aws')
            credentials_file = os.path.join(aws_dir, 'credentials')
            config_file = os.path.join(aws_dir, 'config')
            
            profiles = set(['default'])
            
            if os.path.exists(credentials_file):
                config = configparser.ConfigParser()
                config.read(credentials_file)
                profiles.update(config.sections())
            
            if os.path.exists(config_file):
                config = configparser.ConfigParser()
                config.read(config_file)
                for section in config.sections():
                    if section.startswith('profile '):
                        profile_name = section[8:]
                        profiles.add(profile_name)
                    elif section == 'default':
                        profiles.add('default')
            
            self.available_profiles = sorted(list(profiles))
            return True
            
        except Exception as e:
            print(f"Warning: Could not load AWS profiles: {e}")
            self.available_profiles = ['default']
            return False
    
    def initialize_s3_client(self, profile=None, use_proxy=None, disable_ssl=None):
        """Initialize S3 client with specified settings"""
        try:
            if profile:
                self.current_profile = profile
            if use_proxy is not None:
                self.use_proxy = use_proxy
            if disable_ssl is not None:
                self.disable_ssl = disable_ssl
            
            if self.use_proxy:
                self.set_proxy_environment()
            
            config = Config(
                signature_version='s3v4',
                retries={'max_attempts': 3, 'mode': 'adaptive'}
            )
            
            if self.current_profile == 'default':
                self.session = boto3.Session()
            else:
                self.session = boto3.Session(profile_name=self.current_profile)
            
            self.s3_client = self.session.client(
                's3',
                config=config,
                verify=not self.disable_ssl
            )
            
            # Test connection
            self.s3_client.list_buckets()
            
            # Show connection status
            status_parts = [f"Profile: {self.current_profile}"]
            if self.use_proxy:
                status_parts.append("Proxy: enabled")
            if self.disable_ssl:
                status_parts.append("SSL verification: disabled")
                
            print(f"[OK] Connected to AWS ({', '.join(status_parts)})")
            return True
            
        except ProfileNotFound:
            print(f"[ERROR] AWS profile '{self.current_profile}' not found")
            return False
        except NoCredentialsError:
            print(f"[ERROR] No credentials found for profile '{self.current_profile}'")
            print("   Configure with: aws configure [--profile profile-name]")
            return False
        except Exception as e:
            print(f"[ERROR] connecting to AWS: {str(e)}")
            return False
    
    def list_buckets(self):
        """List all available S3 buckets"""
        if not self.s3_client:
            if not self.initialize_s3_client():
                return []
        
        try:
            response = self.s3_client.list_buckets()
            buckets = [bucket['Name'] for bucket in response['Buckets']]
            return sorted(buckets)
        except Exception as e:
            print(f"[ERROR] listing buckets: {str(e)}")
            return []
    
    def list_objects(self, bucket, prefix=""):
        """List objects in S3 bucket with optional prefix"""
        if not self.s3_client:
            if not self.initialize_s3_client():
                return [], []
        
        try:
            kwargs = {'Bucket': bucket, 'Delimiter': '/', 'MaxKeys': 1000}
            if prefix:
                kwargs['Prefix'] = prefix if prefix.endswith('/') else prefix + '/'
            
            response = self.s3_client.list_objects_v2(**kwargs)
            
            folders = []
            files = []
            
            # Get folders (CommonPrefixes)
            if 'CommonPrefixes' in response:
                for prefix_info in response['CommonPrefixes']:
                    folder_name = prefix_info['Prefix'].rstrip('/')
                    display_name = folder_name.split('/')[-1] if '/' in folder_name else folder_name
                    folders.append(display_name)
            
            # Get files (Contents)
            if 'Contents' in response:
                for obj in response['Contents']:
                    key = obj['Key']
                    if key.endswith('/'):  # Skip folder markers
                        continue
                    
                    file_name = key.split('/')[-1] if '/' in key else key
                    size = self.format_file_size(obj['Size'])
                    modified = obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S')
                    files.append({
                        'name': file_name,
                        'key': key,
                        'size': size,
                        'modified': modified,
                        'size_bytes': obj['Size']
                    })
            
            return sorted(folders), sorted(files, key=lambda x: x['name'])
            
        except Exception as e:
            print(f"[ERROR] listing objects in bucket '{bucket}': {str(e)}")
            return [], []
    
    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"
    
    def upload_file(self, local_path, bucket, s3_key=None, folder=""):
        """Upload file to S3 with progress"""
        if not self.s3_client:
            if not self.initialize_s3_client():
                return False
        
        try:
            if not os.path.exists(local_path):
                print(f"[ERROR] Local file '{local_path}' not found")
                return False
            
            file_name = Path(local_path).name
            if s3_key:
                final_key = s3_key
            else:
                if folder:
                    if not folder.endswith('/'):
                        folder += '/'
                    final_key = folder + file_name
                else:
                    final_key = file_name
            
            file_size = os.path.getsize(local_path)
            print(f"[UPLOAD] Uploading {file_name} ({self.format_file_size(file_size)}) to s3://{bucket}/{final_key}")
            
            # Progress callback
            uploaded = [0]
            
            def progress_callback(bytes_transferred):
                uploaded[0] = bytes_transferred
                percent = (bytes_transferred / file_size) * 100
                bar_length = 50
                filled_length = int(bar_length * bytes_transferred // file_size)
                bar = '█' * filled_length + '-' * (bar_length - filled_length)
                print(f'\r[{bar}] {percent:.1f}% ({self.format_file_size(bytes_transferred)}/{self.format_file_size(file_size)})', end='', flush=True)
            
            # Upload file
            self.s3_client.upload_file(
                local_path, 
                bucket, 
                final_key, 
                Callback=progress_callback
            )
            
            print(f"\n[OK] Upload successful: s3://{bucket}/{final_key}")
            return True
            
        except Exception as e:
            print(f"\n[ERROR] Upload failed: {str(e)}")
            return False
    
    def download_file(self, bucket, s3_key, local_path=None):
        """Download file from S3 with progress"""
        if not self.s3_client:
            if not self.initialize_s3_client():
                return False
        
        try:
            # Determine local path
            if local_path is None:
                file_name = s3_key.split('/')[-1]
                local_path = os.path.join(os.getcwd(), file_name)
            elif os.path.isdir(local_path):
                file_name = s3_key.split('/')[-1]
                local_path = os.path.join(local_path, file_name)
            
            # Get file size
            try:
                response = self.s3_client.head_object(Bucket=bucket, Key=s3_key)
                file_size = response['ContentLength']
            except:
                file_size = 0
            
            print(f"[DOWNLOAD] Downloading s3://{bucket}/{s3_key} ({self.format_file_size(file_size)}) to {local_path}")
            
            # Progress callback
            downloaded = [0]
            
            def progress_callback(bytes_transferred):
                downloaded[0] = bytes_transferred
                if file_size > 0:
                    percent = (bytes_transferred / file_size) * 100
                    bar_length = 50
                    filled_length = int(bar_length * bytes_transferred // file_size)
                    bar = '█' * filled_length + '-' * (bar_length - filled_length)
                    print(f'\r[{bar}] {percent:.1f}% ({self.format_file_size(bytes_transferred)}/{self.format_file_size(file_size)})', end='', flush=True)
                else:
                    print(f'\rDownloaded: {self.format_file_size(bytes_transferred)}', end='', flush=True)
            
            # Download file
            self.s3_client.download_file(
                bucket, 
                s3_key, 
                local_path, 
                Callback=progress_callback
            )
            
            print(f"\n[OK] Download successful: {local_path}")
            return True
            
        except Exception as e:
            print(f"\n[ERROR] Download failed: {str(e)}")
            return False
    
    def interactive_mode(self):
        """Interactive CLI mode"""
        print("S3 CLI File Manager - Interactive Mode")
        print("=" * 50)
        
        # Load profiles
        self.load_aws_profiles()
        
        # Show configuration menu
        self.show_config_menu()
        
        # Initialize connection
        if not self.initialize_s3_client():
            print("[ERROR] Failed to connect to AWS. Please check your configuration.")
            return
        
        # Main interactive loop
        while True:
            try:
                self.show_main_menu()
                choice = input("\nEnter your choice: ").strip()
                
                if choice == '1':
                    self.interactive_upload()
                elif choice == '2':
                    self.interactive_download()
                elif choice == '3':
                    self.interactive_browse()
                elif choice == '4':
                    self.show_config_menu()
                    if not self.initialize_s3_client():
                        print("[ERROR] Failed to update connection")
                elif choice == '5' or choice.lower() == 'q':
                    print("Goodbye!")
                    break
                else:
                    print("[ERROR] Invalid choice. Please try again.")
                    
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"[ERROR] Unexpected error: {str(e)}")
    
    def show_main_menu(self):
        """Show main menu options"""
        print("\n" + "=" * 50)
        print("MAIN MENU")
        print("=" * 50)
        print("1. Upload file to S3")
        print("2. Download file from S3")
        print("3. Browse S3 buckets")
        print("4. Change settings")
        print("5. Quit")
    
    def show_config_menu(self):
        """Show and handle configuration menu"""
        print("\n" + "=" * 50)
        print("CONFIGURATION")
        print("=" * 50)
        
        # Show current settings
        print(f"Current Profile: {self.current_profile}")
        print(f"Proxy: {'Enabled' if self.use_proxy else 'Disabled'}")
        print(f"SSL Verification: {'Disabled' if self.disable_ssl else 'Enabled'}")
        
        # Profile selection
        if len(self.available_profiles) > 1:
            print(f"\nAvailable profiles: {', '.join(self.available_profiles)}")
            new_profile = input(f"Enter profile name (current: {self.current_profile}): ").strip()
            if new_profile and new_profile in self.available_profiles:
                self.current_profile = new_profile
        
        # Proxy settings
        proxy_choice = input(f"Enable proxy (127.0.0.1:9000)? (y/n, current: {'y' if self.use_proxy else 'n'}): ").strip().lower()
        if proxy_choice in ['y', 'yes']:
            self.use_proxy = True
        elif proxy_choice in ['n', 'no']:
            self.use_proxy = False
        
        # SSL settings
        ssl_choice = input(f"Disable SSL verification? (y/n, current: {'y' if self.disable_ssl else 'n'}): ").strip().lower()
        if ssl_choice in ['y', 'yes']:
            self.disable_ssl = True
        elif ssl_choice in ['n', 'no']:
            self.disable_ssl = False
    
    def interactive_upload(self):
        """Interactive upload mode"""
        print("\n" + "=" * 50)
        print("UPLOAD FILE TO S3")
        print("=" * 50)
        
        # Get local file
        local_file = input("Enter local file path: ").strip()
        if not local_file:
            print("[ERROR] No file specified")
            return
        
        if not os.path.exists(local_file):
            print(f"[ERROR] File '{local_file}' not found")
            return
        
        # Show available buckets
        buckets = self.list_buckets()
        if not buckets:
            print("[ERROR] No buckets found")
            return
        
        print(f"\nAvailable buckets ({len(buckets)}):")
        for i, bucket in enumerate(buckets, 1):
            print(f"  {i}. {bucket}")
        
        # Get bucket choice
        try:
            bucket_choice = input("\nSelect bucket (number or name): ").strip()
            if bucket_choice.isdigit():
                bucket_idx = int(bucket_choice) - 1
                if 0 <= bucket_idx < len(buckets):
                    bucket = buckets[bucket_idx]
                else:
                    print("[ERROR] Invalid bucket number")
                    return
            else:
                bucket = bucket_choice
                if bucket not in buckets:
                    print(f"[ERROR] Bucket '{bucket}' not found")
                    return
        except (ValueError, IndexError):
            print("[ERROR] Invalid selection")
            return
        
        # Get folder (optional)
        folder = input("Enter folder path (optional, press Enter for root): ").strip()
        
        # Upload file
        self.upload_file(local_file, bucket, folder=folder)
    
    def interactive_download(self):
        """Interactive download mode"""
        print("\n" + "=" * 50)
        print("DOWNLOAD FILE FROM S3")
        print("=" * 50)
        
        # Get bucket
        buckets = self.list_buckets()
        if not buckets:
            print("[ERROR] No buckets found")
            return
        
        print(f"Available buckets ({len(buckets)}):")
        for i, bucket in enumerate(buckets, 1):
            print(f"  {i}. {bucket}")
        
        try:
            bucket_choice = input("\nSelect bucket (number or name): ").strip()
            if bucket_choice.isdigit():
                bucket_idx = int(bucket_choice) - 1
                if 0 <= bucket_idx < len(buckets):
                    bucket = buckets[bucket_idx]
                else:
                    print("[ERROR] Invalid bucket number")
                    return
            else:
                bucket = bucket_choice
                if bucket not in buckets:
                    print(f"[ERROR] Bucket '{bucket}' not found")
                    return
        except (ValueError, IndexError):
            print("[ERROR] Invalid selection")
            return
        
        # Browse and select file
        current_path = ""
        while True:
            folders, files = self.list_objects(bucket, current_path)
            
            print(f"\n[FOLDER] Contents of s3://{bucket}/{current_path}")
            print("-" * 50)
            
            if current_path:
                print("  0. .. (parent folder)")
            
            # Show folders
            folder_offset = 1 if current_path else 0
            for i, folder in enumerate(folders, folder_offset + 1):
                print(f"  {i}. [DIR] {folder}/")
            
            # Show files
            file_offset = len(folders) + folder_offset
            for i, file in enumerate(files, file_offset + 1):
                print(f"  {i}. [FILE] {file['name']} ({file['size']}) - {file['modified']}")
            
            if not folders and not files:
                print("  (empty)")
            
            choice = input(f"\nSelect item (number), 'q' to quit: ").strip()
            
            if choice.lower() == 'q':
                return
            
            try:
                choice_num = int(choice)
                
                # Handle parent directory
                if current_path and choice_num == 0:
                    current_path = '/'.join(current_path.split('/')[:-1]) if '/' in current_path else ""
                    continue
                
                # Adjust for parent directory option
                if current_path:
                    choice_num -= 1
                
                # Handle folder selection
                if choice_num <= len(folders):
                    folder_idx = choice_num - 1
                    if 0 <= folder_idx < len(folders):
                        folder_name = folders[folder_idx]
                        current_path = f"{current_path}/{folder_name}" if current_path else folder_name
                        continue
                
                # Handle file selection
                file_idx = choice_num - len(folders) - 1
                if 0 <= file_idx < len(files):
                    selected_file = files[file_idx]
                    s3_key = selected_file['key']
                    
                    # Get download destination
                    dest = input(f"\nDownload destination (default: current directory): ").strip()
                    if not dest:
                        dest = os.getcwd()
                    
                    # Download file
                    self.download_file(bucket, s3_key, dest)
                    return
                
                print("[ERROR] Invalid selection")
                
            except ValueError:
                print("[ERROR] Please enter a valid number")
    
    def interactive_browse(self):
        """Interactive browse mode"""
        print("\n" + "=" * 50)
        print("BROWSE S3 BUCKETS")
        print("=" * 50)
        
        buckets = self.list_buckets()
        if not buckets:
            print("[ERROR] No buckets found")
            return
        
        print(f"Available buckets ({len(buckets)}):")
        for i, bucket in enumerate(buckets, 1):
            print(f"  {i}. {bucket}")
        
        try:
            bucket_choice = input("\nSelect bucket to browse (number or name): ").strip()
            if bucket_choice.isdigit():
                bucket_idx = int(bucket_choice) - 1
                if 0 <= bucket_idx < len(buckets):
                    bucket = buckets[bucket_idx]
                else:
                    print("[ERROR] Invalid bucket number")
                    return
            else:
                bucket = bucket_choice
                if bucket not in buckets:
                    print(f"[ERROR] Bucket '{bucket}' not found")
                    return
        except (ValueError, IndexError):
            print("[ERROR] Invalid selection")
            return
        
        # Browse bucket contents
        current_path = ""
        while True:
            folders, files = self.list_objects(bucket, current_path)
            
            print(f"\n[FOLDER] Contents of s3://{bucket}/{current_path}")
            print("-" * 80)
            
            if current_path:
                print("  0. .. (parent folder)")
            
            # Show folders
            folder_offset = 1 if current_path else 0
            for i, folder in enumerate(folders, folder_offset + 1):
                print(f"  {i}. [DIR] {folder}/")
            
            # Show files
            file_offset = len(folders) + folder_offset
            for i, file in enumerate(files, file_offset + 1):
                print(f"  {i}. [FILE] {file['name']:<30} {file['size']:>10} {file['modified']}")
            
            if not folders and not files:
                print("  (empty)")
            
            print(f"\nTotal: {len(folders)} folders, {len(files)} files")
            
            choice = input("Select folder (number) or 'q' to quit: ").strip()
            
            if choice.lower() == 'q':
                return
            
            try:
                choice_num = int(choice)
                
                # Handle parent directory
                if current_path and choice_num == 0:
                    current_path = '/'.join(current_path.split('/')[:-1]) if '/' in current_path else ""
                    continue
                
                # Adjust for parent directory option
                if current_path:
                    choice_num -= 1
                
                # Handle folder selection
                if 1 <= choice_num <= len(folders):
                    folder_idx = choice_num - 1
                    folder_name = folders[folder_idx]
                    current_path = f"{current_path}/{folder_name}" if current_path else folder_name
                    continue
                
                print("[ERROR] Invalid selection or file selected (only folders can be opened)")
                
            except ValueError:
                print("[ERROR] Please enter a valid number")

def main():
    """Main function to handle command line arguments"""
    manager = S3CLIManager()
    
    parser = argparse.ArgumentParser(
        description='S3 CLI File Manager with proxy and SSL support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Interactive mode
  %(prog)s upload file.txt mybucket          # Upload file to bucket root
  %(prog)s upload file.txt mybucket/folder   # Upload to specific folder
  %(prog)s download mybucket/file.txt        # Download to current directory
  %(prog)s download mybucket/file.txt ./dest # Download to specific directory
  %(prog)s list mybucket                     # List bucket contents
  %(prog)s list mybucket/folder              # List folder contents
  
Settings:
  --profile PROFILE                          # Use specific AWS profile
  --proxy                                    # Enable proxy (127.0.0.1:9000)
  --no-ssl                                   # Disable SSL verification
        """
    )
    
    parser.add_argument('command', nargs='?', choices=['upload', 'download', 'list'], 
                       help='Command to execute')
    parser.add_argument('source', nargs='?', help='Source file/path')
    parser.add_argument('destination', nargs='?', help='Destination bucket/path')
    parser.add_argument('--profile', default='default', help='AWS profile to use')
    parser.add_argument('--proxy', action='store_true', help='Enable proxy (127.0.0.1:9000)')
    parser.add_argument('--no-ssl', action='store_true', help='Disable SSL verification')
    
    args = parser.parse_args()
    
    # Load profiles
    manager.load_aws_profiles()
    
    # Initialize with command line settings
    if not manager.initialize_s3_client(
        profile=args.profile,
        use_proxy=args.proxy,
        disable_ssl=args.no_ssl
    ):
        sys.exit(1)
    
    # Handle commands
    if args.command == 'upload':
        if not args.source or not args.destination:
            print("[ERROR] upload requires source file and destination bucket")
            print("Usage: s3_cli.py upload <local_file> <bucket>[/folder]")
            sys.exit(1)
        
        # Parse destination
        dest_parts = args.destination.split('/', 1)
        bucket = dest_parts[0]
        folder = dest_parts[1] if len(dest_parts) > 1 else ""
        
        success = manager.upload_file(args.source, bucket, folder=folder)
        sys.exit(0 if success else 1)
    
    elif args.command == 'download':
        if not args.source:
            print("[ERROR] download requires source S3 path")
            print("Usage: s3_cli.py download <bucket/key> [local_destination]")
            sys.exit(1)
        
        # Parse source
        source_parts = args.source.split('/', 1)
        if len(source_parts) < 2:
            print("[ERROR] source must include bucket and key (bucket/file.txt)")
            sys.exit(1)
        
        bucket = source_parts[0]
        s3_key = source_parts[1]
        
        success = manager.download_file(bucket, s3_key, args.destination)
        sys.exit(0 if success else 1)
    
    elif args.command == 'list':
        if not args.source:
            # List all buckets
            buckets = manager.list_buckets()
            print(f"\nAvailable buckets ({len(buckets)}):")
            for bucket in buckets:
                print(f"  [BUCKET] {bucket}")
        else:
            # List bucket contents
            source_parts = args.source.split('/', 1)
            bucket = source_parts[0]
            prefix = source_parts[1] if len(source_parts) > 1 else ""
            
            folders, files = manager.list_objects(bucket, prefix)
            
            print(f"\n[FOLDER] Contents of s3://{bucket}/{prefix}")
            print("-" * 80)
            
            if folders:
                print("Folders:")
                for folder in folders:
                    print(f"  [DIR] {folder}/")
            
            if files:
                print("Files:")
                for file in files:
                    print(f"  [FILE] {file['name']:<40} {file['size']:>10} {file['modified']}")
            
            if not folders and not files:
                print("  (empty)")
            
            print(f"\nTotal: {len(folders)} folders, {len(files)} files")
    
    else:
        # Interactive mode
        manager.interactive_mode()

if __name__ == "__main__":
    main()
