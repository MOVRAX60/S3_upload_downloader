import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from botocore.config import Config
import os
import threading
from pathlib import Path
import configparser
import urllib3


class S3FileManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("S3 File Manager - Upload & Download")
        self.root.geometry("800x700")

        # Shared Variables
        self.aws_profile = tk.StringVar()
        self.upload_status = tk.StringVar(value="Ready")
        self.download_status = tk.StringVar(value="Ready")
        self.use_proxy = tk.BooleanVar(value=self.check_proxy_settings())
        self.disable_ssl = tk.BooleanVar(value=True)

        # Upload Variables
        self.upload_file_path = tk.StringVar()
        self.upload_bucket_name = tk.StringVar()
        self.upload_folder_path = tk.StringVar()

        # Download Variables
        self.download_bucket_name = tk.StringVar()
        self.download_folder_path = tk.StringVar(value="")
        self.download_destination = tk.StringVar()
        self.selected_download_file = tk.StringVar()

        # S3 client and session
        self.s3_client = None
        self.session = None

        # Data storage
        self.available_profiles = []
        self.upload_buckets = []
        self.upload_folders = []
        self.download_buckets = []
        self.download_files = []

        # Disable SSL warnings when SSL verification is disabled
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.create_widgets()
        self.load_aws_profiles()
        self.initialize_s3_client()

    def check_proxy_settings(self):
        """Check if proxy environment variables are set"""
        proxy_vars = ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']
        return any(os.environ.get(var) for var in proxy_vars)

    def set_proxy_environment(self):
        """Set proxy environment variables if not already set"""
        proxy_url = 'http://127.0.0.1:9000'
        if not os.environ.get('http_proxy'):
            os.environ['http_proxy'] = proxy_url
        if not os.environ.get('https_proxy'):
            os.environ['https_proxy'] = proxy_url
        if not os.environ.get('HTTP_PROXY'):
            os.environ['HTTP_PROXY'] = proxy_url
        if not os.environ.get('HTTPS_PROXY'):
            os.environ['HTTPS_PROXY'] = proxy_url

    def load_aws_profiles(self):
        """Load available AWS profiles from credentials file"""
        try:
            aws_dir = os.path.expanduser('~/.aws')
            credentials_file = os.path.join(aws_dir, 'credentials')
            config_file = os.path.join(aws_dir, 'config')

            profiles = set()

            # Read profiles from credentials file
            if os.path.exists(credentials_file):
                config = configparser.ConfigParser()
                config.read(credentials_file)
                profiles.update(config.sections())

            # Read profiles from config file
            if os.path.exists(config_file):
                config = configparser.ConfigParser()
                config.read(config_file)
                for section in config.sections():
                    if section.startswith('profile '):
                        profile_name = section[8:]
                        profiles.add(profile_name)
                    elif section == 'default':
                        profiles.add('default')

            profiles.add('default')
            self.available_profiles = sorted(list(profiles))
            self.update_profile_combo()

            if 'default' in self.available_profiles:
                self.aws_profile.set('default')
            elif self.available_profiles:
                self.aws_profile.set(self.available_profiles[0])

        except Exception as e:
            self.available_profiles = ['default']
            self.aws_profile.set('default')
            print(f"Warning: Could not load AWS profiles: {e}")

    def initialize_s3_client(self):
        """Initialize S3 client with credentials, proxy, and SSL settings"""
        try:
            profile = self.aws_profile.get() or 'default'

            if self.use_proxy.get():
                self.set_proxy_environment()

            config = Config(
                signature_version='s3v4',
                retries={'max_attempts': 3, 'mode': 'adaptive'}
            )

            if profile == 'default':
                self.session = boto3.Session()
            else:
                self.session = boto3.Session(profile_name=profile)

            self.s3_client = self.session.client(
                's3',
                config=config,
                verify=not self.disable_ssl.get()
            )

            self.s3_client.list_buckets()

            status_parts = [f"Connected with profile '{profile}'"]
            if self.use_proxy.get():
                status_parts.append("using proxy")
            if self.disable_ssl.get():
                status_parts.append("SSL verification disabled")

            status = " - ".join(status_parts) + " - Ready"
            self.upload_status.set(status)
            self.download_status.set(status)

            # Load buckets for both tabs
            self.load_upload_buckets()
            self.load_download_buckets()

        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.upload_status.set(error_msg)
            self.download_status.set(error_msg)
            messagebox.showerror("AWS Error", f"Failed to initialize AWS client: {str(e)}")

    def create_widgets(self):
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Create frames for each tab
        self.upload_frame = ttk.Frame(self.notebook)
        self.download_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.upload_frame, text="Upload to S3")
        self.notebook.add(self.download_frame, text="Download from S3")

        # Shared settings frame at the top
        self.create_shared_settings()

        # Create upload tab content
        self.create_upload_tab()

        # Create download tab content
        self.create_download_tab()

    def create_shared_settings(self):
        """Create shared AWS configuration at the top"""
        # Shared settings frame
        shared_frame = ttk.Frame(self.root)
        shared_frame.pack(fill=tk.X, padx=10, pady=5)

        # AWS Configuration
        ttk.Label(shared_frame, text="AWS Configuration", font=('TkDefaultFont', 12, 'bold')).pack(anchor=tk.W)

        config_frame = ttk.Frame(shared_frame)
        config_frame.pack(fill=tk.X, pady=5)

        # Profile selection
        ttk.Label(config_frame, text="Profile:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.profile_combo = ttk.Combobox(config_frame, textvariable=self.aws_profile,
                                          width=20, state='readonly')
        self.profile_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.profile_combo.bind('<<ComboboxSelected>>', self.on_settings_changed)

        # Connection settings
        settings_group = ttk.LabelFrame(config_frame, text="Connection", padding=5)
        settings_group.grid(row=0, column=2, columnspan=2, sticky=(tk.W, tk.E), padx=10)

        ttk.Checkbutton(settings_group, text="Use proxy (127.0.0.1:9000)",
                        variable=self.use_proxy, command=self.on_settings_changed).pack(side=tk.LEFT)
        ttk.Checkbutton(settings_group, text="Disable SSL verification",
                        variable=self.disable_ssl, command=self.on_settings_changed).pack(side=tk.LEFT, padx=10)

    def create_upload_tab(self):
        """Create the upload tab interface"""
        main_frame = ttk.Frame(self.upload_frame, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(1, weight=1)

        # Bucket selection
        ttk.Label(main_frame, text="S3 Upload Configuration", font=('TkDefaultFont', 12, 'bold')).grid(
            row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))

        ttk.Label(main_frame, text="Bucket:").grid(row=1, column=0, sticky=tk.W, pady=2)
        bucket_frame = ttk.Frame(main_frame)
        bucket_frame.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2, padx=(5, 0))
        bucket_frame.columnconfigure(0, weight=1)

        self.upload_bucket_combo = ttk.Combobox(bucket_frame, textvariable=self.upload_bucket_name)
        self.upload_bucket_combo.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        self.upload_bucket_combo.bind('<<ComboboxSelected>>', self.on_upload_bucket_selected)

        self.refresh_upload_buckets_btn = ttk.Button(bucket_frame, text="↻", width=3,
                                                     command=self.load_upload_buckets)
        self.refresh_upload_buckets_btn.grid(row=0, column=1)

        # Folder selection
        ttk.Label(main_frame, text="Folder:").grid(row=2, column=0, sticky=tk.W, pady=2)
        folder_frame = ttk.Frame(main_frame)
        folder_frame.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2, padx=(5, 0))
        folder_frame.columnconfigure(0, weight=1)

        self.upload_folder_combo = ttk.Combobox(folder_frame, textvariable=self.upload_folder_path)
        self.upload_folder_combo.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))

        self.refresh_upload_folders_btn = ttk.Button(folder_frame, text="↻", width=3,
                                                     command=self.load_upload_folders)
        self.refresh_upload_folders_btn.grid(row=0, column=1)
        self.refresh_upload_folders_btn.config(state='disabled')

        ttk.Label(main_frame, text="(Optional - leave empty for root)",
                  font=('TkDefaultFont', 8)).grid(row=3, column=1, sticky=tk.W, padx=(5, 0))

        # File selection
        ttk.Label(main_frame, text="File Selection", font=('TkDefaultFont', 12, 'bold')).grid(
            row=4, column=0, columnspan=3, sticky=tk.W, pady=(20, 10))

        ttk.Label(main_frame, text="File:").grid(row=5, column=0, sticky=tk.W, pady=2)
        file_frame = ttk.Frame(main_frame)
        file_frame.grid(row=5, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2, padx=(5, 0))
        file_frame.columnconfigure(0, weight=1)

        ttk.Label(file_frame, textvariable=self.upload_file_path,
                  relief="sunken", padding=5).grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(file_frame, text="Browse", command=self.browse_upload_file).grid(row=0, column=1)

        # Upload section
        ttk.Label(main_frame, text="Upload", font=('TkDefaultFont', 12, 'bold')).grid(
            row=6, column=0, columnspan=3, sticky=tk.W, pady=(20, 10))

        self.upload_progress = ttk.Progressbar(main_frame, mode='determinate', length=400)
        self.upload_progress.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        self.upload_button = ttk.Button(main_frame, text="Upload to S3", command=self.upload_file)
        self.upload_button.grid(row=8, column=0, columnspan=3, pady=10)

        ttk.Label(main_frame, textvariable=self.upload_status,
                  font=('TkDefaultFont', 9)).grid(row=9, column=0, columnspan=3, pady=5)

    def create_download_tab(self):
        """Create the download tab interface"""
        main_frame = ttk.Frame(self.download_frame, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(6, weight=1)

        # Bucket selection
        ttk.Label(main_frame, text="S3 Download Configuration", font=('TkDefaultFont', 12, 'bold')).grid(
            row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))

        ttk.Label(main_frame, text="Bucket:").grid(row=1, column=0, sticky=tk.W, pady=2)
        bucket_frame = ttk.Frame(main_frame)
        bucket_frame.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2, padx=(5, 0))
        bucket_frame.columnconfigure(0, weight=1)

        self.download_bucket_combo = ttk.Combobox(bucket_frame, textvariable=self.download_bucket_name)
        self.download_bucket_combo.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        self.download_bucket_combo.bind('<<ComboboxSelected>>', self.on_download_bucket_selected)

        self.refresh_download_buckets_btn = ttk.Button(bucket_frame, text="↻", width=3,
                                                       command=self.load_download_buckets)
        self.refresh_download_buckets_btn.grid(row=0, column=1)

        # Folder navigation
        ttk.Label(main_frame, text="Current Folder:").grid(row=2, column=0, sticky=tk.W, pady=2)
        nav_frame = ttk.Frame(main_frame)
        nav_frame.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2, padx=(5, 0))
        nav_frame.columnconfigure(1, weight=1)

        ttk.Button(nav_frame, text="← Back", command=self.go_back_folder).grid(row=0, column=0, padx=(0, 5))
        ttk.Label(nav_frame, textvariable=self.download_folder_path,
                  relief="sunken", padding=5).grid(row=0, column=1, sticky=(tk.W, tk.E))

        # File browser
        ttk.Label(main_frame, text="Files & Folders", font=('TkDefaultFont', 12, 'bold')).grid(
            row=3, column=0, columnspan=3, sticky=tk.W, pady=(20, 5))

        # Create treeview for file browser
        tree_frame = ttk.Frame(main_frame)
        tree_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.file_tree = ttk.Treeview(tree_frame, columns=('Size', 'Modified'), show='tree headings', height=10)
        self.file_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure columns
        self.file_tree.heading('#0', text='Name')
        self.file_tree.heading('Size', text='Size')
        self.file_tree.heading('Modified', text='Last Modified')
        self.file_tree.column('#0', width=300)
        self.file_tree.column('Size', width=100)
        self.file_tree.column('Modified', width=150)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.file_tree.configure(yscrollcommand=scrollbar.set)

        # Bind double-click
        self.file_tree.bind('<Double-1>', self.on_file_double_click)
        self.file_tree.bind('<<TreeviewSelect>>', self.on_file_select)

        # Download destination
        ttk.Label(main_frame, text="Download to:").grid(row=5, column=0, sticky=tk.W, pady=2)
        dest_frame = ttk.Frame(main_frame)
        dest_frame.grid(row=5, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2, padx=(5, 0))
        dest_frame.columnconfigure(0, weight=1)

        ttk.Label(dest_frame, textvariable=self.download_destination,
                  relief="sunken", padding=5).grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(dest_frame, text="Browse", command=self.browse_download_destination).grid(row=0, column=1)

        # Download section
        ttk.Label(main_frame, text="Download", font=('TkDefaultFont', 12, 'bold')).grid(
            row=6, column=0, columnspan=3, sticky=tk.W, pady=(20, 10))

        self.download_progress = ttk.Progressbar(main_frame, mode='determinate', length=400)
        self.download_progress.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        self.download_button = ttk.Button(main_frame, text="Download Selected File", command=self.download_file)
        self.download_button.grid(row=8, column=0, columnspan=3, pady=10)
        self.download_button.config(state='disabled')

        ttk.Label(main_frame, textvariable=self.download_status,
                  font=('TkDefaultFont', 9)).grid(row=9, column=0, columnspan=3, pady=5)

    def update_profile_combo(self):
        """Update the profile combobox with available profiles"""
        if hasattr(self, 'profile_combo'):
            self.profile_combo['values'] = self.available_profiles

    def on_settings_changed(self, event=None):
        """Handle settings changes (profile, proxy, SSL)"""
        self.upload_status.set("Updating connection...")
        self.download_status.set("Updating connection...")

        # Clear existing data
        self.clear_all_data()

        # Reinitialize
        threading.Thread(target=self.initialize_s3_client, daemon=True).start()

    def clear_all_data(self):
        """Clear all cached data"""
        self.upload_buckets = []
        self.upload_folders = []
        self.download_buckets = []
        self.download_files = []

        if hasattr(self, 'upload_bucket_combo'):
            self.upload_bucket_combo['values'] = []
            self.upload_folder_combo['values'] = []

        if hasattr(self, 'download_bucket_combo'):
            self.download_bucket_combo['values'] = []

        if hasattr(self, 'file_tree'):
            for item in self.file_tree.get_children():
                self.file_tree.delete(item)

        # Clear selections
        self.upload_bucket_name.set("")
        self.upload_folder_path.set("")
        self.download_bucket_name.set("")
        self.download_folder_path.set("")
        self.selected_download_file.set("")

    # Upload Tab Methods
    def load_upload_buckets(self):
        """Load available S3 buckets for upload"""
        if not self.s3_client:
            return

        try:
            self.upload_status.set("Loading buckets...")
            response = self.s3_client.list_buckets()
            self.upload_buckets = [bucket['Name'] for bucket in response['Buckets']]
            if hasattr(self, 'upload_bucket_combo'):
                self.upload_bucket_combo['values'] = self.upload_buckets
            self.upload_status.set(f"Loaded {len(self.upload_buckets)} buckets - Ready")
        except Exception as e:
            self.upload_status.set(f"Error loading buckets: {str(e)}")

    def load_upload_folders(self):
        """Load available folders from selected upload bucket"""
        bucket = self.upload_bucket_name.get().strip()
        if not bucket or not self.s3_client:
            return

        try:
            self.upload_status.set("Loading folders...")
            response = self.s3_client.list_objects_v2(Bucket=bucket, Delimiter='/', MaxKeys=1000)

            folders = [""]  # Root folder option
            if 'CommonPrefixes' in response:
                for prefix in response['CommonPrefixes']:
                    folder_name = prefix['Prefix'].rstrip('/')
                    folders.append(folder_name)

            self.upload_folders = folders
            if hasattr(self, 'upload_folder_combo'):
                self.upload_folder_combo['values'] = self.upload_folders
            self.upload_status.set(f"Loaded {len(folders) - 1} folders")

        except Exception as e:
            self.upload_status.set(f"Error loading folders: {str(e)}")

    def on_upload_bucket_selected(self, event=None):
        """Handle upload bucket selection"""
        bucket = self.upload_bucket_name.get().strip()
        if bucket:
            self.refresh_upload_folders_btn.config(state='normal')
            self.upload_folder_path.set("")
            threading.Thread(target=self.load_upload_folders, daemon=True).start()
        else:
            self.refresh_upload_folders_btn.config(state='disabled')

    def browse_upload_file(self):
        """Browse for file to upload"""
        file_path = filedialog.askopenfilename(title="Select file to upload")
        if file_path:
            self.upload_file_path.set(file_path)
            self.upload_status.set(f"Selected: {Path(file_path).name}")

    def upload_file(self):
        """Upload file to S3"""
        if not self.validate_upload_inputs():
            return

        self.upload_button.config(state='disabled')
        threading.Thread(target=self.upload_file_thread, daemon=True).start()

    def validate_upload_inputs(self):
        """Validate upload inputs"""
        if not self.upload_bucket_name.get().strip():
            messagebox.showerror("Error", "Please select a bucket")
            return False
        if not self.upload_file_path.get():
            messagebox.showerror("Error", "Please select a file to upload")
            return False
        if not os.path.exists(self.upload_file_path.get()):
            messagebox.showerror("Error", "Selected file does not exist")
            return False
        return True

    def upload_file_thread(self):
        """Upload file in separate thread"""
        try:
            file_path = self.upload_file_path.get()
            bucket = self.upload_bucket_name.get().strip()
            folder = self.upload_folder_path.get().strip()

            file_name = Path(file_path).name
            if folder:
                if not folder.endswith('/'):
                    folder += '/'
                s3_key = folder + file_name
            else:
                s3_key = file_name

            file_size = os.path.getsize(file_path)
            self.upload_progress['value'] = 0
            self.upload_progress['maximum'] = 100

            def upload_callback(bytes_transferred):
                progress = (bytes_transferred / file_size) * 100
                self.upload_progress['value'] = progress
                self.root.update_idletasks()

            self.upload_status.set("Uploading...")
            self.s3_client.upload_file(file_path, bucket, s3_key, Callback=upload_callback)

            self.upload_progress['value'] = 100
            self.upload_status.set(f"Upload successful: s3://{bucket}/{s3_key}")
            messagebox.showinfo("Success", f"File uploaded successfully to:\ns3://{bucket}/{s3_key}")

        except Exception as e:
            self.upload_status.set(f"Upload failed: {str(e)}")
            messagebox.showerror("Error", f"Upload failed: {str(e)}")
        finally:
            self.upload_button.config(state='normal')

    # Download Tab Methods
    def load_download_buckets(self):
        """Load available S3 buckets for download"""
        if not self.s3_client:
            return

        try:
            self.download_status.set("Loading buckets...")
            response = self.s3_client.list_buckets()
            self.download_buckets = [bucket['Name'] for bucket in response['Buckets']]
            if hasattr(self, 'download_bucket_combo'):
                self.download_bucket_combo['values'] = self.download_buckets
            self.download_status.set(f"Loaded {len(self.download_buckets)} buckets - Ready")
        except Exception as e:
            self.download_status.set(f"Error loading buckets: {str(e)}")

    def on_download_bucket_selected(self, event=None):
        """Handle download bucket selection"""
        bucket = self.download_bucket_name.get().strip()
        if bucket:
            self.download_folder_path.set("")
            threading.Thread(target=self.load_bucket_contents, daemon=True).start()

    def load_bucket_contents(self, folder_path=""):
        """Load contents of S3 bucket/folder"""
        bucket = self.download_bucket_name.get().strip()
        if not bucket or not self.s3_client:
            return

        try:
            self.download_status.set("Loading files...")

            # Clear existing items
            for item in self.file_tree.get_children():
                self.file_tree.delete(item)

            # Set current folder
            self.download_folder_path.set(folder_path)

            # List objects with prefix
            kwargs = {'Bucket': bucket, 'Delimiter': '/', 'MaxKeys': 1000}
            if folder_path:
                kwargs['Prefix'] = folder_path if folder_path.endswith('/') else folder_path + '/'

            response = self.s3_client.list_objects_v2(**kwargs)

            # Add folders (CommonPrefixes)
            if 'CommonPrefixes' in response:
                for prefix_info in response['CommonPrefixes']:
                    folder_name = prefix_info['Prefix'].rstrip('/')
                    display_name = folder_name.split('/')[-1] if '/' in folder_name else folder_name
                    self.file_tree.insert('', tk.END, text=f"📁 {display_name}",
                                          values=('Folder', ''), tags=('folder',))

            # Add files (Contents)
            if 'Contents' in response:
                for obj in response['Contents']:
                    key = obj['Key']
                    # Skip folder markers
                    if key.endswith('/'):
                        continue

                    file_name = key.split('/')[-1] if '/' in key else key
                    size = self.format_file_size(obj['Size'])
                    modified = obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S')

                    self.file_tree.insert('', tk.END, text=f"📄 {file_name}",
                                          values=(size, modified), tags=('file',))

            file_count = len(self.file_tree.get_children())
            self.download_status.set(f"Loaded {file_count} items")

        except Exception as e:
            self.download_status.set(f"Error loading contents: {str(e)}")
            messagebox.showerror("Error", f"Failed to load bucket contents: {str(e)}")

    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def go_back_folder(self):
        """Navigate back to parent folder"""
        current_path = self.download_folder_path.get()
        if current_path:
            # Go up one level
            parent_path = '/'.join(current_path.split('/')[:-1])
            self.load_bucket_contents(parent_path)
        else:
            # Already at root, reload
            self.load_bucket_contents("")

    def on_file_double_click(self, event):
        """Handle double-click on file/folder"""
        selection = self.file_tree.selection()
        if not selection:
            return

        item = selection[0]
        text = self.file_tree.item(item, 'text')

        if text.startswith('📁'):  # Folder
            folder_name = text[2:]  # Remove folder emoji
            current_path = self.download_folder_path.get()
            if current_path:
                new_path = f"{current_path}/{folder_name}"
            else:
                new_path = folder_name
            self.load_bucket_contents(new_path)

    def on_file_select(self, event):
        """Handle file selection"""
        selection = self.file_tree.selection()
        if not selection:
            self.download_button.config(state='disabled')
            self.selected_download_file.set("")
            return

        item = selection[0]
        text = self.file_tree.item(item, 'text')

        if text.startswith('📄'):  # File
            file_name = text[2:]  # Remove file emoji
            current_path = self.download_folder_path.get()
            if current_path:
                full_path = f"{current_path}/{file_name}"
            else:
                full_path = file_name

            self.selected_download_file.set(full_path)
            self.download_button.config(state='normal')
            self.download_status.set(f"Selected: {file_name}")
        else:  # Folder
            self.download_button.config(state='disabled')
            self.selected_download_file.set("")

    def browse_download_destination(self):
        """Browse for download destination folder"""
        folder = filedialog.askdirectory(title="Select download destination")
        if folder:
            self.download_destination.set(folder)

    def download_file(self):
        """Download selected file from S3"""
        if not self.validate_download_inputs():
            return

        self.download_button.config(state='disabled')
        threading.Thread(target=self.download_file_thread, daemon=True).start()

    def validate_download_inputs(self):
        """Validate download inputs"""
        if not self.download_bucket_name.get().strip():
            messagebox.showerror("Error", "Please select a bucket")
            return False
        if not self.selected_download_file.get():
            messagebox.showerror("Error", "Please select a file to download")
            return False
        if not self.download_destination.get():
            messagebox.showerror("Error", "Please select a download destination")
            return False
        return True

    def download_file_thread(self):
        """Download file in separate thread"""
        try:
            bucket = self.download_bucket_name.get().strip()
            s3_key = self.selected_download_file.get()
            destination_folder = self.download_destination.get()

            file_name = s3_key.split('/')[-1]
            local_path = os.path.join(destination_folder, file_name)

            # Get file size for progress tracking
            response = self.s3_client.head_object(Bucket=bucket, Key=s3_key)
            file_size = response['ContentLength']

            self.download_progress['value'] = 0
            self.download_progress['maximum'] = 100

            def download_callback(bytes_transferred):
                if file_size > 0:
                    progress = (bytes_transferred / file_size) * 100
                    self.download_progress['value'] = progress
                    self.root.update_idletasks()

            self.download_status.set("Downloading...")
            self.s3_client.download_file(bucket, s3_key, local_path, Callback=download_callback)

            self.download_progress['value'] = 100
            self.download_status.set(f"Download successful: {local_path}")
            messagebox.showinfo("Success", f"File downloaded successfully to:\n{local_path}")

        except Exception as e:
            self.download_status.set(f"Download failed: {str(e)}")
            messagebox.showerror("Error", f"Download failed: {str(e)}")
        finally:
            self.download_button.config(state='normal')


def main():
    root = tk.Tk()
    app = S3FileManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
