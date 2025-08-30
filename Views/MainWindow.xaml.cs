using Microsoft.Win32;
using SecureFileShareP2P.Network;
using SecureFileShareP2P.Services;
using SecureFileShareP2P.Utils;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace SecureFileShareP2P
{
    public partial class MainWindow : Window
    {
        private string _selectedFilePath;
        private BigInteger _rsaPublicKey, _rsaModulus, _rsaPrivateKey;
        private DiscoveredPeer _selectedPeer;

        // Threading control
        private CancellationTokenSource _broadcastCts;
        private CancellationTokenSource _discoveryCts;
        private Task _listenerTask;

        private readonly string _currentUser;

        // Constructor for login flow
        public MainWindow(string username)
        {
            InitializeComponent();
            _currentUser = username;
            InitializeApplication();
        }

        // Default constructor for testing (if needed)
        public MainWindow()
        {
            InitializeComponent();
            _currentUser = "TestUser (Default)";
            InitializeApplication();
        }

        private void InitializeApplication()
        {
            this.Title = $"Secure File Share P2P - Logged in as: {_currentUser}";
            try
            {
                ReceiverPortBox.Text = GetFreePort().ToString();
            }
            catch (Exception ex)
            {
                ReceiverIPBox.Text = "127.0.0.1";
                ReceiverPortBox.Text = "12345";
                StatusText.Text = $"Auto-config failed: {ex.Message}";
            }
            (_rsaModulus, _rsaPublicKey, _rsaPrivateKey) = Cryptography.RSAKeyGenerator.GenerateKeys();
            ResetUI_Click(null, null); // Set initial UI state
        }

        private static int GetFreePort()
        {
            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                socket.Bind(new IPEndPoint(IPAddress.Any, 0));
                return ((IPEndPoint)socket.LocalEndPoint).Port;
            }
        }

        private void SelectFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            if (dialog.ShowDialog() == true)
            {
                _selectedFilePath = dialog.FileName;
                SelectedFileText.Text = $"Selected: {Path.GetFileName(_selectedFilePath)}";
            }
        }

        // FILE: Views/MainWindow.xaml.cs

        // ... (keep the rest of the file the same)

        private void StartReceiver_Click(object sender, RoutedEventArgs e)
        {
            if (_listenerTask != null && !_listenerTask.IsCompleted)
            {
                StatusText.Text = "Listener is already running.";
                return;
            }

            if (!int.TryParse(ReceiverPortBox.Text, out int port))
            {
                StatusText.Text = "Invalid port number.";
                return;
            }

            StatusText.Text = $"Listening on port {port}...";
            StartReceiverButton.IsEnabled = false;

            Func<string, long, bool> onFileRequest = (fileName, fileSize) =>
            {
                bool accepted = false;
                Dispatcher.Invoke(() =>
                {
                    string message = $"Incoming file transfer request:\n\n" +
                                     $"File: {fileName}\n" +
                                     $"Size: {fileSize / 1024.0:F2} KB\n\n" +
                                     $"Do you want to accept this file?";
                    var result = MessageBox.Show(this, message, "File Transfer Request", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    accepted = (result == MessageBoxResult.Yes);
                });
                return accepted;
            };

            // Replace the 'onFileReceived' delegate with this new version
            Func<string, byte[], byte[], byte[], bool> onFileReceived = (fileName, encryptedFile, encryptedAesKey, iv) =>
            {
                bool success = false;
                Dispatcher.Invoke(() =>
                {
                    try
                    {
                        SaveFileDialog saveDialog = new SaveFileDialog();
                        // Pre-populate the name, which includes the extension
                        saveDialog.FileName = fileName;

                        // === NEW CODE TO PRESERVE THE EXTENSION ===
                        string extension = Path.GetExtension(fileName); // e.g., ".txt", ".jpg"
                        if (!string.IsNullOrEmpty(extension))
                        {
                            // Create a user-friendly file type description, e.g., "TXT file (*.txt)"
                            string fileTypeDescription = $"{extension.Substring(1).ToUpper()} File (*{extension})";
                            // Set the filter so the dialog defaults to the correct file type
                            saveDialog.Filter = $"{fileTypeDescription}|*{extension}|All files|*.*";
                            // Ensure the extension is automatically added if the user removes it
                            saveDialog.DefaultExt = extension;
                        }
                        else
                        {
                            // Fallback for files that have no extension
                            saveDialog.Filter = "All files|*.*";
                        }
                        // === END OF NEW CODE ===

                        if (saveDialog.ShowDialog() == true)
                        {
                            FileCryptoService.DecryptFileWithHybrid(
                                encryptedFile, encryptedAesKey, iv,
                                _rsaPrivateKey, _rsaModulus,
                                saveDialog.FileName
                            );
                            MessageBox.Show($"File '{fileName}' saved and decrypted successfully!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                            ResetUI_Click(null, null);
                            success = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Failed to decrypt or save file: {ex.Message}", "Decryption Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                });
                return success;
            };

            Action<string> onError = (errorMessage) =>
            {
                Dispatcher.Invoke(() =>
                {
                    StatusText.Text = errorMessage;
                    StartReceiverButton.IsEnabled = true;
                });
            };

            _listenerTask = Task.Run(() => FileTransferManager.ReceiveFileAsync(port, onFileRequest, onFileReceived, onError));
        }

        // ... (The rest of your methods like SendFile_Click, ScanPeers_Click, etc. remain unchanged)
        private async void SendFile_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_selectedFilePath))
            {
                MessageBox.Show("Please select a file to send.", "No File Selected", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (_selectedPeer == null)
            {
                MessageBox.Show("Please scan and select a peer from the list.", "No Peer Selected", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            TransferProgress.Value = 0;
            StatusText.Text = "Connecting and waiting for receiver to accept...";

            try
            {
                await FileTransferManager.SendFileAsync(
                    _selectedFilePath, _selectedPeer.IP, _selectedPeer.Port,
                    _selectedPeer.RsaPublicKey, _selectedPeer.RsaModulus,
                    (bytesSent, totalBytes) =>
                    {
                        Dispatcher.Invoke(() =>
                        {
                            if (totalBytes > 0)
                            {
                                double percentage = (double)bytesSent / totalBytes * 100;
                                TransferProgress.Value = percentage;
                                StatusText.Text = $"Sending: {bytesSent / 1024} KB / {totalBytes / 1024} KB ({percentage:F0}%)";

                                if (bytesSent == totalBytes)
                                {
                                    StatusText.Text = "File sent. Waiting for decryption confirmation...";
                                }
                            }
                        });
                    }
                );

                StatusText.Text = "Success! Receiver confirmed successful decryption.";
                MessageBox.Show("File sent and successfully decrypted by the receiver!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                ResetUI_Click(null, null);
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Error: {ex.Message}";
                MessageBox.Show($"Error sending file: {ex.Message}", "Send Error", MessageBoxButton.OK, MessageBoxImage.Error);
                TransferProgress.Value = 0;
            }
        }

        private async void ScanPeers_Click(object sender, RoutedEventArgs e)
        {
            _discoveryCts?.Cancel();
            _discoveryCts = new CancellationTokenSource();

            PeerList.ItemsSource = null;
            StatusText.Text = "Scanning for peers...";

            try
            {
                var peers = await PeerDiscovery.DiscoverPeersAsync(_discoveryCts.Token);
                string myIP = NetworkUtils.GetLocalIPAddress();
                PeerList.ItemsSource = peers.Where(p => p.IP != myIP || p.Username != _currentUser).ToList();
                StatusText.Text = $"Found {PeerList.Items.Count} other peer(s)";
            }
            catch (OperationCanceledException) { StatusText.Text = "Scan cancelled"; }
            catch (Exception ex) { StatusText.Text = $"Scan failed: {ex.Message}"; }
        }

        private async void StartBroadcast_Click(object sender, RoutedEventArgs e)
        {
            _broadcastCts?.Cancel();
            _broadcastCts = new CancellationTokenSource();

            try
            {
                int myPort = int.Parse(ReceiverPortBox.Text);
                StatusText.Text = $"Broadcasting as '{_currentUser}' on port {myPort}...";
                StartBroadcastButton.IsEnabled = false;

                await Task.Run(() => PeerDiscovery.BroadcastPresenceAsync(
                    _currentUser, myPort,
                    _rsaModulus, _rsaPublicKey,
                    _broadcastCts.Token
                ));
            }
            catch (OperationCanceledException)
            {
                StatusText.Text = "Broadcasting stopped.";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Broadcast error: {ex.Message}";
                StartBroadcastButton.IsEnabled = true;
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            _broadcastCts?.Cancel();
            _discoveryCts?.Cancel();
            base.OnClosed(e);
            Application.Current.Shutdown();
        }

        private void PeerList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PeerList.SelectedItem is DiscoveredPeer selectedPeer)
            {
                _selectedPeer = selectedPeer;
                ReceiverIPBox.Text = selectedPeer.IP;
                StatusText.Text = $"Selected peer: {selectedPeer.Username} ({selectedPeer.IP})";
            }
        }

        private void QuitButton_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void ResetUI_Click(object sender, RoutedEventArgs e)
        {
            _broadcastCts?.Cancel();
            _broadcastCts = new CancellationTokenSource();
            _discoveryCts?.Cancel();

            _selectedFilePath = null;
            _selectedPeer = null;
            SelectedFileText.Text = "No file selected.";

            PeerList.ItemsSource = null;
            if (PeerList.Items.Count > 0) PeerList.Items.Clear();

            StatusText.Text = "Ready. Select an action.";
            TransferProgress.Value = 0;
            ReceiverIPBox.Text = "Select a peer from the list";

            StartBroadcastButton.IsEnabled = true;
        }
    }
}