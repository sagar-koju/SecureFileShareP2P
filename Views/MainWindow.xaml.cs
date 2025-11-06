// FILE: Views/MainWindow.xaml.cs

using Microsoft.Win32;
using SecureFileShareP2P.Network;
using SecureFileShareP2P.Services;
using SecureFileShareP2P.Utils;
using SecureFileShareP2P.Views;
using SecureFileShareP2P.Models;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Collections.ObjectModel;
using System.Collections.Generic;

namespace SecureFileShareP2P
{
    public partial class MainWindow : Window
    {
        // === NULLABILITY FIX: Fields that can be null are marked with '?' ===
        private string? _selectedFilePath;
        private BigInteger _rsaPublicKey, _rsaModulus, _rsaPrivateKey;
        private DiscoveredPeer? _selectedPeer;

        // Threading, Timers, and Cancellation
        private CancellationTokenSource? _broadcastCts;
        private CancellationTokenSource? _discoveryCts;
        private CancellationTokenSource? _transferCts;
        private readonly DispatcherTimer _peerCleanupTimer;
        private const int PeerTimeoutSeconds = 10;

        // Data Sources for UI binding
        private readonly Dictionary<string, DiscoveredPeer> _discoveredPeers = new Dictionary<string, DiscoveredPeer>();
        private readonly ObservableCollection<DiscoveredPeer> _peerListSource = new ObservableCollection<DiscoveredPeer>();
        private readonly ObservableCollection<IncomingRequest> _incomingRequests = new ObservableCollection<IncomingRequest>();

        // Core components
        private readonly string _currentUser;
        private readonly CommunicationManager _communicationManager;

        public MainWindow(string username)
        {
            InitializeComponent();
            _currentUser = username;

            (_rsaModulus, _rsaPublicKey, _rsaPrivateKey) = Cryptography.RSAKeyGenerator.GenerateKeys();
            _communicationManager = new CommunicationManager(_rsaModulus, _rsaPrivateKey);

            _peerCleanupTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
            _peerCleanupTimer.Tick += PeerCleanupTimer_Tick;

            InitializeApplication();
        }

        private void InitializeApplication()
        {
            this.Title = $"Secure File Share P2P - Logged in as: {_currentUser}";
            try { ReceiverPortBox.Text = GetFreePort().ToString(); }
            catch (Exception ex)
            {
                ReceiverPortBox.Text = "12345";
                StatusText.Text = $"Auto-config failed: {ex.Message}";
            }

            PeerList.ItemsSource = _peerListSource;
            RequestsList.ItemsSource = _incomingRequests;

            _communicationManager.ListenerStatusChanged += (s, msg) => Dispatcher.Invoke(() => StatusText.Text = msg);
            _communicationManager.FileRequestReceived += OnFileRequestReceived;
            _communicationManager.ChatRequestReceived += OnChatRequestReceived;

            _peerCleanupTimer.Start();
            ResetUI_Click(null, null);
        }

        #region UI Event Handlers (Buttons, Selection, etc.)

        // ... All the UI Event Handler methods are unchanged ...
        private void SelectFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog();
            if (dialog.ShowDialog() == true)
            {
                _selectedFilePath = dialog.FileName;
                SelectedFileText.Text = $"Selected: {Path.GetFileName(_selectedFilePath)}";
            }
        }

        private void StartReceiver_Click(object sender, RoutedEventArgs e)
        {
            if (int.TryParse(ReceiverPortBox.Text, out int port))
            {
                _communicationManager.StartListening(port);
                StartReceiverButton.IsEnabled = false;
            }
            else
            {
                StatusText.Text = "Invalid port number.";
            }
        }

        private void ScanPeers_Click(object sender, RoutedEventArgs e)
        {
            _discoveryCts?.Cancel();
            _discoveryCts = new CancellationTokenSource();
            var token = _discoveryCts.Token;

            StatusText.Text = "Continuously scanning for peers...";

            Task.Run(async () =>
            {
                string myIP = NetworkUtils.GetLocalIPAddress();
                while (!token.IsCancellationRequested)
                {
                    var discoveredThisRound = await PeerDiscovery.DiscoverPeersAsync(token);
                    if (token.IsCancellationRequested) break;

                    Dispatcher.Invoke(() =>
                    {
                        foreach (var peer in discoveredThisRound)
                        {
                            if (peer.IP == myIP && peer.Username == _currentUser) continue;
                            peer.LastSeen = DateTime.UtcNow;
                            if (_discoveredPeers.ContainsKey(peer.EndpointIdentifier))
                            {
                                _discoveredPeers[peer.EndpointIdentifier].LastSeen = peer.LastSeen;
                            }
                            else
                            {
                                _discoveredPeers[peer.EndpointIdentifier] = peer;
                                _peerListSource.Add(peer);
                            }
                        }
                    });
                }
            }, token);
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
                    _currentUser, myPort, _rsaModulus, _rsaPublicKey, _broadcastCts.Token
                ));
            }
            catch (OperationCanceledException) { StatusText.Text = "Broadcasting stopped."; }
            catch (Exception ex)
            {
                StatusText.Text = $"Broadcast error: {ex.Message}";
                StartBroadcastButton.IsEnabled = true;
            }
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

        #endregion

        #region Request Handling (Accept/Reject)

        // ... Request handling methods are unchanged ...
        private void AcceptRequest_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as Button)?.CommandParameter is IncomingRequest request)
            {
                _incomingRequests.Remove(request);
                if (request.Type == RequestType.Chat)
                {
                    var args = (ChatRequestEventArgs)request.EventArgs;
                    new ChatWindow(args.Client, args.SessionAesKey, _currentUser, args.RemoteUser).Show();
                }
                else if (request.Type == RequestType.File)
                {
                    var args = (FileRequestEventArgs)request.EventArgs;
                    HandleIncomingFile(args.Client, args.Stream, args.FileName, args.FileSize, accepted: true);
                }
            }
        }

        private void RejectRequest_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as Button)?.CommandParameter is IncomingRequest request)
            {
                _incomingRequests.Remove(request);
                if (request.Type == RequestType.Chat)
                {
                    var args = (ChatRequestEventArgs)request.EventArgs;
                    args.Client.Close();
                }
                else if (request.Type == RequestType.File)
                {
                    var args = (FileRequestEventArgs)request.EventArgs;
                    Task.Run(async () => await WriteChunkAsync(args.Stream, Encoding.UTF8.GetBytes("REJECT")))
                        .ContinueWith(_ => args.Client.Close());
                }
            }
        }

        #endregion

        #region Communication and Transfer Logic

        // ... Communication and transfer methods are unchanged ...
        private async void StartChat_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as Button)?.CommandParameter is DiscoveredPeer peer)
            {
                try
                {
                    var client = new TcpClient();
                    await client.ConnectAsync(peer.IP, peer.Port);
                    var stream = client.GetStream();

                    await WriteChunkAsync(stream, Encoding.UTF8.GetBytes($"CHAT_INIT:{_currentUser}"));

                    var sessionAesKey = new byte[32];
                    System.Security.Cryptography.RandomNumberGenerator.Fill(sessionAesKey);

                    string aesKeyBase64 = Convert.ToBase64String(sessionAesKey);
                    string encryptedAesKeyBase64 = Cryptography.RSACrypto.Encrypt(aesKeyBase64, peer.RsaModulus, peer.RsaPublicKey);
                    await WriteChunkAsync(stream, Convert.FromBase64String(encryptedAesKeyBase64));

                    new ChatWindow(client, sessionAesKey, _currentUser, peer.Username).Show();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Could not start chat: {ex.Message}", "Connection Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async void SendFile_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_selectedFilePath) || _selectedPeer == null)
            {
                MessageBox.Show("Please select a file and a peer first.", "Input Missing", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _transferCts = new CancellationTokenSource();
            var progress = new Progress<TransferProgressReport>(UpdateTransferProgress);
            var manager = new FileTransferManager();

            SetTransferInProgress(true);

            try
            {
                await manager.SendFileAsync(
                    _selectedFilePath, _selectedPeer.IP, _selectedPeer.Port,
                    _selectedPeer.RsaPublicKey, _selectedPeer.RsaModulus,
                    progress, _transferCts.Token);

                StatusText.Text = "Success! Receiver confirmed successful decryption.";
                MessageBox.Show("File sent and successfully decrypted!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (OperationCanceledException) { StatusText.Text = "Transfer cancelled by user."; }
            catch (Exception ex)
            {
                StatusText.Text = $"Error: {ex.Message}";
                MessageBox.Show($"Error sending file: {ex.Message}", "Send Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                SetTransferInProgress(false);
            }
        }

        private void HandleIncomingFile(TcpClient client, NetworkStream stream, string fileName, long encryptedFileSize, bool accepted)
        {
            if (!accepted)
            {
                Task.Run(async () => await WriteChunkAsync(stream, Encoding.UTF8.GetBytes("REJECT"))).ContinueWith(_ => client.Close());
                return;
            }

            string savePath = "";
            Dispatcher.Invoke(() =>
            {
                var saveDialog = new SaveFileDialog { FileName = fileName, Filter = "All files|*.*", DefaultExt = Path.GetExtension(fileName) };
                if (saveDialog.ShowDialog() == true) savePath = saveDialog.FileName;
            });

            if (string.IsNullOrEmpty(savePath))
            {
                Task.Run(async () => await WriteChunkAsync(stream, Encoding.UTF8.GetBytes("REJECT"))).ContinueWith(_ => client.Close());
                return;
            }

            _transferCts = new CancellationTokenSource();
            var progress = new Progress<TransferProgressReport>(UpdateTransferProgress);
            var manager = new FileTransferManager();

            SetTransferInProgress(true);

            Task.Run(async () =>
            {
                try
                {
                    await manager.ReceiveFileAsync(
                        stream, encryptedFileSize, savePath, _rsaPrivateKey, _rsaModulus, progress, _transferCts.Token);

                    Dispatcher.Invoke(() => {
                        StatusText.Text = "File received and decrypted successfully!";
                        MessageBox.Show($"File '{fileName}' saved!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    });
                }
                catch (OperationCanceledException) { Dispatcher.Invoke(() => StatusText.Text = "Transfer cancelled by user."); }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() => {
                        StatusText.Text = $"File receive error: {ex.Message}";
                        MessageBox.Show($"Failed to receive file: {ex.Message}", "Receive Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
                finally
                {
                    Dispatcher.Invoke(() => SetTransferInProgress(false));
                    client.Close();
                }
            });
        }

        #endregion

        #region CommunicationManager Event Handlers

        private void OnChatRequestReceived(object? sender, ChatRequestEventArgs e)
        {
            var request = new IncomingRequest { Type = RequestType.Chat, Message = $"Chat from {e.RemoteUser}", EventArgs = e };
            Dispatcher.Invoke(() => _incomingRequests.Add(request));
        }

        private void OnFileRequestReceived(object? sender, FileRequestEventArgs e)
        {
            string fileSizeKB = (e.FileSize / 1024.0).ToString("F2");
            var request = new IncomingRequest { Type = RequestType.File, Message = $"File '{e.FileName}' ({fileSizeKB} KB)", EventArgs = e };
            Dispatcher.Invoke(() => _incomingRequests.Add(request));
        }

        #endregion

        #region Helper Methods & Cleanup

        // ... Most helper methods are unchanged ...

        private void CancelTransfer_Click(object sender, RoutedEventArgs e) => _transferCts?.Cancel();

        private void UpdateTransferProgress(TransferProgressReport report)
        {
            StatusText.Text = report.Message;
            if (report.TotalBytes > 0)
            {
                double percentage = (double)report.BytesTransferred / report.TotalBytes * 100;
                TransferProgress.Value = percentage;
                StatusText.Text = $"Transferring: {report.BytesTransferred / 1024:N0} KB / {report.TotalBytes / 1024:N0} KB ({percentage:F0}%)";
            }
        }

        private void SetTransferInProgress(bool inProgress)
        {
            if (inProgress)
            {
                TransferProgress.Value = 0;
                MainGrid.IsEnabled = false;
                CancelTransferButton.Visibility = Visibility.Visible;
            }
            else
            {
                MainGrid.IsEnabled = true;
                CancelTransferButton.Visibility = Visibility.Collapsed;
                _transferCts?.Dispose();
                _transferCts = null;
            }
        }

        private void PeerCleanupTimer_Tick(object? sender, EventArgs e)
        {
            var peersToRemove = _discoveredPeers.Values
                .Where(p => (DateTime.UtcNow - p.LastSeen).TotalSeconds > PeerTimeoutSeconds)
                .ToList();

            foreach (var peer in peersToRemove)
            {
                _discoveredPeers.Remove(peer.EndpointIdentifier);
                _peerListSource.Remove(peer);
            }
        }

        private static async Task WriteChunkAsync(NetworkStream stream, byte[] data)
        {
            await stream.WriteAsync(BitConverter.GetBytes(data.Length));
            await stream.WriteAsync(data);
        }

        private static int GetFreePort()
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Any, 0));
            return ((IPEndPoint)socket.LocalEndPoint).Port;
        }

        // === MODIFIED METHOD ===
        protected override void OnClosed(EventArgs e)
        {
            // This event fires when the window is closed for any reason.
            // Its only job is to clean up this window's resources.
            _broadcastCts?.Cancel();
            _discoveryCts?.Cancel();
            _peerCleanupTimer.Stop();
            base.OnClosed(e);
            // DO NOT SHUT DOWN THE APPLICATION HERE
        }

        // === MODIFIED METHOD ===
        private void QuitButton_Click(object sender, RoutedEventArgs e)
        {
            // This is now the ONLY place where we shut down the application.
            Application.Current.Shutdown();
        }

        // The LogoutButton_Click method is now correct and requires no changes.
        // It will close this window, trigger the cleanup in OnClosed, but the app will stay alive.
        private void LogoutButton_Click(object sender, RoutedEventArgs e)
        {
            // Stop all background activities
            _broadcastCts?.Cancel();
            _discoveryCts?.Cancel();
            _peerCleanupTimer.Stop();

            // Create and show a new LoginWindow
            var loginWindow = new LoginWindow();
            loginWindow.Show();

            // Close the current MainWindow
            this.Close();
        }

        private void ResetUI_Click(object? sender, RoutedEventArgs? e)
        {
            _broadcastCts?.Cancel();
            _broadcastCts = new CancellationTokenSource();
            _discoveryCts?.Cancel();

            _selectedFilePath = null;
            _selectedPeer = null;
            SelectedFileText.Text = "No file selected.";
            StatusText.Text = "Ready. Select an action.";
            TransferProgress.Value = 0;
            ReceiverIPBox.Text = "Select a peer from the list";
            StartBroadcastButton.IsEnabled = true;
            StartReceiverButton.IsEnabled = true;
        }

        #endregion
    }
}