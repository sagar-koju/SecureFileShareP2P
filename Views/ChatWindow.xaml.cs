// FILE: Views/ChatWindow.xaml.cs

using SecureFileShareP2P.Cryptography;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace SecureFileShareP2P.Views
{
    public partial class ChatWindow : Window
    {
        private readonly NetworkStream _stream;
        private readonly byte[] _sessionAesKey;
        private readonly string _localUser;
        private readonly string _remoteUser;
        private readonly TcpClient _client;
        private bool _isExiting = false;

        public ObservableCollection<string> Messages { get; } = new ObservableCollection<string>();

        public ChatWindow(TcpClient client, byte[] sessionAesKey, string localUser, string remoteUser)
        {
            InitializeComponent();
            _client = client;
            _stream = client.GetStream();
            _sessionAesKey = sessionAesKey;
            _localUser = localUser;
            _remoteUser = remoteUser;

            this.Title = $"Chat with {_remoteUser}";
            MessagesListBox.ItemsSource = Messages;

            Task.Run(ListenForMessages);
        }

        private async void SendButton_Click(object sender, RoutedEventArgs e)
        {
            await SendMessageAsync();
        }

        private async void MessageTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                await SendMessageAsync();
            }
        }

        private async Task SendMessageAsync()
        {
            if (string.IsNullOrWhiteSpace(MessageTextBox.Text)) return;

            string message = MessageTextBox.Text;
            try
            {
                var (ciphertext, iv) = AESCrypto.Encrypt(Encoding.UTF8.GetBytes(message), _sessionAesKey);

                await WriteChunkAsync(_stream, iv);
                await WriteChunkAsync(_stream, ciphertext);

                AddMessageToUI($"{_localUser} (You): {message}");
                MessageTextBox.Clear();
            }
            catch (Exception ex)
            {
                AddMessageToUI($"[Error sending message: {ex.Message}]");
            }
        }

        private async Task ListenForMessages()
        {
            try
            {
                while (!_isExiting && _client.Connected)
                {
                    byte[] iv = await ReadChunkAsync(_stream);
                    byte[] ciphertext = await ReadChunkAsync(_stream);

                    byte[] decryptedBytes = AESCrypto.Decrypt(ciphertext, _sessionAesKey, iv);
                    string message = Encoding.UTF8.GetString(decryptedBytes);

                    AddMessageToUI($"{_remoteUser}: {message}");
                }
            }
            catch (IOException)
            {
                if (!_isExiting) AddMessageToUI($"[{_remoteUser} has disconnected.]");
            }
            catch (Exception)
            {
                if (!_isExiting) AddMessageToUI($"[Connection lost.]");
            }
        }

        private void AddMessageToUI(string message)
        {
            Dispatcher.Invoke(() => Messages.Add(message));
        }

        private static async Task WriteChunkAsync(NetworkStream stream, byte[] data)
        {
            byte[] lengthPrefix = BitConverter.GetBytes(data.Length);
            await stream.WriteAsync(lengthPrefix, 0, lengthPrefix.Length);
            await stream.WriteAsync(data, 0, data.Length);
        }

        private static async Task<byte[]> ReadChunkAsync(NetworkStream stream)
        {
            byte[] lengthBuffer = new byte[4];
            await stream.ReadExactlyAsync(lengthBuffer, 0, 4);
            int length = BitConverter.ToInt32(lengthBuffer, 0);
            byte[] dataBuffer = new byte[length];
            if (length > 0)
            {
                await stream.ReadExactlyAsync(dataBuffer, 0, length);
            }
            return dataBuffer;
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            _isExiting = true;
            _client.Close();
        }
    }
}