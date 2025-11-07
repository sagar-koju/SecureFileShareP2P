// FILE: Views/ChatWindow.xaml.cs

using SecureFileShareP2P.Cryptography;
using SecureFileShareP2P.Models;
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
        private readonly string _remoteUser;
        private readonly TcpClient _client;
        private bool _isExiting = false;

        public ObservableCollection<ChatMessage> Messages { get; } = new ObservableCollection<ChatMessage>();

        public ChatWindow(TcpClient client, byte[] sessionAesKey, string localUser, string remoteUser)
        {
            InitializeComponent();
            _client = client;
            _stream = client.GetStream();
            _sessionAesKey = sessionAesKey;
            _remoteUser = remoteUser;

            this.Title = $"Chat with {_remoteUser}";
            MessagesListBox.ItemsSource = Messages;

            // Listen for new messages in the background
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

            string messageText = MessageTextBox.Text;
            try
            {
                var (ciphertext, iv) = AESCrypto.Encrypt(Encoding.UTF8.GetBytes(messageText), _sessionAesKey);
                await WriteChunkAsync(_stream, iv);
                await WriteChunkAsync(_stream, ciphertext);

                var message = new ChatMessage { Content = messageText, Sender = MessageSender.LocalUser, Timestamp = DateTime.Now };
                AddMessageToUI(message);

                MessageTextBox.Clear();
            }
            catch (Exception ex)
            {
                var errorMessage = new ChatMessage { Content = $"[Error sending message: {ex.Message}]", Sender = MessageSender.System, Timestamp = DateTime.Now };
                AddMessageToUI(errorMessage);
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
                    string messageText = Encoding.UTF8.GetString(decryptedBytes);

                    var message = new ChatMessage { Content = messageText, Sender = MessageSender.RemoteUser, Timestamp = DateTime.Now };
                    AddMessageToUI(message);
                }
            }
            catch (IOException)
            {
                if (!_isExiting)
                {
                    var disconnectMessage = new ChatMessage { Content = $"[{_remoteUser} has disconnected.]", Sender = MessageSender.System, Timestamp = DateTime.Now };
                    AddMessageToUI(disconnectMessage);
                }
            }
            catch (Exception)
            {
                if (!_isExiting)
                {
                    var connectionLostMessage = new ChatMessage { Content = "[Connection lost.]", Sender = MessageSender.System, Timestamp = DateTime.Now };
                    AddMessageToUI(connectionLostMessage);
                }
            }
        }

        private void AddMessageToUI(ChatMessage message)
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