// FILE: Network/CommunicationManager.cs

using SecureFileShareP2P.Cryptography;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace SecureFileShareP2P.Network
{
    // Define arguments for our events
    public class ChatRequestEventArgs : EventArgs
    {
        public TcpClient Client { get; }
        public string RemoteUser { get; }
        public byte[] SessionAesKey { get; }
        public ChatRequestEventArgs(TcpClient client, string remoteUser, byte[] sessionKey)
        {
            Client = client;
            RemoteUser = remoteUser;
            SessionAesKey = sessionKey;
        }
    }

    public class FileRequestEventArgs : EventArgs
    {
        public TcpClient Client { get; }
        public NetworkStream Stream { get; }
        public string FileName { get; }
        public long FileSize { get; }
        public FileRequestEventArgs(TcpClient client, NetworkStream stream, string fileName, long fileSize)
        {
            Client = client;
            Stream = stream;
            FileName = fileName;
            FileSize = fileSize;
        }
    }


    public class CommunicationManager
    {
        private readonly BigInteger _rsaModulus;
        private readonly BigInteger _rsaPrivateKey;
        private TcpListener _listener;
        private Task _listenerTask;

        // Events that the UI will subscribe to
        public event EventHandler<ChatRequestEventArgs> ChatRequestReceived;
        public event EventHandler<FileRequestEventArgs> FileRequestReceived;
        public event EventHandler<string> ListenerStatusChanged;

        public CommunicationManager(BigInteger rsaModulus, BigInteger rsaPrivateKey)
        {
            _rsaModulus = rsaModulus;
            _rsaPrivateKey = rsaPrivateKey;
        }

        public void StartListening(int port)
        {
            if (_listenerTask != null && !_listenerTask.IsCompleted)
            {
                ListenerStatusChanged?.Invoke(this, "Listener is already running.");
                return;
            }

            _listenerTask = Task.Run(async () =>
            {
                try
                {
                    _listener = new TcpListener(IPAddress.Any, port);
                    _listener.Start();
                    ListenerStatusChanged?.Invoke(this, $"Listening for files and chats on port {port}...");

                    while (true)
                    {
                        TcpClient client = await _listener.AcceptTcpClientAsync();
                        // Handle each client in a new task to not block the listener
                        _ = Task.Run(() => HandleIncomingConnection(client));
                    }
                }
                catch (Exception ex)
                {
                    ListenerStatusChanged?.Invoke(this, $"Listener Error: {ex.Message}");
                }
            });
        }

        private async Task HandleIncomingConnection(TcpClient client)
        {
            try
            {
                NetworkStream stream = client.GetStream();

                // Read the first chunk, which should be the command
                byte[] commandBytes = await ReadChunkAsync(stream);
                string commandFull = Encoding.UTF8.GetString(commandBytes);
                var parts = commandFull.Split(':');
                string commandType = parts[0];

                if (commandType == "REQUEST") // File Transfer
                {
                    string fileName = parts[1];
                    long fileSize = long.Parse(parts[2]);
                    // Raise the event for the UI to handle
                    FileRequestReceived?.Invoke(this, new FileRequestEventArgs(client, stream, fileName, fileSize));
                }
                else if (commandType == "CHAT_INIT") // Chat Request
                {
                    string remoteUser = parts[1];
                    await HandleIncomingChat(client, stream, remoteUser);
                }
                else
                {
                    // If the command is unknown, just close the connection.
                    client.Close();
                }
            }
            catch (Exception ex)
            {
                ListenerStatusChanged?.Invoke(this, $"Connection handling error: {ex.Message}");
                client.Close();
            }
        }

        private async Task HandleIncomingChat(TcpClient client, NetworkStream stream, string remoteUser)
        {
            // 1. Receive and decrypt the session AES key
            byte[] encryptedAesKey = await ReadChunkAsync(stream);
            string encryptedAesKeyBase64 = Convert.ToBase64String(encryptedAesKey);
            string aesKeyBase64 = RSACrypto.Decrypt(encryptedAesKeyBase64, _rsaModulus, _rsaPrivateKey);
            byte[] sessionAesKey = Convert.FromBase64String(aesKeyBase64);

            // 2. Raise the event for the UI to handle (ask user to accept)
            ChatRequestReceived?.Invoke(this, new ChatRequestEventArgs(client, remoteUser, sessionAesKey));
        }

        // Helper methods (can be static as they don't depend on instance state)
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
    }
}