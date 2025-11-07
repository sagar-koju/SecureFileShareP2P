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
        public string RemoteUser { get; }
        public FileRequestEventArgs(TcpClient client, NetworkStream stream, string fileName, long fileSize, string remoteUser)
        {
            Client = client;
            Stream = stream;
            FileName = fileName;
            FileSize = fileSize;
            RemoteUser = remoteUser;
        }
    }


    public class CommunicationManager
    {
        private readonly BigInteger _rsaModulus;
        private readonly BigInteger _rsaPrivateKey;
        private TcpListener _listener;
        private Task _listenerTask;

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

                byte[] commandBytes = await ReadChunkAsync(stream);
                string commandFull = Encoding.UTF8.GetString(commandBytes);
                var parts = commandFull.Split(':');
                string commandType = parts[0];

                if (commandType == "REQUEST" && parts.Length >= 4) // File Transfer (e.g., "REQUEST:SENDER_USER:file.zip:12345")
                {
                    string remoteUser = parts[1];
                    string fileName = parts[2];
                    long fileSize = long.Parse(parts[3]);
                    FileRequestReceived?.Invoke(this, new FileRequestEventArgs(client, stream, fileName, fileSize, remoteUser));
                }
                else if (commandType == "CHAT_INIT") // Chat Request
                {
                    string remoteUser = parts[1];
                    await HandleIncomingChat(client, stream, remoteUser);
                }
                else
                {
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
            byte[] encryptedAesKey = await ReadChunkAsync(stream);
            string encryptedAesKeyBase64 = Convert.ToBase64String(encryptedAesKey);
            string aesKeyBase64 = RSACrypto.Decrypt(encryptedAesKeyBase64, _rsaModulus, _rsaPrivateKey);
            byte[] sessionAesKey = Convert.FromBase64String(aesKeyBase64);

            ChatRequestReceived?.Invoke(this, new ChatRequestEventArgs(client, remoteUser, sessionAesKey));
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
    }
}