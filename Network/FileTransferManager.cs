using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using SecureFileShareP2P.Services;

namespace SecureFileShareP2P.Network
{
    public static class FileTransferManager
    {
        private const int ChunkSize = 8192; // 8 KB chunk for streaming

        public static async Task SendFileAsync(
            string filePath,
            string receiverIP,
            int port,
            BigInteger rsaPublicKey,
            BigInteger rsaModulus,
            Action<long, long> progress)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("File not found.", filePath);
            }

            if (new FileInfo(filePath).Length == 0)
            {
                throw new Exception("Cannot send an empty file.");
            }

            using (TcpClient client = new TcpClient())
            {
                await client.ConnectAsync(receiverIP, port);
                using (NetworkStream stream = client.GetStream())
                {
                    var (encryptedFile, encryptedAesKey, iv) =
                        FileCryptoService.EncryptFileWithHybrid(filePath, rsaPublicKey, rsaModulus);

                    string request = $"REQUEST:{Path.GetFileName(filePath)}:{encryptedFile.Length}";
                    await WriteChunkAsync(stream, Encoding.UTF8.GetBytes(request));

                    string response = Encoding.UTF8.GetString(await ReadChunkAsync(stream));
                    if (response != "ACCEPT")
                    {
                        throw new Exception("File transfer was rejected by the receiver.");
                    }

                    await WriteChunkAsync(stream, encryptedAesKey);
                    await WriteChunkAsync(stream, iv);

                    using (var memoryStream = new MemoryStream(encryptedFile))
                    {
                        byte[] buffer = new byte[ChunkSize];
                        int bytesRead;
                        long totalBytesSent = 0;
                        while ((bytesRead = await memoryStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            await stream.WriteAsync(buffer, 0, bytesRead);
                            totalBytesSent += bytesRead;
                            progress?.Invoke(totalBytesSent, encryptedFile.Length);
                        }
                    }

                    string finalAck = Encoding.UTF8.GetString(await ReadChunkAsync(stream));
                    if (finalAck != "ACK_SUCCESS")
                    {
                        throw new Exception("Receiver failed to decrypt the file. Transfer incomplete.");
                    }
                }
            }
        }

        public static async Task ReceiveFileAsync(int port, Func<string, long, bool> onFileRequest, Func<string, byte[], byte[], byte[], bool> onFileReceived, Action<string> onError)
        {
            TcpListener listener = null;
            try
            {
                listener = new TcpListener(IPAddress.Any, port);
                listener.Start();

                while (true)
                {
                    using (TcpClient client = await listener.AcceptTcpClientAsync())
                    using (NetworkStream stream = client.GetStream())
                    {
                        try
                        {
                            byte[] requestBytes = await ReadChunkAsync(stream);
                            string request = Encoding.UTF8.GetString(requestBytes);
                            var parts = request.Split(':');

                            if (parts.Length == 3 && parts[0] == "REQUEST")
                            {
                                string fileName = parts[1];
                                long encryptedFileSize = long.Parse(parts[2]);

                                bool accepted = onFileRequest?.Invoke(fileName, encryptedFileSize) ?? false;
                                if (accepted)
                                {
                                    await WriteChunkAsync(stream, Encoding.UTF8.GetBytes("ACCEPT"));
                                }
                                else
                                {
                                    await WriteChunkAsync(stream, Encoding.UTF8.GetBytes("REJECT"));
                                    continue;
                                }

                                byte[] encryptedAesKey = await ReadChunkAsync(stream);
                                byte[] iv = await ReadChunkAsync(stream);

                                byte[] encryptedFile;

                                // === MODIFIED: Replaced CopyToAsync with a precise byte read loop to prevent deadlock ===
                                using (var ms = new MemoryStream())
                                {
                                    byte[] buffer = new byte[ChunkSize];
                                    long totalBytesRead = 0;
                                    while (totalBytesRead < encryptedFileSize)
                                    {
                                        int bytesToRead = (int)Math.Min(buffer.Length, encryptedFileSize - totalBytesRead);
                                        int bytesRead = await stream.ReadAsync(buffer, 0, bytesToRead);
                                        if (bytesRead == 0)
                                        {
                                            // Connection closed prematurely
                                            throw new EndOfStreamException("Connection was closed before all file data could be received.");
                                        }
                                        ms.Write(buffer, 0, bytesRead);
                                        totalBytesRead += bytesRead;
                                    }
                                    encryptedFile = ms.ToArray();
                                }
                                // === END OF MODIFIED BLOCK ===

                                bool decryptionSuccess = onFileReceived?.Invoke(fileName, encryptedFile, encryptedAesKey, iv) ?? false;

                                if (decryptionSuccess)
                                {
                                    await WriteChunkAsync(stream, Encoding.UTF8.GetBytes("ACK_SUCCESS"));
                                }
                                else
                                {
                                    await WriteChunkAsync(stream, Encoding.UTF8.GetBytes("ACK_FAIL"));
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            onError?.Invoke($"Client connection error: {ex.Message}");
                        }
                    }
                }
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
            {
                onError?.Invoke($"Error: Port {port} is already in use.");
            }
            catch (Exception ex)
            {
                onError?.Invoke($"Receiver listener error: {ex.Message}");
            }
            finally
            {
                listener?.Stop();
            }
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
    }
}