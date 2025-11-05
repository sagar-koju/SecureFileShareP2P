// FILE: Network/FileTransferManager.cs

using SecureFileShareP2P.Models;
using SecureFileShareP2P.Services;
using System;
using System.IO;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureFileShareP2P.Network
{
    public class FileTransferManager
    {
        private const int ChunkSize = 8192; // 8 KB

        // SENDER'S METHOD
        public async Task SendFileAsync(
            string filePath, string receiverIP, int port,
            BigInteger rsaPublicKey, BigInteger rsaModulus,
            IProgress<TransferProgressReport> progress, CancellationToken ct)
        {
            using var client = new TcpClient();
            await client.ConnectAsync(receiverIP, port, ct);
            using var stream = client.GetStream();

            var (encryptedFile, encryptedAesKey, iv) = FileCryptoService.EncryptFileWithHybrid(filePath, rsaPublicKey, rsaModulus);

            progress.Report(new TransferProgressReport { Message = "Requesting transfer..." });
            string request = $"REQUEST:{Path.GetFileName(filePath)}:{encryptedFile.Length}";
            await WriteChunkAsync(stream, Encoding.UTF8.GetBytes(request), ct);

            string response = Encoding.UTF8.GetString(await ReadChunkAsync(stream, ct));
            if (response != "ACCEPT") throw new InvalidOperationException("File transfer was rejected by the receiver.");

            await WriteChunkAsync(stream, encryptedAesKey, ct);
            await WriteChunkAsync(stream, iv, ct);

            using var memoryStream = new MemoryStream(encryptedFile);
            byte[] buffer = new byte[ChunkSize];
            int bytesRead;
            long totalBytesSent = 0;

            while ((bytesRead = await memoryStream.ReadAsync(buffer, 0, buffer.Length, ct)) > 0)
            {
                await stream.WriteAsync(buffer, 0, bytesRead, ct);
                totalBytesSent += bytesRead;
                progress.Report(new TransferProgressReport
                {
                    BytesTransferred = totalBytesSent,
                    TotalBytes = encryptedFile.Length,
                    Message = "Sending..."
                });
            }

            progress.Report(new TransferProgressReport { Message = "Waiting for final confirmation..." });
            string finalAck = Encoding.UTF8.GetString(await ReadChunkAsync(stream, ct));
            if (finalAck != "ACK_SUCCESS") throw new Exception("Receiver failed to decrypt the file.");
        }

        // RECEIVER'S METHOD
        public async Task ReceiveFileAsync(
            NetworkStream stream, long encryptedFileSize, string savePath,
            BigInteger rsaPrivateKey, BigInteger rsaModulus,
            IProgress<TransferProgressReport> progress, CancellationToken ct)
        {
            await WriteChunkAsync(stream, Encoding.UTF8.GetBytes("ACCEPT"), ct);

            byte[] encryptedAesKey = await ReadChunkAsync(stream, ct);
            byte[] iv = await ReadChunkAsync(stream, ct);

            using var ms = new MemoryStream();
            byte[] buffer = new byte[ChunkSize];
            long totalBytesRead = 0;
            progress.Report(new TransferProgressReport { Message = "Receiving file..." });

            while (totalBytesRead < encryptedFileSize)
            {
                ct.ThrowIfCancellationRequested();
                int bytesToRead = (int)Math.Min(buffer.Length, encryptedFileSize - totalBytesRead);
                int bytesRead = await stream.ReadAsync(buffer, 0, bytesToRead, ct);
                if (bytesRead == 0) throw new EndOfStreamException("Connection was closed prematurely.");

                ms.Write(buffer, 0, bytesRead);
                totalBytesRead += bytesRead;
                progress.Report(new TransferProgressReport
                {
                    BytesTransferred = totalBytesRead,
                    TotalBytes = encryptedFileSize,
                    Message = "Receiving..."
                });
            }
            byte[] encryptedFile = ms.ToArray();

            progress.Report(new TransferProgressReport { Message = "Decrypting and saving file..." });
            bool success = false;
            try
            {
                // Decrypt and save in one step
                FileCryptoService.DecryptFileWithHybrid(encryptedFile, encryptedAesKey, iv, rsaPrivateKey, rsaModulus, savePath);
                success = true;
            }
            catch (Exception ex)
            {
                // Propagate the specific error
                throw new Exception("File decryption or saving failed.", ex);
            }
            finally
            {
                // Always send acknowledgment, regardless of success
                await WriteChunkAsync(stream, Encoding.UTF8.GetBytes(success ? "ACK_SUCCESS" : "ACK_FAIL"), CancellationToken.None);
            }
        }

        private async Task WriteChunkAsync(NetworkStream stream, byte[] data, CancellationToken ct)
        {
            byte[] lengthPrefix = BitConverter.GetBytes(data.Length);
            await stream.WriteAsync(lengthPrefix, 0, lengthPrefix.Length, ct);
            await stream.WriteAsync(data, 0, data.Length, ct);
        }

        private async Task<byte[]> ReadChunkAsync(NetworkStream stream, CancellationToken ct)
        {
            byte[] lengthBuffer = new byte[4];
            await stream.ReadExactlyAsync(lengthBuffer, 0, 4, ct);
            int length = BitConverter.ToInt32(lengthBuffer, 0);
            byte[] dataBuffer = new byte[length];
            if (length > 0)
            {
                await stream.ReadExactlyAsync(dataBuffer, 0, length, ct);
            }
            return dataBuffer;
        }
    }
}