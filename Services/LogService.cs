// FILE: Services/LogService.cs

using SecureFileShareP2P.Database;
using SecureFileShareP2P.Models;
using System;
using System.Threading.Tasks;

namespace SecureFileShareP2P.Services
{
    public static class LogService
    {
        // === MODIFIED METHOD SIGNATURE ===
        public static Task LogFileTransferAsync(string fileName, long fileSize, string sender, string receiver, string status, string ownerUsername)
        {
            return Task.Run(() =>
            {
                try
                {
                    using (var db = new AppDbContext())
                    {
                        var log = new FileLog
                        {
                            FileName = fileName,
                            FileSize = fileSize,
                            SenderUsername = sender,
                            ReceiverUsername = receiver,
                            Status = status,
                            // === SET THE NEW PROPERTY ===
                            OwnerUsername = ownerUsername,
                            Timestamp = DateTime.UtcNow
                        };
                        db.FileLogs.Add(log);
                        db.SaveChanges();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to log file transfer: {ex.Message}");
                }
            });
        }
    }
}