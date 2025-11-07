namespace SecureFileShareP2P.Models
{
    public class TransferProgressReport
    {
        public long BytesTransferred { get; set; }
        public long TotalBytes { get; set; }
        public string Message { get; set; }
    }
}