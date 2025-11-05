// FILE: Models/IncomingRequest.cs

using System;

namespace SecureFileShareP2P.Models
{
    public enum RequestType { File, Chat }

    public class IncomingRequest
    {
        public Guid Id { get; } = Guid.NewGuid();
        public RequestType Type { get; set; }
        public string Message { get; set; }
        public object EventArgs { get; set; } // To hold the original ChatRequestEventArgs or FileRequestEventArgs
    }
}