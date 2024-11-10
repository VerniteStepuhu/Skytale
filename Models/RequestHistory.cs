public class RequestHistory
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string RequestType { get; set; } = string.Empty;
    public string InputText { get; set; } = string.Empty;
    public string OutputText { get; set; } = string.Empty;
    public int Key { get; set; }
    public DateTime Timestamp { get; set; }
    
    public User User { get; set; } = null!;
} 