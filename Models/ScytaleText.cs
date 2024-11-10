using System;

public class ScytaleText
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string OriginalText { get; set; } = string.Empty;
    public string? EncryptedText { get; set; }
    public int? Key { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
    
    public User User { get; set; } = null!;
} 