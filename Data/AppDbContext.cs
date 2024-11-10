using Microsoft.EntityFrameworkCore;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    
    public DbSet<User> Users { get; set; }
    public DbSet<RequestHistory> RequestHistory { get; set; }
    public DbSet<ScytaleText> ScytaleTexts { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Индекс для быстрого поиска пользователя по username
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Username)
            .IsUnique();

        // Индекс для быстрого поиска по email
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Email)
            .IsUnique();

        // Индекс для истории запросов
        modelBuilder.Entity<RequestHistory>()
            .HasIndex(h => new { h.UserId, h.Timestamp });

        // Индекс для текстов пользователя
        modelBuilder.Entity<ScytaleText>()
            .HasIndex(t => new { t.UserId, t.CreatedAt });
    }
}
