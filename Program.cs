using System;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddDirectoryBrowser();
builder.Services.AddControllers();
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite("Data Source=scytale.db"));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? 
                    "your-super-secret-key-with-at-least-32-characters"))
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseCors(builder => builder
    .AllowAnyOrigin()
    .AllowAnyMethod()
    .AllowAnyHeader()
    .WithExposedHeaders("Authorization"));

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// Добавляем перенаправление с корневого маршрута
app.MapGet("/", context =>
{
    context.Response.Redirect("/login");
    return Task.CompletedTask;
});

// Если используете контроллеры, добавьте их маппинг
app.MapControllers();

// Добавить после UseAuthorization()
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (Exception ex)
    {
        context.Response.StatusCode = 500;
        await context.Response.WriteAsJsonAsync(new { error = "Внутренняя ошибка сервера" });
        
        // Логирование ошибки
        Console.WriteLine($"Error: {ex.Message}");
        Console.WriteLine($"StackTrace: {ex.StackTrace}");
    }
});

// Все маршруты
app.MapPost("/encrypt", Program.HandleEncrypt).RequireAuthorization();
app.MapPost("/decrypt", Program.HandleDecrypt).RequireAuthorization();
app.MapPost("/register", Program.HandleRegister);
app.MapPost("/login", Program.HandleLogin);

// Добавьте этот код после существующих MapPost
app.MapGet("/api/test", async (HttpContext context) =>
{
    await context.Response.WriteAsJsonAsync(new { 
        message = "Тестовое сообщение",
        timestamp = DateTime.Now
    });
});

app.MapGet("/api/users", async (HttpContext context, AppDbContext db) =>
{
    var users = await db.Users
        .Select(u => new { u.Id, u.Username, u.Email, u.RegisterDate })
        .ToListAsync();
    await context.Response.WriteAsJsonAsync(users);
}).RequireAuthorization();

app.MapGet("/api/history", async (HttpContext context, AppDbContext db) =>
{
    var userId = int.Parse(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
    var history = await db.RequestHistory
        .Where(h => h.UserId == userId)
        .OrderByDescending(h => h.Timestamp)
        .Select(h => new
        {
            h.Id,
            h.RequestType,
            h.InputText,
            h.OutputText,
            h.Key,
            h.Timestamp
        })
        .ToListAsync();
    
    await context.Response.WriteAsJsonAsync(history);
}).RequireAuthorization();

app.MapDelete("/api/history", async (HttpContext context, AppDbContext db) =>
{
    var userId = int.Parse(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
    var history = await db.RequestHistory
        .Where(h => h.UserId == userId)
        .ToListAsync();
    
    db.RequestHistory.RemoveRange(history);
    await db.SaveChangesAsync();
    
    await context.Response.WriteAsJsonAsync(new { message = "История успешно удалена" });
}).RequireAuthorization();

app.MapPatch("/api/password", async (HttpContext context, AppDbContext db) =>
{
    try
    {
        var userId = int.Parse(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
        var request = await JsonSerializer.DeserializeAsync<ChangePasswordRequest>(
            context.Request.Body,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
        );

        if (request == null)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { error = "Неверный формат запроса" });
            return;
        }

        var user = await db.Users.FindAsync(userId);
        if (user == null)
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsJsonAsync(new { error = "Пользователь не найден" });
            return;
        }

        if (!BCrypt.Net.BCrypt.Verify(request.OldPassword, user.Password))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { error = "Неверный текущий пароль" });
            return;
        }

        user.Password = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
        await db.SaveChangesAsync();

        var newToken = GenerateJwtToken(user);
        await context.Response.WriteAsJsonAsync(new { 
            message = "Пароль успешно изменен",
            token = newToken 
        });
    }
    catch (Exception ex)
    {
        context.Response.StatusCode = 500;
        await context.Response.WriteAsJsonAsync(new { error = $"Ошибка сервера: {ex.Message}" });
    }
}).RequireAuthorization();

// Добавление текста
app.MapPost("/api/texts", async (HttpContext context, AppDbContext db) =>
{
    var userId = int.Parse(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
    var request = await JsonSerializer.DeserializeAsync<AddTextRequest>(
        context.Request.Body,
        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
    );

    if (request == null || string.IsNullOrEmpty(request.Text))
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsJsonAsync(new { error = "Текст не может быть пустым" });
        return;
    }

    var text = new ScytaleText
    {
        UserId = userId,
        OriginalText = request.Text,
        CreatedAt = DateTime.UtcNow
    };

    db.ScytaleTexts.Add(text);
    await db.SaveChangesAsync();

    context.Response.StatusCode = 201;
    await context.Response.WriteAsJsonAsync(text);
}).RequireAuthorization();

// Изменение текста
app.MapPatch("/api/texts/{id}", async (HttpContext context, AppDbContext db, int id) =>
{
    var userId = int.Parse(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
    var text = await db.ScytaleTexts.FirstOrDefaultAsync(t => t.Id == id && t.UserId == userId);

    if (text == null)
    {
        context.Response.StatusCode = 404;
        await context.Response.WriteAsJsonAsync(new { error = "Текст не найден" });
        return;
    }

    var request = await JsonSerializer.DeserializeAsync<UpdateTextRequest>(
        context.Request.Body,
        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
    );

    if (request == null || string.IsNullOrEmpty(request.Text))
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsJsonAsync(new { error = "Текст не может быть пустым" });
        return;
    }

    text.OriginalText = request.Text;
    text.UpdatedAt = DateTime.UtcNow;
    text.EncryptedText = null; // Сбрасываем зашифрованный текст
    text.Key = null;

    await db.SaveChangesAsync();
    await context.Response.WriteAsJsonAsync(text);
}).RequireAuthorization();

// Удаление текста
app.MapDelete("/api/texts/{id}", async (HttpContext context, AppDbContext db, int id) =>
{
    var userId = int.Parse(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
    var text = await db.ScytaleTexts.FirstOrDefaultAsync(t => t.Id == id && t.UserId == userId);

    if (text == null)
    {
        context.Response.StatusCode = 404;
        await context.Response.WriteAsJsonAsync(new { error = "Текст не найден" });
        return;
    }

    db.ScytaleTexts.Remove(text);
    await db.SaveChangesAsync();

    await context.Response.WriteAsJsonAsync(new { message = "Текст успешно удален" });
}).RequireAuthorization();

// Получение одного текста
app.MapGet("/api/texts/{id}", async (HttpContext context, AppDbContext db, int id) =>
{
    var userId = int.Parse(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
    var text = await db.ScytaleTexts.FirstOrDefaultAsync(t => t.Id == id && t.UserId == userId);

    if (text == null)
    {
        context.Response.StatusCode = 404;
        await context.Response.WriteAsJsonAsync(new { error = "Текст не найден" });
        return;
    }

    await context.Response.WriteAsJsonAsync(text);
}).RequireAuthorization();

// Получение всех текстов
app.MapGet("/api/texts", async (HttpContext context, AppDbContext db) =>
{
    var userId = int.Parse(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
    var texts = await db.ScytaleTexts
        .Where(t => t.UserId == userId)
        .OrderByDescending(t => t.CreatedAt)
        .ToListAsync();

    await context.Response.WriteAsJsonAsync(texts);
}).RequireAuthorization();

// Шифрование текста
app.MapPost("/api/texts/{id}/encrypt", async (HttpContext context, AppDbContext db, int id) =>
{
    var userId = int.Parse(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
    var text = await db.ScytaleTexts.FirstOrDefaultAsync(t => t.Id == id && t.UserId == userId);

    if (text == null)
    {
        context.Response.StatusCode = 404;
        await context.Response.WriteAsJsonAsync(new { error = "Текст не найден" });
        return;
    }

    var request = await JsonSerializer.DeserializeAsync<EncryptRequest>(
        context.Request.Body,
        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
    );

    if (request == null || request.Key <= 0)
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsJsonAsync(new { error = "Неверный ключ шифрования" });
        return;
    }

    text.EncryptedText = Encrypt(text.OriginalText, request.Key);
    text.Key = request.Key;
    text.UpdatedAt = DateTime.UtcNow;

    await db.SaveChangesAsync();
    await context.Response.WriteAsJsonAsync(text);
}).RequireAuthorization();

// Расшифрование текста
app.MapPost("/api/texts/{id}/decrypt", async (HttpContext context, AppDbContext db, int id) =>
{
    var userId = int.Parse(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
    var text = await db.ScytaleTexts.FirstOrDefaultAsync(t => t.Id == id && t.UserId == userId);

    if (text == null)
    {
        context.Response.StatusCode = 404;
        await context.Response.WriteAsJsonAsync(new { error = "Текст не найден" });
        return;
    }

    if (text.EncryptedText == null || text.Key == null)
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsJsonAsync(new { error = "Текст не был зашифрован" });
        return;
    }

    var decryptedText = Decrypt(text.EncryptedText, text.Key.Value);
    await context.Response.WriteAsJsonAsync(new { decryptedText });
}).RequireAuthorization();

app.Run();

// Только после этого идут объявления классов
public class EncryptRequest
{
    public string? Text { get; set; }
    public int Key { get; set; }
}

public class DecryptRequest
{
    public string? EncryptedText { get; set; }
    public int Key { get; set; }
}

public class RegisterRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}

public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class ChangePasswordRequest
{
    public string OldPassword { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
}

public class AddTextRequest
{
    public string Text { get; set; } = string.Empty;
}

public class UpdateTextRequest
{
    public string Text { get; set; } = string.Empty;
}

public partial class Program
{
    // ... методы Program ...

    public static string GenerateJwtToken(User user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email)
        };

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes("your-super-secret-key-with-at-least-32-characters"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            expires: DateTime.Now.AddDays(1),
            claims: claims,
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static string Encrypt(string text, int key)
    {
        if (string.IsNullOrEmpty(text) || key <= 0)
            return text;

        if (key > text.Length)
            key = text.Length;

        var result = new StringBuilder();
        
        for (int i = 0; i < key; i++)
        {
            for (int j = i; j < text.Length; j += key)
            {
                result.Append(text[j]);
            }
        }

        return result.ToString();
    }

    public static string Decrypt(string encryptedText, int key)
    {
        if (string.IsNullOrEmpty(encryptedText) || key <= 0)
            return encryptedText;

        if (key > encryptedText.Length)
            key = encryptedText.Length;

        int rows = (int)Math.Ceiling((double)encryptedText.Length / key);
        char[] decrypted = new char[encryptedText.Length];
        int k = 0;

        for (int i = 0; i < key; i++)
        {
            for (int j = 0; j < rows; j++)
            {
                int pos = j * key + i;
                if (pos < encryptedText.Length)
                {
                    decrypted[pos] = encryptedText[k++];
                }
            }
        }

        return new string(decrypted);
    }

    public static async Task HandleEncrypt(HttpContext context, AppDbContext db)
    {
        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { error = "Требуется авторизация" });
            return;
        }
        try 
        {
            var request = await JsonSerializer.DeserializeAsync<EncryptRequest>(
                context.Request.Body,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );
            
            if (request == null || string.IsNullOrEmpty(request.Text))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Неверный формат запроса" });
                return;
            }

            var encryptedText = Encrypt(request.Text, request.Key);
            await context.Response.WriteAsJsonAsync(new { encryptedText });
        }
        catch (Exception ex)
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsJsonAsync(new { error = $"Ошибка сервера: {ex.Message}" });
        }
    }

    public static async Task HandleDecrypt(HttpContext context, AppDbContext db)
    {
        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { error = "Требуется авторизация" });
            return;
        }
        try 
        {
            string requestBody;
            using (var reader = new StreamReader(context.Request.Body))
            {
                requestBody = await reader.ReadToEndAsync();
            }

            Console.WriteLine($"Decrypt request body: {requestBody}"); // Для отладки

            var request = JsonSerializer.Deserialize<DecryptRequest>(
                requestBody,
                new JsonSerializerOptions 
                { 
                    PropertyNameCaseInsensitive = true,
                    AllowTrailingCommas = true
                }
            );
            
            if (request == null || string.IsNullOrEmpty(request.EncryptedText))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Неверный формат запроса" });
                return;
            }
            
            if (request.Key <= 0)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Ключ должен быть больше 0" });
                return;
            }

            var decryptedText = Decrypt(request.EncryptedText, request.Key);
            
            // Сохраняем в историю
            var userId = int.Parse(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
            var history = new RequestHistory
            {
                UserId = userId,
                RequestType = "Decrypt",
                InputText = request.EncryptedText,
                OutputText = decryptedText,
                Key = request.Key,
                Timestamp = DateTime.UtcNow
            };
            
            db.RequestHistory.Add(history);
            await db.SaveChangesAsync();

            await context.Response.WriteAsJsonAsync(new { decryptedText });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Decrypt error: {ex}"); // Логируем ошибку
            context.Response.StatusCode = 500;
            await context.Response.WriteAsJsonAsync(new { error = $"Ошибка сервера: {ex.Message}" });
        }
    }

    public static async Task HandleRegister(HttpContext context, AppDbContext db)
    {
        try
        {
            string requestBody;
            using (var reader = new StreamReader(context.Request.Body))
            {
                requestBody = await reader.ReadToEndAsync();
            }

            Console.WriteLine($"Received registration request: {requestBody}"); // Для отладки

            var request = JsonSerializer.Deserialize<RegisterRequest>(
                requestBody,
                new JsonSerializerOptions 
                { 
                    PropertyNameCaseInsensitive = true,
                    AllowTrailingCommas = true
                }
            );

            if (request == null)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Неверный формат запроса" });
                return;
            }

            // Валидация
            if (!Validators.IsValidUsername(request.Username))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Имя пользователя должно содержать минимум 3 символа" });
                return;
            }

            if (!Validators.IsValidEmail(request.Email))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Неверный формат email" });
                return;
            }

            if (!Validators.IsValidPassword(request.Password))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Пароль должен содержать минимум 6 символов" });
                return;
            }

            // Проверка существующего пользователя
            if (await db.Users.AnyAsync(u => u.Username == request.Username))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Пользователь с таким именем уже существует" });
                return;
            }

            if (await db.Users.AnyAsync(u => u.Email == request.Email))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Email уже используется" });
                return;
            }

            // Создание пользователя
            var user = new User
            {
                Username = request.Username,
                Password = BCrypt.Net.BCrypt.HashPassword(request.Password),
                Email = request.Email,
                RegisterDate = DateTime.UtcNow
            };

            db.Users.Add(user);
            await db.SaveChangesAsync();

            // Генерация токена для нового пользователя
            var token = GenerateJwtToken(user);

            context.Response.StatusCode = 201;
            await context.Response.WriteAsJsonAsync(new { 
                message = "Регистрация успешна",
                token = token,
                username = user.Username
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Registration error: {ex}"); // Логируем ошибку
            context.Response.StatusCode = 500;
            await context.Response.WriteAsJsonAsync(new { error = $"Ошибка сервера: {ex.Message}" });
        }
    }

    public static async Task HandleLogin(HttpContext context, AppDbContext db)
    {
        try
        {
            // Читаем тело запроса как строку
            string requestBody;
            using (var reader = new StreamReader(context.Request.Body))
            {
                requestBody = await reader.ReadToEndAsync();
            }

            Console.WriteLine($"Received request body: {requestBody}"); // Для отладки

            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Пустой запрос" });
                return;
            }

            var request = JsonSerializer.Deserialize<LoginRequest>(requestBody, 
                new JsonSerializerOptions 
                { 
                    PropertyNameCaseInsensitive = true,
                    AllowTrailingCommas = true
                });

            if (request == null)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Неверный формат запроса" });
                return;
            }

            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.Password))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "Неверное имя пользователя или пароль" });
                return;
            }

            var token = GenerateJwtToken(user);
            
            // Отправляем ответ с токеном
            await context.Response.WriteAsJsonAsync(new { 
                token = token,
                username = user.Username
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Login error: {ex}"); // Логируем ошибку
            context.Response.StatusCode = 500;
            await context.Response.WriteAsJsonAsync(new { error = $"Ошибка сервера: {ex.Message}" });
        }
    }
}
