using Microsoft.AspNetCore.Mvc;

public class HomeController : Controller
{
    [Route("/")]
    public IActionResult Index()
    {
        return RedirectToAction("Index", "Login");
    }
} 