dotnetapp:
--------------------------------------
AuthenticationController:
using Microsoft.AspNetCore.Mvc;
using dotnetapp.Models;
using dotnetapp.Services;

namespace dotnetapp.Controllers
{
    [Route("api")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(IAuthService authService, ILogger<AuthenticationController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "Invalid request data" });
                }

                var (status, message) = await _authService.Login(model);

                if (status == 0)
                {
                    return BadRequest(new { message });
                }

                _logger.LogInformation("User logged in successfully: {Email}", model.Email);
                return Ok(new { token = message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during login for email: {Email}", model.Email);
                return StatusCode(500, new { message = ex.Message });
            }
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] User model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "Invalid request data" });
                }

                var (status, message) = await _authService.Registration(model, model.UserRole);

                if (status == 0)
                {
                    return BadRequest(new { message });
                }

                _logger.LogInformation("User registered successfully: {Email}", model.Email);
                return Ok(new { message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during registration for email: {Email}", model.Email);
                return StatusCode(500, new { message = ex.Message });
            }
        }
    }
}
---------------------------------------
FeedbackController
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using dotnetapp.Models;
using dotnetapp.Services;

namespace dotnetapp.Controllers
{
    [Route("api/feedback")]
    [ApiController]
    public class FeedbackController : ControllerBase
    {
        private readonly FeedbackService _feedbackService;
        private readonly ILogger<FeedbackController> _logger;

        public FeedbackController(FeedbackService feedbackService, ILogger<FeedbackController> logger)
        {
            _feedbackService = feedbackService;
            _logger = logger;
        }

        [HttpGet]
        [Authorize(Roles = "Admin")] // Only Admin can view all feedbacks
        public async Task<IActionResult> GetAllFeedbacks()
        {
            try
            {
                var feedbacks = await _feedbackService.GetAllFeedbacks();
                _logger.LogInformation("Retrieved {Count} feedbacks", feedbacks.Count());
                return Ok(feedbacks);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while fetching all feedbacks");
                return StatusCode(500, new { message = ex.Message });
            }
        }

        [HttpGet("user/{userId}")]
        [Authorize(Roles = "User")] // Only User can view their own feedbacks
        public async Task<IActionResult> GetFeedbacksByUserId(int userId)
        {
            try
            {
                var feedbacks = await _feedbackService.GetFeedbacksByUserId(userId);
                _logger.LogInformation("Retrieved {Count} feedbacks for user ID: {UserId}", feedbacks.Count(), userId);
                return Ok(feedbacks);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while fetching feedbacks for user ID: {UserId}", userId);
                return StatusCode(500, new { message = ex.Message });
            }
        }

        [HttpPost]
        [Authorize(Roles = "User")] // Only User can add feedback
        public async Task<IActionResult> AddFeedback([FromBody] Feedback feedback)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "Invalid request data" });
                }

                await _feedbackService.AddFeedback(feedback);
                _logger.LogInformation("Feedback added successfully");
                return Ok(new { message = "Feedback added successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while adding feedback");
                return StatusCode(500, new { message = ex.Message });
            }
        }

        [HttpDelete("{feedbackId}")]
        [Authorize(Roles = "User")] // Only User can delete their own feedback
        public async Task<IActionResult> DeleteFeedback(int feedbackId)
        {
            try
            {
                var result = await _feedbackService.DeleteFeedback(feedbackId);
                
                if (!result)
                {
                    return NotFound(new { message = "Cannot find any feedback" });
                }

                _logger.LogInformation("Feedback deleted successfully with ID: {FeedbackId}", feedbackId);
                return Ok(new { message = "Feedback deleted successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while deleting feedback with ID: {FeedbackId}", feedbackId);
                return StatusCode(500, new { message = ex.Message });
            }
        }
    }
}
-------------------------------
InternshipApplicationContrroller
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using dotnetapp.Models;
using dotnetapp.Services;
using dotnetapp.Exceptions;

namespace dotnetapp.Controllers
{
    [Route("api/internship-application")]
    [ApiController]
    public class InternshipApplicationController : ControllerBase
    {
        private readonly InternshipApplicationService _applicationService;
        private readonly ILogger<InternshipApplicationController> _logger;

        public InternshipApplicationController(
            InternshipApplicationService applicationService,
            ILogger<InternshipApplicationController> logger)
        {
            _applicationService = applicationService;
            _logger = logger;
        }

        [HttpGet]
        [Authorize(Roles = "Admin")] // Only Admin can view all applications
        public async Task<IActionResult> GetAllInternshipApplications()
        {
            try
            {
                var applications = await _applicationService.GetAllInternshipApplications();
                _logger.LogInformation("Retrieved {Count} internship applications", applications.Count());
                return Ok(applications);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while fetching all internship applications");
                return StatusCode(500, new { message = ex.Message });
            }
        }

        [HttpGet("user/{userId}")]
        [Authorize] // Both Admin and User can view applications by user ID
        public async Task<IActionResult> GetInternshipApplicationByUserId(int userId)
        {
            try
            {
                var applications = await _applicationService.GetInternshipApplicationsByUserId(userId);

                if (!applications.Any())
                {
                    return NotFound(new { message = "Cannot find any internship application" });
                }

                _logger.LogInformation("Retrieved {Count} applications for user ID: {UserId}", applications.Count(), userId);
                return Ok(applications);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while fetching applications for user ID: {UserId}", userId);
                return StatusCode(500, new { message = ex.Message });
            }
        }

        [HttpPost]
        [Authorize(Roles = "User")] // Only User can apply for internship
        public async Task<IActionResult> AddInternshipApplication([FromBody] InternshipApplication internshipApplication)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "Invalid request data" });
                }

                await _applicationService.AddInternshipApplication(internshipApplication);
                _logger.LogInformation("Internship application added successfully");
                return Ok(new { message = "Internship application added successfully" });
            }
            catch (InternshipException ex)
            {
                _logger.LogWarning(ex, "Failed to add internship application");
                return StatusCode(500, new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while adding internship application");
                return StatusCode(500, new { message = ex.Message });
            }
        }

        [HttpPut("{internshipApplicationId}")]
        [Authorize] // Both Admin and User can update application (Admin for status, User for their own)
        public async Task<IActionResult> UpdateInternshipApplication(
            int internshipApplicationId,
            [FromBody] InternshipApplication internshipApplication)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "Invalid request data" });
                }

                var result = await _applicationService.UpdateInternshipApplication(
                    internshipApplicationId,
                    internshipApplication);

                if (!result)
                {
                    return NotFound(new { message = "Cannot find any internship application" });
                }

                _logger.LogInformation("Internship application updated successfully with ID: {InternshipApplicationId}",
                    internshipApplicationId);
                return Ok(new { message = "Internship application updated successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while updating internship application with ID: {InternshipApplicationId}",
                    internshipApplicationId);
                return StatusCode(500, new { message = ex.Message });
            }
        }

        [HttpDelete("{internshipApplicationId}")]
        [Authorize(Roles = "User")] // Only User can delete their own application
        public async Task<IActionResult> DeleteInternshipApplication(int internshipApplicationId)
        {
            try
            {
                var result = await _applicationService.DeleteInternshipApplication(internshipApplicationId);

                if (!result)
                {
                    return NotFound(new { message = "Cannot find any internship application" });
                }

                _logger.LogInformation("Internship application deleted successfully with ID: {InternshipApplicationId}",
                    internshipApplicationId);
                return Ok(new { message = "Internship application deleted successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while deleting internship application with ID: {InternshipApplicationId}",
                    internshipApplicationId);
                return StatusCode(500, new { message = ex.Message });
            }
        }
    }
}
---------------------------------------
InternshipController
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using dotnetapp.Models;
using dotnetapp.Services;
using dotnetapp.Exceptions;
using System.Text;

namespace dotnetapp.Controllers
{
    [Route("api/internship")]
    [ApiController]
    public class InternshipController : ControllerBase
    {
        private readonly InternshipService _internshipService;
        private readonly ILogger<InternshipController> _logger;

        public InternshipController(InternshipService internshipService, ILogger<InternshipController> logger)
        {
            _internshipService = internshipService;
            _logger = logger;
        }

        [HttpGet]
        [Authorize] // Both Admin and User can view all internships
        public async Task<IActionResult> GetAllInternships()
        {
            try
            {
                var internships = await _internshipService.GetAllInternships();
                _logger.LogInformation("Retrieved {Count} internships", internships.Count());
                return Ok(internships);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while fetching all internships");
                return StatusCode(500, new { message = ex.Message });
            }
        }

        [HttpGet("{internshipId}")]
        [Authorize] // Only Admin can view specific internship
        public async Task<IActionResult> GetInternshipById(int internshipId)
        {
            try
            {
                var internship = await _internshipService.GetInternshipById(internshipId);
                
                if (internship == null)
                {
                    return NotFound(new { message = "Cannot find any internship" });
                }

                _logger.LogInformation("Retrieved internship with ID: {InternshipId}", internshipId);
                return Ok(internship);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while fetching internship with ID: {InternshipId}", internshipId);
                return StatusCode(500, new { message = ex.Message });
            }
        }

        [HttpPost]
        [Authorize(Roles = "Admin")] // Only Admin can add internship
        public async Task<IActionResult> AddInternship([FromBody] Internship internship)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "Invalid request data" });
                }

                await _internshipService.AddInternship(internship);
                _logger.LogInformation("Internship added successfully");
                return Ok(new { message = "Internship added successfully" });
            }
            catch (InternshipException ex)
            {
                _logger.LogWarning(ex, "Failed to add internship");
                return StatusCode(500, new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while adding internship");
                return StatusCode(500, new { message = "Failed to add internship" });
            }
        }

        [HttpPut("{internshipId}")]
        [Authorize(Roles = "Admin")] // Only Admin can update internship
        public async Task<IActionResult> UpdateInternship(int internshipId, [FromBody] Internship internship)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "Invalid request data" });
                }

                var result = await _internshipService.UpdateInternship(internshipId, internship);
                
                if (!result)
                {
                    return NotFound(new { message = "Cannot find any internship" });
                }

                _logger.LogInformation("Internship updated successfully with ID: {InternshipId}", internshipId);
                return Ok(new { message = "Internship updated successfully" });
            }
            catch (InternshipException ex)
            {
                _logger.LogWarning(ex, "Failed to update internship");
                return StatusCode(500, new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while updating internship with ID: {InternshipId}", internshipId);
                return StatusCode(500, new { message = ex.Message });
            }
        }

        [HttpDelete("{internshipId}")]
        [Authorize(Roles = "Admin")] // Only Admin can delete internship
        public async Task<IActionResult> DeleteInternship(int internshipId)
        {
            try
            {
                var result = await _internshipService.DeleteInternship(internshipId);
                
                if (!result)
                {
                    return NotFound(new { message = "Cannot find any internship" });
                }

                _logger.LogInformation("Internship deleted successfully with ID: {InternshipId}", internshipId);
                return Ok(new { message = "Internship deleted successfully" });
            }
            catch (InternshipException ex)
            {
                _logger.LogWarning(ex, "Failed to delete internship");
                return StatusCode(500, new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while deleting internship with ID: {InternshipId}", internshipId);
                return StatusCode(500, new { message = ex.Message });
            }
        }


        [HttpGet("export-csv")]
        [AllowAnonymous]// Only admins should be able to export data
        public async Task<IActionResult> ExportInternshipsToCsv()
        {
            try
            {
                var internships = await _internshipService.GetAllInternships();

                if (internships == null || !internships.Any())
                {
                    return NotFound(new { message = "No internships found to export." });
                }

                var csv = new StringBuilder();
                // Add CSV header
                csv.AppendLine("ID,Title,Company,Location,DurationInMonths,Stipend,SkillsRequired,ApplicationDeadline");

                // Add CSV data rows
                foreach (var internship in internships)
                {
                    csv.AppendLine($"{internship.InternshipId},{internship.Title},{internship.CompanyName},{internship.Location},{internship.DurationInMonths},{internship.Stipend},{internship.SkillsRequired},{internship.ApplicationDeadline:yyyy-MM-dd}");
                }

                var bytes = Encoding.UTF8.GetBytes(csv.ToString());
                _logger.LogInformation("Exported {Count} internships to CSV", internships.Count());
                return File(bytes, "text/csv", "internships.csv");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while exporting internships to CSV");
                return StatusCode(500, new { message = ex.Message });
            }
        }
    }
}
--------------------------------------
IAuthSerice.cs
using dotnetapp.Models;

namespace dotnetapp.Services
{
    public interface IAuthService
    {
        Task<(int, string)> Registration(User model, string role);
        Task<(int, string)> Login(LoginModel model);
    }
}
--------------------------------------
AuthService.cs
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using dotnetapp.Data;
using dotnetapp.Models;

namespace dotnetapp.Services
{
    public class AuthService : IAuthService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            ILogger<AuthService> logger)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<(int, string)> Registration(User model, string role)
        {
            _logger.LogInformation("Registration attempt for email: {Email}", model.Email);

            if (role != UserRoles.Admin && role != UserRoles.User)
            {
                return (0, "Invalid role. Only 'Admin' or 'User' roles are allowed.");
            }

            // Validation (email, username, mobile, password)
            if (string.IsNullOrWhiteSpace(model.Email) || !model.Email.Contains("@"))
                return (0, "Invalid email format");
                
            if (string.IsNullOrWhiteSpace(model.Username))
                return (0, "Username is required");

            if (string.IsNullOrWhiteSpace(model.MobileNumber) || model.MobileNumber.Length != 10 || !model.MobileNumber.All(char.IsDigit))
                return (0, "Mobile number must be 10 digits");

            if (string.IsNullOrWhiteSpace(model.Password))
                return (0, "Password is required");

            // Admin secret key check
            if (role == UserRoles.Admin)
            {
                var adminSecretKey = _configuration["AdminSettings:SecretKey"];
                if (model.SecretKey != adminSecretKey)
                    return (0, "Invalid admin secret key");
            }

            // Check if user already exists in Users table
            if (await _context.Users.AnyAsync(u => u.Email == model.Email))
                return (0, "User already exists");

            // Create Identity user
            var appUser = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                Name = model.Username
            };

            var result = await _userManager.CreateAsync(appUser, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return (0, $"User creation failed: {errors}");
            }

            // Assign role
            if (!await _roleManager.RoleExistsAsync(role))
                await _roleManager.CreateAsync(new IdentityRole(role));

            await _userManager.AddToRoleAsync(appUser, role);

            // Save to custom Users table
            var passwordHasher = new PasswordHasher<ApplicationUser>();
            var hashedPassword = passwordHasher.HashPassword(appUser, model.Password);

            var newUser = new User
            {
                Email = model.Email,
                Password = hashedPassword,
                Username = model.Username,
                MobileNumber = model.MobileNumber,
                UserRole = role,
                SecretKey = model.SecretKey
            };

            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();

            _logger.LogInformation("User registered successfully with UserId: {UserId}", newUser.UserId);
            return (1, $"User created successfully! Your UserId is {newUser.UserId}");
        }

        public async Task<(int, string)> Login(LoginModel model)
        {
            var appUser = await _userManager.FindByEmailAsync(model.Email);
            if (appUser == null)
                return (0, "Invalid email");

            if (!await _userManager.CheckPasswordAsync(appUser, model.Password))
                return (0, "Invalid password");

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == model.Email);
            if (user == null)
                return (0, "User not found in Users table");

            var roles = await _userManager.GetRolesAsync(appUser);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, appUser.Name),
                new Claim("UserId", user.UserId.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            foreach (var r in roles)
                claims.Add(new Claim(ClaimTypes.Role, r));

            var token = GenerateToken(claims);
            return (1, token);
        }

        private string GenerateToken(IEnumerable<Claim> claims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(3),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
---------------------------------------
FeedbackService.cs
using Microsoft.EntityFrameworkCore;
using dotnetapp.Data;
using dotnetapp.Models;

namespace dotnetapp.Services
{
    public class FeedbackService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<FeedbackService> _logger;

        public FeedbackService(ApplicationDbContext context, ILogger<FeedbackService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<Feedback>> GetAllFeedbacks()
        {
            _logger.LogInformation("Fetching all feedbacks");
            return await _context.Feedbacks.ToListAsync();
        }

        public async Task<IEnumerable<Feedback>> GetFeedbacksByUserId(int userId)
        {
            _logger.LogInformation("Fetching feedbacks for user ID: {UserId}", userId);
            return await _context.Feedbacks
                .Where(f => f.UserId == userId)
                .ToListAsync();
        }

        public async Task<bool> AddFeedback(Feedback feedback)
        {
            _logger.LogInformation("Adding new feedback for user ID: {UserId}", feedback.UserId);

            feedback.Date = DateTime.Now;

            _context.Feedbacks.Add(feedback);
            await _context.SaveChangesAsync();
            
            _logger.LogInformation("Feedback added successfully with ID: {FeedbackId}", feedback.FeedbackId);
            return true;
        }

        public async Task<bool> DeleteFeedback(int feedbackId)
        {
            _logger.LogInformation("Deleting feedback with ID: {FeedbackId}", feedbackId);

            var feedback = await _context.Feedbacks.FindAsync(feedbackId);
            if (feedback == null)
            {
                _logger.LogWarning("Feedback not found with ID: {FeedbackId}", feedbackId);
                return false;
            }

            _context.Feedbacks.Remove(feedback);
            await _context.SaveChangesAsync();
            
            _logger.LogInformation("Feedback deleted successfully with ID: {FeedbackId}", feedbackId);
            return true;
        }
    }
}
-------------------------------------
InternshipApplicationService.cs
using Microsoft.EntityFrameworkCore;
using dotnetapp.Data;
using dotnetapp.Models;
using dotnetapp.Exceptions;

namespace dotnetapp.Services
{
    public class InternshipApplicationService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<InternshipApplicationService> _logger;

        public InternshipApplicationService(ApplicationDbContext context, ILogger<InternshipApplicationService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<InternshipApplication>> GetAllInternshipApplications()
        {
            _logger.LogInformation("Fetching all internship applications");
            return await _context.InternshipApplications.ToListAsync();
        }

        public async Task<IEnumerable<InternshipApplication>> GetInternshipApplicationsByUserId(int userId)
        {
            _logger.LogInformation("Fetching internship applications for user ID: {UserId}", userId);
            return await _context.InternshipApplications
                .Where(ia => ia.UserId == userId)
                .ToListAsync();
        }

        public async Task<bool> AddInternshipApplication(InternshipApplication internshipApplication)
        {
            _logger.LogInformation("Adding new internship application for user ID: {UserId}, internship ID: {InternshipId}",
                internshipApplication.UserId, internshipApplication.InternshipId);

            // Check if user already applied for this internship
            var existingApplication = await _context.InternshipApplications
                .FirstOrDefaultAsync(ia => ia.UserId == internshipApplication.UserId
                    && ia.InternshipId == internshipApplication.InternshipId);

            if (existingApplication != null)
            {
                _logger.LogWarning("User {UserId} already applied for internship {InternshipId}",
                    internshipApplication.UserId, internshipApplication.InternshipId);
                throw new InternshipException("User already applied for this internship");
            }

            internshipApplication.ApplicationDate = DateTime.Now;
            internshipApplication.ApplicationStatus = "Pending";

            _context.InternshipApplications.Add(internshipApplication);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Internship application added successfully with ID: {InternshipApplicationId}",
                internshipApplication.InternshipApplicationId);
            return true;
        }

        public async Task<bool> UpdateInternshipApplication(int internshipApplicationId, InternshipApplication internshipApplication)
        {
            _logger.LogInformation("Updating internship application with ID: {InternshipApplicationId}", internshipApplicationId);

            var existingApplication = await _context.InternshipApplications.FindAsync(internshipApplicationId);
            if (existingApplication == null)
            {
                _logger.LogWarning("Internship application not found with ID: {InternshipApplicationId}", internshipApplicationId);
                return false;
            }

            existingApplication.UniversityName = internshipApplication.UniversityName;
            existingApplication.DegreeProgram = internshipApplication.DegreeProgram;
            existingApplication.Resume = internshipApplication.Resume;
            existingApplication.LinkedInProfile = internshipApplication.LinkedInProfile;
            existingApplication.ApplicationStatus = internshipApplication.ApplicationStatus;

            await _context.SaveChangesAsync();

            _logger.LogInformation("Internship application updated successfully with ID: {InternshipApplicationId}", internshipApplicationId);
            return true;
        }

        public async Task<bool> DeleteInternshipApplication(int internshipApplicationId)
        {
            _logger.LogInformation("Deleting internship application with ID: {InternshipApplicationId}", internshipApplicationId);

            var application = await _context.InternshipApplications.FindAsync(internshipApplicationId);
            if (application == null)
            {
                _logger.LogWarning("Internship application not found with ID: {InternshipApplicationId}", internshipApplicationId);
                return false;
            }

            _context.InternshipApplications.Remove(application);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Internship application deleted successfully with ID: {InternshipApplicationId}", internshipApplicationId);
            return true;
        }
    }
}
-----------------------------
InternshipService.cs
using Microsoft.EntityFrameworkCore;
using dotnetapp.Data;
using dotnetapp.Models;
using dotnetapp.Exceptions;

namespace dotnetapp.Services
{
    public class InternshipService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<InternshipService> _logger;

        public InternshipService(ApplicationDbContext context, ILogger<InternshipService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<Internship>> GetAllInternships()
        {
            _logger.LogInformation("Fetching all internships");
            return await _context.Internships.ToListAsync();
        }

        public async Task<Internship> GetInternshipById(int internshipId)
        {
            _logger.LogInformation("Fetching internship with ID: {InternshipId}", internshipId);
            var internship = await _context.Internships.FindAsync(internshipId);
            
            if (internship == null)
            {
                _logger.LogWarning("Internship not found with ID: {InternshipId}", internshipId);
            }
            
            return internship;
        }

        public async Task<bool> AddInternship(Internship internship)
        {
            _logger.LogInformation("Adding new internship for company: {CompanyName}", internship.CompanyName);
            _context.Internships.Add(internship);
            await _context.SaveChangesAsync();
            
            _logger.LogInformation("Internship added successfully with ID: {InternshipId}", internship.InternshipId);
            return true;
        }

        public async Task<bool> UpdateInternship(int internshipId, Internship internship)
        {
            _logger.LogInformation("Updating internship with ID: {InternshipId}", internshipId);

            var existingInternship = await _context.Internships.FindAsync(internshipId);
            if (existingInternship == null)
            {
                _logger.LogWarning("Internship not found with ID: {InternshipId}", internshipId);
                return false;
            }

            // Check if another internship with same company name exists
            var duplicateInternship = await _context.Internships
                .FirstOrDefaultAsync(i => i.CompanyName == internship.CompanyName && i.InternshipId != internshipId);

            if (duplicateInternship != null)
            {
                _logger.LogWarning("Another internship with company name {CompanyName} already exists", internship.CompanyName);
                throw new InternshipException("Company with the same name already exists");
            }

            existingInternship.Title = internship.Title;
            existingInternship.CompanyName = internship.CompanyName;
            existingInternship.Location = internship.Location;
            existingInternship.DurationInMonths = internship.DurationInMonths;
            existingInternship.Stipend = internship.Stipend;
            existingInternship.Description = internship.Description;
            existingInternship.SkillsRequired = internship.SkillsRequired;
            existingInternship.ApplicationDeadline = internship.ApplicationDeadline;

            await _context.SaveChangesAsync();
            
            _logger.LogInformation("Internship updated successfully with ID: {InternshipId}", internshipId);
            return true;
        }

        public async Task<bool> DeleteInternship(int internshipId)
        {
            _logger.LogInformation("Deleting internship with ID: {InternshipId}", internshipId);

            var internship = await _context.Internships.FindAsync(internshipId);
            if (internship == null)
            {
                _logger.LogWarning("Internship not found with ID: {InternshipId}", internshipId);
                return false;
            }

            // Check if internship is referenced in any InternshipApplication
            var isReferenced = await _context.InternshipApplications
                .AnyAsync(ia => ia.InternshipId == internshipId);

            if (isReferenced)
            {
                _logger.LogWarning("Cannot delete internship with ID: {InternshipId} as it is referenced in applications", internshipId);
                throw new InternshipException("Internship cannot be deleted, it is referenced in internshipapplication");
            }

            _context.Internships.Remove(internship);
            await _context.SaveChangesAsync();
            
            _logger.LogInformation("Internship deleted successfully with ID: {InternshipId}", internshipId);
            return true;
        }
    }
}
---------------------------------------
ApplicationDbContext.cs
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using dotnetapp.Models;

namespace dotnetapp.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Internship> Internships { get; set; }
        public DbSet<InternshipApplication> InternshipApplications { get; set; }
        public DbSet<Feedback> Feedbacks { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure User entity
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.UserId);
                entity.Property(e => e.UserId)
                    .ValueGeneratedOnAdd()
                    .UseIdentityColumn();
                entity.HasIndex(e => e.Email).IsUnique();
            });

            // Configure Internship entity
            modelBuilder.Entity<Internship>(entity =>
            {
                entity.HasKey(e => e.InternshipId);
                entity.Property(e => e.InternshipId)
                    .ValueGeneratedOnAdd();
                entity.HasIndex(e => e.CompanyName);
            });

            // Configure InternshipApplication entity
            modelBuilder.Entity<InternshipApplication>(entity =>
            {
                entity.HasKey(e => e.InternshipApplicationId);
                entity.Property(e => e.InternshipApplicationId)
                    .ValueGeneratedOnAdd();

                entity.HasOne(e => e.User)
                    .WithMany(u => u.InternshipApplications)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasOne(e => e.Internship)
                    .WithMany(i => i.InternshipApplications)
                    .HasForeignKey(e => e.InternshipId)
                    .OnDelete(DeleteBehavior.Restrict);
            });

            // Configure Feedback entity
            modelBuilder.Entity<Feedback>(entity =>
            {
                entity.HasKey(e => e.FeedbackId);
                entity.Property(e => e.FeedbackId)
                    .ValueGeneratedOnAdd();

                entity.HasOne(e => e.User)
                    .WithMany(u => u.Feedbacks)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Restrict);
            });
        }
    }
}
--------------------------------------
InternshipException.cs
using System;

namespace dotnetapp.Exceptions
{
    public class InternshipException : Exception
    {
        public InternshipException()
        {
        }

        public InternshipException(string message)
            : base(message)
        {
        }

        public InternshipException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
-----------------------------------
Models:
ApplicationUser.cs
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace dotnetapp.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [StringLength(30)]
        public string Name { get; set; }
    }
}
------------------------------------
Feedback.cs
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace dotnetapp.Models
{
    public class Feedback
    {
        [Key]
        public int FeedbackId { get; set; }

        [Required]
        public int UserId { get; set; }

        [Required]
        [StringLength(2000)]
        public string FeedbackText { get; set; }

        [Required]
        public DateTime Date { get; set; }

        // Navigation properties
        [ForeignKey("UserId")]
        [JsonIgnore]
        public virtual User? User { get; set; }
    }
}
----------------------------------
Internship.cs
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace dotnetapp.Models
{
    public class Internship
    {
        [Key]
        public int InternshipId { get; set; }

        [Required]
        [StringLength(200)]
        public string Title { get; set; }

        [Required]
        [StringLength(200)]
        public string CompanyName { get; set; }

        [Required]
        [StringLength(200)]
        public string Location { get; set; }

        [Required]
        public int DurationInMonths { get; set; }

        [Required]
        [Column(TypeName = "decimal(18,2)")]
        public decimal Stipend { get; set; }

        [Required]
        [StringLength(2000)]
        public string Description { get; set; }

        [Required]
        [StringLength(500)]
        public string SkillsRequired { get; set; }

        [Required]
        [StringLength(100)]
        public string ApplicationDeadline { get; set; }

        // Navigation properties
        [JsonIgnore]
        public virtual ICollection<InternshipApplication>? InternshipApplications { get; set; }
    }
}
------------------------------------
InternshipApplicatio.cs
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace dotnetapp.Models
{
    public class InternshipApplication
    {
        [Key]
        public int InternshipApplicationId { get; set; }

        [Required]
        public int UserId { get; set; }

        [Required]
        public int InternshipId { get; set; }

        [Required]
        [StringLength(200)]
        public string UniversityName { get; set; }

        [Required]
        [StringLength(200)]
        public string DegreeProgram { get; set; }

        [Required]
        [StringLength(500)]
        public string Resume { get; set; }

        [StringLength(200)]
        public string? LinkedInProfile { get; set; }

        [Required]
        [StringLength(50)]
        public string ApplicationStatus { get; set; }

        [Required]
        public DateTime ApplicationDate { get; set; }

        // Navigation properties
        [ForeignKey("UserId")]
        [JsonIgnore]
        public virtual User? User { get; set; }

        [ForeignKey("InternshipId")]
        [JsonIgnore]
        public virtual Internship? Internship { get; set; }
    }
}
-----------------------------
LoginModel.cs
using System.ComponentModel.DataAnnotations;

namespace dotnetapp.Models
{
    public class LoginModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
-----------------------------------
User.cs
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace dotnetapp.Models
{
    public class User
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int UserId { get; set; }

        [Required]
        [StringLength(50)]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [StringLength(100)]
        public string Password { get; set; }

        [Required]
        [StringLength(100)]
        public string Username { get; set; }

        [Required]
        [StringLength(15)]
        public string MobileNumber { get; set; }

        [Required]
        [StringLength(50)]
        public string UserRole { get; set; }

        [StringLength(100)]
        public string? SecretKey { get; set; }

        // Navigation properties
        [JsonIgnore]
        public virtual ICollection<InternshipApplication>? InternshipApplications { get; set; }

        [JsonIgnore]
        public virtual ICollection<Feedback>? Feedbacks { get; set; }
    }
}

-------------------------------------
UserRoles.cs
namespace dotnetapp.Models
{
    public static class UserRoles
    {
        public const string Admin = "Admin";
        public const string User = "User";
    }
}
-----------------------------------
.env
DB_CONNECTION_STRING=User ID=sa;Password=examlyMssql@123;Server=localhost;Database=appdb;Trusted_Connection=False;Encrypt=False;
JWT_SECRET_KEY=JWTAuthenticationHIGHsecuredPasswordVVVp1OH7Xzyr

ADMIN_SECRET_KEY=SuperSecureAdminCode123!

--------------------------------------
appsettingsjson
{
  "ConnectionStrings": {
    "DefaultConnection": "User ID=sa;password=examlyMssql@123;server=localhost;Database=appdb;trusted_connection=false;Persist Security Info=False;Encrypt=False"
  },
  "JWT": {
    "ValidAudience": "https://8081-eaabbcaebcdeffadacaefcaeacaadabeafeaccfe.premiumproject.examly.io",
    "ValidIssuer": "https://8080-eaabbcaebcdeffadacaefcaeacaadabeafeaccfe.premiumproject.examly.io",
    "Secret": "ThisIsAVerySecretKeyForJWTTokenGeneration12345"
  },
  "AdminSettings": {
    "SecretKey": "Admin@123"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.EntityFrameworkCore": "Information"
    }
  },
  "AllowedHosts": "*"
}
---------------------------------------
Program.cs
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
using System.Text;
using dotnetapp.Data;
using dotnetapp.Models;
using dotnetapp.Services;

var builder = WebApplication.CreateBuilder(args);

// 🔹 Add Serilog configuration
// builder.Host.UseSerilog((context, config) =>
//     config.WriteTo.File("logs/app.txt", rollingInterval: RollingInterval.Day));
builder.Host.UseSerilog((context, config) =>
    config.WriteTo.File(
        "logs/app.txt",
        rollingInterval: RollingInterval.Day,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level}] {Message}{NewLine}{Exception}"
    ));


// Add services to the container
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles;
        options.JsonSerializerOptions.DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull;
        options.JsonSerializerOptions.PropertyNamingPolicy = null;
        options.JsonSerializerOptions.WriteIndented = true;
    });

// Configure DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Identity options
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 6;
    options.User.RequireUniqueEmail = true;
});

// JWT Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ClockSkew = TimeSpan.Zero,
        ValidAudience = builder.Configuration["JWT:ValidAudience"],
        ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]))
    };
});

// Register Services
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<InternshipService>();
builder.Services.AddScoped<InternshipApplicationService>();
builder.Services.AddScoped<FeedbackService>();

// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAngularApp",
        policy =>
        {
            policy.WithOrigins("https://8081-eaabbcaebcdeffadacaefcaeacaadabeafeaccfe.premiumproject.examly.io")
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        });
});

// Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Internship Application System API", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

// Logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();
builder.Logging.AddEventSourceLogger();

var app = builder.Build();

// Middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Internship Application System API V1");
    });
}

app.UseHttpsRedirection();
app.UseCors("AllowAngularApp");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Seed roles
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var roles = new[] { "Admin", "User" };

    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
        }
    }
}

app.Run();
--------------------------------------
angularapp:

usermodel.ts
import { InternshipApplication } from './internshipapplication.model';
import { Feedback } from './feedback.model';

export interface User {
  UserId?: number;
  Email: string;
  Password: string;
  Username: string;
  MobileNumber: string;
  UserRole: string;
  SecretKey?: string;
  
  // Navigation properties
  InternshipApplications?: InternshipApplication[];
  Feedbacks?: Feedback[];
}
--------------------------------------
loginmodel.ts
export interface Login {
  Email: string;
  Password: string;
}
-------------------------------------
internshipapplicationmodel.ts
import { User } from './user.model';
import { Internship } from './internship.model';

export interface InternshipApplication {
  InternshipApplicationId?: number;
  UserId: number;
  InternshipId: number;
  UniversityName: string;
  DegreeProgram: string;
  Resume: string;
  LinkedInProfile?: string;
  ApplicationStatus: string;
  ApplicationDate: string;
  
  // Navigation properties
  User?: User;
  Internship?: Internship;
}
------------------------------------
internshipmodel.ts
import { InternshipApplication } from './internshipapplication.model';

export interface Internship {
  InternshipId?: number;
  Title: string;
  CompanyName: string;
  Location: string;
  DurationInMonths: number;
  Stipend: number;
  Description: string;
  SkillsRequired: string;
  ApplicationDeadline: string;
  
  // Navigation property
  InternshipApplications?: InternshipApplication[];
}
------------------------------
feedbackmodel.ts
import { User } from './user.model';

export interface Feedback {
  FeedbackId?: number;
  UserId: number;
  FeedbackText: string;
  Date: Date;
  
  // Navigation property
  User?: User;
}
-------------------------------
authservice.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { tap } from 'rxjs/operators';
import { environment } from '../../environments/environment';
import { User } from '../models/user.model';
import { Login } from '../models/login.model';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = `${environment.apiUrl}/api`;
  
  private userRoleSubject = new BehaviorSubject<string>('');
  private userIdSubject = new BehaviorSubject<number>(0);
  private usernameSubject = new BehaviorSubject<string>('');
  
  public userRole$ = this.userRoleSubject.asObservable();
  public userId$ = this.userIdSubject.asObservable();
  public username$ = this.usernameSubject.asObservable();

  constructor(private http: HttpClient) {
    // Load user data from localStorage on service initialization
    const token = this.getToken();
    if (token) {
      this.loadUserDataFromToken();
    }
  }

  register(user: User): Observable<any> {
    return this.http.post(`${this.apiUrl}/register`, user);
  }

  login(loginData: Login): Observable<any> {
    return this.http.post(`${this.apiUrl}/login`, loginData).pipe(
      tap((response: any) => {
        if (response.token) {
          localStorage.setItem('token', response.token);
          this.loadUserDataFromToken();
        }
      })
    );
  }

  logout(): void {
    localStorage.removeItem('token');
    localStorage.removeItem('userRole');
    localStorage.removeItem('userId');
    localStorage.removeItem('username');
    this.userRoleSubject.next('');
    this.userIdSubject.next(0);
    this.usernameSubject.next('');
  }

  getToken(): string | null {
    return localStorage.getItem('token');
  }

  isLoggedIn(): boolean {
    return !!this.getToken();
  }

  getUserRole(): string {
    return localStorage.getItem('userRole') || '';
  }

  getUserId(): number {
    return parseInt(localStorage.getItem('userId') || '0');
  }

  getUsername(): string {
    return localStorage.getItem('username') || '';
  }

  private loadUserDataFromToken(): void {
    const token = this.getToken();
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        
        console.log('Decoded JWT payload:', payload);
        console.log('Available claim keys:', Object.keys(payload));

        const role = payload['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'] || '';
        const userId = payload['UserId'] || '0';
        
        const username = payload['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'] || '';
        
        localStorage.setItem('userRole', role);
        localStorage.setItem('userId', userId);
        localStorage.setItem('username', username);
        
        this.userRoleSubject.next(role);
        this.userIdSubject.next(parseInt(userId));
        this.usernameSubject.next(username);
      } catch (error) {
        console.error('Error parsing token:', error);
      }
    }
  }

  getAuthHeaders(): HttpHeaders {
    const token = this.getToken();
    return new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    });
  }
}
----------------------------------
feedbackservice.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { Feedback } from '../models/feedback.model';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})
export class FeedbackService {
  private apiUrl = `${environment.apiUrl}/api/Feedback`;

  constructor(
    private http: HttpClient,
    private authService: AuthService
  ) { }

  getAllFeedbacks(): Observable<Feedback[]> {
    return this.http.get<Feedback[]>(this.apiUrl, {
      headers: this.authService.getAuthHeaders()
    });
  }

  getFeedbacksByUserId(userId: number): Observable<Feedback[]> {
    return this.http.get<Feedback[]>(`${this.apiUrl}/user/${userId}`, {
      headers: this.authService.getAuthHeaders()
    });
  }

  addFeedback(feedback: Feedback): Observable<any> {
    return this.http.post(this.apiUrl, feedback, {
      headers: this.authService.getAuthHeaders()
    });
  }

  deleteFeedback(id: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}/${id}`, {
      headers: this.authService.getAuthHeaders()
    });
  }
}
--------------------
internshipservice.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { Internship } from '../models/internship.model';
import { AuthService } from './auth.service';
import Swal from 'sweetalert2';
@Injectable({
  providedIn: 'root'
})

export class InternshipService {
  
  private apiUrl = `${environment.apiUrl}/api/internship`;

  constructor(private http: HttpClient, private authService: AuthService) {}

  getAllInternships(): Observable<Internship[]> {
    return this.http.get<Internship[]>(this.apiUrl, {
      headers: this.authService.getAuthHeaders()
    });
  }

  getInternshipById(id: number): Observable<Internship> {
    return this.http.get<Internship>(`${this.apiUrl}/${id}`, {
      headers: this.authService.getAuthHeaders()
    });
  }

  addInternship(internship: Internship): Observable<any> {
    return this.http.post(this.apiUrl, internship, {
      headers: this.authService.getAuthHeaders()
    });
  }

  updateInternship(id: number, internship: Internship): Observable<any> {
    return this.http.put(`${this.apiUrl}/${id}`, internship, {
      headers: this.authService.getAuthHeaders()
    });
  }

  deleteInternship(id: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}/${id}`, {
      headers: this.authService.getAuthHeaders()
    });
  }



  downloadInternshipsCSV(): void {
    const url = `${this.apiUrl}/export-csv`;
    const token = localStorage.getItem('token'); // or this.authService.getToken()
 
    if (!token) {
        // Handle case where token is not available
        Swal.fire({
            icon: 'error',
            title: 'Authentication Error',
            text: 'You must be logged in to download the CSV file.',
            confirmButtonColor: '#667eea'
        });
        return;
    }

    fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(response => {
      if (!response.ok) {
        // Handle specific error codes if needed, for example, 401 Unauthorized
        if (response.status === 401) {
            throw new Error('Authentication failed. Please log in again.');
        }
        throw new Error('Failed to download internships CSV');
      }
      return response.blob();
    })
    .then(blob => {
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = 'internships.csv';
      link.click();
      URL.revokeObjectURL(link.href);
    })
    .catch(error => {
      console.error('Download error:', error);
      Swal.fire({
        icon: 'error',
        title: 'Download Failed',
        text: error.message || 'Failed to download CSV file. Please try again.',
        confirmButtonColor: '#667eea'
      });
    });
  }
}
---------------------------------------
internshippplicationservice.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { InternshipApplication } from '../models/internshipapplication.model';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})

export class InternshipApplicationService {
  private apiUrl = `${environment.apiUrl}/api/Internship-application`;

  constructor(
    private http: HttpClient,
    private authService: AuthService
  ) { }

  getAllInternshipApplications(): Observable<InternshipApplication[]> {
    return this.http.get<InternshipApplication[]>(this.apiUrl, {
      headers: this.authService.getAuthHeaders()
    });
  }

  getInternshipApplicationsByUserId(userId: number): Observable<InternshipApplication[]> {
    return this.http.get<InternshipApplication[]>(`${this.apiUrl}/user/${userId}`, {
      headers: this.authService.getAuthHeaders()
    });
  }

  addInternshipApplication(application: InternshipApplication): Observable<any> {
    return this.http.post(this.apiUrl, application, {
      headers: this.authService.getAuthHeaders()
    });
  }

  updateInternshipApplication(id: number, application: InternshipApplication): Observable<any> {
    return this.http.put(`${this.apiUrl}/${id}`, application, {
      headers: this.authService.getAuthHeaders()
    });
  }

  deleteInternshipApplication(id: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}/${id}`, {
      headers: this.authService.getAuthHeaders()
    });
  }
}

------------------------------------
components:
admineititrnship:
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { NgForm } from '@angular/forms';
import { finalize } from 'rxjs/operators';
import Swal from 'sweetalert2';

import { InternshipService } from '../../services/internship.service';
import { Internship } from 'src/app/models/internship.model';

@Component({
  selector: 'app-admineditinternship',
  templateUrl: './admineditinternship.component.html',
  styleUrls: ['./admineditinternship.component.css']
})
export class AdmineditinternshipComponent implements OnInit {
  internship: Internship | null = null;
  errorMessage = '';
  isLoading = false;

  constructor(
    private route: ActivatedRoute,
    private internshipService: InternshipService,
    private router: Router
  ) {}

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id');
    if (id) {
      this.isLoading = true;
      this.internshipService
        .getInternshipById(+id)
        .pipe(finalize(() => (this.isLoading = false)))
        .subscribe({
          next: (data) => {
            // Normalize date for <input type="date"> if needed
            if (data?.ApplicationDeadline) {
              data.ApplicationDeadline = this.toDateInputValue(data.ApplicationDeadline);
            }
            this.internship = data;
          },
          error: () => {
            this.errorMessage = 'Failed to load internship details';
          }
        });
    }
  }

  updateInternship(form: NgForm): void {
    if (!form.valid || !this.internship) {
      return;
    }

    this.isLoading = true;

    // If your backend expects ISO date, convert from "yyyy-MM-dd" to ISO.
    // If it expects "yyyy-MM-dd" already, you can keep ApplicationDeadline as is.
    const payload: Internship = {
      ...this.internship,
      ApplicationDeadline: this.toISODate(this.internship.ApplicationDeadline as any)
    };

    this.internshipService
      .updateInternship(this.internship.InternshipId, payload)
      .pipe(finalize(() => (this.isLoading = false)))
      .subscribe({
        next: () => {
          Swal.fire({
            icon: 'success',
            title: 'Success!',
            text: 'Internship updated successfully',
            confirmButtonColor: '#667eea'
          }).then(() => {
            this.router.navigate(['/admin/internship/view']);
          });
        },
        error: (error) => {
          Swal.fire({
            icon: 'error',
            title: 'Error',
            text: error?.error?.message || 'Failed to update internship',
            confirmButtonColor: '#667eea'
          });
        }
      });
  }

  onCancel(): void {
    this.router.navigate(['/admin/internship/view']);
  }

  /**
   * Converts date-like input (ISO string/Date/string) to "yyyy-MM-dd" for <input type="date">
   */
  private toDateInputValue(dateLike: string | Date): string {
    const d = new Date(dateLike);
    if (isNaN(d.getTime())) return '';
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    return `${yyyy}-${mm}-${dd}`;
  }

  /**
   * Converts "yyyy-MM-dd" to ISO (UTC) string for API.
   * Adjust this if your backend expects a different format (e.g., keep "yyyy-MM-dd").
   */
  private toISODate(yyyyMmDd: string): string {
    if (!yyyyMmDd) return yyyyMmDd;
    const [y, m, d] = yyyyMmDd.split('-').map(Number);
    const dt = new Date(y, (m ?? 1) - 1, d ?? 1);
    return dt.toISOString();
  }
}
-------------------
<div class="internship-form-container" *ngIf="internship">
  <div class="form-card">
    <div class="form-header">
      <h2><i class="fa fa-edit"></i> Edit Internship</h2>
    </div>

    <form #editForm="ngForm" (ngSubmit)="updateInternship(editForm)" class="application-form">
      <!-- Title -->
      <div class="form-group">
        <label><i class="fa fa-tag"></i> Title *</label>
        <input type="text" [(ngModel)]="internship.Title" name="title" required />
      </div>

      <!-- Company Name -->
      <div class="form-group">
        <label><i class="fa fa-building"></i> Company Name *</label>
        <input type="text" [(ngModel)]="internship.CompanyName" name="companyName" required />
      </div>

      <!-- Location -->
      <div class="form-group">
        <label><i class="fa fa-map-marker"></i> Location *</label>
        <input type="text" [(ngModel)]="internship.Location" name="location" required />
      </div>

      <!-- Duration -->
      <div class="form-group">
        <label><i class="fa fa-hourglass-half"></i> Duration (Months) *</label>
        <input type="number" [(ngModel)]="internship.DurationInMonths" name="duration" required min="1" />
      </div>

      <!-- Stipend -->
      <div class="form-group">
        <label><i class="fa fa-rupee"></i> Stipend *</label>
        <input type="number" [(ngModel)]="internship.Stipend" name="stipend" required min="0" />
      </div>

      <!-- Description -->
      <div class="form-group">
        <label><i class="fa fa-align-left"></i> Description *</label>
        <textarea [(ngModel)]="internship.Description" name="description" required rows="4"></textarea>
      </div>

      <!-- Skills -->
      <div class="form-group">
        <label><i class="fa fa-code"></i> Skills Required *</label>
        <input type="text" [(ngModel)]="internship.SkillsRequired" name="skills" required />
      </div>

      <!-- Deadline -->
      <div class="form-group">
        <label><i class="fa fa-calendar"></i> Application Deadline *</label>
        <input type="date" [(ngModel)]="internship.ApplicationDeadline" name="deadline" required />
      </div>

      <!-- Buttons -->
      <div class="form-actions">
        <button type="button" class="btn-outline" (click)="onCancel()">Cancel</button>
        <button type="reset" class="btn-outline">Reset</button>
        <button type="submit" class="update-btn" [disabled]="!editForm.valid">
          <i class="fa fa-refresh"></i> Update Internship
        </button>
      </div>
    </form>

    <div *ngIf="errorMessage" class="alert alert-danger">{{ errorMessage }}</div>
  </div>
</div>
``--------------------------------------
/* Internship Form Component Styles */
.internship-form-container {
  padding: 20px;
  max-width: 800px;
  margin: 0 auto;
}

.form-card {
  background: white;
  border-radius: 15px;
  padding: 40px;
  box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
}

.form-header {
  text-align: center;
  margin-bottom: 40px;
  padding-bottom: 20px;
  border-bottom: 2px solid #f0f0f0;
}

.form-header h2 {
  font-size: 28px;
  font-weight: 700;
  color: #333;
  margin: 0 0 20px 0;
}

.form-header h2 i {
  color: #11998e;
  margin-right: 10px;
}

.internship-info {
  background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
  padding: 20px;
  border-radius: 10px;
  color: white;
  margin-top: 20px;
}

.internship-info h3 {
  font-size: 22px;
  margin: 0 0 10px 0;
}

.internship-info p {
  margin: 0;
  font-size: 16px;
  opacity: 0.9;
}

.internship-info i {
  margin-right: 5px;
}

.application-form {
  max-width: 700px;
  margin: 0 auto;
}

.form-group {
  display: flex;
  flex-direction: column;
  margin-bottom: 16px;
}

.form-group label i {
  margin-right: 8px;
  color: #11998e;
}

.form-group input,
.form-group textarea,
.form-group select {
  padding: 12px 14px;
  border: 1px solid #e6e6e6;
  border-radius: 8px;
  font-size: 14px;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}

.form-group input:focus,
.form-group textarea:focus,
.form-group select:focus {
  border-color: #11998e;
  box-shadow: 0 0 0 3px rgba(17, 153, 142, 0.15);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 15px;
  margin-top: 30px;
  padding-top: 20px;
  border-top: 2px solid #f0f0f0;
}

/* Stylish Update Button */
.update-btn {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: #fff;
  font-weight: 600;
  text-transform: uppercase;
  padding: 12px 30px;
  border: none;
  border-radius: 8px;
  font-size: 16px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 10px;
  transition: background 0.3s ease, transform 0.2s ease;
}

.update-btn i {
  font-size: 18px;
}

.update-btn:hover {
  background: linear-gradient(135deg, #5a67d8 0%, #6b46c1 100%);
  transform: scale(1.03);
}

/* Optional: Cancel and Reset buttons */
.btn-outline {
  background: #fff;
  color: #11998e;
  border: 2px solid #11998e;
  padding: 12px 30px;
  font-size: 16px;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.btn-outline:hover {
  background: rgba(17, 153, 142, 0.08);
}

/* Responsive */
@media (max-width: 768px) {
  .form-card {
    padding: 20px;
  }

  .form-actions {
    flex-direction: column;
  }

  .form-actions .btn,
  .form-actions .update-btn,
  .form-actions .btn-outline {
    width: 100%;
  }
}
----------------------------------
adminnav
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-adminnav',
  templateUrl: './adminnav.component.html',
  styleUrls: ['./adminnav.component.css']
})
export class AdminnavComponent implements OnInit {
  username: string = '';
  isSidebarOpen: boolean = true;

  constructor(
    private authService: AuthService,
    private router: Router
  ) { }

  ngOnInit(): void {
    this.username = this.authService.getUsername();
    console.log(localStorage.getItem('username'));
  }

  toggleSidebar(): void {
    this.isSidebarOpen = !this.isSidebarOpen;
  }

  logout(): void {
    Swal.fire({
      title: 'Are you sure?',
      text: 'Do you want to logout?',
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#667eea',
      cancelButtonColor: '#eb3349',
      confirmButtonText: 'Yes, logout!'
    }).then((result) => {
      if (result.isConfirmed) {
        this.authService.logout();
        
        Swal.fire({
          icon: 'success',
          title: 'Logged Out',
          text: 'You have been successfully logged out',
          timer: 2000,
          showConfirmButton: false
        });
        
        setTimeout(() => {
          this.router.navigate(['/login']);
        }, 2000);
      }
    });
  }
}
----------------------------------
<div class="admin-layout">
  <div class="sidebar" [class.collapsed]="!isSidebarOpen">
    <div class="sidebar-header">
      <i class="fas fa-briefcase"></i>
      <h3 *ngIf="isSidebarOpen">Admin Panel</h3>
    </div>
    
    <nav class="sidebar-nav">
      <a routerLink="/admin/internship/view" routerLinkActive="active" class="nav-item">
        <i class="fas fa-list"></i>
        <span *ngIf="isSidebarOpen">View Internships</span>
      </a>
      <a routerLink="/admin/internship/create" routerLinkActive="active" class="nav-item">
        <i class="fas fa-plus-circle"></i>
        <span *ngIf="isSidebarOpen">Create Internship</span>
      </a>
      <a routerLink="/admin/internship-requested" routerLinkActive="active" class="nav-item">
        <i class="fas fa-file-alt"></i>
        <span *ngIf="isSidebarOpen">Applications</span>
      </a>
      <a routerLink="/admin/feedbacks" routerLinkActive="active" class="nav-item">
        <i class="fas fa-comments"></i>
        <span *ngIf="isSidebarOpen">Feedbacks</span>
      </a>
      <a routerLink="/admin/piechart" routerLinkActive="active" class="nav-item">
        <i class="fas fa-chart-pie"></i>
        <span *ngIf="isSidebarOpen">Statistics</span>
      </a>
    </nav>
    
    <div class="sidebar-footer">
      <button class="nav-item logout-btn" (click)="logout()">
        <i class="fas fa-sign-out-alt"></i>
        <span *ngIf="isSidebarOpen">Logout</span>
      </button>
    </div>
  </div>
  
  <div class="main-content">
    <header class="top-header">
      <button class="toggle-btn" (click)="toggleSidebar()">
        <i class="fas fa-bars"></i>
      </button>
      <div class="header-right">
        <div class="user-info">
          <i class="fas fa-user-circle"></i>
          <span>{{ username }}/<b>Admin</b></span>
        </div>
      </div>
    </header>
    
    <div class="content-area">
      <router-outlet></router-outlet>
    </div>
  </div>
</div>
------------------------------
/* Admin Navigation Styles */
.admin-layout {
  display: flex;
  min-height: 100vh;
}

.sidebar {
  width: 250px;
  background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
  color: white;
  transition: all 0.3s ease;
  display: flex;
  flex-direction: column;
  position: fixed;
  height: 100vh;
  z-index: 1000;
}

.sidebar.collapsed {
  width: 70px;
}

.sidebar-header {
  padding: 30px 20px;
  text-align: center;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.sidebar-header i {
  font-size: 40px;
  margin-bottom: 10px;
}

.sidebar-header h3 {
  font-size: 20px;
  font-weight: 600;
  margin: 0;
}

.sidebar-nav {
  flex: 1;
  padding: 20px 0;
}

.nav-item {
  display: flex;
  align-items: center;
  padding: 15px 20px;
  color: white;
  text-decoration: none;
  transition: all 0.3s ease;
  cursor: pointer;
  border: none;
  background: transparent;
  width: 100%;
  text-align: left;
}

.nav-item i {
  font-size: 20px;
  min-width: 30px;
}

.nav-item span {
  margin-left: 15px;
  font-size: 16px;
}

.nav-item:hover {
  background: rgba(255, 255, 255, 0.1);
  padding-left: 25px;
}

.nav-item.active {
  background: rgba(255, 255, 255, 0.2);
  border-left: 4px solid #ffd700;
}

.sidebar-footer {
  padding: 20px 0;
  border-top: 1px solid rgba(255, 255, 255, 0.1);
}

.logout-btn {
  color: #ffcccc;
}

.logout-btn:hover {
  background: rgba(255, 0, 0, 0.2);
  color: white;
}

.main-content {
  flex: 1;
  margin-left: 250px;
  transition: all 0.3s ease;
  background: #f5f7fa;
}

.sidebar.collapsed ~ .main-content {
  margin-left: 70px;
}

.top-header {
  background: white;
  padding: 20px 30px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
  position: sticky;
  top: 0;
  z-index: 999;
}

.toggle-btn {
  background: transparent;
  border: none;
  font-size: 24px;
  color: #667eea;
  cursor: pointer;
  transition: all 0.3s ease;
}

.toggle-btn:hover {
  transform: scale(1.1);
}

.header-right {
  display: flex;
  align-items: center;
  gap: 20px;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 600;
  color: #333;
}

.user-info i {
  font-size: 28px;
  color: #667eea;
}

.content-area {
  padding: 30px;
  min-height: calc(100vh - 80px);
}

/* Responsive */
@media (max-width: 768px) {
  .sidebar {
    width: 70px;
  }
  
  .sidebar-header h3,
  .nav-item span {
    display: none;
  }
  
  .main-content {
    margin-left: 70px;
  }
}
------------------------
admiviewfeedback
import { Component, OnInit } from '@angular/core';
import { FeedbackService } from '../../services/feedback.service';
import { Feedback } from '../../models/feedback.model';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-adminviewfeedback',
  templateUrl: './adminviewfeedback.component.html',
  styleUrls: ['./adminviewfeedback.component.css']
})
export class AdminviewfeedbackComponent implements OnInit {
  feedbacks: Feedback[] = [];
  isLoading: boolean = false;

  columnDefs = [
    { headerName: 'Feedback ID', field: 'FeedbackId', sortable: true, filter: true, width: 130 },
    { headerName: 'Feedback Text', field: 'FeedbackText', sortable: true, filter: true, width: 400 },
    { headerName: 'Date', field: 'Date', sortable: true, filter: true, width: 150,
      valueFormatter: (params: any) => new Date(params.value).toLocaleDateString() }
  ];

  defaultColDef = {
    flex: 1,
    minWidth: 100,
    resizable: true
  };

  paginationPageSize = 10;
  paginationPageSizeSelector = [5, 10, 20, 50];

  constructor(
    private feedbackService: FeedbackService
  ) { }

  ngOnInit(): void {
    this.loadFeedbacks();
  }

  loadFeedbacks(): void {
    this.isLoading = true;
    this.feedbackService.getAllFeedbacks().subscribe(
      (data) => {
        this.feedbacks = data;
        this.isLoading = false;
      },
      (error) => {
        this.isLoading = false;
        Swal.fire({
          icon: 'error',
          title: 'Error',
          text: 'Failed to load feedbacks',
          confirmButtonColor: '#667eea'
        });
      }
    );
  }

  onGridReady(params: any): void {
    params.api.sizeColumnsToFit();
  }
}
-----------------------
<div class="admin-feedback-container fade-in">
  <div class="page-header">
    <h2><i class="fas fa-comments"></i> All Feedbacks</h2>
  </div>

  <div class="grid-container" *ngIf="!isLoading">
    <ag-grid-angular
      style="width: 100%; height: 600px;"
      class="ag-theme-alpine"
      [rowData]="feedbacks"
      [columnDefs]="columnDefs"
      [defaultColDef]="defaultColDef"
      [pagination]="true"
      [paginationPageSize]="paginationPageSize"
      [paginationPageSizeSelector]="paginationPageSizeSelector"
      (gridReady)="onGridReady($event)"
    >
    </ag-grid-angular>
  </div>

  <div class="loading-container" *ngIf="isLoading">
    <div class="spinner"></div>
    <p>Loading feedbacks...</p>
  </div>
</div>
------------------
.admin-feedback-container {
  padding: 20px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
  padding: 20px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.page-header h2 {
  font-size: 28px;
  font-weight: 700;
  color: #333;
  margin: 0;
}

.page-header h2 i {
  color: #667eea;
  margin-right: 10px;
}

.grid-container {
  background: white;
  padding: 20px;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

/* AG Grid Styling Fixes and Enhancements */
.ag-theme-alpine {
  --ag-header-background-color: #667eea;
  --ag-header-foreground-color: #1f2937;
  --ag-font-size: 14px;
  --ag-border-color: #e5e7eb;
  --ag-row-hover-color: #f3f4f6;
  --ag-selected-row-background-color: #e0f2fe;
}

.ag-header-cell-label {
  color: #1f2937 !important;
  font-weight: 600;
  font-size: 14px;
}

.ag-header {
  background-color: #f9fafb !important;
  border-bottom: 1px solid #d1d5db !important;
}

.ag-header-cell:hover {
  background-color: #f3f4f6 !important;
}

.ag-root-wrapper {
  border-radius: 10px;
  overflow: hidden;
}

.ag-row {
  font-size: 13px;
  color: #374151;
}

/* Loading container */
.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 100px 20px;
  background: white;
  border-radius: 10px;
}

.loading-container p {
  margin-top: 20px;
  font-size: 18px;
  color: #667eea;
}
--------------------------
authguard.ts
import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';
import { AuthService } from 'src/app/services/auth.service';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {

  constructor(
    private authService: AuthService,
    private router: Router
  ) { }

  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): boolean {
    // Check if user is logged in
    if (!this.authService.isLoggedIn()) {
      this.router.navigate(['/login']);
      return false;
    }

    // Get user role
    const userRole = this.authService.getUserRole();
    const url = state.url;

    // Role-based access control
    if (url.startsWith('/admin')) {
      if (userRole === 'Admin') {
        return true;
      } else {
        this.router.navigate(['/error']);
        return false;
      }
    } else if (url.startsWith('/user')) {
      if (userRole === 'User') {
        return true;
      } else {
        this.router.navigate(['/error']);
        return false;
      }
    }

    return true;
  }
}
-----------------------------
creatinternship
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { InternshipService } from '../../services/internship.service';
import { Internship } from '../../models/internship.model';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-createinternship',
  templateUrl: './createinternship.component.html',
  styleUrls: ['./createinternship.component.css']
})
export class CreateinternshipComponent implements OnInit {
  internship: Internship = {
    Title: '',
    CompanyName: '',
    Location: '',
    DurationInMonths: 0,
    Stipend: 0,
    Description: '',
    SkillsRequired: '',
    ApplicationDeadline: ''
  };

  errors: any = {
    Title: '',
    CompanyName: '',
    Location: '',
    DurationInMonths: '',
    Stipend: '',
    Description: '',
    SkillsRequired: '',
    ApplicationDeadline: ''
  };

  isLoading: boolean = false;

  constructor(
    private internshipService: InternshipService,
    private router: Router
  ) { }

  ngOnInit(): void {
  }

  validateTitle(): boolean {
    this.errors.Title = '';
    if (!this.internship.Title || this.internship.Title.trim() === '') {
      this.errors.Title = 'Title is required';
      return false;
    }
    if (this.internship.Title.trim() !== this.internship.Title) {
      this.errors.Title = 'Title cannot have leading or trailing spaces';
      return false;
    }
    return true;
  }

  validateCompanyName(): boolean {
    this.errors.CompanyName = '';
    if (!this.internship.CompanyName || this.internship.CompanyName.trim() === '') {
      this.errors.CompanyName = 'Company name is required';
      return false;
    }
    if (this.internship.CompanyName.trim() !== this.internship.CompanyName) {
      this.errors.CompanyName = 'Company name cannot have leading or trailing spaces';
      return false;
    }
    return true;
  }

  validateLocation(): boolean {
    this.errors.Location = '';
    if (!this.internship.Location || this.internship.Location.trim() === '') {
      this.errors.Location = 'Location is required';
      return false;
    }
    if (this.internship.Location.trim() !== this.internship.Location) {
      this.errors.Location = 'Location cannot have leading or trailing spaces';
      return false;
    }
    return true;
  }

  validateDuration(): boolean {
    this.errors.DurationInMonths = '';
    if (!this.internship.DurationInMonths || this.internship.DurationInMonths <= 0) {
      this.errors.DurationInMonths = 'Duration must be greater than 0';
      return false;
    }
    return true;
  }

  validateStipend(): boolean {
    this.errors.Stipend = '';
    if (this.internship.Stipend < 0) {
      this.errors.Stipend = 'Stipend cannot be negative';
      return false;
    }
    return true;
  }

  validateDescription(): boolean {
    this.errors.Description = '';
    if (!this.internship.Description || this.internship.Description.trim() === '') {
      this.errors.Description = 'Description is required';
      return false;
    }
    if (this.internship.Description.trim() !== this.internship.Description) {
      this.errors.Description = 'Description cannot have leading or trailing spaces';
      return false;
    }
    return true;
  }

  validateSkills(): boolean {
    this.errors.SkillsRequired = '';
    if (!this.internship.SkillsRequired || this.internship.SkillsRequired.trim() === '') {
      this.errors.SkillsRequired = 'Skills are required';
      return false;
    }
    if (this.internship.SkillsRequired.trim() !== this.internship.SkillsRequired) {
      this.errors.SkillsRequired = 'Skills cannot have leading or trailing spaces';
      return false;
    }
    return true;
  }

  validateDeadline(): boolean {
    this.errors.ApplicationDeadline = '';
    if (!this.internship.ApplicationDeadline) {
      this.errors.ApplicationDeadline = 'Application deadline is required';
      return false;
    }
    const deadline = new Date(this.internship.ApplicationDeadline);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (deadline < today) {
      this.errors.ApplicationDeadline = 'Deadline cannot be in the past';
      return false;
    }
    return true;
  }

  validateForm(): boolean {
    const isTitleValid = this.validateTitle();
    const isCompanyValid = this.validateCompanyName();
    const isLocationValid = this.validateLocation();
    const isDurationValid = this.validateDuration();
    const isStipendValid = this.validateStipend();
    const isDescriptionValid = this.validateDescription();
    const isSkillsValid = this.validateSkills();
    const isDeadlineValid = this.validateDeadline();

    return isTitleValid && isCompanyValid && isLocationValid && isDurationValid &&
           isStipendValid && isDescriptionValid && isSkillsValid && isDeadlineValid;
  }

  onSubmit(): void {
    if (!this.validateForm()) {
      Swal.fire({
        icon: 'error',
        title: 'Validation Error',
        text: 'Please fix all errors in the form',
        confirmButtonColor: '#667eea'
      });
      return;
    }

    this.isLoading = true;

    this.internshipService.addInternship(this.internship).subscribe(
      (response) => {
        this.isLoading = false;
        Swal.fire({
          icon: 'success',
          title: 'Success!',
          text: 'Internship created successfully',
          confirmButtonColor: '#667eea'
        }).then(() => {
          this.router.navigate(['/admin/internship/view']);
        });
      },
      (error) => {
        this.isLoading = false;
        Swal.fire({
          icon: 'error',
          title: 'Error',
          text: error.error?.message || 'Failed to create internship',
          confirmButtonColor: '#667eea'
        });
      }
    );
  }

  cancel(): void {
    this.router.navigate(['/admin/internship/view']);
  }
}
-------------------------
<div class="create-internship-container fade-in">
    <div class="form-card">
      <div class="form-header">
        <h2><i class="fas fa-plus-circle"></i> Create New Internship</h2>
      </div>
  
      <form (ngSubmit)="onSubmit()" class="internship-form">
        <div class="form-row">
          <div class="form-group">
            <label for="title"><i class="fas fa-heading"></i> Title *</label>
            <input
              type="text"
              id="title"
              name="title"
              [(ngModel)]="internship.Title"
              (blur)="validateTitle()"
              class="form-control"
              [class.error]="errors.Title"
              placeholder="e.g., Software Development Intern"
            />
            <span class="error-message" *ngIf="errors.Title">
              <i class="fas fa-exclamation-circle"></i> {{ errors.Title }}
            </span>
          </div>
  
          <div class="form-group">
            <label for="company"><i class="fas fa-building"></i> Company Name *</label>
            <input
              type="text"
              id="company"
              name="company"
              [(ngModel)]="internship.CompanyName"
              (blur)="validateCompanyName()"
              class="form-control"
              [class.error]="errors.CompanyName"
              placeholder="e.g., Tech Corp"
            />
            <span class="error-message" *ngIf="errors.CompanyName">
              <i class="fas fa-exclamation-circle"></i> {{ errors.CompanyName }}
            </span>
          </div>
        </div>
  
        <div class="form-row">
          <div class="form-group">
            <label for="location"><i class="fas fa-map-marker-alt"></i> Location *</label>
            <input
              type="text"
              id="location"
              name="location"
              [(ngModel)]="internship.Location"
              (blur)="validateLocation()"
              class="form-control"
              [class.error]="errors.Location"
              placeholder="e.g., Bangalore, India"
            />
            <span class="error-message" *ngIf="errors.Location">
              <i class="fas fa-exclamation-circle"></i> {{ errors.Location }}
            </span>
          </div>
  
          <div class="form-group">
            <label for="duration"><i class="fas fa-clock"></i> Duration (Months) *</label>
            <input
              type="number"
              id="duration"
              name="duration"
              [(ngModel)]="internship.DurationInMonths"
              (blur)="validateDuration()"
              class="form-control"
              [class.error]="errors.DurationInMonths"
              placeholder="e.g., 6"
              min="1"
            />
            <span class="error-message" *ngIf="errors.DurationInMonths">
              <i class="fas fa-exclamation-circle"></i> {{ errors.DurationInMonths }}
            </span>
          </div>
        </div>
  
        <div class="form-row">
          <div class="form-group">
            <label for="stipend"><i class="fas fa-rupee-sign"></i> Stipend *</label>
            <input
              type="number"
              id="stipend"
              name="stipend"
              [(ngModel)]="internship.Stipend"
              (blur)="validateStipend()"
              class="form-control"
              [class.error]="errors.Stipend"
              placeholder="e.g., 15000"
              min="0"
            />
            <span class="error-message" *ngIf="errors.Stipend">
              <i class="fas fa-exclamation-circle"></i> {{ errors.Stipend }}
            </span>
          </div>
  
          <div class="form-group">
            <label for="deadline"><i class="fas fa-calendar-alt"></i> Application Deadline *</label>
            <input
              type="date"
              id="deadline"
              name="deadline"
              [(ngModel)]="internship.ApplicationDeadline"
              (blur)="validateDeadline()"
              class="form-control"
              [class.error]="errors.ApplicationDeadline"
            />
            <span class="error-message" *ngIf="errors.ApplicationDeadline">
              <i class="fas fa-exclamation-circle"></i> {{ errors.ApplicationDeadline }}
            </span>
          </div>
        </div>
  
        <div class="form-group">
          <label for="skills"><i class="fas fa-code"></i> Skills Required *</label>
          <input
            type="text"
            id="skills"
            name="skills"
            [(ngModel)]="internship.SkillsRequired"
            (blur)="validateSkills()"
            class="form-control"
            [class.error]="errors.SkillsRequired"
            placeholder="e.g., Java, Spring Boot, MySQL"
          />
          <span class="error-message" *ngIf="errors.SkillsRequired">
            <i class="fas fa-exclamation-circle"></i> {{ errors.SkillsRequired }}
          </span>
        </div>
  
        <div class="form-group">
          <label for="description"><i class="fas fa-align-left"></i> Description *</label>
          <textarea
            id="description"
            name="description"
            [(ngModel)]="internship.Description"
            (blur)="validateDescription()"
            class="form-control"
            [class.error]="errors.Description"
            rows="5"
            placeholder="Enter detailed description of the internship..."
          ></textarea>
          <span class="error-message" *ngIf="errors.Description">
            <i class="fas fa-exclamation-circle"></i> {{ errors.Description }}
          </span>
        </div>
  
        <div class="form-actions">
          <button type="button" class="btn btn-danger" (click)="cancel()">
            <i class="fas fa-times"></i> Cancel
          </button>
          <button type="submit" class="btn btn-primary" [disabled]="isLoading">
            <span *ngIf="!isLoading">
              <i class="fas fa-save"></i> Create Internship
            </span>
            <span *ngIf="isLoading">
              <i class="fas fa-spinner fa-spin"></i> Creating...
            </span>
          </button>
        </div>
      </form>
    </div>
  </div>
  --------------------------------------
/* create-internship.component.css */
form {
  max-width: 600px;
  margin: 60px auto;
  padding: 40px;
  background-color: #ffffff;
  border-radius: 12px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.1);
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

h1 {
  text-align: center;
  margin-bottom: 24px;
  color: #333;
}

div {
  margin-bottom: 20px;
}

label {
  display: block;
  margin-bottom: 8px;
  font-weight: 600;
  color: #555;
}

input[type="text"],
input[type="number"],
input[type="date"],
textarea {
  width: 100%;
  padding: 12px;
  border: 1px solid #ccc;
  border-radius: 8px;
  font-size: 14px;
  transition: border-color 0.3s ease;
}

textarea {
  resize: vertical;
  min-height: 100px;
}

input:focus,
textarea:focus {
  border-color: #0078d4;
  outline: none;
}

small {
  color: #d93025;
  font-size: 13px;
}

button[type="submit"] {
  width: 100%;
  padding: 12px;
  background-color: #0078d4;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 16px;
  cursor: pointer;
  transition: background-color 0.3s ease;
}

button:hover {
  background-color: #005ea2;
}

button:disabled {
  background-color: #a0a0a0;
  cursor: not-allowed;
}

p {
  text-align: center;
  color: #d93025;
  font-weight: 500;
}
-------------------------
error
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';

@Component({
  selector: 'app-error',
  templateUrl: './error.component.html',
  styleUrls: ['./error.component.css']
})
export class ErrorComponent implements OnInit {

  constructor(private router: Router) { }

  ngOnInit(): void {
  }

  goHome(): void {
    this.router.navigate(['/home']);
  }
}
--------------------------
<div class="error-container fade-in">
  <div class="error-content">
    <div class="error-icon bounce">
      <i class="fas fa-exclamation-triangle"></i>
    </div>
    <h1>404</h1>
    <h2>Oops! Page Not Found</h2>
    <p>The page you are looking for might have been removed, had its name changed, or is temporarily unavailable.</p>
    <button class="btn btn-primary" (click)="goHome()">
      <i class="fas fa-home"></i> Go to Home
    </button>
  </div>
</div>
--------------------------
/* Error Component Styles */
.error-container {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 20px;
  }
  
  .error-content {
    text-align: center;
    color: white;
  }
  
  .error-icon {
    font-size: 120px;
    color: #ffd700;
    margin-bottom: 30px;
  }
  
  .error-content h1 {
    font-size: 120px;
    font-weight: 700;
    margin-bottom: 20px;
    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.2);
  }
  
  .error-content h2 {
    font-size: 36px;
    font-weight: 600;
    margin-bottom: 20px;
  }
  
  .error-content p {
    font-size: 18px;
    opacity: 0.9;
    margin-bottom: 40px;
    max-width: 500px;
    margin-left: auto;
    margin-right: auto;
  }
  
  .error-content .btn {
    padding: 15px 40px;
    font-size: 18px;
  }
  
--------------------------
homecomponent.ts
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit {
  isLoggedIn: boolean = false;
  userRole: string = '';

  constructor(
    private authService: AuthService,
    private router: Router
  ) { }

  ngOnInit(): void {
    this.isLoggedIn = this.authService.isLoggedIn();
    this.userRole = this.authService.getUserRole();
  }

  navigateToLogin(): void {
    this.router.navigate(['/login']);
  }

  navigateToRegister(): void {
    this.router.navigate(['/register']);
  }

  navigateToDashboard(): void {
    if (this.userRole === 'Admin') {
      this.router.navigate(['/admin/internship/view']);
    } else if (this.userRole === 'User') {
      this.router.navigate(['/user/internships']);
    }
  }
}
---------------------------
<div class="home-container fade-in">
  <div class="hero-section">
    <div class="hero-content slide-in-left">
      <h1 class="hero-title">
        <i class="fas fa-briefcase"></i>
        Welcome to Internship Application System
      </h1>
      <p class="hero-subtitle">
        Find your dream internship and kickstart your career journey
      </p>
      
      <div class="hero-buttons" *ngIf="!isLoggedIn">
        <button class="btn btn-primary" (click)="navigateToLogin()">
          <i class="fas fa-sign-in-alt"></i> Login
        </button>
        <button class="btn btn-success" (click)="navigateToRegister()">
          <i class="fas fa-user-plus"></i> Register
        </button>
      </div>
      
      <div class="hero-buttons" *ngIf="isLoggedIn">
        <button class="btn btn-primary" (click)="navigateToDashboard()">
          <i class="fas fa-tachometer-alt"></i> Go to Dashboard
        </button>
      </div>
    </div>
    
    <div class="hero-image slide-in-right">
      <div class="floating-card">
        <i class="fas fa-graduation-cap"></i>
        <h3>Learn & Grow</h3>
      </div>
      <div class="floating-card delay-1">
        <i class="fas fa-rocket"></i>
        <h3>Launch Career</h3>
      </div>
      <div class="floating-card delay-2">
        <i class="fas fa-trophy"></i>
        <h3>Achieve Success</h3>
      </div>
    </div>
  </div>
  
  <div class="features-section">
    <h2 class="section-title fade-in">Why Choose Us?</h2>
    <div class="features-grid">
      <div class="feature-card fade-in">
        <div class="feature-icon">
          <i class="fas fa-search"></i>
        </div>
        <h3>Find Opportunities</h3>
        <p>Browse through hundreds of internship opportunities from top companies</p>
      </div>
      
      <div class="feature-card fade-in">
        <div class="feature-icon">
          <i class="fas fa-file-alt"></i>
        </div>
        <h3>Easy Application</h3>
        <p>Apply to internships with just a few clicks and track your applications</p>
      </div>
      
      <div class="feature-card fade-in">
        <div class="feature-icon">
          <i class="fas fa-comments"></i>
        </div>
        <h3>Get Feedback</h3>
        <p>Receive valuable feedback to improve your profile and applications</p>
      </div>
      
      <div class="feature-card fade-in">
        <div class="feature-icon">
          <i class="fas fa-chart-line"></i>
        </div>
        <h3>Track Progress</h3>
        <p>Monitor your application status and manage your internship journey</p>
      </div>
    </div>
  </div>
</div>
---------------------
/* Home Component Styles with Beautiful Animations */
.home-container {
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.hero-section {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 50px;
  padding: 100px 50px;
  max-width: 1400px;
  margin: 0 auto;
  align-items: center;
}

.hero-content {
  color: white;
}

.hero-title {
  font-size: 48px;
  font-weight: 700;
  margin-bottom: 20px;
  line-height: 1.2;
}

.hero-title i {
  color: #ffd700;
  margin-right: 15px;
}

.hero-subtitle {
  font-size: 20px;
  margin-bottom: 40px;
  opacity: 0.9;
}

.hero-buttons {
  display: flex;
  gap: 20px;
}

.hero-buttons .btn {
  padding: 15px 40px;
  font-size: 18px;
}

.hero-buttons .btn i {
  margin-right: 10px;
}

.hero-image {
  position: relative;
  height: 400px;
}

.floating-card {
  position: absolute;
  background: white;
  padding: 30px;
  border-radius: 20px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
  text-align: center;
  animation: float 3s ease-in-out infinite;
}

.floating-card i {
  font-size: 40px;
  color: #667eea;
  margin-bottom: 15px;
}

.floating-card h3 {
  font-size: 18px;
  color: #333;
  margin: 0;
}

.floating-card:nth-child(1) {
  top: 0;
  left: 0;
  width: 200px;
}

.floating-card:nth-child(2) {
  top: 150px;
  right: 50px;
  width: 180px;
  animation-delay: 1s;
}

.floating-card:nth-child(3) {
  bottom: 0;
  left: 100px;
  width: 190px;
  animation-delay: 2s;
}

@keyframes float {
  0%, 100% {
    transform: translateY(0px);
  }
  50% {
    transform: translateY(-20px);
  }
}

.features-section {
  background: white;
  padding: 80px 50px;
}

.section-title {
  text-align: center;
  font-size: 36px;
  font-weight: 700;
  color: #333;
  margin-bottom: 50px;
}

.features-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 30px;
  max-width: 1200px;
  margin: 0 auto;
}

.feature-card {
  background: white;
  padding: 40px;
  border-radius: 15px;
  box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
  text-align: center;
  transition: all 0.3s ease;
}

.feature-card:hover {
  transform: translateY(-10px);
  box-shadow: 0 15px 40px rgba(0, 0, 0, 0.2);
}

.feature-icon {
  width: 80px;
  height: 80px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 20px;
}

.feature-icon i {
  font-size: 32px;
  color: white;
}

.feature-card h3 {
  font-size: 22px;
  font-weight: 600;
  color: #333;
  margin-bottom: 15px;
}

.feature-card p {
  font-size: 14px;
  color: #666;
  line-height: 1.6;
}

/* Responsive */
@media (max-width: 768px) {
  .hero-section {
    grid-template-columns: 1fr;
    padding: 50px 20px;
  }
  
  .hero-title {
    font-size: 32px;
  }
  
  .hero-subtitle {
    font-size: 16px;
  }
  
  .hero-image {
    display: none;
  }
  
  .features-grid {
    grid-template-columns: 1fr;
  }
}
---------------------------
internshipformcomponent
import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { InternshipApplicationService } from 'src/app/services/internshipapplication.service';
import { InternshipService } from '../../services/internship.service';
import { AuthService } from '../../services/auth.service';
import { InternshipApplication } from '../../models/internshipapplication.model';
import { Internship } from '../../models/internship.model';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-internshipform',
  templateUrl: './internshipform.component.html',
  styleUrls: ['./internshipform.component.css']
})
export class InternshipformComponent implements OnInit {
  internshipId: number = 0;
  internship: Internship | null = null;
  
  application: InternshipApplication = {
    UserId: 0,
    InternshipId: 0,
    UniversityName: '',
    DegreeProgram: '',
    Resume: '',
    LinkedInProfile: '',
    ApplicationStatus: 'Pending',
    ApplicationDate: new Date().toISOString()
  };

  errors: any = {
    UniversityName: '',
    DegreeProgram: '',
    Resume: '',
    LinkedInProfile: ''
  };

  isLoading: boolean = false;

  constructor(
    private applicationService: InternshipApplicationService,
    private internshipService: InternshipService,
    private authService: AuthService,
    private router: Router,
    private route: ActivatedRoute
  ) { }

  ngOnInit(): void {
    this.internshipId = parseInt(this.route.snapshot.paramMap.get('id') || '0');
    this.application.UserId = this.authService.getUserId();
    this.application.InternshipId = this.internshipId;
    
    if (this.internshipId) {
      this.loadInternship();
    }
  }

  loadInternship(): void {
    this.internshipService.getInternshipById(this.internshipId).subscribe(
      (data) => {
        this.internship = data;
      },
      (error) => {
        Swal.fire({
          icon: 'error',
          title: 'Error',
          text: 'Failed to load internship details',
          confirmButtonColor: '#667eea'
        });
      }
    );
  }

  validateUniversityName(): boolean {
    this.errors.UniversityName = '';
    if (!this.application.UniversityName || this.application.UniversityName.trim() === '') {
      this.errors.UniversityName = 'University name is required';
      return false;
    }
    if (this.application.UniversityName.trim() !== this.application.UniversityName) {
      this.errors.UniversityName = 'University name cannot have leading or trailing spaces';
      return false;
    }
    return true;
  }

  validateDegreeProgram(): boolean {
    this.errors.DegreeProgram = '';
    if (!this.application.DegreeProgram || this.application.DegreeProgram.trim() === '') {
      this.errors.DegreeProgram = 'Degree program is required';
      return false;
    }
    if (this.application.DegreeProgram.trim() !== this.application.DegreeProgram) {
      this.errors.DegreeProgram = 'Degree program cannot have leading or trailing spaces';
      return false;
    }
    return true;
  }

  validateResume(): boolean {
    this.errors.Resume = '';
    if (!this.application.Resume || this.application.Resume.trim() === '') {
      this.errors.Resume = 'Resume link is required';
      return false;
    }
    if (this.application.Resume.trim() !== this.application.Resume) {
      this.errors.Resume = 'Resume link cannot have leading or trailing spaces';
      return false;
    }
    return true;
  }

  validateLinkedIn(): boolean {
    this.errors.LinkedInProfile = '';
    if (this.application.LinkedInProfile && this.application.LinkedInProfile.trim() !== this.application.LinkedInProfile) {
      this.errors.LinkedInProfile = 'LinkedIn profile cannot have leading or trailing spaces';
      return false;
    }
    return true;
  }

  validateForm(): boolean {
    const isUniversityValid = this.validateUniversityName();
    const isDegreeValid = this.validateDegreeProgram();
    const isResumeValid = this.validateResume();
    const isLinkedInValid = this.validateLinkedIn();

    return isUniversityValid && isDegreeValid && isResumeValid && isLinkedInValid;
  }

  onSubmit(): void {
    if (!this.validateForm()) {
      Swal.fire({
        icon: 'error',
        title: 'Validation Error',
        text: 'Please fix all errors in the form',
        confirmButtonColor: '#667eea'
      });
      return;
    }

    this.isLoading = true;

    this.applicationService.addInternshipApplication(this.application).subscribe(
      (response) => {
        this.isLoading = false;
        Swal.fire({
          icon: 'success',
          title: 'Success!',
          text: 'Application submitted successfully',
          confirmButtonColor: '#667eea'
        }).then(() => {
          this.router.navigate(['/user/applied-internships']);
        });
      },
      (error) => {
        this.isLoading = false;
        Swal.fire({
          icon: 'error',
          title: 'Error',
          text: error.error?.message || 'Failed to submit application',
          confirmButtonColor: '#667eea'
        });
      }
    );
  }

  
}
---------------------
<div class="internship-form-container fade-in">
    <div class="form-card">
      <div class="form-header">
        <h2><i class="fas fa-paper-plane"></i> Apply for Internship</h2>
        <div class="internship-info" *ngIf="internship">
          <h3>{{ internship.Title }}</h3>
          <p><i class="fas fa-building"></i> {{ internship.CompanyName }} | <i class="fas fa-map-marker-alt"></i> {{ internship.Location }}</p>
        </div>
      </div>
  
      <form (ngSubmit)="onSubmit()" class="application-form">
        <div class="form-group">
          <label for="university"><i class="fas fa-university"></i> University Name *</label>
          <input
            type="text"
            id="university"
            name="university"
            [(ngModel)]="application.UniversityName"
            (blur)="validateUniversityName()"
            class="form-control"
            [class.error]="errors.UniversityName"
            placeholder="Enter your university name"
          />
          <span class="error-message" *ngIf="errors.UniversityName">
            <i class="fas fa-exclamation-circle"></i> {{ errors.UniversityName }}
          </span>
        </div>
  
        <div class="form-group">
          <label for="degree"><i class="fas fa-graduation-cap"></i> Degree Program *</label>
          <input
            type="text"
            id="degree"
            name="degree"
            [(ngModel)]="application.DegreeProgram"
            (blur)="validateDegreeProgram()"
            class="form-control"
            [class.error]="errors.DegreeProgram"
            placeholder="e.g., B.Tech Computer Science"
          />
          <span class="error-message" *ngIf="errors.DegreeProgram">
            <i class="fas fa-exclamation-circle"></i> {{ errors.DegreeProgram }}
          </span>
        </div>
  
        <div class="form-group">
          <label for="resume"><i class="fas fa-file-pdf"></i> Resume Link *</label>
          <input
            type="text"
            id="resume"
            name="resume"
            [(ngModel)]="application.Resume"
            (blur)="validateResume()"
            class="form-control"
            [class.error]="errors.Resume"
            placeholder="https://drive.google.com/..."
          />
          <span class="error-message" *ngIf="errors.Resume">
            <i class="fas fa-exclamation-circle"></i> {{ errors.Resume }}
          </span>
        </div>
  
        <div class="form-group">
          <label for="linkedin"><i class="fab fa-linkedin"></i> LinkedIn Profile (Optional)</label>
          <input
            type="text"
            id="linkedin"
            name="linkedin"
            [(ngModel)]="application.LinkedInProfile"
            (blur)="validateLinkedIn()"
            class="form-control"
            [class.error]="errors.LinkedInProfile"
            placeholder="https://linkedin.com/in/..."
          />
          <span class="error-message" *ngIf="errors.LinkedInProfile">
            <i class="fas fa-exclamation-circle"></i> {{ errors.LinkedInProfile }}
          </span>
        </div>
  
        <div class="form-actions">
          
          <button type="submit" class="btn btn-primary" [disabled]="isLoading">
            <span *ngIf="!isLoading">
              <i class="fas fa-paper-plane"></i> Submit Application
            </span>
            <span *ngIf="isLoading">
              <i class="fas fa-spinner fa-spin"></i> Submitting...
            </span>
          </button>
        </div>
      </form>
    </div>
  </div>
  ----------------------
/* Internship Form Component Styles */
.internship-form-container {
    padding: 20px;
    max-width: 800px;
    margin: 0 auto;
  }
  
  .form-card {
    background: white;
    border-radius: 15px;
    padding: 40px;
    box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
  }
  
  .form-header {
    text-align: center;
    margin-bottom: 40px;
    padding-bottom: 20px;
    border-bottom: 2px solid #f0f0f0;
  }
  
  .form-header h2 {
    font-size: 28px;
    font-weight: 700;
    color: #333;
    margin: 0 0 20px 0;
  }
  
  .form-header h2 i {
    color: #11998e;
    margin-right: 10px;
  }
  
  .internship-info {
    background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
    padding: 20px;
    border-radius: 10px;
    color: white;
    margin-top: 20px;
  }
  
  .internship-info h3 {
    font-size: 22px;
    margin: 0 0 10px 0;
  }
  
  .internship-info p {
    margin: 0;
    font-size: 16px;
    opacity: 0.9;
  }
  
  .internship-info i {
    margin-right: 5px;
  }
  
  .application-form {
    max-width: 700px;
    margin: 0 auto;
  }
  
  .form-group label i {
    margin-right: 8px;
    color: #11998e;
  }
  
  .form-actions {
    display: flex;
    justify-content: flex-end;
    gap: 15px;
    margin-top: 30px;
    padding-top: 20px;
    border-top: 2px solid #f0f0f0;
  }
  
  .form-actions .btn {
    padding: 12px 30px;
    font-size: 16px;
  }
  
  /* Responsive */
  @media (max-width: 768px) {
    .form-card {
      padding: 20px;
    }
    
    .form-actions {
      flex-direction: column;
    }
    
    .form-actions .btn {
      width: 100%;
    }
  }
  -----------------------
internshippiechartcomponent
import { Component, OnInit } from '@angular/core';
import { InternshipApplicationService } from 'src/app/services/internshipapplication.service';

@Component({
  selector: 'app-internshippiechart',
  templateUrl: './internshippiechart.component.html',
  styleUrls: ['./internshippiechart.component.css']
})
export class InternshippiechartComponent implements OnInit {
  totalApplications: number = 0;
  approvedApplications: number = 0;
  rejectedApplications: number = 0;
  pendingApplications: number = 0;
  isLoading: boolean = false;

  constructor(
    private applicationService: InternshipApplicationService
  ) { }

  ngOnInit(): void {
    this.loadStatistics();
  }

  loadStatistics(): void {
    this.isLoading = true;
    this.applicationService.getAllInternshipApplications().subscribe(
      (data) => {
        this.totalApplications = data.length;
        this.approvedApplications = data.filter(app => app.ApplicationStatus === 'Approved').length;
        this.rejectedApplications = data.filter(app => app.ApplicationStatus === 'Rejected').length;
        this.pendingApplications = data.filter(app => app.ApplicationStatus === 'Pending').length;
        this.isLoading = false;
      },
      (error) => {
        this.isLoading = false;
      }
    );
  }

  getApprovedPercentage(): number {
    return this.totalApplications > 0 ? (this.approvedApplications / this.totalApplications) * 100 : 0;
  }

  getRejectedPercentage(): number {
    return this.totalApplications > 0 ? (this.rejectedApplications / this.totalApplications) * 100 : 0;
  }

  getPendingPercentage(): number {
    return this.totalApplications > 0 ? (this.pendingApplications / this.totalApplications) * 100 : 0;
  }
}
--------------------------------------
<div class="piechart-container fade-in">
    <div class="page-header">
        <h2><i class="fas fa-chart-pie"></i> Application Statistics</h2>
    </div>

    <div class="stats-grid" *ngIf="!isLoading">
        <div class="stat-card approved">
            <div class="stat-icon">
                <i class="fas fa-check-circle"></i>
            </div>
            <div class="stat-info">
                <h3>{{ approvedApplications }}</h3>
                <p>Approved</p>
                <span class="percentage">{{ getApprovedPercentage().toFixed(1) }}%</span>
            </div>
        </div>

        <div class="stat-card rejected">
            <div class="stat-icon">
                <i class="fas fa-times-circle"></i>
            </div>
            <div class="stat-info">
                <h3>{{ rejectedApplications }}</h3>
                <p>Rejected</p>
                <span class="percentage">{{ getRejectedPercentage().toFixed(1) }}%</span>
            </div>
        </div>

        <div class="stat-card pending">
            <div class="stat-icon">
                <i class="fas fa-clock"></i>
            </div>
            <div class="stat-info">
                <h3>{{ pendingApplications }}</h3>
                <p>Pending</p>
                <span class="percentage">{{ getPendingPercentage().toFixed(1) }}%</span>
            </div>
        </div>

        <div class="stat-card total">
            <div class="stat-icon">
                <i class="fas fa-list"></i>
            </div>
            <div class="stat-info">
                <h3>{{ totalApplications }}</h3>
                <p>Total Applications</p>
                <span class="percentage">100%</span>
            </div>
        </div>
    </div>

    <div class="loading-container" *ngIf="isLoading">
        <div class="spinner"></div>
        <p>Loading statistics...</p>
    </div>
</div>
------------------------------
.piechart-container {
    padding: 20px;
}

.page-header {
    margin-bottom: 30px;
    padding: 20px;
    background: white;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.page-header h2 {
    font-size: 28px;
    font-weight: 700;
    color: #333;
    margin: 0;
}

.page-header h2 i {
    color: #667eea;
    margin-right: 10px;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 30px;
}

.stat-card {
    background: white;
    border-radius: 15px;
    padding: 30px;
    box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
    display: flex;
    align-items: center;
    gap: 20px;
    transition: all 0.3s ease;
    animation: fadeIn 0.6s ease-in-out;
}

.stat-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.15);
}

.stat-icon {
    width: 80px;
    height: 80px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 36px;
    color: white;
}

.stat-card.approved .stat-icon {
    background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
}

.stat-card.rejected .stat-icon {
    background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
}

.stat-card.pending .stat-icon {
    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
}

.stat-card.total .stat-icon {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.stat-info {
    flex: 1;
}

.stat-info h3 {
    font-size: 48px;
    font-weight: 700;
    margin: 0 0 5px 0;
    color: #333;
}

.stat-info p {
    font-size: 18px;
    color: #666;
    margin: 0 0 10px 0;
}

.stat-info .percentage {
    font-size: 16px;
    font-weight: 600;
    color: #667eea;
}

.loading-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 100px 20px;
    background: white;
    border-radius: 10px;
}

.loading-container p {
    margin-top: 20px;
    font-size: 18px;
    color: #667eea;
}

/* Responsive */
@media (max-width: 768px) {
    .stats-grid {
        grid-template-columns: 1fr;
    }
}
------------------------------
logincomponent
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { Login } from '../../models/login.model';
import Swal from 'sweetalert2';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { environment } from 'src/environments/environment';


@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  aFormGroup: FormGroup;
  loginData: Login = {
    Email: '',
    Password: ''
  };

  errors: any = {
    Email: '',
    Password: ''
  };

  isLoading: boolean = false;
  siteKey=environment.siteKey;

  constructor(
    private authService: AuthService,
    private router: Router,
    private formBuilder: FormBuilder
  ) { }

  ngOnInit(): void {
    // Redirect if already logged in
    if (this.authService.isLoggedIn()) {
      const role = this.authService.getUserRole();
      if (role === 'Admin') {
        this.router.navigate(['/admin/home']);
      } else {
        this.router.navigate(['/user/home']);
      }
    }

    this.aFormGroup = this.formBuilder.group({
      recaptcha: ['', Validators.required]
    });
  }

  validateEmail(): boolean {
    this.errors.Email = '';

    if (!this.loginData.Email || this.loginData.Email.trim() === '') {
      this.errors.Email = 'Email is required';
      return false;
    }

    if (this.loginData.Email.trim() !== this.loginData.Email) {
      this.errors.Email = 'Email cannot have leading or trailing spaces';
      return false;
    }

    const emailPattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    if (!emailPattern.test(this.loginData.Email)) {
      this.errors.Email = 'Please enter a valid email address';
      return false;
    }

    return true;
  }

  validatePassword(): boolean {
    this.errors.Password = '';

    if (!this.loginData.Password || this.loginData.Password.trim() === '') {
      this.errors.Password = 'Password is required';
      return false;
    }

    if (this.loginData.Password.trim() !== this.loginData.Password) {
      this.errors.Password = 'Password cannot have leading or trailing spaces';
      return false;
    }

    if (this.loginData.Password.length < 6) {
      this.errors.Password = 'Password must be at least 6 characters';
      return false;
    }

    return true;
  }

  validateForm(): boolean {
    const isEmailValid = this.validateEmail();
    const isPasswordValid = this.validatePassword();

    return isEmailValid && isPasswordValid;
  }

  onSubmit(): void {
    if (!this.validateForm()) {
      Swal.fire({
        icon: 'error',
        title: 'Validation Error',
        text: 'Please fix the errors in the form',
        confirmButtonColor: '#667eea'
      });
      return;
    }

    this.isLoading = true;

    this.authService.login(this.loginData).subscribe(
      (response) => {
        this.isLoading = false;

        Swal.fire({
          icon: 'success',
          title: 'Login Successful!',
          text: 'Welcome back!',
          timer: 2000,
          showConfirmButton: false
        });

        // Navigate based on role
        const role = this.authService.getUserRole();
        setTimeout(() => {
          if (role === 'Admin') {
            this.router.navigate(['/admin/internship/view']);
          } else {
            this.router.navigate(['/user/internships']);
          }
        }, 2000);
      },
      (error) => {
        this.isLoading = false;

        Swal.fire({
          icon: 'error',
          title: 'Login Failed',
          text: error.error?.message || 'Invalid email or password',
          confirmButtonColor: '#667eea'
        });
      }
    );
  }

  navigateToRegister(): void {
    this.router.navigate(['/register']);
  }
}
-----------------
<div class="login-container fade-in">
  <div class="login-card slide-in-left">
    <div class="login-header">
      <i class="fas fa-sign-in-alt"></i>
      <h2>Welcome Back!</h2>
      <p>Login to continue your journey</p>
    </div>

    <form (ngSubmit)="onSubmit()" class="login-form">
      <div class="form-group">
        <label for="email">
          <i class="fas fa-envelope"></i> Email Address
        </label>
        <input type="email" id="email" name="email" [(ngModel)]="loginData.Email" (blur)="validateEmail()"
          class="form-control" [class.error]="errors.Email" placeholder="Enter your email" autocomplete="email" />
        <span class="error-message" *ngIf="errors.Email">
          <i class="fas fa-exclamation-circle"></i> {{ errors.Email }}
        </span>
      </div>

      <div class="form-group">
        <label for="password">
          <i class="fas fa-lock"></i> Password
        </label>
        <input type="password" id="password" name="password" [(ngModel)]="loginData.Password"
          (blur)="validatePassword()" class="form-control" [class.error]="errors.Password"
          placeholder="Enter your password" autocomplete="current-password" />
        <span class="error-message" *ngIf="errors.Password">
          <i class="fas fa-exclamation-circle"></i> {{ errors.Password }}
        </span>
      </div>

      <div>
        <form [formGroup]="aFormGroup">
          <ngx-recaptcha2 #captchaElem
            [siteKey]="siteKey"
            formControlName="recaptcha">
          </ngx-recaptcha2>
        </form>
      </div>

      <button type="submit" class="btn btn-primary btn-block" [disabled]="isLoading">
        <span *ngIf="!isLoading">
          <i class="fas fa-sign-in-alt"></i> Login
        </span>
        <span *ngIf="isLoading">
          <i class="fas fa-spinner fa-spin"></i> Logging in...
        </span>
      </button>
    </form>

    <div class="login-footer">
      <p>Don't have an account?</p>
      <button class="btn btn-success" (click)="navigateToRegister()">
        <i class="fas fa-user-plus"></i> Register Now
      </button>
    </div>
  </div>

  <div class="login-illustration slide-in-right">
    <div class="illustration-content">
      <i class="fas fa-briefcase"></i>
      <h3>Find Your Dream Internship</h3>
      <p>Join thousands of students who have found their perfect internship opportunity</p>
    </div>
  </div>
</div>
------------------------
.login-container {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 1fr 1fr;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.login-card {
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 50px;
  background: white;
}

.login-header {
  text-align: center;
  margin-bottom: 40px;
}

.login-header i {
  font-size: 60px;
  color: #667eea;
  margin-bottom: 20px;
}

.login-header h2 {
  font-size: 32px;
  font-weight: 700;
  color: #333;
  margin-bottom: 10px;
}

.login-header p {
  font-size: 16px;
  color: #666;
}

.login-form {
  max-width: 450px;
  margin: 0 auto;
  width: 100%;
}

.form-group label i {
  margin-right: 8px;
  color: #667eea;
}

.btn-block {
  width: 100%;
  margin-top: 10px;
}

.login-footer {
  text-align: center;
  margin-top: 30px;
}

.login-footer p {
  color: #666;
  margin-bottom: 15px;
}

.login-illustration {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 50px;
}

.illustration-content {
  text-align: center;
  color: white;
}

.illustration-content i {
  font-size: 120px;
  margin-bottom: 30px;
  animation: bounce 2s ease-in-out infinite;
}

.illustration-content h3 {
  font-size: 36px;
  font-weight: 700;
  margin-bottom: 20px;
}

.illustration-content p {
  font-size: 18px;
  opacity: 0.9;
  max-width: 400px;
  margin: 0 auto;
}

/* Responsive */
@media (max-width: 968px) {
  .login-container {
    grid-template-columns: 1fr;
  }

  .login-illustration {
    display: none;
  }

  .login-card {
    padding: 30px 20px;
  }
}
-------------------
navbarcomponent
import { Component } from '@angular/core';
import { AuthService } from 'src/app/services/auth.service';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent { 

  isLoggedIn: boolean = false;
  public aService: AuthService;

  constructor(private authService: AuthService){
    this.isLoggedIn = this.authService.isLoggedIn(); 
    this.aService = authService;
  }
}
---------------------
<div class="navbar" *ngIf="!isLoggedIn">
  <h2 class="logo">Internship Application System</h2>
  <nav class="nav-links">
      <a routerLink="/register">Register</a>
      <a routerLink="/login">Login</a>
  </nav>
</div>
--------------------------
/* Styling for the navbar container with frosted glass effect */
.navbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 15px 40px;
  position: sticky;
  top: 0;
  z-index: 10;
 
  /* Apply semi-transparent background and the blur effect */
  background-color: rgba(255, 255, 255, 0.4); /* Less opaque than the form-card for a lighter feel */
  -webkit-backdrop-filter: blur(8px); /* For Safari */
  backdrop-filter: blur(8px); /* Frosted glass effect */
 
  border-bottom: 1px solid rgba(38, 65, 67, 0.2); /* Thinner, softer border */
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); /* Lighter shadow */
}
 
/* Styling for the logo text */
.logo {
  color: #264143;
  font-weight: 900;
  font-size: 1.2em;
  margin: 0;
  text-shadow: 1px 1px 1px rgba(0, 0, 0, 0.1); /* Subtle text shadow for better readability */
}
 
/* Styling for the navigation links container */
.nav-links {
  display: flex;
  gap: 20px;
}
 
/* Styling for the individual navigation links */
.nav-links a {
  color: #264143;
  text-decoration: none;
  font-weight: 800;
  padding: 8px 12px;
  border-radius: 4px;
  transition: transform 0.1s ease, box-shadow 0.1s ease, color 0.1s ease;
  position: relative;
}
 
/* Hover effect for navigation links to match input focus */
.nav-links a:hover {
  color: white; /* Highlight color on hover */
  transform: translateY(-2px);
  box-shadow: 1px 2px 0px 0px whitesmoke;
  border-bottom-color: transparent; /* Disable the bottom border for a cleaner hover */
}
--------------------------
registrationcomponent
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { User } from '../../models/user.model';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-registration',
  templateUrl: './registration.component.html',
  styleUrls: ['./registration.component.css']
})
export class RegistrationComponent implements OnInit {
  userData: User = {
    Username: '',
    Email: '',
    MobileNumber: '',
    Password: '',
    UserRole: 'User',
    SecretKey: ''
  };

  confirmPassword: string = '';

  errors: any = {
    Email: '',
    Password: '',
    ConfirmPassword: '',
    Username: '',
    MobileNumber: '',
    SecretKey: ''
  };

  isLoading: boolean = false;
  showSecretKey: boolean = false;

  constructor(
    private authService: AuthService,
    private router: Router
  ) { }

  ngOnInit(): void {
    if (this.authService.isLoggedIn()) {
      const role = this.authService.getUserRole();
      if (role === 'Admin') {
        this.router.navigate(['/admin/internship/view']);
      } else {
        this.router.navigate(['/user/internships']);
      }
    }
  }

  onRoleChange(): void {
    this.showSecretKey = this.userData.UserRole === 'Admin';
    if (!this.showSecretKey) {
      this.userData.SecretKey = '';
      this.errors.SecretKey = '';
    }
  }

  validateEmail(): boolean {
    this.errors.Email = '';
    
    if (!this.userData.Email || this.userData.Email.trim() === '') {
      this.errors.Email = 'Email is required';
      return false;
    }
    
    if (this.userData.Email.trim() !== this.userData.Email) {
      this.errors.Email = 'Email cannot have leading or trailing spaces';
      return false;
    }
    
    const emailPattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    if (!emailPattern.test(this.userData.Email)) {
      this.errors.Email = 'Please enter a valid email address';
      return false;
    }
    
    return true;
  }

  validateUsername(): boolean {
    this.errors.Username = '';
    
    if (!this.userData.Username || this.userData.Username.trim() === '') {
      this.errors.Username = 'Username is required';
      return false;
    }
    
    if (this.userData.Username.trim() !== this.userData.Username) {
      this.errors.Username = 'Username cannot have leading or trailing spaces';
      return false;
    }
    
    if (this.userData.Username.length < 3) {
      this.errors.Username = 'Username must be at least 3 characters';
      return false;
    }
    
    return true;
  }

  validateMobileNumber(): boolean {
    this.errors.MobileNumber = '';
    
    if (!this.userData.MobileNumber || this.userData.MobileNumber.trim() === '') {
      this.errors.MobileNumber = 'Mobile number is required';
      return false;
    }
    
    if (this.userData.MobileNumber.trim() !== this.userData.MobileNumber) {
      this.errors.MobileNumber = 'Mobile number cannot have leading or trailing spaces';
      return false;
    }
    
    const mobilePattern = /^[0-9]{10}$/;
    if (!mobilePattern.test(this.userData.MobileNumber)) {
      this.errors.MobileNumber = 'Mobile number must be exactly 10 digits';
      return false;
    }
    
    return true;
  }

  validatePassword(): boolean {
    this.errors.Password = '';
    
    if (!this.userData.Password || this.userData.Password.trim() === '') {
      this.errors.Password = 'Password is required';
      return false;
    }
    
    if (this.userData.Password.trim() !== this.userData.Password) {
      this.errors.Password = 'Password cannot have leading or trailing spaces';
      return false;
    }
    
    if (this.userData.Password.length < 6) {
      this.errors.Password = 'Password must be at least 6 characters';
      return false;
    }
    
    // Check for at least one uppercase, one lowercase, one digit, and one special character
    const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
    if (!passwordPattern.test(this.userData.Password)) {
      this.errors.Password = 'Password must contain uppercase, lowercase, digit, and special character';
      return false;
    }
    
    return true;
  }

  validateConfirmPassword(): boolean {
    this.errors.ConfirmPassword = '';
    
    if (!this.confirmPassword || this.confirmPassword.trim() === '') {
      this.errors.ConfirmPassword = 'Please confirm your password';
      return false;
    }
    
    if (this.confirmPassword !== this.userData.Password) {
      this.errors.ConfirmPassword = 'Passwords do not match';
      return false;
    }
    
    return true;
  }

  validateSecretKey(): boolean {
    this.errors.SecretKey = '';
    
    if (this.userData.UserRole === 'Admin') {
      if (!this.userData.SecretKey || this.userData.SecretKey.trim() === '') {
        this.errors.SecretKey = 'Secret key is required for admin registration';
        return false;
      }
      
      if (this.userData.SecretKey.trim() !== this.userData.SecretKey) {
        this.errors.SecretKey = 'Secret key cannot have leading or trailing spaces';
        return false;
      }
    }
    
    return true;
  }

  validateForm(): boolean {
    const isEmailValid = this.validateEmail();
    const isUsernameValid = this.validateUsername();
    const isMobileValid = this.validateMobileNumber();
    const isPasswordValid = this.validatePassword();
    const isConfirmPasswordValid = this.validateConfirmPassword();
    const isSecretKeyValid = this.validateSecretKey();
    
    return isEmailValid && isUsernameValid && isMobileValid && 
           isPasswordValid && isConfirmPasswordValid && isSecretKeyValid;
  }

  onSubmit(): void {
    if (!this.validateForm()) {
      Swal.fire({
        icon: 'error',
        title: 'Validation Error',
        text: 'Please fix all errors in the form',
        confirmButtonColor: '#667eea'
      });
      return;
    }

    this.isLoading = true;

    this.authService.register(this.userData).subscribe(
      (response) => {
        this.isLoading = false;
        
        Swal.fire({
          icon: 'success',
          title: 'Registration Successful!',
          text: 'Your account has been created. Please login to continue.',
          confirmButtonColor: '#667eea'
        }).then(() => {
          this.router.navigate(['/login']);
        });
      },
      (error) => {
        this.isLoading = false;
        
        Swal.fire({
          icon: 'error',
          title: 'Registration Failed',
          text: error.error?.message || 'An error occurred during registration',
          confirmButtonColor: '#667eea'
        });
      }
    );
  }

  navigateToLogin(): void {
    this.router.navigate(['/login']);
  }
}

----------------------
<div class="registration-container fade-in">
  <div class="registration-card slide-in-left">
    <div class="registration-header">
      <i class="fas fa-user-plus"></i>
      <h2>Create Account</h2>
      <p>Join us and start your internship journey</p>
    </div>

    <form (ngSubmit)="onSubmit()" class="registration-form">
      <div class="form-row">
        <div class="form-group">
          <label for="username">
            <i class="fas fa-user"></i> Username
          </label>
          <input
            type="text"
            id="username"
            name="username"
            [(ngModel)]="userData.Username"
            (blur)="validateUsername()"
            class="form-control"
            [class.error]="errors.Username"
            placeholder="Enter your username"
          />
          <span class="error-message" *ngIf="errors.Username">
            <i class="fas fa-exclamation-circle"></i> {{ errors.Username }}
          </span>
        </div>

        <div class="form-group">
          <label for="email">
            <i class="fas fa-envelope"></i> Email
          </label>
          <input
            type="email"
            id="email"
            name="email"
            [(ngModel)]="userData.Email"
            (blur)="validateEmail()"
            class="form-control"
            [class.error]="errors.Email"
            placeholder="Enter your email"
          />
          <span class="error-message" *ngIf="errors.Email">
            <i class="fas fa-exclamation-circle"></i> {{ errors.Email }}
          </span>
        </div>
      </div>

      <div class="form-group">
        <label for="mobile">
          <i class="fas fa-phone"></i> Mobile Number
        </label>
        <input
          type="text"
          id="mobile"
          name="mobile"
          [(ngModel)]="userData.MobileNumber"
          (blur)="validateMobileNumber()"
          class="form-control"
          [class.error]="errors.MobileNumber"
          placeholder="Enter 10-digit mobile number"
          maxlength="10"
        />
        <span class="error-message" *ngIf="errors.MobileNumber">
          <i class="fas fa-exclamation-circle"></i> {{ errors.MobileNumber }}
        </span>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label for="password">
            <i class="fas fa-lock"></i> Password
          </label>
          <input
            type="password"
            id="password"
            name="password"
            [(ngModel)]="userData.Password"
            (blur)="validatePassword()"
            class="form-control"
            [class.error]="errors.Password"
            placeholder="Enter password"
          />
          <span class="error-message" *ngIf="errors.Password">
            <i class="fas fa-exclamation-circle"></i> {{ errors.Password }}
          </span>
        </div>

        <div class="form-group">
          <label for="confirmPassword">
            <i class="fas fa-lock"></i> Confirm Password
          </label>
          <input
            type="password"
            id="confirmPassword"
            name="confirmPassword"
            [(ngModel)]="confirmPassword"
            (blur)="validateConfirmPassword()"
            class="form-control"
            [class.error]="errors.ConfirmPassword"
            placeholder="Confirm password"
          />
          <span class="error-message" *ngIf="errors.ConfirmPassword">
            <i class="fas fa-exclamation-circle"></i> {{ errors.ConfirmPassword }}
          </span>
        </div>
      </div>

      <div class="form-group">
        <label for="role">
          <i class="fas fa-user-tag"></i> Role
        </label>
        <select
          id="role"
          name="role"
          [(ngModel)]="userData.UserRole"
          (change)="onRoleChange()"
          class="form-control"
        >
          <option value="User">User</option>
          <option value="Admin">Admin</option>
        </select>
      </div>

      <div class="form-group" *ngIf="showSecretKey">
        <label for="secretKey">
          <i class="fas fa-key"></i> Admin Secret Key
        </label>
        <input
          type="password"
          id="secretKey"
          name="secretKey"
          [(ngModel)]="userData.SecretKey"
          (blur)="validateSecretKey()"
          class="form-control"
          [class.error]="errors.SecretKey"
          placeholder="Enter admin secret key"
        />
        <span class="error-message" *ngIf="errors.SecretKey">
          <i class="fas fa-exclamation-circle"></i> {{ errors.SecretKey }}
        </span>
      </div>

      <button type="submit" class="btn btn-primary btn-block" [disabled]="isLoading">
        <span *ngIf="!isLoading">
          <i class="fas fa-user-plus"></i> Register
        </span>
        <span *ngIf="isLoading">
          <i class="fas fa-spinner fa-spin"></i> Registering...
        </span>
      </button>
    </form>

    <div class="registration-footer">
      <p>Already have an account?</p>
      <button class="btn btn-success" (click)="navigateToLogin()">
        <i class="fas fa-sign-in-alt"></i> Login Now
      </button>
    </div>
  </div>

  <div class="registration-illustration slide-in-right">
    <div class="illustration-content">
      <i class="fas fa-rocket"></i>
      <h3>Start Your Career Journey</h3>
      <p>Register now and get access to thousands of internship opportunities</p>
      <div class="features-list">
        <div class="feature-item">
          <i class="fas fa-check-circle"></i>
          <span>Easy Application Process</span>
        </div>
        <div class="feature-item">
          <i class="fas fa-check-circle"></i>
          <span>Track Your Applications</span>
        </div>
        <div class="feature-item">
          <i class="fas fa-check-circle"></i>
          <span>Get Valuable Feedback</span>
        </div>
      </div>
    </div>
  </div>
</div>

-------------------------
/* Registration Component Styles */
.registration-container {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 1fr 1fr;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.registration-card {
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 50px;
  background: white;
  overflow-y: auto;
}

.registration-header {
  text-align: center;
  margin-bottom: 30px;
}

.registration-header i {
  font-size: 50px;
  color: #667eea;
  margin-bottom: 15px;
}

.registration-header h2 {
  font-size: 28px;
  font-weight: 700;
  color: #333;
  margin-bottom: 8px;
}

.registration-header p {
  font-size: 14px;
  color: #666;
}

.registration-form {
  max-width: 600px;
  margin: 0 auto;
  width: 100%;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

.form-group label i {
  margin-right: 8px;
  color: #667eea;
}

.btn-block {
  width: 100%;
  margin-top: 10px;
}

.registration-footer {
  text-align: center;
  margin-top: 20px;
}

.registration-footer p {
  color: #666;
  margin-bottom: 10px;
  font-size: 14px;
}

.registration-illustration {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 50px;
}

.illustration-content {
  text-align: center;
  color: white;
}

.illustration-content i {
  font-size: 100px;
  margin-bottom: 30px;
  animation: bounce 2s ease-in-out infinite;
}

.illustration-content h3 {
  font-size: 32px;
  font-weight: 700;
  margin-bottom: 20px;
}

.illustration-content p {
  font-size: 16px;
  opacity: 0.9;
  max-width: 400px;
  margin: 0 auto 30px;
}

.features-list {
  display: flex;
  flex-direction: column;
  gap: 15px;
  margin-top: 30px;
}

.feature-item {
  display: flex;
  align-items: center;
  gap: 15px;
  font-size: 16px;
}

.feature-item i {
  font-size: 24px;
  color: #ffd700;
}

/* Responsive */
@media (max-width: 968px) {
  .registration-container {
    grid-template-columns: 1fr;
  }
  
  .registration-illustration {
    display: none;
  }
  
  .registration-card {
    padding: 30px 20px;
  }
  
  .form-row {
    grid-template-columns: 1fr;
  }
}
-----------------------------------
requestedinternshipcomponent
import { Component, OnInit } from '@angular/core';
import { InternshipApplicationService } from 'src/app/services/internshipapplication.service';
import { InternshipApplication } from '../../models/internshipapplication.model';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-requestedinternship',
  templateUrl: './requestedinternship.component.html',
  styleUrls: ['./requestedinternship.component.css']
})
export class RequestedinternshipComponent implements OnInit {
  applications: InternshipApplication[] = [];
  isLoading: boolean = false;

  columnDefs = [
    { headerName: 'Application ID', field: 'InternshipApplicationId', sortable: true, filter: true, width: 130 },
    { headerName: 'University', field: 'UniversityName', sortable: true, filter: true, width: 200 },
    { headerName: 'Degree', field: 'DegreeProgram', sortable: true, filter: true, width: 180 },
    { headerName: 'Resume', field: 'Resume', sortable: true, filter: true, width: 150 },
    { headerName: 'LinkedIn', field: 'LinkedInProfile', sortable: true, filter: true, width: 200 },
    { headerName: 'Status', field: 'ApplicationStatus', sortable: true, filter: true, width: 130,
      cellStyle: (params: any) => {
        if (params.value === 'Approved') {
          return { color: 'white', backgroundColor: '#28a745' };
        } else if (params.value === 'Rejected') {
          return { color: 'white', backgroundColor: '#dc3545' };
        } else {
          return { color: 'white', backgroundColor: '#ffc107' };
        }
      }
    },
    { headerName: 'Application Date', field: 'ApplicationDate', sortable: true, filter: true, width: 150,
      valueFormatter: (params: any) => new Date(params.value).toLocaleDateString() },
    { headerName: 'Actions', field: 'InternshipApplicationId', width: 250,
      cellRenderer: (params: any) => {
        return `
          <button class="action-btn approve-btn" data-action="approve" data-id="${params.value}">
            <i class="fas fa-check"></i> Approve
          </button>
          <button class="action-btn reject-btn" data-action="reject" data-id="${params.value}">
            <i class="fas fa-times"></i> Reject
          </button>
        `;
      }
    }
  ];

  defaultColDef = {
    flex: 1,
    minWidth: 100,
    resizable: true
  };

  paginationPageSize = 10;
  paginationPageSizeSelector = [5, 10, 20, 50];

  constructor(
    private applicationService: InternshipApplicationService
  ) { }

  ngOnInit(): void {
    this.loadApplications();
  }

  loadApplications(): void {
    this.isLoading = true;
    this.applicationService.getAllInternshipApplications().subscribe(
      (data) => {
        this.applications = data;
        this.isLoading = false;
      },
      (error) => {
        this.isLoading = false;
        Swal.fire({
          icon: 'error',
          title: 'Error',
          text: 'Failed to load applications',
          confirmButtonColor: '#667eea'
        });
      }
    );
  }

  onGridReady(params: any): void {
    params.api.sizeColumnsToFit();
  }

  onCellClicked(event: any): void {
    if (event.event.target.dataset.action) {
      const action = event.event.target.dataset.action;
      const id = parseInt(event.event.target.dataset.id);

      if (action === 'approve') {
        this.updateStatus(id, 'Approved');
      } else if (action === 'reject') {
        this.updateStatus(id, 'Rejected');
      }
    }
  }

  updateStatus(id: number, status: string): void {
    const application = this.applications.find(app => app.InternshipApplicationId === id);
    
    if (!application) return;

    Swal.fire({
      title: 'Are you sure?',
      text: `Do you want to ${status.toLowerCase()} this application?`,
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: status === 'Approved' ? '#28a745' : '#dc3545',
      cancelButtonColor: '#667eea',
      confirmButtonText: `Yes, ${status.toLowerCase()} it!`
    }).then((result) => {
      if (result.isConfirmed) {
        application.ApplicationStatus = status;
        
        this.applicationService.updateInternshipApplication(id, application).subscribe(
          () => {
            Swal.fire({
              icon: 'success',
              title: 'Updated!',
              text: `Application has been ${status.toLowerCase()} successfully`,
              timer: 2000,
              showConfirmButton: false
            });
            this.loadApplications();
          },
          (error) => {
            Swal.fire({
              icon: 'error',
              title: 'Error',
              text: error.error?.message || 'Failed to update application status',
              confirmButtonColor: '#667eea'
            });
          }
        );
      }
    });
  }
}
--------------------
<div class="requested-internship-container fade-in">
  <div class="page-header">
    <h2><i class="fas fa-file-alt"></i> Internship Applications</h2>
  </div>

  <div class="grid-container" *ngIf="!isLoading">
    <ag-grid-angular
      style="width: 100%; height: 600px;"
      class="ag-theme-alpine"
      [rowData]="applications"
      [columnDefs]="columnDefs"
      [defaultColDef]="defaultColDef"
      [pagination]="true"
      [paginationPageSize]="paginationPageSize"
      [paginationPageSizeSelector]="paginationPageSizeSelector"
      (gridReady)="onGridReady($event)"
      (cellClicked)="onCellClicked($event)"
    >
    </ag-grid-angular>
  </div>

  <div class="loading-container" *ngIf="isLoading">
    <div class="spinner"></div>
    <p>Loading applications...</p>
  </div>
</div>
-------------------------
/* Requested Internship Component Styles */
.requested-internship-container {
  padding: 20px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
  padding: 20px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.page-header h2 {
  font-size: 28px;
  font-weight: 700;
  color: #333;
  margin: 0;
}

.page-header h2 i {
  color: #667eea;
  margin-right: 10px;
}

.grid-container {
  background: white;
  padding: 20px;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

/* AG Grid Styling Fixes and Enhancements */
.ag-theme-alpine {
  --ag-header-background-color: #667eea;
  --ag-header-foreground-color: #1f2937;
  --ag-font-size: 14px;
  --ag-border-color: #e5e7eb;
  --ag-row-hover-color: #f3f4f6;
  --ag-selected-row-background-color: #e0f2fe;
}

.ag-header-cell-label {
  color: #1f2937 !important;
  font-weight: 600;
  font-size: 14px;
}

.ag-header {
  background-color: #f9fafb !important;
  border-bottom: 1px solid #d1d5db !important;
}

.ag-header-cell:hover {
  background-color: #f3f4f6 !important;
}

.ag-root-wrapper {
  border-radius: 10px;
  overflow: hidden;
}

.ag-row {
  font-size: 13px;
  color: #374151;
}

/* Status cell styling handled via cellStyle in component */

/* Action buttons inside grid cells */
.ag-cell .action-btn {
  padding: 6px 10px;
  font-size: 12px;
  border-radius: 4px;
  margin-right: 5px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  transition: all 0.3s ease;
}

.ag-cell .approve-btn {
  background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
  color: white;
}

.ag-cell .approve-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 10px rgba(17, 153, 142, 0.4);
}

.ag-cell .reject-btn {
  background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
  color: white;
}

.ag-cell .reject-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 10px rgba(235, 51, 73, 0.4);
}

/* Loading container */
.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 100px 20px;
  background: white;
  border-radius: 10px;
}

.loading-container p {
  margin-top: 20px;
  font-size: 18px;
  color: #667eea;
}
--------------------------------
useraddfeedbackcomponent
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { FeedbackService } from '../../services/feedback.service';
import { AuthService } from '../../services/auth.service';
import { Feedback } from '../../models/feedback.model';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-useraddfeedback',
  templateUrl: './useraddfeedback.component.html',
  styleUrls: ['./useraddfeedback.component.css']
})
export class UseraddfeedbackComponent implements OnInit {
  feedback: Feedback = {
    UserId: 0,
    FeedbackText: '',
    Date: new Date()
  };

  errors: any = {
    FeedbackText: ''
  };

  isLoading: boolean = false;

  constructor(
    private feedbackService: FeedbackService,
    private authService: AuthService,
    private router: Router
  ) { }

  ngOnInit(): void {
    this.feedback.UserId = this.authService.getUserId();
  }

  validateFeedbackText(): boolean {
    this.errors.FeedbackText = '';
    
    if (!this.feedback.FeedbackText || this.feedback.FeedbackText.trim() === '') {
      this.errors.FeedbackText = 'Feedback text is required';
      return false;
    }
    
    if (this.feedback.FeedbackText.trim() !== this.feedback.FeedbackText) {
      this.errors.FeedbackText = 'Feedback text cannot have leading or trailing spaces';
      return false;
    }
    
    if (this.feedback.FeedbackText.length < 10) {
      this.errors.FeedbackText = 'Feedback must be at least 10 characters long';
      return false;
    }
    
    return true;
  }

  onSubmit(): void {
    if (!this.validateFeedbackText()) {
      Swal.fire({
        icon: 'error',
        title: 'Validation Error',
        text: 'Please fix the errors in the form',
        confirmButtonColor: '#667eea'
      });
      return;
    }

    this.isLoading = true;

    this.feedbackService.addFeedback(this.feedback).subscribe(
      (response) => {
        this.isLoading = false;
        Swal.fire({
          icon: 'success',
          title: 'Success!',
          text: 'Feedback submitted successfully',
          confirmButtonColor: '#667eea'
        }).then(() => {
          this.router.navigate(['/user/feedback/view']);
        });
      },
      (error) => {
        this.isLoading = false;
        Swal.fire({
          icon: 'error',
          title: 'Error',
          text: error.error?.message || 'Failed to submit feedback',
          confirmButtonColor: '#667eea'
        });
      }
    );
  }

  cancel(): void {
    this.router.navigate(['/user/feedback/view']);
  }
}
------------------------------
<div class="add-feedback-container fade-in">
  <div class="form-card">
    <div class="form-header">
      <h2><i class="fas fa-plus-circle"></i> Add Feedback</h2>
      <p>Share your experience and help us improve</p>
    </div>

    <form (ngSubmit)="onSubmit()" class="feedback-form">
      <div class="form-group">
        <label for="feedbackText"><i class="fas fa-comment-alt"></i> Your Feedback *</label>
        <textarea
          id="feedbackText"
          name="feedbackText"
          [(ngModel)]="feedback.FeedbackText"
          (blur)="validateFeedbackText()"
          class="form-control"
          [class.error]="errors.FeedbackText"
          rows="8"
          placeholder="Share your thoughts, suggestions, or experiences..."
        ></textarea>
        <span class="error-message" *ngIf="errors.FeedbackText">
          <i class="fas fa-exclamation-circle"></i> {{ errors.FeedbackText }}
        </span>
      </div>

      <div class="form-actions">
        <button type="button" class="btn btn-danger" (click)="cancel()">
          <i class="fas fa-times"></i> Cancel
        </button>
        <button type="submit" class="btn btn-primary" [disabled]="isLoading">
          <span *ngIf="!isLoading">
            <i class="fas fa-paper-plane"></i> Submit Feedback
          </span>
          <span *ngIf="isLoading">
            <i class="fas fa-spinner fa-spin"></i> Submitting...
          </span>
        </button>
      </div>
    </form>
  </div>
</div>

-----------------------
/* User Add Feedback Component Styles */
.add-feedback-container {
  padding: 20px;
  max-width: 800px;
  margin: 0 auto;
}

.form-card {
  background: white;
  border-radius: 15px;
  padding: 40px;
  box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
}

.form-header {
  text-align: center;
  margin-bottom: 40px;
  padding-bottom: 20px;
  border-bottom: 2px solid #f0f0f0;
}

.form-header h2 {
  font-size: 28px;
  font-weight: 700;
  color: #333;
  margin: 0 0 10px 0;
}

.form-header h2 i {
  color: #11998e;
  margin-right: 10px;
}

.form-header p {
  font-size: 16px;
  color: #666;
  margin: 0;
}

.feedback-form {
  max-width: 700px;
  margin: 0 auto;
}

.form-group label i {
  margin-right: 8px;
  color: #11998e;
}

textarea.form-control {
  resize: vertical;
  font-family: 'Poppins', sans-serif;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 15px;
  margin-top: 30px;
  padding-top: 20px;
  border-top: 2px solid #f0f0f0;
}

.form-actions .btn {
  padding: 12px 30px;
  font-size: 16px;
}

/* Responsive */
@media (max-width: 768px) {
  .form-card {
    padding: 20px;
  }
  
  .form-actions {
    flex-direction: column;
  }
  
  .form-actions .btn {
    width: 100%;
  }
}
------------------------------
userappliedinternship
import { Component, OnInit } from '@angular/core';
import { InternshipApplicationService } from 'src/app/services/internshipapplication.service';
import { AuthService } from '../../services/auth.service';
import { InternshipApplication } from '../../models/internshipapplication.model';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-userappliedinternship',
  templateUrl: './userappliedinternship.component.html',
  styleUrls: ['./userappliedinternship.component.css']
})
export class UserappliedinternshipComponent implements OnInit {
  applications: InternshipApplication[] = [];
  isLoading: boolean = false;
  userId: number = 0;

  columnDefs = [
    { headerName: 'Application ID', field: 'InternshipApplicationId', sortable: true, filter: true, width: 130 },
    { headerName: 'University', field: 'UniversityName', sortable: true, filter: true, width: 200 },
    { headerName: 'Degree', field: 'DegreeProgram', sortable: true, filter: true, width: 180 },
    { headerName: 'Resume', field: 'Resume', sortable: true, filter: true, width: 150,
      cellRenderer: (params: any) => {
        return `<a href="${params.value}" target="_blank" class="resume-link">View Resume</a>`;
      }
    },
    { headerName: 'LinkedIn', field: 'LinkedInProfile', sortable: true, filter: true, width: 150,
      cellRenderer: (params: any) => {
        return params.value ? `<a href="${params.value}" target="_blank" class="linkedin-link">View Profile</a>` : 'N/A';
      }
    },
    { headerName: 'Status', field: 'ApplicationStatus', sortable: true, filter: true, width: 130,
      cellStyle: (params: any) => {
        if (params.value === 'Approved') {
          return { color: 'white', backgroundColor: '#28a745', fontWeight: 'bold' };
        } else if (params.value === 'Rejected') {
          return { color: 'white', backgroundColor: '#dc3545', fontWeight: 'bold' };
        } else {
          return { color: 'white', backgroundColor: '#ffc107', fontWeight: 'bold' };
        }
      }
    },
    { headerName: 'Application Date', field: 'ApplicationDate', sortable: true, filter: true, width: 150,
      valueFormatter: (params: any) => new Date(params.value).toLocaleDateString() }
  ];

  defaultColDef = {
    flex: 1,
    minWidth: 100,
    resizable: true
  };

  paginationPageSize = 10;
  paginationPageSizeSelector = [5, 10, 20, 50];

  constructor(
    private applicationService: InternshipApplicationService,
    private authService: AuthService
  ) { }

  ngOnInit(): void {
    this.userId = this.authService.getUserId();
    this.loadApplications();
  }

  loadApplications(): void {
    this.isLoading = true;
    this.applicationService.getInternshipApplicationsByUserId(this.userId).subscribe(
      (data) => {
        this.applications = data;
        this.isLoading = false;
      },
      (error) => {
        this.isLoading = false;
        Swal.fire({
          icon: 'error',
          title: 'Error',
          text: 'Failed to load your applications',
          confirmButtonColor: '#667eea'
        });
      }
    );
  }

  onGridReady(params: any): void {
    params.api.sizeColumnsToFit();
  }
}
-------------------
<div class="user-applied-container fade-in">
    <div class="page-header">
      <h2><i class="fas fa-file-alt"></i> My Applications</h2>
    </div>
  
    <div class="grid-container" *ngIf="!isLoading">
      <ag-grid-angular
        style="width: 100%; height: 600px;"
        class="ag-theme-alpine"
        [rowData]="applications"
        [columnDefs]="columnDefs"
        [defaultColDef]="defaultColDef"
        [pagination]="true"
        [paginationPageSize]="paginationPageSize"
        [paginationPageSizeSelector]="paginationPageSizeSelector"
        (gridReady)="onGridReady($event)"
      >
      </ag-grid-angular>
    </div>
  
    <div class="loading-container" *ngIf="isLoading">
      <div class="spinner"></div>
      <p>Loading your applications...</p>
    </div>
  </div>
  ------------------
/* User Applied Internship Component Styles */
.user-applied-container {
  padding: 20px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
  padding: 20px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.page-header h2 {
  font-size: 28px;
  font-weight: 700;
  color: #333;
  margin: 0;
}

.page-header h2 i {
  color: #11998e;
  margin-right: 10px;
}

.grid-container {
  background: white;
  padding: 20px;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

/* === AG Grid Styling (Updated) === */
.ag-theme-alpine {
  /* Theme variables */
  --ag-font-size: 14px;
  --ag-border-color: #e5e7eb;                  /* light gray borders */
  --ag-header-background-color: #11998ecf;       /* soft header background */
  --ag-header-foreground-color: #0f172a;       /* near-black header text */
  --ag-row-hover-color: #f3f4f6;               /* subtle row hover */
  --ag-selected-row-background-color: #e6fffa; /* teal-tinted selected row */
}

.ag-root-wrapper {
  border-radius: 10px;
  overflow: hidden; /* clip rounded corners */
  border: 1px solid #e5e7eb;
}

.ag-header {
  background-color: #f9fafb !important;
  border-bottom: 1px solid #e5e7eb !important;
}

.ag-header-cell-label {
  color: #1f2937 !important; /* slate-800 */
  font-weight: 600;
  font-size: 14px;
}

.ag-header-cell:hover {
  background-color: #f3f4f6 !important; /* hover highlight */
}

.ag-row {
  font-size: 13px;
  color: #374151; /* slate-700 */
}

.ag-row-hover {
  background-color: #f3f4f6 !important;
}

.ag-cell:focus,
.ag-cell:focus-within {
  outline: 2px solid rgba(17, 153, 142, 0.25); /* teal focus ring */
  outline-offset: -1px;
}

/* Optional: zebra striping for readability */
.ag-theme-alpine .ag-row:nth-child(even) .ag-cell {
  background-color: #fcfcfd;
}

/* Optional: center status text */
.ag-cell[col-id="ApplicationStatus"] {
  text-align: center;
  font-weight: 700;
  letter-spacing: 0.2px;
}

/* Links inside grid cells */
.resume-link,
.linkedin-link {
  color: #11998e;
  text-decoration: none;
  font-weight: 600;
}

.resume-link:hover,
.linkedin-link:hover {
  text-decoration: underline;
}

/* Loading container */
.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 100px 20px;
  background: white;
  border-radius: 10px;
}

.loading-container p {
  margin-top: 20px;
  font-size: 18px;
  color: #11998e;
}
--------------------
usernavcomponent
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-usernav',
  templateUrl: './usernav.component.html',
  styleUrls: ['./usernav.component.css']
})
export class UsernavComponent implements OnInit {
  username: string = '';
  isSidebarOpen: boolean = true;

  constructor(
    private authService: AuthService,
    private router: Router
  ) { }

  ngOnInit(): void {
    this.username = this.authService.getUsername();
  }

  toggleSidebar(): void {
    this.isSidebarOpen = !this.isSidebarOpen;
  }

  logout(): void {
    Swal.fire({
      title: 'Are you sure?',
      text: 'Do you want to logout?',
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#667eea',
      cancelButtonColor: '#eb3349',
      confirmButtonText: 'Yes, logout!'
    }).then((result) => {
      if (result.isConfirmed) {
        this.authService.logout();
        
        Swal.fire({
          icon: 'success',
          title: 'Logged Out',
          text: 'You have been successfully logged out',
          timer: 2000,
          showConfirmButton: false
        });
        
        setTimeout(() => {
          this.router.navigate(['/login']);
        }, 2000);
      }
    });
  }
}
----------------------
<div class="user-layout">
  <div class="sidebar" [class.collapsed]="!isSidebarOpen">
    <div class="sidebar-header">
      <i class="fas fa-graduation-cap"></i>
      <h3 *ngIf="isSidebarOpen">User Panel</h3>
    </div>
    
    <nav class="sidebar-nav">
      <a routerLink="/user/internships" routerLinkActive="active" class="nav-item">
        <i class="fas fa-briefcase"></i>
        <span *ngIf="isSidebarOpen">Browse Internships</span>
      </a>
      <a routerLink="/user/applied-internships" routerLinkActive="active" class="nav-item">
        <i class="fas fa-file-alt"></i>
        <span *ngIf="isSidebarOpen">My Applications</span>
      </a>
      <a routerLink="/user/feedback/add" routerLinkActive="active" class="nav-item">
        <i class="fas fa-plus-circle"></i>
        <span *ngIf="isSidebarOpen">Add Feedback</span>
      </a>
      <a routerLink="/user/feedback/view" routerLinkActive="active" class="nav-item">
        <i class="fas fa-comments"></i>
        <span *ngIf="isSidebarOpen">My Feedbacks</span>
      </a>
    </nav>
    
    <div class="sidebar-footer">
      <button class="nav-item logout-btn" (click)="logout()">
        <i class="fas fa-sign-out-alt"></i>
        <span *ngIf="isSidebarOpen">Logout</span>
      </button>
    </div>
  </div>
  
  <div class="main-content">
    <header class="top-header">
      <button class="toggle-btn" (click)="toggleSidebar()">
        <i class="fas fa-bars"></i>
      </button>
      <div class="header-right">
        <div class="user-info">
          <i class="fas fa-user-circle"></i>
          <span>{{ username }}/ User</span>
        </div>
      </div>
    </header>
    
    <div class="content-area">
      <router-outlet></router-outlet>
    </div>
  </div>
</div>

---------------------
/* User Navigation Styles */
.user-layout {
  display: flex;
  min-height: 100vh;
}

.sidebar {
  width: 250px;
  background: linear-gradient(180deg, #11998e 0%, #38ef7d 100%);
  color: white;
  transition: all 0.3s ease;
  display: flex;
  flex-direction: column;
  position: fixed;
  height: 100vh;
  z-index: 1000;
}

.sidebar.collapsed {
  width: 70px;
}

.sidebar-header {
  padding: 30px 20px;
  text-align: center;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.sidebar-header i {
  font-size: 40px;
  margin-bottom: 10px;
}

.sidebar-header h3 {
  font-size: 20px;
  font-weight: 600;
  margin: 0;
}

.sidebar-nav {
  flex: 1;
  padding: 20px 0;
}

.nav-item {
  display: flex;
  align-items: center;
  padding: 15px 20px;
  color: white;
  text-decoration: none;
  transition: all 0.3s ease;
  cursor: pointer;
  border: none;
  background: transparent;
  width: 100%;
  text-align: left;
}

.nav-item i {
  font-size: 20px;
  min-width: 30px;
}

.nav-item span {
  margin-left: 15px;
  font-size: 16px;
}

.nav-item:hover {
  background: rgba(255, 255, 255, 0.1);
  padding-left: 25px;
}

.nav-item.active {
  background: rgba(255, 255, 255, 0.2);
  border-left: 4px solid #ffd700;
}

.sidebar-footer {
  padding: 20px 0;
  border-top: 1px solid rgba(255, 255, 255, 0.1);
}

.logout-btn {
  color: #ffcccc;
}

.logout-btn:hover {
  background: rgba(255, 0, 0, 0.2);
  color: white;
}

.main-content {
  flex: 1;
  margin-left: 250px;
  transition: all 0.3s ease;
  background: #f5f7fa;
}

.sidebar.collapsed ~ .main-content {
  margin-left: 70px;
}

.top-header {
  background: white;
  padding: 20px 30px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
  position: sticky;
  top: 0;
  z-index: 999;
}

.toggle-btn {
  background: transparent;
  border: none;
  font-size: 24px;
  color: #11998e;
  cursor: pointer;
  transition: all 0.3s ease;
}

.toggle-btn:hover {
  transform: scale(1.1);
}

.header-right {
  display: flex;
  align-items: center;
  gap: 20px;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 600;
  color: #333;
}

.user-info i {
  font-size: 28px;
  color: #11998e;
}

.content-area {
  padding: 30px;
  min-height: calc(100vh - 80px);
}

/* Responsive */
@media (max-width: 768px) {
  .sidebar {
    width: 70px;
  }
  
  .sidebar-header h3,
  .nav-item span {
    display: none;
  }
  
  .main-content {
    margin-left: 70px;
  }
}
---------------------------
userviewfeedbackcomponent
import { Component, OnInit } from '@angular/core';
import { FeedbackService } from '../../services/feedback.service';
import { AuthService } from '../../services/auth.service';
import { Feedback } from '../../models/feedback.model';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-userviewfeedback',
  templateUrl: './userviewfeedback.component.html',
  styleUrls: ['./userviewfeedback.component.css']
})
export class UserviewfeedbackComponent implements OnInit {
  feedbacks: Feedback[] = [];
  isLoading: boolean = false;
  userId: number = 0;

  columnDefs = [
    { headerName: 'Feedback Text', field: 'FeedbackText', sortable: true, filter: true, width: 500 },
    { headerName: 'Date', field: 'Date', sortable: true, filter: true, width: 150,
      valueFormatter: (params: any) => new Date(params.value).toLocaleDateString() },
    { headerName: 'Actions', field: 'FeedbackId', width: 150,
      cellRenderer: (params: any) => {
        return `
          <button class="action-btn delete-btn" data-action="delete" data-id="${params.value}">
            <i class="fas fa-trash"></i> Delete
          </button>
        `;
      }
    }
  ];

  defaultColDef = {
    flex: 1,
    minWidth: 100,
    resizable: true
  };

  paginationPageSize = 10;
  paginationPageSizeSelector = [5, 10, 20, 50];

  constructor(
    private feedbackService: FeedbackService,
    private authService: AuthService
  ) { }

  ngOnInit(): void {
    this.userId = this.authService.getUserId();
    this.loadFeedbacks();
  }

  loadFeedbacks(): void {
    this.isLoading = true;
    this.feedbackService.getFeedbacksByUserId(this.userId).subscribe(
      (data) => {
        this.feedbacks = data;
        this.isLoading = false;
      },
      (error) => {
        this.isLoading = false;
        Swal.fire({
          icon: 'error',
          title: 'Error',
          text: 'Failed to load feedbacks',
          confirmButtonColor: '#667eea'
        });
      }
    );
  }

  onGridReady(params: any): void {
    params.api.sizeColumnsToFit();
  }

  onCellClicked(event: any): void {
    if (event.event.target.dataset.action === 'delete') {
      const id = parseInt(event.event.target.dataset.id);
      this.deleteFeedback(id);
    }
  }

  deleteFeedback(id: number): void {
    Swal.fire({
      title: 'Are you sure?',
      text: 'Do you want to delete this feedback?',
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#eb3349',
      cancelButtonColor: '#667eea',
      confirmButtonText: 'Yes, delete it!'
    }).then((result) => {
      if (result.isConfirmed) {
        this.feedbackService.deleteFeedback(id).subscribe(
          () => {
            Swal.fire({
              icon: 'success',
              title: 'Deleted!',
              text: 'Feedback has been deleted successfully',
              timer: 2000,
              showConfirmButton: false
            });
            this.loadFeedbacks();
          },
          (error) => {
            Swal.fire({
              icon: 'error',
              title: 'Error',
              text: error.error?.message || 'Failed to delete feedback',
              confirmButtonColor: '#667eea'
            });
          }
        );
      }
    });
  }
}
----------------------
<div class="user-feedback-container fade-in">
    <div class="page-header">
      <h2><i class="fas fa-comments"></i> My Feedbacks</h2>
    </div>
  
    <div class="grid-container" *ngIf="!isLoading">
      <ag-grid-angular
        style="width: 100%; height: 600px;"
        class="ag-theme-alpine"
        [rowData]="feedbacks"
        [columnDefs]="columnDefs"
        [defaultColDef]="defaultColDef"
        [pagination]="true"
        [paginationPageSize]="paginationPageSize"
        [paginationPageSizeSelector]="paginationPageSizeSelector"
        (gridReady)="onGridReady($event)"
        (cellClicked)="onCellClicked($event)"
      >
      </ag-grid-angular>
    </div>
  
    <div class="loading-container" *ngIf="isLoading">
      <div class="spinner"></div>
      <p>Loading feedbacks...</p>
    </div>
  </div>
  --------------------------------
.admin-feedback-container {
  padding: 20px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
  padding: 20px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.page-header h2 {
  font-size: 28px;
  font-weight: 700;
  color: #333;
  margin: 0;
}

.page-header h2 i {
  color: #667eea;
  margin-right: 10px;
}

.grid-container {
  background: white;
  padding: 20px;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

/* AG Grid Styling Fixes and Enhancements */
.ag-theme-alpine {
  --ag-header-background-color: #11998ecf;
  --ag-header-foreground-color: #1f2937;
  --ag-font-size: 14px;
  --ag-border-color: #e5e7eb;
  --ag-row-hover-color: #f3f4f6;
  --ag-selected-row-background-color: #e0f2fe;
}

.ag-header-cell-label {
  color: #1f2937 !important;
  font-weight: 600;
  font-size: 14px;
}

.ag-header {
  background-color: #f9fafb !important;
  border-bottom: 1px solid #d1d5db !important;
}

.ag-header-cell:hover {
  background-color: #f3f4f6 !important;
}

.ag-root-wrapper {
  border-radius: 10px;
  overflow: hidden;
}

.ag-row {
  font-size: 13px;
  color: #374151;
}

/* Loading container */
.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 100px 20px;
  background: white;
  border-radius: 10px;
}

.loading-container p {
  margin-top: 20px;
  font-size: 18px;
  color: #667eea;
}
-------------------------------
userviewinternship
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { InternshipService } from '../../services/internship.service';
import { Internship } from '../../models/internship.model';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-userviewinternship',
  templateUrl: './userviewinternship.component.html',
  styleUrls: ['./userviewinternship.component.css']
})
export class UserviewinternshipComponent implements OnInit {
  internships: Internship[] = [];
  isLoading: boolean = false;

  columnDefs = [
    { headerName: 'Title', field: 'Title', sortable: true, filter: true, width: 200 },
    { headerName: 'Company', field: 'CompanyName', sortable: true, filter: true, width: 180 },
    { headerName: 'Location', field: 'Location', sortable: true, filter: true, width: 150 },
    { headerName: 'Duration (Months)', field: 'DurationInMonths', sortable: true, filter: true, width: 150 },
    { headerName: 'Stipend', field: 'Stipend', sortable: true, filter: true, width: 120,
      valueFormatter: (params: any) => '₹' + params.value },
    { headerName: 'Skills', field: 'SkillsRequired', sortable: true, filter: true, width: 200 },
    { headerName: 'Deadline', field: 'ApplicationDeadline', sortable: true, filter: true, width: 150,
      valueFormatter: (params: any) => new Date(params.value).toLocaleDateString() },
    { headerName: 'Actions', field: 'InternshipId', width: 150,
      cellRenderer: (params: any) => {
        return `
          <button class="action-btn apply-btn" data-action="apply" data-id="${params.value}">
            <i class="fas fa-paper-plane"></i> Apply
          </button>
        `;
      }
    }
  ];

  defaultColDef = {
    flex: 1,
    minWidth: 100,
    resizable: true
  };

  paginationPageSize = 10;
  paginationPageSizeSelector = [5, 10, 20, 50];

  constructor(
    private internshipService: InternshipService,
    private router: Router
  ) { }

  ngOnInit(): void {
    this.loadInternships();
  }

  loadInternships(): void {
    this.isLoading = true;
    this.internshipService.getAllInternships().subscribe(
      (data) => {
        this.internships = data;
        this.isLoading = false;
      },
      (error) => {
        this.isLoading = false;
        Swal.fire({
          icon: 'error',
          title: 'Error',
          text: 'Failed to load internships',
          confirmButtonColor: '#667eea'
        });
      }
    );
  }

  onGridReady(params: any): void {
    params.api.sizeColumnsToFit();
  }

  onCellClicked(event: any): void {
    if (event.event.target.dataset.action === 'apply') {
      const id = event.event.target.dataset.id;
      this.applyForInternship(parseInt(id));
    }
  }

  applyForInternship(id: number): void {
    this.router.navigate(['/user/internship/apply', id]);
  }
}
-----------------
<div class="user-view-internship-container fade-in">
  <div class="page-header">
    <h2><i class="fas fa-briefcase"></i> Available Internships</h2>
  </div>

  <div class="grid-container" *ngIf="!isLoading">
    <ag-grid-angular
      style="width: 100%; height: 600px;"
      class="ag-theme-alpine"
      [rowData]="internships"
      [columnDefs]="columnDefs"
      [defaultColDef]="defaultColDef"
      [pagination]="true"
      [paginationPageSize]="paginationPageSize"
      [paginationPageSizeSelector]="paginationPageSizeSelector"
      (gridReady)="onGridReady($event)"
      (cellClicked)="onCellClicked($event)"
    >
    </ag-grid-angular>
  </div>

  <div class="loading-container" *ngIf="isLoading">
    <div class="spinner"></div>
    <p>Loading internships...</p>
  </div>
</div>
-------------------------
.user-feedback-container {
  padding: 20px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
  padding: 20px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.page-header h2 {
  font-size: 28px;
  font-weight: 700;
  color: #333;
  margin: 0;
}

.page-header h2 i {
  color: #11998e;
  margin-right: 10px;
}

.grid-container {
  background: white;
  padding: 20px;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

/* AG Grid Styling Fixes and Enhancements */
.ag-theme-alpine {
  --ag-header-background-color: #11998ecf;
  --ag-header-foreground-color: #1f2937;
  --ag-font-size: 14px;
  --ag-border-color: #e5e7eb;
  --ag-row-hover-color: #f3f4f6;
  --ag-selected-row-background-color: #e0f2fe;
}

.ag-header-cell-label {
  color: #1f2937 !important;
  font-weight: 600;
  font-size: 14px;
}

.ag-header {
  background-color: #f9fafb !important;
  border-bottom: 1px solid #d1d5db !important;
}

.ag-header-cell:hover {
  background-color: #f3f4f6 !important;
}

.ag-root-wrapper {
  border-radius: 10px;
  overflow: hidden;
}

.ag-row {
  font-size: 13px;
  color: #374151;
}

/* Action buttons inside grid cells */
.ag-cell .action-btn {
  padding: 6px 10px;
  font-size: 12px;
  border-radius: 4px;
  margin-right: 5px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  transition: all 0.3s ease;
}

.ag-cell .delete-btn {
  background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
  color: white;
}

.ag-cell .delete-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 10px rgba(235, 51, 73, 0.4);
}

/* Loading container */
.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 100px 20px;
  background: white;
  border-radius: 10px;
}

.loading-container p {
  margin-top: 20px;
  font-size: 18px;
  color: #11998e;
}
------------------------------
viewinternship
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { InternshipService } from '../../services/internship.service';
import { Internship } from '../../models/internship.model';
import Swal from 'sweetalert2';
@Component({
  selector: 'app-viewinternship',
  templateUrl: './viewinternship.component.html',
  styleUrls: ['./viewinternship.component.css']
})
export class ViewinternshipComponent implements OnInit {
  internships: Internship[] = [];
  isLoading: boolean = false;

  // AG-Grid configuration
  columnDefs = [
    { headerName: 'Title', field: 'Title', sortable: true, filter: true, width: 200 },
    { headerName: 'Company', field: 'CompanyName', sortable: true, filter: true, width: 180 },
    { headerName: 'Location', field: 'Location', sortable: true, filter: true, width: 150 },
    { headerName: 'Duration (Months)', field: 'DurationInMonths', sortable: true, filter: true, width: 150 },
    { headerName: 'Stipend', field: 'Stipend', sortable: true, filter: true, width: 120,
      valueFormatter: (params: any) => '₹' + params.value },
    { headerName: 'Skills', field: 'SkillsRequired', sortable: true, filter: true, width: 200 },
    { headerName: 'Deadline', field: 'ApplicationDeadline', sortable: true, filter: true, width: 150,
      valueFormatter: (params: any) => new Date(params.value).toLocaleDateString() },
    { headerName: 'Actions', field: 'InternshipId', width: 200,
      cellRenderer: (params: any) => {
        return `
          <button class="action-btn edit-btn" data-action="edit" data-id="${params.value}">
            <i class="fas fa-edit"></i> Edit
          </button>
          <button class="action-btn delete-btn" [ngStyle]="{'background-color': 'red' }"
          data-action="delete" data-id="${params.value}">
            <i class="fas fa-trash"></i> Delete
          </button>
        `;
      }
    }
  ];

  defaultColDef = {
    flex: 1,
    minWidth: 100,
    resizable: true
  };

  paginationPageSize = 10;
  paginationPageSizeSelector = [5, 10, 20, 50];

  constructor(
    private internshipService: InternshipService,
    private router: Router
  ) { }

  ngOnInit(): void {
    this.loadInternships();
  }

  loadInternships(): void {
    this.isLoading = true;
    this.internshipService.getAllInternships().subscribe(
      (data) => {
        this.internships = data;
        this.isLoading = false;
      },
      (error) => {
        this.isLoading = false;
        Swal.fire({
          icon: 'error',
          title: 'Error',
          text: 'Failed to load internships',
          confirmButtonColor: '#667eea'
        });
      }
    );
  }

  onGridReady(params: any): void {
    params.api.sizeColumnsToFit();
  }

  onCellClicked(event: any): void {
    if (event.event.target.dataset.action) {
      const action = event.event.target.dataset.action;
      const id = event.event.target.dataset.id;

      if (action === 'edit') {
        this.editInternship(parseInt(id));
      } else if (action === 'delete') {
        this.deleteInternship(parseInt(id));
      }
    }
  }

  editInternship(id: number): void {
    this.router.navigate(['/admin/internship/edit', id]);
  }

  deleteInternship(id: number): void {
    Swal.fire({
      title: 'Are you sure?',
      text: 'Do you want to delete this internship?',
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#eb3349',
      cancelButtonColor: '#667eea',
      confirmButtonText: 'Yes, delete it!'
    }).then((result) => {
      if (result.isConfirmed) {
        this.internshipService.deleteInternship(id).subscribe(
          () => {
            Swal.fire({
              icon: 'success',
              title: 'Deleted!',
              text: 'Internship has been deleted successfully',
              timer: 2000,
              showConfirmButton: false
            });
            this.loadInternships();
          },
          (error) => {
            Swal.fire({
              icon: 'error',
              title: 'Error',
              text: error.error?.message || 'Failed to delete internship',
              confirmButtonColor: '#667eea'
            });
          }
        );
      }
    });
  }

  navigateToCreate(): void {
    this.router.navigate(['/admin/internship/create']);
  }


  downloadInternshipsCsvFromBackend(): void {
    this.internshipService.downloadInternshipsCSV();
  }
}
----------------
<div class="view-internship-container fade-in">
  <div class="page-header">
    <h2><i class="fas fa-list"></i> All Internships</h2>
    <button class="btn btn-primary" (click)="navigateToCreate()">
      <i class="fas fa-plus-circle"></i> Create New Internship
    </button>
  </div>

  <div class="grid-container" *ngIf="!isLoading">
    <ag-grid-angular
      style="width: 100%; height: 600px;"
      class="ag-theme-alpine"
      [rowData]="internships"
      [columnDefs]="columnDefs"
      [defaultColDef]="defaultColDef"
      [pagination]="true"
      [paginationPageSize]="paginationPageSize"
      [paginationPageSizeSelector]="paginationPageSizeSelector"
      (gridReady)="onGridReady($event)"
      (cellClicked)="onCellClicked($event)"
    >
    </ag-grid-angular>
  </div>

  <div class="loading-container" *ngIf="isLoading">
    <div class="spinner"></div>
    <p>Loading internships...</p>
  </div>
</div>

<button class="action-btn csv-download-btn" (click)="downloadInternshipsCsvFromBackend()">
  <i class="fas fa-download"></i> Download Internships CSV
</button>
------------------------------
.view-internship-container {
  padding: 20px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
  padding: 20px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.page-header h2 {
  font-size: 28px;
  font-weight: 700;
  color: #333;
  margin: 0;
}

.page-header h2 i {
  color: #667eea;
  margin-right: 10px;
}

.grid-container {
  background: white;
  padding: 20px;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

/* AG Grid Styling Fixes and Enhancements */
.ag-theme-alpine {
  --ag-header-background-color: #667eea;
  --ag-header-foreground-color: #1f2937;
  --ag-font-size: 14px;
  --ag-border-color: #e5e7eb;
  --ag-row-hover-color: #f3f4f6;
  --ag-selected-row-background-color: #e0f2fe;
}

.ag-header-cell-label {
  color: #1f2937 !important;
  font-weight: 600;
  font-size: 14px;
}

.ag-header {
  background-color: #f9fafb !important;
  border-bottom: 1px solid #d1d5db !important;
}

.ag-header-cell:hover {
  background-color: #f3f4f6 !important;
}

.ag-root-wrapper {
  border-radius: 10px;
  overflow: hidden;
}

.ag-row {
  font-size: 13px;
  color: #374151;
}

/* Action buttons inside grid cells */
.ag-cell .action-btn {
  padding: 6px 10px;
  font-size: 12px;
  border-radius: 4px;
  margin-right: 5px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: none;
  cursor: pointer;
}

/* Blue Edit Button */
.ag-cell .edit-btn {
  background-color: #007bff;
  color: white;
}

.ag-cell .edit-btn:hover {
  background-color: #0056b3;
  transform: translateY(-2px);
  box-shadow: 0 4px 10px rgba(0, 123, 255, 0.4);
}

/* Red Delete Button */
.ag-cell .delete-btn {
  background-color: #dc3545;
  color: white;
}

.ag-cell .delete-btn:hover {
  background-color: #a71d2a;
  transform: translateY(-2px);
  box-shadow: 0 4px 10px rgba(220, 53, 69, 0.4);
}

/* Loading container */
.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 100px 20px;
  background: white;
  border-radius: 10px;
}

.loading-container p {
  margin-top: 20px;
  font-size: 18px;
  color: #667eea;
}
---------------------------
authservice
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { tap } from 'rxjs/operators';
import { environment } from '../../environments/environment';
import { User } from '../models/user.model';
import { Login } from '../models/login.model';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = `${environment.apiUrl}/api`;
  
  private userRoleSubject = new BehaviorSubject<string>('');
  private userIdSubject = new BehaviorSubject<number>(0);
  private usernameSubject = new BehaviorSubject<string>('');
  
  public userRole$ = this.userRoleSubject.asObservable();
  public userId$ = this.userIdSubject.asObservable();
  public username$ = this.usernameSubject.asObservable();

  constructor(private http: HttpClient) {
    // Load user data from localStorage on service initialization
    const token = this.getToken();
    if (token) {
      this.loadUserDataFromToken();
    }
  }

  register(user: User): Observable<any> {
    return this.http.post(`${this.apiUrl}/register`, user);
  }

  login(loginData: Login): Observable<any> {
    return this.http.post(`${this.apiUrl}/login`, loginData).pipe(
      tap((response: any) => {
        if (response.token) {
          localStorage.setItem('token', response.token);
          this.loadUserDataFromToken();
        }
      })
    );
  }

  logout(): void {
    localStorage.removeItem('token');
    localStorage.removeItem('userRole');
    localStorage.removeItem('userId');
    localStorage.removeItem('username');
    this.userRoleSubject.next('');
    this.userIdSubject.next(0);
    this.usernameSubject.next('');
  }

  getToken(): string | null {
    return localStorage.getItem('token');
  }

  isLoggedIn(): boolean {
    return !!this.getToken();
  }

  getUserRole(): string {
    return localStorage.getItem('userRole') || '';
  }

  getUserId(): number {
    return parseInt(localStorage.getItem('userId') || '0');
  }

  getUsername(): string {
    return localStorage.getItem('username') || '';
  }

  private loadUserDataFromToken(): void {
    const token = this.getToken();
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        
        console.log('Decoded JWT payload:', payload);
        console.log('Available claim keys:', Object.keys(payload));

        const role = payload['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'] || '';
        const userId = payload['UserId'] || '0';
        
        const username = payload['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'] || '';
        
        localStorage.setItem('userRole', role);
        localStorage.setItem('userId', userId);
        localStorage.setItem('username', username);
        
        this.userRoleSubject.next(role);
        this.userIdSubject.next(parseInt(userId));
        this.usernameSubject.next(username);
      } catch (error) {
        console.error('Error parsing token:', error);
      }
    }
  }

  getAuthHeaders(): HttpHeaders {
    const token = this.getToken();
    return new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    });
  }
}
-----------------
feedackserviceimport { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { Feedback } from '../models/feedback.model';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})
export class FeedbackService {
  private apiUrl = `${environment.apiUrl}/api/Feedback`;

  constructor(
    private http: HttpClient,
    private authService: AuthService
  ) { }

  getAllFeedbacks(): Observable<Feedback[]> {
    return this.http.get<Feedback[]>(this.apiUrl, {
      headers: this.authService.getAuthHeaders()
    });
  }

  getFeedbacksByUserId(userId: number): Observable<Feedback[]> {
    return this.http.get<Feedback[]>(`${this.apiUrl}/user/${userId}`, {
      headers: this.authService.getAuthHeaders()
    });
  }

  addFeedback(feedback: Feedback): Observable<any> {
    return this.http.post(this.apiUrl, feedback, {
      headers: this.authService.getAuthHeaders()
    });
  }

  deleteFeedback(id: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}/${id}`, {
      headers: this.authService.getAuthHeaders()
    });
  }
}

----------------------------
internshipservice
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { Internship } from '../models/internship.model';
import { AuthService } from './auth.service';
import Swal from 'sweetalert2';
@Injectable({
  providedIn: 'root'
})

export class InternshipService {
  
  private apiUrl = `${environment.apiUrl}/api/internship`;

  constructor(private http: HttpClient, private authService: AuthService) {}

  getAllInternships(): Observable<Internship[]> {
    return this.http.get<Internship[]>(this.apiUrl, {
      headers: this.authService.getAuthHeaders()
    });
  }

  getInternshipById(id: number): Observable<Internship> {
    return this.http.get<Internship>(`${this.apiUrl}/${id}`, {
      headers: this.authService.getAuthHeaders()
    });
  }

  addInternship(internship: Internship): Observable<any> {
    return this.http.post(this.apiUrl, internship, {
      headers: this.authService.getAuthHeaders()
    });
  }

  updateInternship(id: number, internship: Internship): Observable<any> {
    return this.http.put(`${this.apiUrl}/${id}`, internship, {
      headers: this.authService.getAuthHeaders()
    });
  }

  deleteInternship(id: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}/${id}`, {
      headers: this.authService.getAuthHeaders()
    });
  }



  downloadInternshipsCSV(): void {
    const url = `${this.apiUrl}/export-csv`;
    const token = localStorage.getItem('token'); // or this.authService.getToken()
 
    if (!token) {
        // Handle case where token is not available
        Swal.fire({
            icon: 'error',
            title: 'Authentication Error',
            text: 'You must be logged in to download the CSV file.',
            confirmButtonColor: '#667eea'
        });
        return;
    }

    fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(response => {
      if (!response.ok) {
        // Handle specific error codes if needed, for example, 401 Unauthorized
        if (response.status === 401) {
            throw new Error('Authentication failed. Please log in again.');
        }
        throw new Error('Failed to download internships CSV');
      }
      return response.blob();
    })
    .then(blob => {
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = 'internships.csv';
      link.click();
      URL.revokeObjectURL(link.href);
    })
    .catch(error => {
      console.error('Download error:', error);
      Swal.fire({
        icon: 'error',
        title: 'Download Failed',
        text: error.message || 'Failed to download CSV file. Please try again.',
        confirmButtonColor: '#667eea'
      });
    });
  }
}
----------------------------
internshipapplicationservice
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { InternshipApplication } from '../models/internshipapplication.model';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})

export class InternshipApplicationService {
  private apiUrl = `${environment.apiUrl}/api/Internship-application`;

  constructor(
    private http: HttpClient,
    private authService: AuthService
  ) { }

  getAllInternshipApplications(): Observable<InternshipApplication[]> {
    return this.http.get<InternshipApplication[]>(this.apiUrl, {
      headers: this.authService.getAuthHeaders()
    });
  }

  getInternshipApplicationsByUserId(userId: number): Observable<InternshipApplication[]> {
    return this.http.get<InternshipApplication[]>(`${this.apiUrl}/user/${userId}`, {
      headers: this.authService.getAuthHeaders()
    });
  }

  addInternshipApplication(application: InternshipApplication): Observable<any> {
    return this.http.post(this.apiUrl, application, {
      headers: this.authService.getAuthHeaders()
    });
  }

  updateInternshipApplication(id: number, application: InternshipApplication): Observable<any> {
    return this.http.put(`${this.apiUrl}/${id}`, application, {
      headers: this.authService.getAuthHeaders()
    });
  }

  deleteInternshipApplication(id: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}/${id}`, {
      headers: this.authService.getAuthHeaders()
    });
  }
}
-------------------------------
app-routingmodule
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { LoginComponent } from './components/login/login.component';
import { RegistrationComponent } from './components/registration/registration.component';
import { HomeComponent } from './components/home/home.component';
import { ErrorComponent } from './components/error/error.component';
import { AuthGuard } from './components/authguard/auth.guard';

// Admin Components
import { AdminnavComponent } from './components/adminnav/adminnav.component';
import { CreateinternshipComponent } from './components/createinternship/createinternship.component';
import { ViewinternshipComponent } from './components/viewinternship/viewinternship.component';
import { AdmineditinternshipComponent } from './components/admineditinternship/admineditinternship.component';
import { RequestedinternshipComponent } from './components/requestedinternship/requestedinternship.component';
import { AdminviewfeedbackComponent } from './components/adminviewfeedback/adminviewfeedback.component';
import { InternshippiechartComponent } from './components/internshippiechart/internshippiechart.component';

// User Components
import { UsernavComponent } from './components/usernav/usernav.component';
import { UserviewinternshipComponent } from './components/userviewinternship/userviewinternship.component';
import { InternshipformComponent } from './components/internshipform/internshipform.component';
import { UserappliedinternshipComponent } from './components/userappliedinternship/userappliedinternship.component';
import { UseraddfeedbackComponent } from './components/useraddfeedback/useraddfeedback.component';
import { UserviewfeedbackComponent } from './components/userviewfeedback/userviewfeedback.component';

const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent },
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegistrationComponent },
  { path: 'error', component: ErrorComponent },
  
  // Admin Routes
  {
    path: 'admin',
    component: AdminnavComponent,
    canActivate: [AuthGuard],
    children: [
      { path: 'home', component: HomeComponent },
      { path: 'internship/create', component: CreateinternshipComponent },
      { path: 'internship/view', component: ViewinternshipComponent },
      { path: 'internship/edit/:id', component: AdmineditinternshipComponent },
      { path: 'internship-requested', component: RequestedinternshipComponent },
      { path: 'feedbacks', component: AdminviewfeedbackComponent },
      { path: 'piechart', component: InternshippiechartComponent }
    ]
  },
  
  // User Routes
  {
    path: 'user',
    component: UsernavComponent,
    canActivate: [AuthGuard],
    children: [
      { path: 'home', component: HomeComponent },
      { path: 'internships', component: UserviewinternshipComponent },
      { path: 'internship/apply/:id', component: InternshipformComponent },
      { path: 'applied-internships', component: UserappliedinternshipComponent },
      { path: 'feedback/add', component: UseraddfeedbackComponent },
      { path: 'feedback/view', component: UserviewfeedbackComponent }
    ]
  },
  
  { path: '**', redirectTo: '/error' }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
------------------------
app.module.ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { AgGridModule } from 'ag-grid-angular';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { AdminnavComponent } from './components/adminnav/adminnav.component';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import {HttpClientModule} from '@angular/common/http';
import { LoginComponent } from './components/login/login.component';
import { RequestedinternshipComponent } from './components/requestedinternship/requestedinternship.component';
import { UserviewinternshipComponent } from './components/userviewinternship/userviewinternship.component'
import { RegistrationComponent } from './components/registration/registration.component';
import { NavbarComponent } from './components/navbar/navbar.component';
import { HomeComponent } from './components/home/home.component';
import { ErrorComponent } from './components/error/error.component';
import { ViewinternshipComponent } from './components/viewinternship/viewinternship.component'
import { CreateinternshipComponent } from './components/createinternship/createinternship.component';
import { NgxCaptchaModule } from 'ngx-captcha';
import { UsernavComponent } from './components/usernav/usernav.component';
import { InternshipformComponent } from './components/internshipform/internshipform.component';
import { UserappliedinternshipComponent } from './components/userappliedinternship/userappliedinternship.component';
import { UseraddfeedbackComponent } from './components/useraddfeedback/useraddfeedback.component';
import { UserviewfeedbackComponent } from './components/userviewfeedback/userviewfeedback.component';
import { AdminviewfeedbackComponent } from './components/adminviewfeedback/adminviewfeedback.component';
import { AdmineditinternshipComponent } from './components/admineditinternship/admineditinternship.component';
import { InternshippiechartComponent } from './components/internshippiechart/internshippiechart.component';

@NgModule({
  declarations: [
    AppComponent,
    AdminnavComponent,
    AppComponent,
    LoginComponent,
    RequestedinternshipComponent,
    UserviewinternshipComponent,
    RegistrationComponent,
    NavbarComponent,
    HomeComponent,
    ErrorComponent,
    CreateinternshipComponent,
    ViewinternshipComponent,
    UsernavComponent,
    InternshipformComponent,
    UserappliedinternshipComponent,
    UseraddfeedbackComponent,
    UserviewfeedbackComponent,
    AdminviewfeedbackComponent,
    AdmineditinternshipComponent,
    InternshippiechartComponent
   
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    ReactiveFormsModule,
    HttpClientModule,
    AgGridModule.withComponents([]),
    NgxCaptchaModule,
    ReactiveFormsModule
    
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
-------------------
app.component.thtml
<app-navbar></app-navbar>
<router-outlet></router-outlet>
--------------------
app.component.ts
import { Component, OnInit } from '@angular/core';
import { Router, NavigationEnd } from '@angular/router';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {
  showNavbar = true;

  constructor(private router: Router) {}

  ngOnInit() {
    this.router.events.subscribe(event => {
      if (event instanceof NavigationEnd) {
        // Hide nav on dashboard/admin pages ONLY show on login/landing/register
        this.showNavbar = ["/login", "/register", "/"].includes(event.url);
      }
    });
  }
}
--------------------
environment prod
export const environment = {
  production: true
};

-------------------
environment.ts
// This file can be replaced during build by using the `fileReplacements` array.
// `ng build --prod` replaces `environment.ts` with `environment.prod.ts`.
// The list of file replacements can be found in `angular.json`.

export const environment = {
  production: false,
  apiUrl: 'https://8080-eaabbcaebcdeffadacaefcaeacaadabeafeaccfe.premiumproject.examly.io',
  siteKey:"6Lcxd_grAAAAACyeuXwSlefIJRywYMOObGCk6zh9"

};

/*
 * For easier debugging in development mode, you can import the following file
 * to ignore zone related error stack frames such as `zone.run`, `zoneDelegate.invokeTask`.
 *
 * This import should be commented out in production mode because it will have a negative impact
 * on performance if an error is thrown.
 */
// import 'zone.js/dist/zone-error';  // Included with Angular CLI.
-----------------
index.html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Angularapp</title>
  <base href="/">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/x-icon" href="favicon.ico">
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
  <app-root></app-root>
</body>
</html>
------------------------------
main.ts
import { enableProdMode } from '@angular/core';
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';

import { AppModule } from './app/app.module';
import { environment } from './environments/environment';

if (environment.production) {
  enableProdMode();
}

platformBrowserDynamic().bootstrapModule(AppModule)
  .catch(err => console.error(err));
-----------------------
appsettings.json
{
  "ConnectionStrings": {
    "DefaultConnection": "User ID=sa;password=examlyMssql@123;server=localhost;Database=appdb;trusted_connection=false;Persist Security Info=False;Encrypt=False"
  },
  "JWT": {
    "ValidAudience": "https://8081-eaabbcaebcdeffadacaefcaeacaadabeafeaccfe.premiumproject.examly.io",
    "ValidIssuer": "https://8080-eaabbcaebcdeffadacaefcaeacaadabeafeaccfe.premiumproject.examly.io",
    "Secret": "ThisIsAVerySecretKeyForJWTTokenGeneration12345"
  },
  "AdminSettings": {
    "SecretKey": "Admin@123"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.EntityFrameworkCore": "Information"
    }
  },
  "AllowedHosts": "*"
}
----------------------------



