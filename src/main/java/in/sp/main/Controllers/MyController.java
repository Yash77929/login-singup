package in.sp.main.Controllers;

import in.sp.main.filter.JwtBlacklist;
import in.sp.main.utility.JwtUtil;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import in.sp.main.entities.User;
import in.sp.main.services.UserService;

@Controller
public class MyController {

	@Autowired
	private UserService userService;

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private JwtBlacklist jwtBlacklist;

	// --- Registration Page (Thymeleaf) ---
	@GetMapping("/regPage")
	public String openRegPage(Model model) {
		model.addAttribute("user", new User());
		return "register";
	}

	@PostMapping("/regForm")
	public String submitRegForm(@ModelAttribute("user") User user, Model model) {
		boolean status = userService.registerUser(user);
		if (status) {
			model.addAttribute("successMsg", "User registered successfully");
		} else {
			model.addAttribute("errorMsg", "User not registered due to some error");
		}
		return "register";
	}

	// --- Login Page (Thymeleaf) ---
	@GetMapping("/loginPage")
	public String openLoginPage(Model model) {
		model.addAttribute("user", new User());
		return "login";
	}

	@PostMapping("/loginForm")
	public String submitLoginForm(@ModelAttribute("user") User user, Model model, HttpSession session) {
		User validUser = userService.loginUser(user.getEmail(), user.getPassword());
		if (validUser != null) {
			session.setAttribute("loggedInUser", validUser.getEmail()); // Save login state
			model.addAttribute("modelName", validUser.getName());
			return "profile";
		} else {
			model.addAttribute("errorMsg", "Email and password do not match");
			return "login";
		}
	}

	// --- JWT Login API (Postman / Frontend JS) ---
	@PostMapping("/api/login")
	@ResponseBody
	public ResponseEntity<?> loginAndGetToken(@RequestBody User user) {
		User validUser = userService.loginUser(user.getEmail(), user.getPassword());
		if (validUser != null) {
			String token = jwtUtil.generateToken(validUser.getEmail());
			return ResponseEntity.ok("{\"token\": \"" + token + "\"}");
		} else {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
		}
	}

	// --- JWT Profile API ---
	@GetMapping("/api/profile")
	@ResponseBody
	public ResponseEntity<?> getProfile(@RequestHeader("Authorization") String authHeader) {
		try {
			String token = authHeader.substring(7); // Remove "Bearer "
			if (jwtBlacklist.isTokenBlacklisted(token)) {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token has been logged out");
			}

			String email = jwtUtil.extractUsername(token);
			if (jwtUtil.validateToken(token, email)) {
				User user = userService.findByEmail(email);
				return ResponseEntity.ok("Welcome " + user.getName());
			} else {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
			}
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Authorization header");
		}
	}

	// --- JWT Logout API ---
	@PostMapping("/api/logout")
	@ResponseBody
	public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
		try {
			String token = authHeader.substring(7); // Remove "Bearer "
			jwtBlacklist.blacklistToken(token);
			return ResponseEntity.ok("Successfully logged out");
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Authorization header");
		}
	}
	@GetMapping("/logout")
	public String logoutSession(HttpSession session) {
		session.invalidate(); // destroy session
		return "redirect:/loginPage";
	}
	@GetMapping("/profile")
	public String showProfile(HttpSession session, Model model) {
		String email = (String) session.getAttribute("loggedInUser");
		if (email != null) {
			User user = userService.findByEmail(email);
			model.addAttribute("modelName", user.getName());
			return "profile";
		} else {
			return "redirect:/loginPage"; // No session? redirect to login
		}
	}

}
