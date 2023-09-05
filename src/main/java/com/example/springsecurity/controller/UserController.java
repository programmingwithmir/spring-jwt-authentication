package com.example.springsecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.springsecurity.payloads.MessageResponse;

@RestController
@RequestMapping("/api/user")
@PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
public class UserController {
	
	
	@GetMapping("/info")
	public String helloUserController() {
		return "User access level";
	}
	
	@GetMapping("/details")
	public ResponseEntity<?> getuserDetails(Authentication authentication) {
		try {
			UserDetails userDetails = (UserDetails) authentication.getPrincipal();
			return ResponseEntity.ok(userDetails) ;
		} catch (Exception e) {
			return ResponseEntity.ok(new MessageResponse("No details found"));
		} 
	}
	
	
	

}
