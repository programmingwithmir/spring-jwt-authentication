package com.example.springsecurity.exception;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.expression.spel.SpelParseException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<?> handleValidationErrors(MethodArgumentNotValidException ex, WebRequest request) {

		List<String> errors = ex.getBindingResult().getFieldErrors().stream().map((error) -> error.getField()+" : "+error.getDefaultMessage())
				.collect(Collectors.toList());

		Map<String, List<String>> errorResponse = new HashMap<>();
		errorResponse.put("errors", errors);

		return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);

	}
	
	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<?> globalExceptionHandler(AccessDeniedException ex, WebRequest request) {

		ErrorDetails errorDetails = new ErrorDetails(new Date(), ex.getMessage(), "You don't have permission to access this resource.");

		return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
	}
	
	@ExceptionHandler(SpelParseException.class)
	public ResponseEntity<?> globalExceptionHandler(SpelParseException ex, WebRequest request) {

		ErrorDetails errorDetails = new ErrorDetails(new Date(), "Access Denied", "You don't have permission to access this resource.");

		return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
	}
	
	@ExceptionHandler(Exception.class)
	public ResponseEntity<?> globalExceptionHandler(Exception ex, WebRequest request) {
		ErrorDetails errorDetails = new ErrorDetails(new Date(), ex.getMessage(), ex.getClass().getName());
		return new ResponseEntity<>(errorDetails,HttpStatus.INTERNAL_SERVER_ERROR);
	}

}
