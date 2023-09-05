package com.example.springsecurity.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.springsecurity.jwt.AuthTokenFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {

	private AuthenticationEntryPoint unauthorizedHandler;

	private UserDetailsService userDetailsService;

	public SecurityConfiguration(AuthenticationEntryPoint unauthorizedHandler, UserDetailsService userDetailsService) {
		this.unauthorizedHandler = unauthorizedHandler;
		this.userDetailsService = userDetailsService;
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setPasswordEncoder(passwordEncoder());
		authProvider.setUserDetailsService(userDetailsService);
		return authProvider;

	}
	@Bean
	public AuthTokenFilter authJwTokenFilter() {
		return new AuthTokenFilter();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		return authConfig.getAuthenticationManager();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		return http.csrf((csrf) -> csrf.disable())
				.exceptionHandling((exception) -> exception.authenticationEntryPoint(unauthorizedHandler))
				.authorizeHttpRequests((auth) -> 
					auth.requestMatchers("/api/test/**").permitAll()
						.requestMatchers("/api/auth/**").permitAll()
						.requestMatchers("/swagger-ui/**",
		                        "/swagger-resources/*",
		                        "/v3/api-docs/**").permitAll()
					.anyRequest().authenticated())
				.authenticationProvider(authenticationProvider())
				.addFilterBefore(authJwTokenFilter(), UsernamePasswordAuthenticationFilter.class)
				.build();

	}

}
