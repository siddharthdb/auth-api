// src/main/java/com/enterprise/authapi/AuthApiApplication.java
package com.enterprise.authapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main application class
 */
@SpringBootApplication
@EnableScheduling
public class AuthApiApplication {
	public static void main(String[] args) {
		SpringApplication.run(AuthApiApplication.class, args);
	}
}