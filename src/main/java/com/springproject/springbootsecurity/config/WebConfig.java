package com.springproject.springbootsecurity.config;

import com.springproject.springbootsecurity.repository.UserRepository;
import com.springproject.springbootsecurity.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class WebConfig implements WebMvcConfigurer {

    @Autowired @Lazy
    private  JwtTokenFilter jwtTokenFilter;
    @Autowired
    private  JwtService jwtService;

   /* public WebConfig(JwtTokenFilter jwtTokenFilter, JwtService jwtService) {
        this.jwtTokenFilter = jwtTokenFilter;
        this.jwtService = jwtService;
    }*/

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/login", "/register").permitAll()
                        .anyRequest().authenticated() // No role checks
                )
                .formLogin(formLogin -> formLogin
                .successHandler(authenticationSuccessHandler()) // Use custom success handler
                .permitAll()
        ).sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Use sessions if needed
                ).cors(withDefaults())
                .csrf(csrf -> csrf.disable());

        http.addFilterBefore(
                jwtTokenFilter,
                UsernamePasswordAuthenticationFilter.class
        );
        return http.build();

    }
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:3000") // Adjust to your frontend's URL
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowCredentials(true)  // Allow credentials (e.g., cookies, session IDs)
                .allowedHeaders("*");
    }

private AuthenticationSuccessHandler authenticationSuccessHandler() {
    return (HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
        String username = authentication.getName();
        String token = jwtService.generateToken(username);

        // Set the token in the response header
        response.setHeader("Authorization", "Bearer " + token);
        System.out.println(token);
        // Optionally, you can also set it in the response body
        response.getWriter().write("{\"token\":\"" + token + "\"}");
        response.getWriter().flush();
    };
}
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) {
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);

        // Custom SQL query for user authentication
        manager.setUsersByUsernameQuery("SELECT username, password, enabled FROM users WHERE username = ?");

        // Custom SQL query for loading user roles
        manager.setAuthoritiesByUsernameQuery(
                """
                        SELECT u.username, r.name AS authority 
                        FROM users u 
                        JOIN user_roles ur ON u.id = ur.user_id 
                        JOIN roles r ON ur.role_id = r.id 
                        WHERE u.username = ?
                """
        );
        return manager;
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }













    //    @Bean
//    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
//        UserDetails user1 = User.builder()
//                .username("user1")
//                .password(passwordEncoder().encode("password1"))
//                .roles("USER")
//                .build();
//
//        UserDetails user2 = User.builder()
//                .username("admin")
//                .password(passwordEncoder().encode("admin"))
//                .roles("ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(user1, user2);
//    }


//    @Bean
//    public UserDetailsManager userDetailsManager (DataSource dataSource) {
//
//        return  new JdbcUserDetailsManager(dataSource);
//    }
}

