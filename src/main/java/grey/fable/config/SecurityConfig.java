package grey.fable.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security 配置类
 *
 * @author Fable
 * @since 2024/6/13 15:13
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(registry -> registry
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated()
                )
                // 自定义表单登录页面
                .formLogin(configurer -> configurer.loginPage("/login"));
        return http.build();
    }

    /**
     * 配置密码解析器, 使用 BCrypt 的方式对密码进行加密和验证
     *
     * @return {@link PasswordEncoder}
     * @author Fable
     * @since 2024/6/13 15:15
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 暂时配置一个基于内存的用户, Spring Security 在用户认证时默认会调用 {@link UserDetailsService#loadUserByUsername(String)}
     * 方法根据账号查询用户信息, 一般是重写该方法实现自己的逻辑
     *
     * @param passwordEncoder {@link PasswordEncoder}
     * @return {@link UserDetailsService}
     * @author Fable
     * @since 2024/6/13 15:15
     */
    @Bean
    public UserDetailsService users(PasswordEncoder passwordEncoder) {
        UserDetails user = User.withUsername("admin")
                .password(passwordEncoder.encode("123456"))
                .roles("admin", "normal")
                .authorities("app", "web", "test01", "test02")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}