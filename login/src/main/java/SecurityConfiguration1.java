import org.jetbrains.annotations.NotNull;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public abstract class SecurityConfiguration1 extends WebSecurityConfiguration {
    @Bean
    public static BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    protected abstract void configure(@NotNull HttpSecurity http) throws Exception;

    protected abstract void configure(@NotNull AuthenticationManagerBuilder auth) throws Exception;
}
