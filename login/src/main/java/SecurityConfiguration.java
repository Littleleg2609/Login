import org.jetbrains.annotations.NotNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends SecurityConfiguration1 {
    @Override
    protected void configure(@NotNull HttpSecurity http) throws Exception{
        http.authorizeRequests().anyRequest().authenticated().and().formLogin();
    }
    @Override
    protected void configure(@NotNull AuthenticationManagerBuilder auth) throws Exception{
        auth.inMemoryAuthentication().withUser("user").password(passwordEncoder().encode("password")).authorities("USER");
    }
    

}

